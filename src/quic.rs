//! QUIC packet and header protection (RFC 9001).
//!
//! Provides AEAD packet protection and header protection for the TLS 1.3
//! cipher suites that QUIC uses: AES-128-GCM, AES-256-GCM, AES-128-CCM, and
//! ChaCha20-Poly1305. AES-128-CCM-8 is not supported for QUIC because header
//! protection requires a 16-byte authentication tag sample.

#![allow(clippy::duplicate_mod)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aead::{AeadInOut, KeyInit as AeadKeyInit, KeySizeUser};
use aes::cipher::BlockCipherEncrypt;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20,
};
use crypto_common::typenum::Unsigned;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::{quic, Error};

/// Sample length shared by all header-protection algorithms in RFC 9001.
const SAMPLE_LEN: usize = 16;

/// Header-protection mask size: 1 byte for the first header byte + 4 for PN.
const MASK_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Header protection
// ---------------------------------------------------------------------------

enum HeaderProtectionKey {
    // AES expanded keys are large; box them so the enum stays compact.
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
    ChaCha20(chacha20::Key),
}

impl HeaderProtectionKey {
    fn new_aes128(key: AeadKey) -> Result<Self, Error> {
        aes::Aes128::new_from_slice(key.as_ref())
            .map(|cipher| Self::Aes128(Box::new(cipher)))
            .map_err(|_| Error::General("invalid AES-128 header protection key".into()))
    }

    fn new_aes256(key: AeadKey) -> Result<Self, Error> {
        aes::Aes256::new_from_slice(key.as_ref())
            .map(|cipher| Self::Aes256(Box::new(cipher)))
            .map_err(|_| Error::General("invalid AES-256 header protection key".into()))
    }

    fn new_chacha20(key: AeadKey) -> Result<Self, Error> {
        let key = chacha20::Key::try_from(key.as_ref())
            .map_err(|_| Error::General("invalid ChaCha20 header protection key".into()))?;
        Ok(Self::ChaCha20(key))
    }

    /// Produce the 5-byte header-protection mask from a 16-byte sample.
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; MASK_LEN], Error> {
        if sample.len() < SAMPLE_LEN {
            return Err(Error::General("sample of invalid length".into()));
        }

        match self {
            // RFC 9001 §5.4.3 — AES-ECB over the 16-byte sample.
            Self::Aes128(cipher) => {
                let mut block = sample[..SAMPLE_LEN]
                    .try_into()
                    .map_err(|_| Error::General("sample of invalid length".into()))?;
                cipher.encrypt_block(&mut block);
                block[..MASK_LEN]
                    .try_into()
                    .map_err(|_| Error::General("mask of invalid length".into()))
            }
            Self::Aes256(cipher) => {
                let mut block = sample[..SAMPLE_LEN]
                    .try_into()
                    .map_err(|_| Error::General("sample of invalid length".into()))?;
                cipher.encrypt_block(&mut block);
                block[..MASK_LEN]
                    .try_into()
                    .map_err(|_| Error::General("mask of invalid length".into()))
            }
            // RFC 9001 §5.4.4 — ChaCha20 keystream over five zero bytes.
            Self::ChaCha20(key) => {
                let counter = u32::from_le_bytes(
                    sample[0..4]
                        .try_into()
                        .map_err(|_| Error::General("sample of invalid length".into()))?,
                );
                let nonce = sample[4..SAMPLE_LEN]
                    .try_into()
                    .map_err(|_| Error::General("sample of invalid length".into()))?;
                let mut chacha = ChaCha20::new(key, &nonce);
                chacha
                    .try_seek(counter)
                    .map_err(|_| Error::General("ChaCha20 seek failed".into()))?;
                let mut mask = [0u8; MASK_LEN];
                chacha.apply_keystream(&mut mask);
                Ok(mask)
            }
        }
    }

    /// Apply or remove header protection (RFC 9001 §5.4.1).
    ///
    /// When `masked` is true the first byte is currently protected (decrypt
    /// path); when false it is still plaintext (encrypt path).
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let mask = self.new_mask(sample)?;
        let (first_mask, pn_mask) = mask
            .split_first()
            .ok_or_else(|| Error::General("mask of invalid length".into()))?;

        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f // Long header: 4 bits masked
        } else {
            0x1f // Short header: 5 bits masked
        };

        // When unmasking, recover the packet-number length from the unmasked first byte.
        let first_plain = if masked {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    #[inline]
    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

// ---------------------------------------------------------------------------
// Packet keys
// ---------------------------------------------------------------------------

struct PacketKey<A> {
    key: A,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl<A> PacketKey<A>
where
    A: AeadKeyInit + AeadInOut + Send + Sync,
{
    fn new(key: AeadKey, iv: Iv, confidentiality_limit: u64, integrity_limit: u64) -> Self {
        Self {
            key: A::new_from_slice(key.as_ref()).expect("invalid AEAD key length"),
            iv,
            confidentiality_limit,
            integrity_limit,
        }
    }

    fn encrypt_with_nonce(
        &self,
        nonce: &[u8; rustls::crypto::cipher::NONCE_LEN],
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = aead::Nonce::<A>::try_from(&nonce[..])
            .map_err(|_| Error::General("invalid AEAD nonce length".into()))?;
        let tag = self
            .key
            .encrypt_inout_detached(&nonce, header, payload.into())
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn decrypt_with_nonce<'a>(
        &self,
        nonce: &[u8; rustls::crypto::cipher::NONCE_LEN],
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let tag_len = A::TagSize::to_usize();
        if payload.len() < tag_len {
            return Err(Error::DecryptError);
        }
        let (body, tag_bytes) = payload.split_at_mut(payload.len() - tag_len);
        let nonce = aead::Nonce::<A>::try_from(&nonce[..])
            .map_err(|_| Error::General("invalid AEAD nonce length".into()))?;
        let tag = aead::Tag::<A>::try_from(&tag_bytes[..]).map_err(|_| Error::DecryptError)?;
        self.key
            .decrypt_inout_detached(&nonce, header, body.into(), &tag)
            .map_err(|_| Error::DecryptError)?;
        let plain_len = payload.len() - tag_len;
        Ok(&payload[..plain_len])
    }
}

impl<A> quic::PacketKey for PacketKey<A>
where
    A: AeadKeyInit + AeadInOut + Send + Sync,
{
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.encrypt_with_nonce(&Nonce::new(&self.iv, packet_number).0, header, payload)
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.encrypt_with_nonce(
            &Nonce::for_path(path_id, &self.iv, packet_number).0,
            header,
            payload,
        )
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.decrypt_with_nonce(&Nonce::new(&self.iv, packet_number).0, header, payload)
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.decrypt_with_nonce(
            &Nonce::for_path(path_id, &self.iv, packet_number).0,
            header,
            payload,
        )
    }

    #[inline]
    fn tag_len(&self) -> usize {
        A::TagSize::to_usize()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

// ---------------------------------------------------------------------------
// Algorithm builders wired into TLS 1.3 suites
// ---------------------------------------------------------------------------

/// Which AEAD + header-protection pair a [`KeyBuilder`] constructs.
#[derive(Clone, Copy)]
enum AlgorithmKind {
    Aes128Gcm,
    Aes256Gcm,
    Aes128Ccm,
    ChaCha20Poly1305,
}

/// QUIC key algorithm for a single TLS 1.3 cipher suite.
pub struct KeyBuilder {
    kind: AlgorithmKind,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

/// AES-128-GCM packet protection with AES-128-ECB header protection.
///
/// Limits match the ring provider (RFC 9001 §6.6).
pub static AES_128_GCM: &dyn quic::Algorithm = &KeyBuilder {
    kind: AlgorithmKind::Aes128Gcm,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// AES-256-GCM packet protection with AES-256-ECB header protection.
pub static AES_256_GCM: &dyn quic::Algorithm = &KeyBuilder {
    kind: AlgorithmKind::Aes256Gcm,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// AES-128-CCM packet protection with AES-128-ECB header protection.
///
/// Same header-protection construction as AES-GCM (RFC 9001 §5.4.3).
pub static AES_128_CCM: &dyn quic::Algorithm = &KeyBuilder {
    kind: AlgorithmKind::Aes128Ccm,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
};

/// ChaCha20-Poly1305 packet protection with ChaCha20 header protection.
pub static CHACHA20_POLY1305: &dyn quic::Algorithm = &KeyBuilder {
    kind: AlgorithmKind::ChaCha20Poly1305,
    confidentiality_limit: u64::MAX,
    integrity_limit: 1 << 36,
};

impl quic::Algorithm for KeyBuilder {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        match self.kind {
            AlgorithmKind::Aes128Gcm => Box::new(PacketKey::<aes_gcm::Aes128Gcm>::new(
                key,
                iv,
                self.confidentiality_limit,
                self.integrity_limit,
            )),
            AlgorithmKind::Aes256Gcm => Box::new(PacketKey::<aes_gcm::Aes256Gcm>::new(
                key,
                iv,
                self.confidentiality_limit,
                self.integrity_limit,
            )),
            AlgorithmKind::Aes128Ccm => Box::new(PacketKey::<crate::aead::ccm::Aes128Ccm>::new(
                key,
                iv,
                self.confidentiality_limit,
                self.integrity_limit,
            )),
            AlgorithmKind::ChaCha20Poly1305 => {
                Box::new(PacketKey::<chacha20poly1305::ChaCha20Poly1305>::new(
                    key,
                    iv,
                    self.confidentiality_limit,
                    self.integrity_limit,
                ))
            }
        }
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        let hpk = match self.kind {
            AlgorithmKind::Aes128Gcm | AlgorithmKind::Aes128Ccm => {
                HeaderProtectionKey::new_aes128(key).expect("AES-128 HP key")
            }
            AlgorithmKind::Aes256Gcm => {
                HeaderProtectionKey::new_aes256(key).expect("AES-256 HP key")
            }
            AlgorithmKind::ChaCha20Poly1305 => {
                HeaderProtectionKey::new_chacha20(key).expect("ChaCha20 HP key")
            }
        };
        Box::new(hpk)
    }

    fn aead_key_len(&self) -> usize {
        match self.kind {
            AlgorithmKind::Aes128Gcm => aes_gcm::Aes128Gcm::key_size(),
            AlgorithmKind::Aes256Gcm => aes_gcm::Aes256Gcm::key_size(),
            AlgorithmKind::Aes128Ccm => crate::aead::ccm::Aes128Ccm::key_size(),
            AlgorithmKind::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::key_size(),
        }
    }

    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::quic::{Keys, Version};
    use rustls::Side;

    fn tls13_suite(suite: rustls::SupportedCipherSuite) -> &'static rustls::Tls13CipherSuite {
        match suite {
            rustls::SupportedCipherSuite::Tls13(s) => s,
            _ => panic!("expected TLS 1.3 suite"),
        }
    }

    /// Encrypt/decrypt round-trip through initial keys derived like a real QUIC handshake.
    fn packet_roundtrip(suite: rustls::SupportedCipherSuite) {
        let suite = tls13_suite(suite);
        let quic_alg = suite.quic.expect("suite should advertise QUIC support");
        let keys = Keys::initial(
            Version::V1,
            suite,
            quic_alg,
            b"\x00\x01\x02\x03\x04\x05\x06\x07",
            Side::Client,
        );

        let header = b"quic-aad";
        let mut payload = b"hello from quic packet key".to_vec();
        let original = payload.clone();
        let tag = keys
            .local
            .packet
            .encrypt_in_place(42, header, &mut payload)
            .expect("encrypt");
        payload.extend_from_slice(tag.as_ref());

        // Peer's remote key is our local key when roles are swapped; re-derive server view.
        let server = Keys::initial(
            Version::V1,
            suite,
            quic_alg,
            b"\x00\x01\x02\x03\x04\x05\x06\x07",
            Side::Server,
        );
        let plain = server
            .remote
            .packet
            .decrypt_in_place(42, header, &mut payload)
            .expect("decrypt");
        assert_eq!(plain, original.as_slice());
    }

    #[test]
    fn aes128_gcm_initial_packet_roundtrip() {
        packet_roundtrip(crate::TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn aes256_gcm_initial_packet_roundtrip() {
        packet_roundtrip(crate::TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn chacha20_initial_packet_roundtrip() {
        packet_roundtrip(crate::TLS13_CHACHA20_POLY1305_SHA256);
    }

    #[test]
    fn aes128_ccm_initial_packet_roundtrip() {
        packet_roundtrip(crate::TLS13_AES_128_CCM_SHA256);
    }

    #[test]
    fn header_protection_roundtrip_aes128() {
        let suite = tls13_suite(crate::TLS13_AES_128_GCM_SHA256);
        let quic_alg = suite.quic.unwrap();
        let keys = Keys::initial(Version::V1, suite, quic_alg, b"conn-id!", Side::Client);
        let hpk = &keys.local.header;
        let sample = [0xab_u8; 16];
        let mut first = 0x40; // short header
        let mut pn = [0x00, 0x01, 0x02, 0x03];
        let first_orig = first;
        let pn_orig = pn;
        hpk.encrypt_in_place(&sample, &mut first, &mut pn)
            .expect("hp encrypt");
        assert_ne!((first, pn), (first_orig, pn_orig));
        hpk.decrypt_in_place(&sample, &mut first, &mut pn)
            .expect("hp decrypt");
        assert_eq!(first, first_orig);
        assert_eq!(pn, pn_orig);
    }

    #[test]
    fn header_protection_roundtrip_chacha20() {
        let suite = tls13_suite(crate::TLS13_CHACHA20_POLY1305_SHA256);
        let quic_alg = suite.quic.unwrap();
        let keys = Keys::initial(Version::V1, suite, quic_alg, b"conn-id!", Side::Client);
        let hpk = &keys.local.header;
        let sample = [0xcd_u8; 16];
        let mut first = 0xc0; // long header form
        let mut pn = [0x11, 0x22, 0x33, 0x44];
        let first_orig = first;
        let pn_orig = pn;
        hpk.encrypt_in_place(&sample, &mut first, &mut pn)
            .expect("hp encrypt");
        hpk.decrypt_in_place(&sample, &mut first, &mut pn)
            .expect("hp decrypt");
        assert_eq!(first, first_orig);
        assert_eq!(pn, pn_orig);
    }

    #[test]
    fn aead_key_lens() {
        assert_eq!(AES_128_GCM.aead_key_len(), 16);
        assert_eq!(AES_256_GCM.aead_key_len(), 32);
        assert_eq!(AES_128_CCM.aead_key_len(), 16);
        assert_eq!(CHACHA20_POLY1305.aead_key_len(), 32);
    }

    #[test]
    fn ccm8_has_no_quic() {
        let suite = tls13_suite(crate::TLS13_AES_128_CCM_8_SHA256);
        assert!(suite.quic.is_none());
    }
}
