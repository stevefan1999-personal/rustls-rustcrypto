#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aead::AeadCore;
use chacha20::{cipher::StreamCipher, ChaCha20};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, KeySizeUser, Nonce};
use crypto_common::{typenum::Unsigned, KeyIvInit};
use rustls::{
    crypto::cipher::{self, AeadKey, Iv},
    quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag},
    Error,
};

pub struct QuicChacha20;

impl Algorithm for QuicChacha20 {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(QuicChacha20PacketKey {
            iv,
            crypto: ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("key should be valid"),
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(QuicChacha20HeaderProtectionKey(key))
    }

    fn aead_key_len(&self) -> usize {
        ChaCha20Poly1305::key_size()
    }
}

pub struct QuicChacha20PacketKey {
    iv: Iv,
    crypto: ChaCha20Poly1305,
}

impl PacketKey for QuicChacha20PacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let nonce = cipher::Nonce::new(&self.iv, packet_number).0;

        let tag = self
            .crypto
            .encrypt_in_place_detached(&nonce.into(), header, payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let mut payload_ = payload.to_vec();
        let payload_len = payload_.len();
        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.iv, packet_number).0);

        self.crypto
            .decrypt_in_place(&nonce, header, &mut payload_)
            .map_err(|_| rustls::Error::DecryptError)?;

        // Unfortunately the lifetime bound on decrypt_in_place sucks
        payload.copy_from_slice(&payload_);

        let plain_len = payload_len - self.tag_len();
        Ok(&payload[..plain_len])
    }

    fn tag_len(&self) -> usize {
        <ChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
    }

    fn confidentiality_limit(&self) -> u64 {
        1 << 36
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

pub struct QuicChacha20HeaderProtectionKey(AeadKey);

impl QuicChacha20HeaderProtectionKey {
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let mut mask: [u8; 5] = [0; 5];
        let iv = Nonce::from_slice(sample);

        let mut cipher = ChaCha20::new_from_slices(self.0.as_ref(), iv).unwrap();
        cipher.apply_keystream(&mut mask);

        let (first_mask, pn_mask) = mask.split_first().unwrap();
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

impl HeaderProtectionKey for QuicChacha20HeaderProtectionKey {
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

    fn sample_len(&self) -> usize {
        <ChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
    }
}
