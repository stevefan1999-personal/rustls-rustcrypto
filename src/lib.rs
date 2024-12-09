#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::from_iter_instead_of_collect,
    clippy::missing_errors_doc,
    clippy::mod_module_files,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    rust_2018_idioms,
    trivial_numeric_casts,
    unused_lifetimes
)]

#[cfg(not(feature = "alloc"))]
compile_error!("Rustls currently does not support alloc-less environments");

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::sync::Arc;

use pki_types::PrivateKeyDer;
use rustls::crypto::{CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom};
use rustls::sign::SigningKey;
use rustls::SupportedCipherSuite;

#[derive(Debug)]
pub struct Provider;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

impl SecureRandom for Provider {
    fn fill(&self, #[allow(unused_variables)] bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        #[cfg(feature = "rand")]
        {
            use rand_core::RngCore;
            rand_core::OsRng
                .try_fill_bytes(bytes)
                .map_err(|_| GetRandomFailed)
        }

        #[cfg(not(feature = "rand"))]
        {
            Err(GetRandomFailed)
        }
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        #[allow(unused_variables)] key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        #[cfg(feature = "sign")]
        {
            sign::any_supported_type(&key_der)
        }
        #[cfg(not(feature = "sign"))]
        {
            Err(rustls::Error::General("not key providers supported".into()))
        }
    }
}

pub const ALL_CIPHER_SUITES: &[SupportedCipherSuite] = misc::const_concat_slices!(
    SupportedCipherSuite,
    {
        #[cfg(feature = "tls12")]
        {
            tls12::suites::TLS12_SUITES
        }

        #[cfg(not(feature = "tls12"))]
        {
            &[]
        }
    },
    tls13::suites::TLS13_SUITES
);

#[cfg(feature = "aead")]
pub mod aead;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "hash")]
pub mod hmac;
#[cfg(feature = "kx")]
pub mod kx;
pub mod misc;
#[cfg(feature = "sign")]
pub mod sign;
#[cfg(feature = "tls12")]
pub mod tls12;
pub mod tls13;
#[cfg(feature = "verify")]
pub mod verify;

const _: () = assert!(
    !ALL_CIPHER_SUITES.is_empty(),
    "At least one cipher suite should be enabled"
);

const _: () = assert!(
    !kx::ALL_KX_GROUPS.is_empty(),
    "At least one key exchange algorithm should be enabled"
);
