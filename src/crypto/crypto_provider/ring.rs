use super::*;
use crate::crypto::hash::HashScheme;
use crate::crypto::hpke::algs::{Aead, Kdf, Kem};
use crate::crypto::hpke::HpkeSuite;
use crate::crypto::signature::SignatureScheme;

pub struct RingCryptoProvider;

impl CryptoProvider for RingCryptoProvider {
    fn supports(&self, cipher_suite: CipherSuite) -> Result<()> {
        match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(()),
            _ => Err(Error::UnsupportedCipherSuite),
        }
    }

    fn supported(&self) -> Vec<CipherSuite> {
        vec![
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    fn hash(&self, cipher_suite: CipherSuite) -> Arc<dyn Hash> {
        let hs = match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HashScheme::SHA256
            }
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HashScheme::SHA384,
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HashScheme::SHA512,
        };
        Arc::new(hs)
    }

    fn hpke(&self, cipher_suite: CipherSuite) -> Arc<dyn Hpke> {
        let hs = match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => HpkeSuite::new(
                Kem::KEM_X25519_HKDF_SHA256,
                Kdf::KDF_HKDF_SHA256,
                Aead::AEAD_AES128GCM,
            ),
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeSuite::new(
                Kem::KEM_P256_HKDF_SHA256,
                Kdf::KDF_HKDF_SHA256,
                Aead::AEAD_AES128GCM,
            ),
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => HpkeSuite::new(
                Kem::KEM_X25519_HKDF_SHA256,
                Kdf::KDF_HKDF_SHA256,
                Aead::AEAD_ChaCha20Poly1305,
            ),
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => HpkeSuite::new(
                Kem::KEM_X448_HKDF_SHA512,
                Kdf::KDF_HKDF_SHA512,
                Aead::AEAD_AES256GCM,
            ),
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeSuite::new(
                Kem::KEM_P521_HKDF_SHA512,
                Kdf::KDF_HKDF_SHA512,
                Aead::AEAD_AES256GCM,
            ),
            CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HpkeSuite::new(
                Kem::KEM_X448_HKDF_SHA512,
                Kdf::KDF_HKDF_SHA512,
                Aead::AEAD_ChaCha20Poly1305,
            ),
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeSuite::new(
                Kem::KEM_P384_HKDF_SHA384,
                Kdf::KDF_HKDF_SHA384,
                Aead::AEAD_AES256GCM,
            ),
        };
        Arc::new(hs)
    }

    fn signature(&self, cipher_suite: CipherSuite) -> Arc<dyn Signature> {
        let ss = match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::Ed25519
            }
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_P256_SHA256
            }
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_P384_SHA384
            }
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_P521_SHA512
            }
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureScheme::Ed448
            }
        };
        Arc::new(ss)
    }
}
