mod hash;
mod hpke;
mod signature;

use self::hash::HashScheme;
use self::hpke::{
    algs::{Aead, Kdf, Kem},
    HpkeSuite,
};
use self::signature::SignatureScheme;
use super::*;

use std::collections::HashMap;

lazy_static! {
    static ref CIPHER_SUITE_DESCRIPTIONS: HashMap<CipherSuite, CipherSuiteDescription> =
        HashMap::from_iter([
            (
                CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA256),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_X25519_HKDF_SHA256,
                        Kdf::KDF_HKDF_SHA256,
                        Aead::AEAD_AES128GCM,
                    )),
                    signature: Arc::new(SignatureScheme::Ed25519),
                },
            ),
            (
                CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA256),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_P256_HKDF_SHA256,
                        Kdf::KDF_HKDF_SHA256,
                        Aead::AEAD_AES128GCM,
                    )),
                    signature: Arc::new(SignatureScheme::ECDSA_P256_SHA256),
                },
            ),
            (
                CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA256),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_X25519_HKDF_SHA256,
                        Kdf::KDF_HKDF_SHA256,
                        Aead::AEAD_ChaCha20Poly1305,
                    )),
                    signature: Arc::new(SignatureScheme::Ed25519),
                },
            ),
            (
                CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA512),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_X448_HKDF_SHA512,
                        Kdf::KDF_HKDF_SHA512,
                        Aead::AEAD_AES256GCM,
                    )),
                    signature: Arc::new(SignatureScheme::Ed448),
                },
            ),
            (
                CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA512),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_P521_HKDF_SHA512,
                        Kdf::KDF_HKDF_SHA512,
                        Aead::AEAD_AES256GCM,
                    )),
                    signature: Arc::new(SignatureScheme::ECDSA_P521_SHA512),
                },
            ),
            (
                CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA512),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_X448_HKDF_SHA512,
                        Kdf::KDF_HKDF_SHA512,
                        Aead::AEAD_ChaCha20Poly1305,
                    )),
                    signature: Arc::new(SignatureScheme::Ed448),
                },
            ),
            (
                CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
                CipherSuiteDescription {
                    hash: Arc::new(HashScheme::SHA384),
                    hpke: Arc::new(HpkeSuite::new(
                        Kem::KEM_P384_HKDF_SHA384,
                        Kdf::KDF_HKDF_SHA384,
                        Aead::AEAD_AES256GCM,
                    )),
                    signature: Arc::new(SignatureScheme::ECDSA_P384_SHA384),
                },
            ),
        ]);
}

pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {
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
        CIPHER_SUITE_DESCRIPTIONS
            .get(&cipher_suite)
            .unwrap()
            .hash
            .clone()
    }

    fn hpke(&self, cipher_suite: CipherSuite) -> Arc<dyn Hpke> {
        CIPHER_SUITE_DESCRIPTIONS
            .get(&cipher_suite)
            .unwrap()
            .hpke
            .clone()
    }

    fn signature(&self, cipher_suite: CipherSuite) -> Arc<dyn Signature> {
        CIPHER_SUITE_DESCRIPTIONS
            .get(&cipher_suite)
            .unwrap()
            .signature
            .clone()
    }
}
