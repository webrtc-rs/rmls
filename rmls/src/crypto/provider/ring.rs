mod hash;
mod hpke;
mod rand;
mod signature;

use self::hash::HashSchemeWrapper;
use self::hpke::HpkeSuiteWrapper;
use self::rand::RandChacha;
use self::signature::SignatureSchemeWrapper;
use super::*;
use crate::crypto::*;

struct CipherSuiteDescription {
    hash: HashSchemeWrapper,
    hpke: HpkeSuiteWrapper,
    signature: SignatureSchemeWrapper,
}

static CIPHER_SUITE_DESCRIPTIONS: [CipherSuiteDescription; 7 /*CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384*/] = [
    //1: CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA256),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_X25519_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_AES128GCM,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ED25519),
    },
    //2: CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA256),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_P256_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_AES128GCM,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ECDSA_SECP256R1_SHA256),
    },
    //3: CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA256),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_X25519_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_ChaCha20Poly1305,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ED25519),
    },
    //4: CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA512),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_X448_HKDF_SHA512,
            kdf: Kdf::KDF_HKDF_SHA512,
            aead: Aead::AEAD_AES256GCM,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ED448),
    },
    //5: CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA512),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_P521_HKDF_SHA512,
            kdf: Kdf::KDF_HKDF_SHA512,
            aead: Aead::AEAD_AES256GCM,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ECDSA_SECP521R1_SHA512),
    },
    //6: CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA512),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_X448_HKDF_SHA512,
            kdf: Kdf::KDF_HKDF_SHA512,
            aead: Aead::AEAD_ChaCha20Poly1305,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ED448),
    },
    //7: CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA384),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_P384_HKDF_SHA384,
            kdf: Kdf::KDF_HKDF_SHA384,
            aead: Aead::AEAD_AES256GCM,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ECDSA_SECP384R1_SHA384),
    },
];

/// [ring](https://github.com/briansmith/ring) based crypto provider
#[derive(Default, Debug)]
pub struct RingCryptoProvider {
    rand: RandChacha,
}

impl CryptoProvider for RingCryptoProvider {
    fn supports(&self, cipher_suite: CipherSuite) -> bool {
        matches!(
            cipher_suite,
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                | CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        )
    }

    fn supported(&self) -> Vec<CipherSuite> {
        vec![
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        ]
    }

    fn rand(&self) -> &dyn Rand {
        &self.rand
    }

    fn hash(&self, cipher_suite: CipherSuite) -> Result<&dyn Hash> {
        if self.supports(cipher_suite) {
            let index: u16 = cipher_suite.into();
            Ok(&CIPHER_SUITE_DESCRIPTIONS[index as usize - 1].hash)
        } else {
            Err(Error::UnsupportedCipherSuite)
        }
    }

    fn hpke(&self, cipher_suite: CipherSuite) -> Result<&dyn Hpke> {
        if self.supports(cipher_suite) {
            let index: u16 = cipher_suite.into();
            Ok(&CIPHER_SUITE_DESCRIPTIONS[index as usize - 1].hpke)
        } else {
            Err(Error::UnsupportedCipherSuite)
        }
    }

    fn signature(&self, cipher_suite: CipherSuite) -> Result<&dyn Signature> {
        if self.supports(cipher_suite) {
            let index: u16 = cipher_suite.into();
            Ok(&CIPHER_SUITE_DESCRIPTIONS[index as usize - 1].signature)
        } else {
            Err(Error::UnsupportedCipherSuite)
        }
    }
}
