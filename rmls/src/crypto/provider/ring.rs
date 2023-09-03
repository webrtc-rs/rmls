mod hash;
mod hpke;
mod rand;
mod signature;

use self::hash::HashScheme;
use self::hpke::HpkeSuite;
use self::rand::RandChacha;
use self::signature::SignatureScheme;
use super::*;
use crate::crypto::*;

struct CipherSuiteDescription {
    hash: HashScheme,
    hpke: HpkeSuite,
    signature: SignatureScheme,
}

static CIPHER_SUITE_DESCRIPTIONS: [CipherSuiteDescription; 7 /*CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384*/] = [
    //1: CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    CipherSuiteDescription {
        hash: HashScheme::SHA256,
        hpke: HpkeSuite {
            kem: Kem::KEM_X25519_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_AES128GCM,
        },
        signature: SignatureScheme::Ed25519,
    },
    //2: CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    CipherSuiteDescription {
        hash: HashScheme::SHA256,
        hpke: HpkeSuite {
            kem: Kem::KEM_P256_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_AES128GCM,
        },
        signature: SignatureScheme::ECDSA_P256_SHA256,
    },
    //3: CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    CipherSuiteDescription {
        hash: HashScheme::SHA256,
        hpke: HpkeSuite {
            kem: Kem::KEM_X25519_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_ChaCha20Poly1305,
        },
        signature: SignatureScheme::Ed25519,
    },
    //4: CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
    CipherSuiteDescription {
        hash: HashScheme::SHA512,
        hpke: HpkeSuite {
            kem: Kem::KEM_X448_HKDF_SHA512,
            kdf: Kdf::KDF_HKDF_SHA512,
            aead: Aead::AEAD_AES256GCM,
        },
        signature: SignatureScheme::Ed448,
    },
    //5: CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    CipherSuiteDescription {
        hash: HashScheme::SHA512,
        hpke: HpkeSuite {
            kem: Kem::KEM_P521_HKDF_SHA512,
            kdf: Kdf::KDF_HKDF_SHA512,
            aead: Aead::AEAD_AES256GCM,
        },
        signature: SignatureScheme::ECDSA_P521_SHA512,
    },
    //6:C ipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
    CipherSuiteDescription {
        hash: HashScheme::SHA512,
        hpke: HpkeSuite {
            kem: Kem::KEM_X448_HKDF_SHA512,
            kdf: Kdf::KDF_HKDF_SHA512,
            aead: Aead::AEAD_ChaCha20Poly1305,
        },
        signature: SignatureScheme::Ed448,
    },
    //7: CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    CipherSuiteDescription {
        hash: HashScheme::SHA384,
        hpke: HpkeSuite {
            kem: Kem::KEM_P384_HKDF_SHA384,
            kdf: Kdf::KDF_HKDF_SHA384,
            aead: Aead::AEAD_AES256GCM,
        },
        signature: SignatureScheme::ECDSA_P384_SHA384,
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

    fn hash(&self, cipher_suite: CipherSuite) -> &dyn Hash {
        &CIPHER_SUITE_DESCRIPTIONS[cipher_suite as usize - 1].hash
    }

    fn hpke(&self, cipher_suite: CipherSuite) -> &dyn Hpke {
        &CIPHER_SUITE_DESCRIPTIONS[cipher_suite as usize - 1].hpke
    }

    fn signature(&self, cipher_suite: CipherSuite) -> &dyn Signature {
        &CIPHER_SUITE_DESCRIPTIONS[cipher_suite as usize - 1].signature
    }
}
