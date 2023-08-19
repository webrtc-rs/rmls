use crate::crypto::{
    hash::Hash,
    hpke::{
        algs::{Aead, Kdf, Kem},
        HpkeSuite,
    },
    signature::SignatureScheme,
};
use crate::error::Error;
use bytes::Bytes;
use std::fmt::{Display, Formatter};

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum CipherSuite {
    #[default]
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;

    fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            0x0007 => Ok(CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
            _ => Err(Error::InvalidCipherSuiteValue(v)),
        }
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl CipherSuite {
    pub(crate) fn hash(&self) -> Hash {
        match *self {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => Hash::SHA256,
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Hash::SHA256,
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => Hash::SHA256,
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => Hash::SHA512,
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Hash::SHA512,
            CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => Hash::SHA512,
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Hash::SHA384,
        }
    }

    pub(crate) fn hpke(&self) -> HpkeSuite {
        match *self {
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
        }
    }

    pub(crate) fn signature_scheme(&self) -> SignatureScheme {
        match *self {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => SignatureScheme::Ed25519,
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_P256_SHA256_ASN1
            }
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::Ed25519
            }
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => SignatureScheme::Ed448,
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_P521_SHA512_ASN1
            }
            CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => SignatureScheme::Ed448,
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_P384_SHA384_ASN1
            }
        }
    }

    pub(crate) fn verify_with_label(
        &self,
        _verif_key: &Bytes,
        _label: &Bytes,
        _content: &Bytes,
        _sign_value: &Bytes,
    ) -> bool {
        /*TODO(yngrtc): signContent, err := marshalSignContent(label, content)
        if err != nil {
            return false
        }

        return cs.signatureScheme().Verify(verifKey, signContent, signValue)*/
        true
    }
}
