use crate::crypto::hash::Hash;
use bytes::Bytes;
use std::fmt::{Display, Formatter};

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct CipherSuite(pub(crate) u16);

pub(crate) const CIPHER_SUITE_MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519: CipherSuite =
    CipherSuite(0x0001);
pub(crate) const CIPHER_SUITE_MLS_128_DHKEMP256_AES128GCM_SHA256_P256: CipherSuite =
    CipherSuite(0x0002);
pub(crate) const CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519: CipherSuite =
    CipherSuite(0x0003);
pub(crate) const CIPHER_SUITE_MLS_256_DHKEMX448_AES256GCM_SHA512_ED448: CipherSuite =
    CipherSuite(0x0004);
pub(crate) const CIPHER_SUITE_MLS_256_DHKEMP521_AES256GCM_SHA512_P521: CipherSuite =
    CipherSuite(0x0005);
pub(crate) const CIPHER_SUITE_MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448: CipherSuite =
    CipherSuite(0x0006);
pub(crate) const CIPHER_SUITE_MLS_256_DHKEMP384_AES256GCM_SHA384_P384: CipherSuite =
    CipherSuite(0x0007);

impl Display for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            CIPHER_SUITE_MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519 => {
                write!(f, "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
            }
            CIPHER_SUITE_MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                write!(f, "MLS_128_DHKEMP256_AES128GCM_SHA256_P256")
            }
            CIPHER_SUITE_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519 => {
                write!(f, "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519")
            }
            CIPHER_SUITE_MLS_256_DHKEMX448_AES256GCM_SHA512_ED448 => {
                write!(f, "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448")
            }
            CIPHER_SUITE_MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                write!(f, "MLS_256_DHKEMP521_AES256GCM_SHA512_P521")
            }
            CIPHER_SUITE_MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448 => {
                write!(f, "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448")
            }
            CIPHER_SUITE_MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                write!(f, "MLS_256_DHKEMP384_AES256GCM_SHA384_P384")
            }
            _ => write!(f, "<{}>", self.0),
        }
    }
}

impl CipherSuite {
    pub(crate) fn hash(&self) -> Hash {
        /*TODO:desc, ok := cipherSuiteDescriptions[cs]
        if !ok {
            panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
        }
        return desc.hash*/
        Hash(0)
    }

    pub(crate) fn verify_with_label(
        &self,
        _verif_key: &Bytes,
        _label: &Bytes,
        _content: &Bytes,
        _sign_value: &Bytes,
    ) -> bool {
        /*TODO: signContent, err := marshalSignContent(label, content)
        if err != nil {
            return false
        }

        return cs.signatureScheme().Verify(verifKey, signContent, signValue)*/
        true
    }
}
