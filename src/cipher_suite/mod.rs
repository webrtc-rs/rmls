use crate::crypto::signature_scheme::SignatureScheme;
use crate::crypto::{hash::Hash, hpke};
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

struct CipherSuiteDescription<T: SignatureScheme> {
    hash: Hash,
    hpke: hpke::Suite,
    sig: T,
}
/*
var cipherSuiteDescriptions = map[cipherSuite]cipherSuiteDescription{
    cipherSuiteMLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: {
        hash: crypto.SHA256,
        hpke: hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM),
        sig:  ed25519SignatureScheme{},
    },
    cipherSuiteMLS_128_DHKEMP256_AES128GCM_SHA256_P256: {
        hash: crypto.SHA256,
        hpke: hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM),
        sig:  ecdsaSignatureScheme{elliptic.P256(), crypto.SHA256},
    },
    cipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519: {
        hash: crypto.SHA256,
        hpke: hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305),
        sig:  ed25519SignatureScheme{},
    },
    cipherSuiteMLS_256_DHKEMX448_AES256GCM_SHA512_Ed448: {
        hash: crypto.SHA512,
        hpke: hpke.NewSuite(hpke.KEM_X448_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_AES256GCM),
        sig:  ed448SignatureScheme{},
    },
    cipherSuiteMLS_256_DHKEMP521_AES256GCM_SHA512_P521: {
        hash: crypto.SHA512,
        hpke: hpke.NewSuite(hpke.KEM_P521_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_AES256GCM),
        sig:  ecdsaSignatureScheme{elliptic.P521(), crypto.SHA512},
    },
    cipherSuiteMLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: {
        hash: crypto.SHA512,
        hpke: hpke.NewSuite(hpke.KEM_X448_HKDF_SHA512, hpke.KDF_HKDF_SHA512, hpke.AEAD_ChaCha20Poly1305),
        sig:  ed448SignatureScheme{},
    },
    cipherSuiteMLS_256_DHKEMP384_AES256GCM_SHA384_P384: {
        hash: crypto.SHA384,
        hpke: hpke.NewSuite(hpke.KEM_P384_HKDF_SHA384, hpke.KDF_HKDF_SHA384, hpke.AEAD_AES256GCM),
        sig:  ecdsaSignatureScheme{elliptic.P384(), crypto.SHA384},
    },
}
*/

impl CipherSuite {
    pub(crate) fn hash(&self) -> Hash {
        /*TODO(yngrtc):desc, ok := cipherSuiteDescriptions[cs]
        if !ok {
            panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
        }
        return desc.hash*/
        Hash(0)
    }

    /*pub(crate) fn hpke(&self) -> hpke::Suite {
        desc, ok := cipherSuiteDescriptions[cs]
        if !ok {
            panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
        }
        return desc.hpke
    }

    func (cs cipherSuite) signature_scheme(&self) ->signatureScheme {
        desc, ok := cipherSuiteDescriptions[cs]
        if !ok {
            panic(fmt.Errorf("mls: invalid cipher suite %d", cs))
        }
        return desc.sig
    }
    */

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
