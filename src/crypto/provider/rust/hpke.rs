use bytes::Bytes;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::hpke_algs::*;
use crate::error::*;

// Suite is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(super) struct HpkeSuite {
    pub(super) kem: Kem,
    pub(super) kdf: Kdf,
    pub(super) aead: Aead,
}

impl HpkeSuite {
    pub(super) fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        HpkeSuite { kem, kdf, aead }
    }
}

impl crate::crypto::provider::Hpke for HpkeSuite {
    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes> {
        let mut out = vec![0u8; length as usize];

        match self.kdf {
            Kdf::KDF_HKDF_SHA256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
            Kdf::KDF_HKDF_SHA384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
            Kdf::KDF_HKDF_SHA512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
        };

        Ok(Bytes::from(out))
    }

    fn kdf_extract_size(&self) -> usize {
        match self.kdf {
            Kdf::KDF_HKDF_SHA256 => 32,
            Kdf::KDF_HKDF_SHA384 => 48,
            Kdf::KDF_HKDF_SHA512 => 64,
        }
    }
}
