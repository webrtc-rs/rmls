pub mod algs;

use bytes::Bytes;

use crate::error::*;
use algs::*;

// Suite is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct HpkeSuite {
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
}

impl HpkeSuite {
    pub fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        HpkeSuite { kem, kdf, aead }
    }
}

impl crate::crypto::provider::Hpke for HpkeSuite {
    fn kdf_expand(&self, _secret: &[u8], _info: &[u8], _length: u16) -> Result<Bytes> {
        Ok(Bytes::new())
    }
    fn kdf_extract_size(&self) -> usize {
        match self.kdf {
            Kdf::KDF_HKDF_SHA256 => 32,
            Kdf::KDF_HKDF_SHA384 => 48,
            Kdf::KDF_HKDF_SHA512 => 64,
        }
    }
}
