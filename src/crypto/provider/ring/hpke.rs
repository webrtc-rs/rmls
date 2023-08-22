use bytes::Bytes;
use ring::digest::{SHA256_OUTPUT_LEN, SHA384_OUTPUT_LEN, SHA512_OUTPUT_LEN};
use ring::hkdf::{KeyType, Prk, HKDF_SHA256, HKDF_SHA384, HKDF_SHA512};

use crate::crypto::*;

// Suite is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
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

/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.
#[derive(Debug, PartialEq)]
struct MyKeyType<T: core::fmt::Debug + PartialEq>(T);

impl KeyType for MyKeyType<u16> {
    fn len(&self) -> usize {
        self.0 as usize
    }
}

impl crate::crypto::provider::Hpke for HpkeSuite {
    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes> {
        let prk = match self.kdf {
            Kdf::KDF_HKDF_SHA256 => Prk::new_less_safe(HKDF_SHA256, secret),
            Kdf::KDF_HKDF_SHA384 => Prk::new_less_safe(HKDF_SHA384, secret),
            Kdf::KDF_HKDF_SHA512 => Prk::new_less_safe(HKDF_SHA512, secret),
        };

        let infos = [info];
        let okm = prk
            .expand(&infos, MyKeyType(length))
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;

        let mut out = vec![0u8; length as usize];
        okm.fill(&mut out)
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;

        Ok(Bytes::from(out))
    }

    fn kdf_extract_size(&self) -> usize {
        match self.kdf {
            Kdf::KDF_HKDF_SHA256 => SHA256_OUTPUT_LEN,
            Kdf::KDF_HKDF_SHA384 => SHA384_OUTPUT_LEN,
            Kdf::KDF_HKDF_SHA512 => SHA512_OUTPUT_LEN,
        }
    }
}
