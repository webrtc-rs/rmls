pub mod algs;

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

impl crate::crypto::crypto_provider::Hpke for HpkeSuite {}
