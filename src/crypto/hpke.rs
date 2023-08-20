pub mod algs;

use algs::*;

pub trait Hpke {}

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

impl Hpke for HpkeSuite {}
