pub mod algs;

use algs::*;

// Suite is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Suite {
    kem: Kem,
    kdf: Kdf,
    aead: Aead,
}

impl Suite {
    pub fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Self {
        Suite { kem, kdf, aead }
    }
}
