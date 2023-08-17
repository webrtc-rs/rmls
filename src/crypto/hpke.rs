pub mod algs;

use algs::*;

// Suite is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
pub struct Suite {
    kem_id: Kem,
    kdf_id: Kdf,
    aead_id: Aead,
}