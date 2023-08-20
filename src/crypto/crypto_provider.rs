pub mod ring;
pub mod rust_crypto;

use crate::cipher_suite::CipherSuite;
use crate::crypto::{hash::Hash, hpke::Hpke, signature::Signature};
use crate::error::*;

use std::sync::Arc;

pub trait CryptoProvider {
    fn supports(&self, cipher_suite: CipherSuite) -> Result<()>;

    fn supported(&self) -> Vec<CipherSuite>;

    fn hash(&self, cipher_suite: CipherSuite) -> Arc<dyn Hash>;

    fn hpke(&self, cipher_suite: CipherSuite) -> Arc<dyn Hpke>;

    fn signature(&self, cipher_suite: CipherSuite) -> Arc<dyn Signature>;
}
