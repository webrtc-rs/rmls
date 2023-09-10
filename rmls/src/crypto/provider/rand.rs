use rand_core::{RngCore, SeedableRng};
use std::sync::RwLock;

use crate::utilities::error::*;

#[derive(Debug)]
pub(super) struct RandChacha {
    pub(super) rng: RwLock<rand_chacha::ChaCha20Rng>,
}

impl Default for RandChacha {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

impl crate::crypto::provider::Rand for RandChacha {
    fn fill(&self, buf: &mut [u8]) -> Result<()> {
        let mut rng = self
            .rng
            .write()
            .map_err(|err| Error::Other(err.to_string()))?;
        rng.try_fill_bytes(buf)
            .map_err(|err| Error::Other(err.to_string()))?;
        Ok(())
    }
}
