use crate::crypto::{HPKEPublicKey, SignaturePublicKey};
use bytes::Bytes;

use crate::crypto::provider::SignatureScheme;

/// SignatureKeyPair is a wrapper of CryptoProvider's signature key pair
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SignatureKeyPair {
    pub(crate) private_key: Bytes,
    pub(crate) public_key: SignaturePublicKey,
    pub(crate) signature_scheme: SignatureScheme,
}

impl SignatureKeyPair {
    /// Returns private key
    pub fn private_key(&self) -> &Bytes {
        &self.private_key
    }

    /// Returns public key
    pub fn public_key(&self) -> &SignaturePublicKey {
        &self.public_key
    }

    /// Returns signature scheme
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

/// HPKEKeyPair is a wrapper of CryptoProvider's HPKE key pair
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct HPKEKeyPair {
    pub(crate) private_key: Bytes,
    pub(crate) public_key: HPKEPublicKey,
}

impl HPKEKeyPair {
    /// Returns private key
    pub fn private_key(&self) -> &Bytes {
        &self.private_key
    }

    /// Returns public key
    pub fn public_key(&self) -> &HPKEPublicKey {
        &self.public_key
    }
}
