use crate::crypto::provider::SignatureScheme;
use crate::crypto::{HPKEPrivateKey, HPKEPublicKey, SignaturePrivateKey, SignaturePublicKey};
use crate::utilities::error::*;
use crate::utilities::serde::{Deserializer, Serializer};
use bytes::{Buf, BufMut};

/// SignatureKeyPair is a wrapper of CryptoProvider's signature key pair
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SignatureKeyPair {
    pub(crate) private_key: SignaturePrivateKey,
    pub(crate) public_key: SignaturePublicKey,
    pub(crate) signature_scheme: SignatureScheme,
}

impl Deserializer for SignatureKeyPair {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let private_key = SignaturePrivateKey::deserialize(buf)?;
        let public_key = SignaturePublicKey::deserialize(buf)?;
        let signature_scheme = SignatureScheme::deserialize(buf)?;
        Ok(Self {
            private_key,
            public_key,
            signature_scheme,
        })
    }
}

impl Serializer for SignatureKeyPair {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.private_key.serialize(buf)?;
        self.public_key.serialize(buf)?;
        self.signature_scheme.serialize(buf)
    }
}

impl SignatureKeyPair {
    /// Returns private key
    pub fn private_key(&self) -> &SignaturePrivateKey {
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
    pub(crate) private_key: HPKEPrivateKey,
    pub(crate) public_key: HPKEPublicKey,
}

impl Deserializer for HPKEKeyPair {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let private_key = SignaturePrivateKey::deserialize(buf)?;
        let public_key = SignaturePublicKey::deserialize(buf)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

impl Serializer for HPKEKeyPair {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.private_key.serialize(buf)?;
        self.public_key.serialize(buf)
    }
}

impl HPKEKeyPair {
    /// Returns private key
    pub fn private_key(&self) -> &HPKEPrivateKey {
        &self.private_key
    }

    /// Returns public key
    pub fn public_key(&self) -> &HPKEPublicKey {
        &self.public_key
    }
}

pub type EncryptionKeyPair = HPKEKeyPair;
