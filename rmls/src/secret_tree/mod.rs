//! [RFC9420 Sec.9](https://www.rfc-editor.org/rfc/rfc9420.html#section-9) Secret Tree

#[cfg(test)]
mod secret_tree_test;

use bytes::{BufMut, Bytes, BytesMut};
use std::fmt::{Display, Formatter};

use crate::crypto::{cipher_suite::*, provider::CryptoProvider};
use crate::framing::*;
use crate::utilities::error::*;
use crate::utilities::tree_math::*;

const RATCHET_LABEL_HANDSHAKE_STR: &str = "handshake";
const RATCHET_LABEL_APPLICATION_STR: &str = "application";

/// [RFC9420 Sec.9](https://www.rfc-editor.org/rfc/rfc9420.html#section-9) RatchetLabel
///
/// RatchetLabel::Handshake: "handshake"
///
/// RatchetLabel::Application: "application"
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum RatchetLabel {
    #[default]
    Handshake,
    Application,
}

impl Display for RatchetLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            RatchetLabel::Handshake => write!(f, "{}", RATCHET_LABEL_HANDSHAKE_STR),
            RatchetLabel::Application => write!(f, "{}", RATCHET_LABEL_APPLICATION_STR),
        }
    }
}

impl From<ContentType> for RatchetLabel {
    fn from(content_type: ContentType) -> Self {
        match content_type {
            ContentType::Application => RatchetLabel::Application,
            ContentType::Proposal | ContentType::Commit => RatchetLabel::Handshake,
        }
    }
}

/// [RFC9420 Sec.9](https://www.rfc-editor.org/rfc/rfc9420.html#section-9) SecretTree
///
/// It holds tree node secrets used for the generation of encryption keys and nonces.
///
/// For the generation of encryption keys and nonces, the key schedule begins with the
/// encryption_secret at the root and derives a tree of secrets with the same structure
/// as the group's ratchet tree. Each leaf in the secret tree is associated with the same
/// group member as the corresponding leaf in the ratchet tree.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SecretTree(pub(crate) Vec<Option<Bytes>>);

impl SecretTree {
    /// Create a SecretTree
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        n: NumLeaves,
        encryption_secret: &[u8],
    ) -> Result<Self> {
        let mut tree = SecretTree(vec![None; n.width() as usize]);
        tree.set(n.root(), encryption_secret.to_vec().into());
        tree.derive_children(crypto_provider, cipher_suite, n.root())?;
        Ok(tree)
    }

    fn derive_children(
        &mut self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        x: NodeIndex,
    ) -> Result<()> {
        let (l, r, ok) = x.children();
        if !ok {
            return Ok(());
        }

        let parent_secret = self
            .get(x)
            .ok_or(Error::InvalidParentNode)?
            .as_ref()
            .ok_or(Error::InvalidParentNode)?;
        let nh = crypto_provider.hpke(cipher_suite).kdf_extract_size() as u16;
        let left_secret =
            crypto_provider.expand_with_label(cipher_suite, parent_secret, b"tree", b"left", nh)?;
        let right_secret = crypto_provider.expand_with_label(
            cipher_suite,
            parent_secret,
            b"tree",
            b"right",
            nh,
        )?;

        self.set(l, left_secret);
        self.set(r, right_secret);

        self.derive_children(crypto_provider, cipher_suite, l)?;
        self.derive_children(crypto_provider, cipher_suite, r)?;

        Ok(())
    }

    fn get(&self, ni: NodeIndex) -> Option<&Option<Bytes>> {
        self.0.get(ni.0 as usize)
    }

    fn set(&mut self, ni: NodeIndex, secret: Bytes) {
        if (ni.0 as usize) < self.0.len() {
            self.0[ni.0 as usize] = Some(secret);
        }
    }

    /// derive_ratchet_root derives the root of a ratchet for a tree node.
    pub fn derive_ratchet_root(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        ni: NodeIndex,
        label: RatchetLabel,
    ) -> Result<RatchetSecret> {
        let parent_secret = self
            .get(ni)
            .ok_or(Error::InvalidParentNode)?
            .as_ref()
            .ok_or(Error::InvalidParentNode)?;
        let nh = crypto_provider.hpke(cipher_suite).kdf_extract_size() as u16;
        let secret = crypto_provider.expand_with_label(
            cipher_suite,
            parent_secret,
            label.to_string().as_bytes(),
            &[],
            nh,
        )?;
        Ok(RatchetSecret {
            secret,
            generation: 0,
        })
    }
}

/// [RFC9420 Sec.9.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-9.1) RatchetSecret
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct RatchetSecret {
    pub secret: Bytes,
    pub generation: u32,
}

impl RatchetSecret {
    /// nonce in RatchetSecret is derived using derive_tree_secret.
    pub fn derive_nonce(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
    ) -> Result<Bytes> {
        let nn = crypto_provider.hpke(cipher_suite).aead_nonce_size() as u16;
        derive_tree_secret(
            crypto_provider,
            cipher_suite,
            &self.secret,
            b"nonce",
            self.generation,
            nn,
        )
    }

    /// Key in ratchet is derived using derive_tree_secret.
    pub fn derive_key(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
    ) -> Result<Bytes> {
        let nk = crypto_provider.hpke(cipher_suite).aead_key_size() as u16;
        derive_tree_secret(
            crypto_provider,
            cipher_suite,
            &self.secret,
            b"key",
            self.generation,
            nk,
        )
    }

    /// Next RatchetSecret is derived using derive_tree_secret.
    pub fn derive_next(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
    ) -> Result<RatchetSecret> {
        let nh = crypto_provider.hpke(cipher_suite).kdf_extract_size() as u16;
        let secret = derive_tree_secret(
            crypto_provider,
            cipher_suite,
            &self.secret,
            b"secret",
            self.generation,
            nh,
        )?;
        Ok(RatchetSecret {
            secret,
            generation: self.generation + 1,
        })
    }
}

/// [RFC9420 Sec.9.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-9.1)
/// Keys, nonces, and the secrets in ratchets are derived using derive_tree_secret.
/// ```text
/// DeriveTreeSecret(Secret, Label, Generation, Length) =
///     ExpandWithLabel(Secret, Label, Generation, Length)
/// ```
pub fn derive_tree_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    secret: &[u8],
    label: &[u8],
    generation: u32,
    length: u16,
) -> Result<Bytes> {
    let mut buf = BytesMut::new();
    buf.put_u32(generation);
    let context = buf.freeze();

    crypto_provider.expand_with_label(cipher_suite, secret, label, &context, length)
}
