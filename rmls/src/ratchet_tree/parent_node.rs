use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::crypto::{cipher_suite::*, provider::CryptoProvider, *};
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

/// [RFC9420 Sec.7.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.1) ParentNode
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ParentNode {
    /// The encryption_key field contains an HPKE public key whose private key is held only
    /// by the members at the leaves among its descendants.
    pub encryption_key: HPKEPublicKey,

    /// The parent_hash field contains a hash of this node's parent node, as described in
    /// [RFC9420 Sec.7.9](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.9)
    pub parent_hash: Bytes,

    /// The unmerged_leaves field lists the leaves under this parent node that are unmerged,
    /// according to their indices among all the leaves in the tree.
    /// The entries in the unmerged_leaves vector MUST be sorted in increasing order.
    pub unmerged_leaves: Vec<LeafIndex>,
}

impl Deserializer for ParentNode {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let encryption_key = HPKEPublicKey::deserialize(buf)?;
        let parent_hash = deserialize_opaque_vec(buf)?;

        let mut unmerged_leaves = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if !b.has_remaining() {
                return Err(Error::BufferTooSmall);
            }
            let i: LeafIndex = LeafIndex(b.get_u32());
            unmerged_leaves.push(i);
            Ok(())
        })?;

        Ok(Self {
            encryption_key,
            parent_hash,
            unmerged_leaves,
        })
    }
}

impl Serializer for ParentNode {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.encryption_key, buf)?;
        serialize_opaque_vec(&self.parent_hash, buf)?;
        serialize_vector(
            self.unmerged_leaves.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u32(self.unmerged_leaves[i].0);
                Ok(())
            },
        )
    }
}

impl ParentNode {
    /// [RFC9420 Sec.7.9](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.9) Compute parent hash,
    /// where original_sibling_tree_hash is the tree hash of S in the ratchet tree modified as follows:
    /// For each leaf L in P.unmerged_leaves, blank L and remove it from the unmerged_leaves sets of all parent nodes.
    pub fn compute_parent_hash(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        original_sibling_tree_hash: &[u8],
    ) -> Result<Bytes> {
        let input = ParentNode::serialize_parent_hash_input(
            &self.encryption_key,
            &self.parent_hash,
            original_sibling_tree_hash,
        )?;
        let h = crypto_provider.hash(cipher_suite)?;
        Ok(h.digest(&input))
    }

    fn serialize_parent_hash_input(
        encryption_key: &HPKEPublicKey,
        parent_hash: &[u8],
        original_sibling_tree_hash: &[u8],
    ) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        serialize_opaque_vec(encryption_key, &mut buf)?;
        serialize_opaque_vec(parent_hash, &mut buf)?;
        serialize_opaque_vec(original_sibling_tree_hash, &mut buf)?;
        Ok(buf.freeze())
    }
}
