//! [RFC9420 Sec.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-7) Ratchet Tree Operations
//!
//! The ratchet tree for an epoch describes the membership of a group in that epoch,
//! providing public key encryption (HPKE) keys that can be used to encrypt to subsets of the group
//! as well as information to authenticate the members. In order to reflect changes to the membership
//! of the group from one epoch to the next, corresponding changes are made to the ratchet tree.

#[cfg(test)]
mod ratchet_tree_test;

pub mod leaf_node;
pub mod parent_node;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use crate::crypto::{cipher_suite::*, credential::*, provider::CryptoProvider, *};
use crate::group::proposal::*;
use crate::key_schedule::*;
use crate::ratchet_tree::leaf_node::*;
use crate::ratchet_tree::parent_node::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

/// [RFC9420 Sec.7.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.6) HPKECiphertext
///
/// it is used to keep encrypted path secret in Update Path.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct HPKECiphertext {
    pub kem_output: Bytes,
    pub ciphertext: Bytes,
}

impl Deserializer for HPKECiphertext {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let kem_output = deserialize_opaque_vec(buf)?;
        let ciphertext = deserialize_opaque_vec(buf)?;

        Ok(Self {
            kem_output,
            ciphertext,
        })
    }
}

impl Serializer for HPKECiphertext {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.kem_output, buf)?;
        serialize_opaque_vec(&self.ciphertext, buf)?;
        Ok(())
    }
}

/// [RFC9420 Sec.7.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.6) UpdatePathNode
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UpdatePathNode {
    pub encryption_key: HPKEPublicKey,
    pub encrypted_path_secret: Vec<HPKECiphertext>,
}

impl Deserializer for UpdatePathNode {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let encryption_key = HPKEPublicKey::deserialize(buf)?;

        let mut encrypted_path_secret = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            encrypted_path_secret.push(HPKECiphertext::deserialize(b)?);
            Ok(())
        })?;

        Ok(Self {
            encryption_key,
            encrypted_path_secret,
        })
    }
}

impl Serializer for UpdatePathNode {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.encryption_key, buf)?;
        serialize_vector(
            self.encrypted_path_secret.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                self.encrypted_path_secret[i].serialize(b)
            },
        )
    }
}

/// [RFC9420 Sec.7.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.6) UpdatePath
///
/// each Commit message may optionally contain an UpdatePath, with a new LeafNode and set of parent
/// nodes for the sender's filtered direct path. For each parent node, the UpdatePath contains
/// a new public key and encrypted path secret. The parent nodes are kept in the same order
/// as the filtered direct path.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UpdatePath {
    pub leaf_node: LeafNode,
    pub nodes: Vec<UpdatePathNode>,
}

impl Deserializer for UpdatePath {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let leaf_node = LeafNode::deserialize(buf)?;

        let mut nodes = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            nodes.push(UpdatePathNode::deserialize(b)?);
            Ok(())
        })?;

        Ok(Self { leaf_node, nodes })
    }
}

impl Serializer for UpdatePath {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.leaf_node.serialize(buf)?;
        serialize_vector(
            self.nodes.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.nodes[i].serialize(b) },
        )
    }
}

/// [RFC9420 Sec.7.8](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8) NodeType
#[derive(Default, Debug, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum NodeType {
    #[default]
    Leaf = 1,
    Parent = 2,
}

impl Deserializer for NodeType {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }

        let v = buf.get_u8();
        match v {
            1 => Ok(NodeType::Leaf),
            2 => Ok(NodeType::Parent),
            _ => Err(Error::InvalidNodeTypeValue(v)),
        }
    }
}

impl Serializer for NodeType {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            NodeType::Leaf => {
                buf.put_u8(1);
            }
            NodeType::Parent => {
                buf.put_u8(2);
            }
        }

        Ok(())
    }
}

/// [RFC9420 Sec.7.8](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8) Node
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Node {
    Leaf(LeafNode),
    Parent(ParentNode),
}

impl Default for Node {
    fn default() -> Self {
        Node::Leaf(LeafNode::default())
    }
}

impl Deserializer for Node {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }

        let node_type = NodeType::deserialize(buf)?;
        match node_type {
            NodeType::Leaf => Ok(Node::Leaf(LeafNode::deserialize(buf)?)),
            NodeType::Parent => Ok(Node::Parent(ParentNode::deserialize(buf)?)),
        }
    }
}

impl Serializer for Node {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.node_type().serialize(buf)?;
        match self {
            Node::Leaf(leaf_node) => leaf_node.serialize(buf),
            Node::Parent(parent_node) => parent_node.serialize(buf),
        }
    }
}

impl Node {
    pub fn node_type(&self) -> NodeType {
        match self {
            Node::Leaf(_) => NodeType::Leaf,
            Node::Parent(_) => NodeType::Parent,
        }
    }
}

/// [RFC9420 Sec.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-7) RatchetTree
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct RatchetTree(pub(crate) Vec<Option<Node>>);

impl Deserializer for RatchetTree {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let mut nodes = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if deserialize_optional(b)? {
                let node = Node::deserialize(b)?;
                nodes.push(Some(node));
            } else {
                nodes.push(None);
            }
            Ok(())
        })?;

        // The raw tree doesn't include blank nodes at the end, fill it until next
        // power of 2
        while !is_power_of_two(nodes.len() as u32 + 1) {
            nodes.push(None);
        }

        Ok(Self(nodes))
    }
}

impl Serializer for RatchetTree {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        let mut end = self.0.len();
        while end > 0 && self.0[end - 1].is_none() {
            end -= 1;
        }

        serialize_vector(end, buf, |i: usize, b: &mut BytesMut| -> Result<()> {
            serialize_optional(self.0[i].is_some(), b)?;
            if let Some(n) = &self.0[i] {
                n.serialize(b)?;
            }
            Ok(())
        })
    }
}

impl RatchetTree {
    /// Return the ref node at the provided index.
    pub fn get(&self, i: NodeIndex) -> Option<&Node> {
        if (i.0 as usize) < self.0.len() {
            self.0[i.0 as usize].as_ref()
        } else {
            None
        }
    }

    /// Return the mutable node at the provided index
    pub fn get_mut(&mut self, i: NodeIndex) -> Option<&mut Node> {
        if (i.0 as usize) < self.0.len() {
            self.0[i.0 as usize].as_mut()
        } else {
            None
        }
    }

    /// Set the node at the provided index
    pub fn set(&mut self, i: NodeIndex, node: Option<Node>) {
        if (i.0 as usize) < self.0.len() {
            self.0[i.0 as usize] = node;
        }
    }

    /// Return the ref LeafNode at the provided index.
    pub fn get_leaf(&self, li: LeafIndex) -> Option<&LeafNode> {
        if let Some(Node::Leaf(leaf_node)) = self.get(li.node_index()) {
            Some(leaf_node)
        } else {
            None
        }
    }

    /// Compute the resolution of a node.
    pub fn resolve(&self, x: NodeIndex) -> Vec<NodeIndex> {
        if let Some(n) = self.get(x) {
            let mut res = vec![x];
            if let Node::Parent(parent_node) = n {
                for leaf_index in &parent_node.unmerged_leaves {
                    res.push(leaf_index.node_index());
                }
            }
            res
        } else {
            let (l, r, ok) = x.children();
            if !ok {
                vec![] // leaf
            } else {
                let mut res = self.resolve(l);
                let mut right = self.resolve(r);
                res.append(&mut right);
                res
            }
        }
    }

    /// Return supported CredentialTypes
    pub fn supported_creds(&self) -> HashSet<CredentialType> {
        let mut num_members = 0;
        let mut supported_creds_count = HashMap::<CredentialType, usize>::new();
        for li in 0..self.num_leaves().0 {
            if let Some(node) = self.get_leaf(LeafIndex(li)) {
                num_members += 1;
                for ct in &node.capabilities.credentials {
                    if let Some(count) = supported_creds_count.get_mut(ct) {
                        *count += 1;
                    } else {
                        supported_creds_count.insert(*ct, 1);
                    }
                }
            }
        }

        let mut supported_creds = HashSet::new();
        for (ct, n) in supported_creds_count {
            if n == num_members {
                supported_creds.insert(ct);
            }
        }

        supported_creds
    }

    /// Return signature keys and encryption keys
    pub fn keys(&self) -> (HashSet<SignaturePublicKey>, HashSet<HPKEPublicKey>) {
        #[allow(clippy::mutable_key_type)]
        let mut signature_keys = HashSet::new();
        #[allow(clippy::mutable_key_type)]
        let mut encryption_keys = HashSet::new();
        for li in 0..self.num_leaves().0 {
            if let Some(node) = self.get_leaf(LeafIndex(li)) {
                signature_keys.insert(node.signature_key.clone());
                encryption_keys.insert(node.encryption_key.clone());
            }
        }
        (signature_keys, encryption_keys)
    }

    /// Verify the integrity of the ratchet tree, as described in
    /// section 12.4.3.1.
    ///
    /// This function does not perform full leaf node validation. In particular:
    ///
    ///   - It doesn't check that credentials are valid.
    ///   - It doesn't check the lifetime field.
    pub fn verify_integrity(
        &self,
        crypto_provider: &impl CryptoProvider,
        ctx: &GroupContext,
        now: impl Fn() -> SystemTime,
    ) -> Result<()> {
        let cipher_suite = ctx.cipher_suite;
        let num_leaves = self.num_leaves();

        let h = self.compute_root_tree_hash(crypto_provider, cipher_suite)?;

        if h.as_ref() != ctx.tree_hash.as_ref() {
            return Err(Error::TreeHashVerificationFailed);
        }

        if !self.verify_parent_hashes(crypto_provider, cipher_suite) {
            return Err(Error::ParentHashesVerificationFailed);
        }

        let supported_creds = self.supported_creds();
        #[allow(clippy::mutable_key_type)]
        let mut signature_keys: HashSet<SignaturePublicKey> = HashSet::new();
        #[allow(clippy::mutable_key_type)]
        let mut encryption_keys: HashSet<HPKEPublicKey> = HashSet::new();
        for li in 0..num_leaves.0 {
            if let Some(node) = self.get_leaf(LeafIndex(li)) {
                node.verify(
                    crypto_provider,
                    LeafNodeVerifyOptions {
                        cipher_suite,
                        group_id: &ctx.group_id,
                        leaf_index: LeafIndex(li),
                        supported_creds: &supported_creds,
                        signature_keys: &signature_keys,
                        encryption_keys: &encryption_keys,
                        now: &now,
                    },
                )?;

                signature_keys.insert(node.signature_key.clone());
                encryption_keys.insert(node.encryption_key.clone());
            }
        }

        for (i, node) in self.0.iter().enumerate() {
            if let Some(Node::Parent(parent_node)) = node {
                let p = NodeIndex(i as u32);
                for unmerged_leaf in &parent_node.unmerged_leaves {
                    let mut x = unmerged_leaf.node_index();
                    loop {
                        let (y, ok) = num_leaves.parent(x);
                        if !ok {
                            return Err(Error::UnmergedLeafIsNotDescendantOfTheParentNode);
                        } else if y == p {
                            break;
                        }
                        x = y;

                        if let Some(Node::Parent(intermediate_node_parent_node)) = self.get(x) {
                            if !RatchetTree::has_unmerged_leaf(
                                intermediate_node_parent_node,
                                unmerged_leaf,
                            ) {
                                return Err(Error::NonBlankIntermediateNodeMissingUnmergedLeaf);
                            }
                        }
                    }
                }

                if encryption_keys.contains(&parent_node.encryption_key) {
                    return Err(Error::DuplicateEncryptionKeyInRatchetTree);
                }
                encryption_keys.insert(parent_node.encryption_key.clone());
            }
        }

        Ok(())
    }

    /// Check whether the parent node has unmerged leaf at LeafIndex or not
    pub fn has_unmerged_leaf(node: &ParentNode, unmerged_leaf: &LeafIndex) -> bool {
        for li in &node.unmerged_leaves {
            if li == unmerged_leaf {
                return true;
            }
        }
        false
    }

    /// Compute the tree hash for root of this Ratchet tree
    pub fn compute_root_tree_hash(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
    ) -> Result<Bytes> {
        self.compute_tree_hash(
            crypto_provider,
            cipher_suite,
            self.num_leaves().root(),
            &HashSet::new(),
        )
    }

    /// Compute the tree hash for the given node index of this Ratchet tree, excluding some LeafIndices
    pub fn compute_tree_hash(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        x: NodeIndex,
        exclude: &HashSet<LeafIndex>,
    ) -> Result<Bytes> {
        let n = self.get(x);

        let mut buf = BytesMut::new();
        let (li, ok) = x.leaf_index();
        if ok {
            let excluded = exclude.contains(&li);

            let mut l = None;
            if let Some(n) = n {
                if !excluded {
                    match n {
                        Node::Leaf(leaf_node) => {
                            l = Some(leaf_node);
                        }
                        Node::Parent(_) => return Err(Error::InvalidLeafNode),
                    }
                }
            }
            RatchetTree::serialize_leaf_node_hash_input(&mut buf, li, l)?;
        } else {
            let (left, right, ok) = x.children();
            if !ok {
                return Err(Error::InvalidChildren);
            }

            let left_hash = self.compute_tree_hash(crypto_provider, cipher_suite, left, exclude)?;
            let right_hash =
                self.compute_tree_hash(crypto_provider, cipher_suite, right, exclude)?;

            let mut filtered_parent;

            let p = if let Some(n) = n {
                if let Node::Parent(p) = n {
                    if !p.unmerged_leaves.is_empty() && !exclude.is_empty() {
                        let mut unmerged_leaves = vec![]; // make([]leaf_index, 0, len(p.unmerged_leaves))
                        for li in &p.unmerged_leaves {
                            if !exclude.contains(li) {
                                unmerged_leaves.push(*li);
                            }
                        }

                        filtered_parent = p.clone();
                        filtered_parent.unmerged_leaves = unmerged_leaves;
                        Some(&filtered_parent)
                    } else {
                        Some(p)
                    }
                } else {
                    return Err(Error::InvalidParentNode);
                }
            } else {
                None
            };

            RatchetTree::serialize_parent_node_hash_input(
                &mut buf,
                p,
                left_hash.as_ref(),
                right_hash.as_ref(),
            )?;
        }

        let input = buf.freeze();
        let h = crypto_provider.hash(cipher_suite)?;
        Ok(h.digest(&input))
    }

    fn serialize_leaf_node_hash_input<B: BufMut>(
        buf: &mut B,
        i: LeafIndex,
        node: Option<&LeafNode>,
    ) -> Result<()> {
        buf.put_u8(1); //NodeType::Leaf
        buf.put_u32(i.0);
        serialize_optional(node.is_some(), buf)?;
        if let Some(node) = node {
            node.serialize(buf)?;
        }
        Ok(())
    }

    fn serialize_parent_node_hash_input<B: BufMut>(
        buf: &mut B,
        node: Option<&ParentNode>,
        left_hash: &[u8],
        right_hash: &[u8],
    ) -> Result<()> {
        buf.put_u8(2); //NodeType::Parent
        serialize_optional(node.is_some(), buf)?;
        if let Some(node) = node {
            node.serialize(buf)?;
        }
        serialize_opaque_vec(left_hash, buf)?;
        serialize_opaque_vec(right_hash, buf)
    }

    /// Verify parent hashes
    pub fn verify_parent_hashes(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
    ) -> bool {
        for (i, node) in self.0.iter().enumerate() {
            if let Some(node) = node {
                let x = NodeIndex(i as u32);
                let (l, r, ok) = x.children();
                if !ok {
                    continue;
                }

                if let Node::Parent(parent_node) = node {
                    let mut exclude = HashSet::new();
                    for li in &parent_node.unmerged_leaves {
                        exclude.insert(*li);
                    }

                    let left_tree_hash = if let Ok(left_tree_hash) =
                        self.compute_tree_hash(crypto_provider, cipher_suite, l, &exclude)
                    {
                        left_tree_hash
                    } else {
                        return false;
                    };
                    let right_tree_hash = if let Ok(right_tree_hash) =
                        self.compute_tree_hash(crypto_provider, cipher_suite, r, &exclude)
                    {
                        right_tree_hash
                    } else {
                        return false;
                    };

                    let left_parent_hash = if let Ok(left_parent_hash) = parent_node
                        .compute_parent_hash(
                            crypto_provider,
                            cipher_suite,
                            right_tree_hash.as_ref(),
                        ) {
                        left_parent_hash
                    } else {
                        return false;
                    };
                    let right_parent_hash = if let Ok(right_parent_hash) = parent_node
                        .compute_parent_hash(crypto_provider, cipher_suite, left_tree_hash.as_ref())
                    {
                        right_parent_hash
                    } else {
                        return false;
                    };

                    let is_left_descendant =
                        self.find_parent_hash(&self.resolve(l), left_parent_hash.as_ref());
                    let is_right_descendant =
                        self.find_parent_hash(&self.resolve(r), right_parent_hash.as_ref());
                    if is_left_descendant == is_right_descendant {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn find_parent_hash(&self, node_indices: &[NodeIndex], parent_hash: &[u8]) -> bool {
        for x in node_indices {
            if let Some(node) = self.get(*x) {
                let h = match node {
                    Node::Leaf(leaf_node) => match &leaf_node.leaf_node_source {
                        LeafNodeSource::Commit(parent_hash) => parent_hash,
                        _ => continue,
                    },
                    Node::Parent(parent_node) => &parent_node.parent_hash,
                };
                if h == parent_hash {
                    return true;
                }
            }
        }
        false
    }

    fn num_leaves(&self) -> NumLeaves {
        NumLeaves::new(self.0.len() as u32)
    }

    /// Find leaf index given the leaf node
    pub fn find_leaf(&self, node: &LeafNode) -> (LeafIndex, bool) {
        for li in 0..self.num_leaves().0 {
            if let Some(n) = self.get_leaf(LeafIndex(li)) {
                // Encryption keys are unique
                if n.encryption_key != node.encryption_key {
                    continue;
                }

                // Make sure both nodes are identical
                if let (Ok(raw1), Ok(raw2)) = (node.serialize_detached(), n.serialize_detached()) {
                    return (LeafIndex(li), raw1 == raw2);
                } else {
                    return (LeafIndex(li), false);
                }
            }
        }
        (LeafIndex(0), false)
    }

    /// Add the leaf node into the Ratchet tree
    pub fn add(&mut self, leaf_node: LeafNode) {
        let mut li = LeafIndex(0);
        let mut ni: NodeIndex;
        let mut found = false;
        loop {
            ni = li.node_index();
            if (ni.0 as usize) >= self.0.len() {
                break;
            }
            if self.get(ni).is_none() {
                found = true;
                break;
            }
            li.0 += 1;
        }
        if !found {
            ni = NodeIndex(self.0.len() as u32 + 1);
            let new_len = ((self.0.len() + 1) * 2) - 1;
            while self.0.len() < new_len {
                self.0.push(None);
            }
        }

        let num_leaves = self.num_leaves();
        let mut p = ni;
        loop {
            let (q, ok) = num_leaves.parent(p);
            if !ok {
                break;
            }
            p = q;
            if let Some(Node::Parent(parent_node)) = self.get_mut(p) {
                parent_node.unmerged_leaves.push(li);
            }
        }

        self.set(ni, Some(Node::Leaf(leaf_node)));
    }

    /// Update the leaf index position with the given leaf node
    pub fn update(&mut self, li: LeafIndex, leaf_node: LeafNode) {
        let mut ni = li.node_index();

        self.set(ni, Some(Node::Leaf(leaf_node)));

        let num_leaves = self.num_leaves();
        loop {
            let (mi, ok) = num_leaves.parent(ni);
            if !ok {
                break;
            }
            ni = mi;
            self.set(ni, None);
        }
    }

    /// Remove the leaf node for the given leaf index position
    pub fn remove(&mut self, mut li: LeafIndex) {
        let mut ni = li.node_index();

        let num_leaves = self.num_leaves();
        loop {
            self.set(ni, None);

            let (mi, ok) = num_leaves.parent(ni);
            if !ok {
                break;
            }
            ni = mi;
        }

        li = LeafIndex(num_leaves.0 - 1);
        let mut last_power_of_two = self.0.len();
        loop {
            ni = li.node_index();
            if self.get(ni).is_some() {
                break;
            }

            if is_power_of_two(ni.0) {
                last_power_of_two = ni.0 as usize;
            }

            if li.0 == 0 {
                self.0.clear();
                return;
            }
            li.0 -= 1;
        }

        if last_power_of_two < self.0.len() {
            self.0.drain(last_power_of_two..);
        }
    }

    fn filtered_direct_path(&self, mut x: NodeIndex) -> Result<Vec<NodeIndex>> {
        let num_leaves = self.num_leaves();

        let mut path = vec![];
        loop {
            let (p, ok) = num_leaves.parent(x);
            if !ok {
                break;
            }

            let (s, ok) = num_leaves.sibling(x);
            if !ok {
                return Err(Error::InvalidSibling);
            }

            if !self.resolve(s).is_empty() {
                path.push(p);
            }

            x = p;
        }

        Ok(path)
    }

    /// Merge UpdatePath
    pub fn merge_update_path(
        &mut self,
        crypto_provide: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sender_leaf_index: LeafIndex,
        path: &UpdatePath,
    ) -> Result<()> {
        let sender_node_index = sender_leaf_index.node_index();
        let num_leaves = self.num_leaves();

        let direct_path = num_leaves.direct_path(sender_node_index);
        for ni in &direct_path {
            self.set(*ni, None);
        }

        let filtered_direct_path = self.filtered_direct_path(sender_node_index)?;
        if filtered_direct_path.len() != path.nodes.len() {
            return Err(Error::UpdatePathAndFilteredDirectPathHasDifferentNode);
        }
        for (i, ni) in filtered_direct_path.iter().enumerate() {
            let path_node = &path.nodes[i];
            self.set(
                *ni,
                Some(Node::Parent(ParentNode {
                    encryption_key: path_node.encryption_key.clone(),
                    ..Default::default()
                })),
            );
        }

        let exclude = HashSet::new();
        // Compute parent hashes, from root to leaf
        let mut prev_parent_hash = None;
        for i in (0..filtered_direct_path.len()).rev() {
            let ni = filtered_direct_path[i];
            let (node_parent_hash, tree_hash) =
                if let Some(Node::Parent(_parent_node)) = self.get(ni) {
                    let (l, r, ok) = ni.children();
                    if !ok {
                        return Err(Error::InvalidChildren);
                    }

                    let mut s = l;
                    let mut found = false;
                    for ni in &direct_path {
                        if *ni == s {
                            found = true;
                            break;
                        }
                    }
                    if s == sender_node_index || found {
                        s = r;
                    }

                    let tree_hash =
                        self.compute_tree_hash(crypto_provide, cipher_suite, s, &exclude)?;

                    (prev_parent_hash.take(), tree_hash)
                } else {
                    (None, Bytes::new())
                };

            //workaround to assign node.parent_hash
            if let Some(Node::Parent(parent_node)) = self.get_mut(ni) {
                if let Some(node_parent_hash) = node_parent_hash {
                    parent_node.parent_hash = node_parent_hash;
                } else {
                    parent_node.parent_hash = Bytes::new();
                }
                let h = parent_node.compute_parent_hash(
                    crypto_provide,
                    cipher_suite,
                    tree_hash.as_ref(),
                )?;
                prev_parent_hash = Some(h);
            }
        }

        if let (LeafNodeSource::Commit(parent_hash), Some(prev_parent_hash)) =
            (&path.leaf_node.leaf_node_source, prev_parent_hash)
        {
            if parent_hash != prev_parent_hash.as_ref() {
                return Err(Error::ParentHashMismatchForUpdatePathLeafNode);
            }
        } else {
            return Err(Error::ParentHashMismatchForUpdatePathLeafNode);
        }

        self.set(sender_node_index, Some(Node::Leaf(path.leaf_node.clone())));

        Ok(())
    }

    /// Apply the proposals
    pub fn apply(&mut self, proposals: &[Proposal], senders: &[LeafIndex]) {
        // Apply all update proposals
        for (i, prop) in proposals.iter().enumerate() {
            if let Proposal::Update(update) = prop {
                self.update(senders[i], update.leaf_node.clone());
            }
        }

        // Apply all remove proposals
        for prop in proposals {
            if let Proposal::Remove(remove) = prop {
                self.remove(remove.removed);
            }
        }

        // Apply all add proposals
        for prop in proposals {
            if let Proposal::Add(add) = prop {
                self.add(add.key_package.payload.leaf_node.clone());
            }
        }
    }
}
