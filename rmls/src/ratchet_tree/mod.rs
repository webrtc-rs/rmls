//! [RFC9420 Sec.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-7) Ratchet Tree Operations
//!
//! The ratchet tree for an epoch describes the membership of a group in that epoch,
//! providing public key encryption (HPKE) keys that can be used to encrypt to subsets of the group
//! as well as information to authenticate the members. In order to reflect changes to the membership
//! of the group from one epoch to the next, corresponding changes are made to the ratchet tree.

#[cfg(test)]
mod ratchet_tree_test;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::{cipher_suite::*, credential::*, provider::CryptoProvider, *};
use crate::framing::*;
use crate::group::proposal::*;
use crate::key_schedule::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

/// [RFC9420 Sec.7.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.1) Parent Node
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
        let encryption_key = deserialize_opaque_vec(buf)?;
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
        let h = crypto_provider.hash(cipher_suite);
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

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) LeafNodeSource
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum LeafNodeSource {
    KeyPackage(Lifetime), // = 1,
    #[default]
    Update, // = 2,
    Commit(Bytes),        // = 3,
}

impl Deserializer for LeafNodeSource {
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
            1 => Ok(LeafNodeSource::KeyPackage(Lifetime::deserialize(buf)?)),
            2 => Ok(LeafNodeSource::Update),
            3 => Ok(LeafNodeSource::Commit(deserialize_opaque_vec(buf)?)),
            _ => Err(Error::InvalidLeafNodeSourceValue(v)),
        }
    }
}

impl Serializer for LeafNodeSource {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            LeafNodeSource::KeyPackage(lifetime) => {
                buf.put_u8(1);
                lifetime.serialize(buf)?;
            }
            LeafNodeSource::Update => buf.put_u8(2),
            LeafNodeSource::Commit(parent_hash) => {
                buf.put_u8(3);
                serialize_opaque_vec(parent_hash, buf)?
            }
        };

        Ok(())
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Capabilities
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Capabilities {
    versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuiteCapability>,
    extensions: Vec<ExtensionType>,
    proposals: Vec<ProposalTypeCapability>,
    pub(crate) credentials: Vec<CredentialType>,
}

impl Deserializer for Capabilities {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        // Note: all unknown values here must be ignored
        let mut versions = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let ver: ProtocolVersion = b.get_u16().into();
            versions.push(ver);
            Ok(())
        })?;

        let mut cipher_suites = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            cipher_suites.push(CipherSuiteCapability(b.get_u16()));
            Ok(())
        })?;

        let mut extensions = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let et: ExtensionType = b.get_u16().into();
            extensions.push(et);
            Ok(())
        })?;

        let mut proposals = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let pt: ProposalTypeCapability = b.get_u16().into();
            proposals.push(pt);
            Ok(())
        })?;

        let mut credentials = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let ct: CredentialType = b.get_u16().into();
            credentials.push(ct);
            Ok(())
        })?;

        Ok(Self {
            versions,
            cipher_suites,
            extensions,
            proposals,
            credentials,
        })
    }
}

impl Serializer for Capabilities {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_vector(
            self.versions.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.versions[i].into());
                Ok(())
            },
        )?;

        serialize_vector(
            self.cipher_suites.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.cipher_suites[i].0);
                Ok(())
            },
        )?;

        serialize_vector(
            self.extensions.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.extensions[i].into());
                Ok(())
            },
        )?;

        serialize_vector(
            self.proposals.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.proposals[i].into());
                Ok(())
            },
        )?;

        serialize_vector(
            self.credentials.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.credentials[i].into());
                Ok(())
            },
        )?;

        Ok(())
    }
}

const ZERO_DURATION: Duration = Duration::from_secs(0);
const MAX_LEAF_NODE_LIFETIME: Duration = Duration::from_secs(3 * 30 * 24);

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Lifetime
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
}

impl Deserializer for Lifetime {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }

        let not_before = buf.get_u64();
        let not_after = buf.get_u64();

        Ok(Self {
            not_before,
            not_after,
        })
    }
}

impl Serializer for Lifetime {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u64(self.not_before);
        buf.put_u64(self.not_after);
        Ok(())
    }
}

impl Lifetime {
    fn not_before_time(&self) -> SystemTime {
        UNIX_EPOCH.add(Duration::from_micros(self.not_before))
    }

    fn not_after_time(&self) -> SystemTime {
        UNIX_EPOCH.add(Duration::from_micros(self.not_after))
    }

    // verify ensures that the lifetime is valid: it has an acceptable range and
    // the current time is within that range.
    fn verify(&self, t: SystemTime) -> bool {
        let (not_before, not_after) = (self.not_before_time(), self.not_after_time());

        if let Ok(d) = not_after.duration_since(not_before) {
            if d == ZERO_DURATION || d < MAX_LEAF_NODE_LIFETIME {
                false
            } else {
                t > not_before && not_after < t
            }
        } else {
            false
        }
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) ExtensionType
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    #[default]
    ApplicationId = 0x0001,
    RatchetTree = 0x0002,
    RequiredCapabilities = 0x0003,
    ExternalPub = 0x0004,
    ExternalSenders = 0x0005,
    /// A currently unknown extension type.
    Unknown(u16),
}

impl From<u16> for ExtensionType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => ExtensionType::ApplicationId,
            0x0002 => ExtensionType::RatchetTree,
            0x0003 => ExtensionType::RequiredCapabilities,
            0x0004 => ExtensionType::ExternalPub,
            0x0005 => ExtensionType::ExternalSenders,
            _ => ExtensionType::Unknown(v),
        }
    }
}

impl From<ExtensionType> for u16 {
    fn from(val: ExtensionType) -> Self {
        match val {
            ExtensionType::ApplicationId => 0x0001,
            ExtensionType::RatchetTree => 0x0002,
            ExtensionType::RequiredCapabilities => 0x0003,
            ExtensionType::ExternalPub => 0x0004,
            ExtensionType::ExternalSenders => 0x0005,
            ExtensionType::Unknown(v) => v,
        }
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: Bytes,
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Extensions
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Extensions(pub Vec<Extension>);

impl Deserializer for Extensions {
    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self> {
        let mut exts = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let extension_type: ExtensionType = b.get_u16().into();
            let extension_data = deserialize_opaque_vec(b)?;
            exts.push(Extension {
                extension_type,
                extension_data,
            });
            Ok(())
        })?;
        Ok(Extensions(exts))
    }
}

impl Serializer for Extensions {
    fn serialize<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        serialize_vector(
            self.0.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.0[i].extension_type.into());
                serialize_opaque_vec(&self.0[i].extension_data, b)
            },
        )
    }
}

impl Extensions {
    pub(crate) fn find_extension_data(&self, t: ExtensionType) -> Option<Bytes> {
        for ext in &self.0 {
            if ext.extension_type == t {
                return Some(ext.extension_data.clone());
            }
        }
        None
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) LeafNode
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct LeafNode {
    pub(crate) encryption_key: HPKEPublicKey,
    pub(crate) signature_key: SignaturePublicKey,
    credential: Credential,
    pub(crate) capabilities: Capabilities,
    pub(crate) leaf_node_source: LeafNodeSource,
    extensions: Extensions,

    signature: Bytes,
}

impl LeafNode {
    fn serialize_base<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        serialize_opaque_vec(&self.encryption_key, buf)?;
        serialize_opaque_vec(&self.signature_key, buf)?;
        self.credential.serialize(buf)?;
        self.capabilities.serialize(buf)?;
        self.leaf_node_source.serialize(buf)?;
        self.extensions.serialize(buf)
    }
}

impl Deserializer for LeafNode {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let encryption_key = deserialize_opaque_vec(buf)?;
        let signature_key = deserialize_opaque_vec(buf)?;

        let credential = Credential::deserialize(buf)?;
        let capabilities = Capabilities::deserialize(buf)?;
        let leaf_node_source = LeafNodeSource::deserialize(buf)?;

        let extensions = Extensions::deserialize(buf)?;
        let signature = deserialize_opaque_vec(buf)?;

        Ok(Self {
            encryption_key,
            signature_key,
            credential,
            capabilities,
            leaf_node_source,
            extensions,
            signature,
        })
    }
}

impl Serializer for LeafNode {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.serialize_base(buf)?;
        serialize_opaque_vec(&self.signature, buf)
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) LeafNodeTBS
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LeafNodeTBS<'a> {
    leaf_node: &'a LeafNode,

    // for LEAF_NODE_SOURCE_UPDATE and LEAF_NODE_SOURCE_COMMIT
    group_id: &'a GroupID,
    leaf_index: LeafIndex,
}

impl<'a> Serializer for LeafNodeTBS<'a> {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.leaf_node.serialize_base(buf)?;

        match &self.leaf_node.leaf_node_source {
            LeafNodeSource::Update | LeafNodeSource::Commit(_) => {
                serialize_opaque_vec(self.group_id, buf)?;
                buf.put_u32(self.leaf_index.0);
            }
            _ => {}
        }
        Ok(())
    }
}

impl LeafNode {
    /// Verify the signature of the leaf node.
    ///
    /// group_id and li can be left unspecified if the leaf node source is neither
    /// update nor commit.
    pub fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        group_id: &GroupID,
        leaf_index: LeafIndex,
    ) -> bool {
        let tbs = LeafNodeTBS {
            leaf_node: self,
            group_id,
            leaf_index,
        };
        let leaf_node_tbs = if let Ok(leaf_node_tbs) = tbs.serialize_detached() {
            leaf_node_tbs
        } else {
            return false;
        };
        crypto_provider
            .verify_with_label(
                cipher_suite,
                &self.signature_key,
                "LeafNodeTBS".as_bytes(),
                &leaf_node_tbs,
                &self.signature,
            )
            .is_ok()
    }

    /// [RFC9420 Sec.7.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.3) Leaf Node Validation
    ///
    /// It does not perform all checks: it does not check that the credential is valid.
    pub fn verify(
        &self,
        crypto_provider: &impl CryptoProvider,
        options: LeafNodeVerifyOptions<'_>,
    ) -> Result<()> {
        let li = options.leaf_index;

        if !self.verify_signature(crypto_provider, options.cipher_suite, options.group_id, li) {
            return Err(Error::LeafNodeSignatureVerificationFailed);
        }

        // TODO: check required_capabilities group extension

        if !options
            .supported_creds
            .contains(&self.credential.credential_type())
        {
            return Err(Error::CredentialTypeUsedByLeafNodeNotSupportedByAllMembers(
                self.credential.credential_type().into(),
            ));
        }

        if let LeafNodeSource::KeyPackage(lifetime) = &self.leaf_node_source {
            let t = (options.now)();
            if t > UNIX_EPOCH && !lifetime.verify(t) {
                return Err(Error::LifetimeVerificationFailed);
            }
        }

        let mut supported_exts = HashSet::new();
        for et in &self.capabilities.extensions {
            supported_exts.insert(*et);
        }
        for ext in &self.extensions.0 {
            if !supported_exts.contains(&ext.extension_type) {
                return Err(
                    Error::ExtensionTypeUsedByLeafNodeNotSupportedByThatLeafNode(
                        ext.extension_type.into(),
                    ),
                );
            }
        }

        if options.signature_keys.contains(&self.signature_key) {
            return Err(Error::DuplicateSignatureKeyInRatchetTree);
        }
        if options.encryption_keys.contains(&self.encryption_key) {
            return Err(Error::DuplicateEncryptionKeyInRatchetTree);
        }

        Ok(())
    }
}

/// [RFC9420 Sec.7.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.6) LeafNodeVerifyOptions
pub struct LeafNodeVerifyOptions<'a> {
    pub cipher_suite: CipherSuite,
    pub group_id: &'a GroupID,
    pub leaf_index: LeafIndex,
    pub supported_creds: &'a HashSet<CredentialType>,
    pub signature_keys: &'a HashSet<Bytes>,
    pub encryption_keys: &'a HashSet<Bytes>,
    pub now: &'a dyn Fn() -> SystemTime,
}

/// [RFC9420 Sec.7.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.6) HPKECiphertext is used to
/// keep encrypted path secret in Update Path.
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
        let encryption_key = deserialize_opaque_vec(buf)?;

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
    pub(crate) leaf_node: LeafNode,
    pub(crate) nodes: Vec<UpdatePathNode>,
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

/// [RFC9420 Sec.7.8](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8) Node Type
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

/// [RFC9420 Sec.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-7) Ratchet Tree
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
    pub fn keys(&self) -> (HashSet<Bytes>, HashSet<Bytes>) {
        let mut signature_keys = HashSet::new();
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
        let mut signature_keys = HashSet::new();
        let mut encryption_keys = HashSet::new();
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
        let h = crypto_provider.hash(cipher_suite);
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
                self.add(add.key_package.leaf_node.clone());
            }
        }
    }
}
