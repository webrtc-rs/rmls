#[cfg(test)]
mod secret_tree_test;
#[cfg(test)]
mod tree_math_test;
#[cfg(test)]
mod tree_test;

pub(crate) mod math;
pub(crate) mod ratchet;
pub(crate) mod secret;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::{cipher_suite::*, provider::CryptoProvider, *};
use crate::error::*;
use crate::message::{framing::*, proposal::*};
use crate::serde::*;
use crate::tree::math::*;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct ParentNode {
    encryption_key: HpkePublicKey,
    parent_hash: Bytes,
    unmerged_leaves: Vec<LeafIndex>,
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
    pub(crate) fn compute_parent_hash(
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

    pub(crate) fn serialize_parent_hash_input(
        encryption_key: &HpkePublicKey,
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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) enum LeafNodeSource {
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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Capabilities {
    versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuiteCapability>,
    extensions: Vec<ExtensionType>,
    proposals: Vec<ProposalTypeCapability>,
    credentials: Vec<CredentialType>,
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
            let ver: ProtocolVersion = b.get_u16();
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
                b.put_u16(self.versions[i]);
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

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Lifetime {
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

// http://www.iana.org/assignments/mls/mls.xhtml#mls-extension-types
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub(crate) enum ExtensionType {
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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Extension {
    extension_type: ExtensionType,
    extension_data: Bytes,
}

pub(crate) fn deserialize_extensions<B: Buf>(buf: &mut B) -> Result<Vec<Extension>> {
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
    Ok(exts)
}

pub(crate) fn serialize_extensions<B: BufMut>(exts: &[Extension], buf: &mut B) -> Result<()> {
    serialize_vector(
        exts.len(),
        buf,
        |i: usize, b: &mut BytesMut| -> Result<()> {
            b.put_u16(exts[i].extension_type.into());
            serialize_opaque_vec(&exts[i].extension_data, b)
        },
    )
}

pub(crate) fn find_extension_data(exts: &[Extension], t: ExtensionType) -> Option<Bytes> {
    for ext in exts {
        if ext.extension_type == t {
            return Some(ext.extension_data.clone());
        }
    }
    None
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct LeafNode {
    pub(crate) encryption_key: HpkePublicKey,
    pub(crate) signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,
    pub(crate) leaf_node_source: LeafNodeSource,
    extensions: Vec<Extension>,

    signature: Bytes,
}

impl LeafNode {
    fn serialize_base<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        serialize_opaque_vec(&self.encryption_key, buf)?;
        serialize_opaque_vec(&self.signature_key, buf)?;
        self.credential.serialize(buf)?;
        self.capabilities.serialize(buf)?;
        self.leaf_node_source.serialize(buf)?;

        serialize_extensions(&self.extensions, buf)
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

        let extensions = deserialize_extensions(buf)?;
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct LeafNodeTBS<'a> {
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
    // verify_signature verifies the signature of the leaf node.
    //
    // group_id and li can be left unspecified if the leaf node source is neither
    // update nor commit.
    fn verify_signature(
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

    // verify performs leaf node validation described in section 7.3.
    //
    // It does not perform all checks: it does not check that the credential is
    // valid.
    pub(crate) fn verify(
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
        for ext in &self.extensions {
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

pub(crate) struct LeafNodeVerifyOptions<'a> {
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) group_id: &'a GroupID,
    pub(crate) leaf_index: LeafIndex,
    pub(crate) supported_creds: &'a HashSet<CredentialType>,
    pub(crate) signature_keys: &'a HashSet<Bytes>,
    pub(crate) encryption_keys: &'a HashSet<Bytes>,
    pub(crate) now: &'a dyn Fn() -> SystemTime,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct UpdatePathNode {
    pub(crate) encryption_key: HpkePublicKey,
    encrypted_path_secret: Vec<HpkeCiphertext>,
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
            encrypted_path_secret.push(HpkeCiphertext::deserialize(b)?);
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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct UpdatePath {
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Node {
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

        let v = buf.get_u8();
        match v {
            1 => Ok(Node::Leaf(LeafNode::deserialize(buf)?)),
            2 => Ok(Node::Parent(ParentNode::deserialize(buf)?)),
            _ => Err(Error::InvalidNodeTypeValue(v)),
        }
    }
}

impl Serializer for Node {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Node::Leaf(leaf_node) => {
                buf.put_u8(1);
                leaf_node.serialize(buf)
            }
            Node::Parent(parent_node) => {
                buf.put_u8(2);
                parent_node.serialize(buf)
            }
        }
    }
}
