pub(crate) mod ratchet_tree;
pub(crate) mod secret_tree;
pub(crate) mod tree_math;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cipher_suite::*;
use crate::codec::*;
use crate::crypto::*;
use crate::error::*;
use crate::framing::*;
use crate::group::*;
use tree_math::*;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct ParentNode {
    encryption_key: HpkePublicKey,
    parent_hash: Bytes,
    unmerged_leaves: Vec<LeafIndex>,
}

impl Reader for ParentNode {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        *self = ParentNode::default();

        self.encryption_key = read_opaque_vec(buf)?;
        self.parent_hash = read_opaque_vec(buf)?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if !b.has_remaining() {
                return Err(Error::BufferTooSmall);
            }
            let i: LeafIndex = LeafIndex(b.get_u32());
            self.unmerged_leaves.push(i);
            Ok(())
        })
    }
}

impl Writer for ParentNode {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.encryption_key, buf)?;
        write_opaque_vec(&self.parent_hash, buf)?;
        write_vector(
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
        _cs: CipherSuite,
        original_sibling_tree_hash: &Bytes,
    ) -> Result<Bytes> {
        let raw_input = ParentNode::marshal_parent_hash_input(
            &self.encryption_key,
            &self.parent_hash,
            original_sibling_tree_hash,
        )?;
        /*TODO(yngrtc):let h = cs.hash().New()
        h.Write(rawInput)
        return h.Sum(nil), nil*/
        Ok(raw_input)
    }

    pub(crate) fn marshal_parent_hash_input(
        encryption_key: &HpkePublicKey,
        parent_hash: &Bytes,
        original_sibling_tree_hash: &Bytes,
    ) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        write_opaque_vec(encryption_key, &mut buf)?;
        write_opaque_vec(parent_hash, &mut buf)?;
        write_opaque_vec(original_sibling_tree_hash, &mut buf)?;
        Ok(buf.freeze())
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct LeafNodeSource(pub(crate) u8);

pub(crate) const LEAF_NODE_SOURCE_KEY_PACKAGE: LeafNodeSource = LeafNodeSource(1);
pub(crate) const LEAF_NODE_SOURCE_UPDATE: LeafNodeSource = LeafNodeSource(2);
pub(crate) const LEAF_NODE_SOURCE_COMMIT: LeafNodeSource = LeafNodeSource(3);

impl Reader for LeafNodeSource {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }

        self.0 = buf.get_u8();
        match *self {
            LEAF_NODE_SOURCE_KEY_PACKAGE | LEAF_NODE_SOURCE_UPDATE | LEAF_NODE_SOURCE_COMMIT => {
                Ok(())
            }
            _ => Err(Error::InvalidLeafNodeSource(self.0)),
        }
    }
}

impl Writer for LeafNodeSource {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(self.0);
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Capabilities {
    versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
    extensions: Vec<ExtensionType>,
    proposals: Vec<ProposalType>,
    credentials: Vec<CredentialType>,
}

impl Reader for Capabilities {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        *self = Capabilities::default();

        // Note: all unknown values here must be ignored

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let ver: ProtocolVersion = b.get_u16();
            self.versions.push(ver);
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let cs: CipherSuite = b.get_u16().try_into()?;
            self.cipher_suites.push(cs);
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let et: ExtensionType = b.get_u16();
            self.extensions.push(et);
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let pt: ProposalType = ProposalType(b.get_u16());
            self.proposals.push(pt);
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let ct: CredentialType = b.get_u16();
            self.credentials.push(ct);
            Ok(())
        })?;

        Ok(())
    }
}

impl Writer for Capabilities {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_vector(
            self.versions.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.versions[i]);
                Ok(())
            },
        )?;

        write_vector(
            self.cipher_suites.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.cipher_suites[i] as u16);
                Ok(())
            },
        )?;

        write_vector(
            self.extensions.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.extensions[i]);
                Ok(())
            },
        )?;

        write_vector(
            self.proposals.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.proposals[i].0);
                Ok(())
            },
        )?;

        write_vector(
            self.credentials.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.credentials[i]);
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

impl Reader for Lifetime {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }

        *self = Lifetime::default();
        self.not_before = buf.get_u64();
        self.not_after = buf.get_u64();

        Ok(())
    }
}

impl Writer for Lifetime {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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

pub(crate) type ExtensionType = u16;

// http://www.iana.org/assignments/mls/mls.xhtml#mls-extension-types
pub(crate) const EXTENSION_TYPE_APPLICATION_ID: ExtensionType = 0x0001;
pub(crate) const EXTENSION_TYPE_RATCHET_TREE: ExtensionType = 0x0002;
pub(crate) const EXTENSION_TYPE_REQUIRED_CAPABILITIES: ExtensionType = 0x0003;
pub(crate) const EXTENSION_TYPE_EXTERNAL_PUB: ExtensionType = 0x0004;
pub(crate) const EXTENSION_TYPE_EXTERNAL_SENDERS: ExtensionType = 0x0005;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Extension {
    extension_type: ExtensionType,
    extension_data: Bytes,
}

fn unmarshal_extension_vec<B: Buf>(buf: &mut B) -> Result<Vec<Extension>> {
    let mut exts = vec![];
    read_vector(buf, |b: &mut Bytes| -> Result<()> {
        if b.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let extension_type: ExtensionType = b.get_u16();
        let extension_data = read_opaque_vec(b)?;
        exts.push(Extension {
            extension_type,
            extension_data,
        });
        Ok(())
    })?;
    Ok(exts)
}

fn marshal_extension_vec<B: BufMut>(exts: &[Extension], buf: &mut B) -> Result<()> {
    write_vector(
        exts.len(),
        buf,
        |i: usize, b: &mut BytesMut| -> Result<()> {
            b.put_u16(exts[i].extension_type);
            write_opaque_vec(&exts[i].extension_data, b)
        },
    )
}

fn find_extension_data(exts: &[Extension], t: ExtensionType) -> Option<Bytes> {
    for ext in exts {
        if ext.extension_type == t {
            return Some(ext.extension_data.clone());
        }
    }
    None
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct LeafNode {
    encryption_key: HpkePublicKey,
    signature_key: SignaturePublicKey,
    credential: Credential,
    capabilities: Capabilities,

    leaf_node_source: LeafNodeSource,
    lifetime: Option<Lifetime>, // for LEAF_NODE_SOURCE_KEY_PACKAGE
    parent_hash: Bytes,         // for LEAF_NODE_SOURCE_COMMIT

    extensions: Vec<Extension>,
    signature: Bytes,
}

impl LeafNode {
    fn write_base<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        write_opaque_vec(&self.encryption_key, buf)?;
        write_opaque_vec(&self.signature_key, buf)?;
        self.credential.write(buf)?;
        self.capabilities.write(buf)?;
        self.leaf_node_source.write(buf)?;
        match self.leaf_node_source {
            LEAF_NODE_SOURCE_KEY_PACKAGE => {
                if let Some(lifetime) = &self.lifetime {
                    lifetime.write(buf)?;
                } else {
                    return Err(Error::InvalidLeafNodeSourceWithNullLifetime);
                }
            }
            LEAF_NODE_SOURCE_COMMIT => write_opaque_vec(&self.parent_hash, buf)?,
            _ => {}
        };
        marshal_extension_vec(&self.extensions, buf)
    }
}

impl Reader for LeafNode {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        *self = LeafNode::default();

        self.encryption_key = read_opaque_vec(buf)?;
        self.signature_key = read_opaque_vec(buf)?;

        self.credential.read(buf)?;
        self.capabilities.read(buf)?;
        self.leaf_node_source.read(buf)?;

        match self.leaf_node_source {
            LEAF_NODE_SOURCE_KEY_PACKAGE => {
                let mut lifetime = Lifetime::default();
                lifetime.read(buf)?;
                self.lifetime = Some(lifetime);
            }
            LEAF_NODE_SOURCE_COMMIT => {
                self.parent_hash = read_opaque_vec(buf)?;
            }
            _ => {}
        };

        self.extensions = unmarshal_extension_vec(buf)?;
        self.signature = read_opaque_vec(buf)?;

        Ok(())
    }
}

impl Writer for LeafNode {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.write_base(buf)?;
        write_opaque_vec(&self.signature, buf)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct LeafNodeTBS<'a> {
    leaf_node: &'a LeafNode,

    // for LEAF_NODE_SOURCE_UPDATE and LEAF_NODE_SOURCE_COMMIT
    group_id: &'a GroupID,
    leaf_index: LeafIndex,
}

impl<'a> Writer for LeafNodeTBS<'a> {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.leaf_node.write_base(buf)?;

        match self.leaf_node.leaf_node_source {
            LEAF_NODE_SOURCE_UPDATE | LEAF_NODE_SOURCE_COMMIT => {
                write_opaque_vec(self.group_id, buf)?;
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
    fn verify_signature(&self, cs: CipherSuite, group_id: &GroupID, leaf_index: LeafIndex) -> bool {
        let leaf_node_tbs = if let Ok(leaf_node_tbs) = write(&LeafNodeTBS {
            leaf_node: self,
            group_id,
            leaf_index,
        }) {
            leaf_node_tbs
        } else {
            return false;
        };
        cs.verify_with_label(
            &self.signature_key,
            &Bytes::from("LeafNodeTBS".as_bytes()),
            &leaf_node_tbs,
            &self.signature,
        )
    }

    // verify performs leaf node validation described in section 7.3.
    //
    // It does not perform all checks: it does not check that the credential is
    // valid.
    fn verify(&self, options: LeafNodeVerifyOptions<'_>) -> Result<()> {
        let li = options.leaf_index;

        if !self.verify_signature(options.cipher_suite, options.group_id, li) {
            return Err(Error::LeafNodeSignatureVerificationFailed);
        }

        // TODO: check required_capabilities group extension

        if !options
            .supported_creds
            .contains(&self.credential.credential_type)
        {
            return Err(Error::CredentialTypeUsedByLeafNodeNotSupportedByAllMembers(
                self.credential.credential_type,
            ));
        }

        if let Some(lifetime) = &self.lifetime {
            let t = (options.now)();
            if !lifetime.verify(t) {
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
                        ext.extension_type,
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
    cipher_suite: CipherSuite,
    group_id: &'a GroupID,
    leaf_index: LeafIndex,
    supported_creds: &'a HashSet<CredentialType>,
    signature_keys: &'a HashSet<Bytes>,
    encryption_keys: &'a HashSet<Bytes>,
    now: &'a dyn Fn() -> SystemTime,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct UpdatePathNode {
    encryption_key: HpkePublicKey,
    encrypted_path_secret: Vec<HpkeCiphertext>,
}

impl Reader for UpdatePathNode {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.encryption_key = read_opaque_vec(buf)?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            let mut ciphertext = HpkeCiphertext::default();
            ciphertext.read(b)?;
            self.encrypted_path_secret.push(ciphertext);
            Ok(())
        })
    }
}

impl Writer for UpdatePathNode {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.encryption_key, buf)?;
        write_vector(
            self.encrypted_path_secret.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.encrypted_path_secret[i].write(b) },
        )
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct UpdatePath {
    leaf_node: LeafNode,
    nodes: Vec<UpdatePathNode>,
}

impl Reader for UpdatePath {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.leaf_node.read(buf)?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            let mut node = UpdatePathNode::default();
            node.read(b)?;
            self.nodes.push(node);
            Ok(())
        })
    }
}

impl Writer for UpdatePath {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.leaf_node.write(buf)?;
        write_vector(
            self.nodes.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.nodes[i].write(b) },
        )
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct NodeType(u8);

pub(crate) const NODE_TYPE_LEAF: NodeType = NodeType(1);
pub(crate) const NODE_TYPE_PARENT: NodeType = NodeType(2);

impl Reader for NodeType {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        self.0 = buf.get_u8();
        match *self {
            NODE_TYPE_LEAF | NODE_TYPE_PARENT => Ok(()),

            _ => Err(Error::InvalidNodeType(self.0)),
        }
    }
}
impl Writer for NodeType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(self.0);
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Node {
    node_type: NodeType,
    leaf_node: Option<LeafNode>,     // for nodeTypeLeaf
    parent_node: Option<ParentNode>, // for nodeTypeParent
}

impl Reader for Node {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.node_type.read(buf)?;

        match self.node_type {
            NODE_TYPE_LEAF => {
                let mut leaf_node = LeafNode::default();
                leaf_node.read(buf)?;
                self.leaf_node = Some(leaf_node);
                Ok(())
            }
            NODE_TYPE_PARENT => {
                let mut parent_node = ParentNode::default();
                parent_node.read(buf)?;
                self.parent_node = Some(parent_node);
                Ok(())
            }

            _ => Err(Error::InvalidNodeType(self.node_type.0)),
        }
    }
}

impl Writer for Node {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.node_type.write(buf)?;
        match self.node_type {
            NODE_TYPE_LEAF => {
                if let Some(leaf_node) = &self.leaf_node {
                    leaf_node.write(buf)
                } else {
                    Err(Error::InvalidNodeType(self.node_type.0))
                }
            }
            NODE_TYPE_PARENT => {
                if let Some(parent_node) = &self.parent_node {
                    parent_node.write(buf)
                } else {
                    Err(Error::InvalidNodeType(self.node_type.0))
                }
            }
            _ => Err(Error::InvalidNodeType(self.node_type.0)),
        }
    }
}
