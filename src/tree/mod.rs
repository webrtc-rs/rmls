pub(crate) mod ratchet_tree;
pub(crate) mod secret_tree;
pub(crate) mod tree_math;
#[cfg(test)]
mod tree_test;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cipher_suite::*;
use crate::codec::*;
use crate::crypto::provider::CryptoProvider;
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
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        original_sibling_tree_hash: &[u8],
    ) -> Result<Bytes> {
        let input = ParentNode::marshal_parent_hash_input(
            &self.encryption_key,
            &self.parent_hash,
            original_sibling_tree_hash,
        )?;
        let h = crypto_provider.hash(cipher_suite);
        Ok(h.digest(&input))
    }

    pub(crate) fn marshal_parent_hash_input(
        encryption_key: &HpkePublicKey,
        parent_hash: &[u8],
        original_sibling_tree_hash: &[u8],
    ) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        write_opaque_vec(encryption_key, &mut buf)?;
        write_opaque_vec(parent_hash, &mut buf)?;
        write_opaque_vec(original_sibling_tree_hash, &mut buf)?;
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

impl Reader for LeafNodeSource {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let v = buf.get_u8();
        match v {
            1 => {
                let mut lifetime = Lifetime::default();
                lifetime.read(buf)?;
                *self = LeafNodeSource::KeyPackage(lifetime);
            }
            2 => *self = LeafNodeSource::Update,
            3 => *self = LeafNodeSource::Commit(read_opaque_vec(buf)?),
            _ => return Err(Error::InvalidLeafNodeSourceValue(v)),
        };

        Ok(())
    }
}

impl Writer for LeafNodeSource {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            LeafNodeSource::KeyPackage(lifetime) => {
                buf.put_u8(1);
                lifetime.write(buf)?;
            }
            LeafNodeSource::Update => buf.put_u8(2),
            LeafNodeSource::Commit(parent_hash) => {
                buf.put_u8(3);
                write_opaque_vec(parent_hash, buf)?
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
            self.cipher_suites.push(CipherSuiteCapability(b.get_u16()));
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let et: ExtensionType = b.get_u16().into();
            self.extensions.push(et);
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let pt: ProposalType = b.get_u16().into();
            self.proposals.push(pt);
            Ok(())
        })?;

        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let ct: CredentialType = b.get_u16().into();
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
                b.put_u16(self.cipher_suites[i].0);
                Ok(())
            },
        )?;

        write_vector(
            self.extensions.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.extensions[i].into());
                Ok(())
            },
        )?;

        write_vector(
            self.proposals.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.proposals[i].into());
                Ok(())
            },
        )?;

        write_vector(
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

fn unmarshal_extension_vec<B: Buf>(buf: &mut B) -> Result<Vec<Extension>> {
    let mut exts = vec![];
    read_vector(buf, |b: &mut Bytes| -> Result<()> {
        if b.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let extension_type: ExtensionType = b.get_u16().into();
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
            b.put_u16(exts[i].extension_type.into());
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

        match &self.leaf_node.leaf_node_source {
            LeafNodeSource::Update | LeafNodeSource::Commit(_) => {
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
    fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        group_id: &GroupID,
        leaf_index: LeafIndex,
    ) -> bool {
        let leaf_node_tbs = if let Ok(leaf_node_tbs) = write(&LeafNodeTBS {
            leaf_node: self,
            group_id,
            leaf_index,
        }) {
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
    fn verify(
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
            .contains(&self.credential.credential_type)
        {
            return Err(Error::CredentialTypeUsedByLeafNodeNotSupportedByAllMembers(
                self.credential.credential_type.into(),
            ));
        }

        if let LeafNodeSource::KeyPackage(lifetime) = &self.leaf_node_source {
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

impl Reader for Node {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }

        let v = buf.get_u8();
        match v {
            1 => {
                let mut leaf_node = LeafNode::default();
                leaf_node.read(buf)?;
                *self = Node::Leaf(leaf_node);
                Ok(())
            }
            2 => {
                let mut parent_node = ParentNode::default();
                parent_node.read(buf)?;
                *self = Node::Parent(parent_node);
                Ok(())
            }
            _ => Err(Error::InvalidNodeTypeValue(v)),
        }
    }
}

impl Writer for Node {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Node::Leaf(leaf_node) => {
                buf.put_u8(1);
                leaf_node.write(buf)
            }
            Node::Parent(parent_node) => {
                buf.put_u8(2);
                parent_node.write(buf)
            }
        }
    }
}
