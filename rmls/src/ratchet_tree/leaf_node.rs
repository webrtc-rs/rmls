use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;
use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::config::CryptoConfig;
use crate::crypto::key_pair::{EncryptionKeyPair, SignatureKeyPair};
use crate::crypto::{cipher_suite::*, credential::*, provider::CryptoProvider, *};
use crate::extensibility::*;
use crate::framing::*;
use crate::group::proposal::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

const LEAF_NODE_SIGNATURE_LABEL: &str = "LeafNodeTBS";

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
    pub versions: Vec<ProtocolVersion>,
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
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
            cipher_suites.push(b.get_u16().into());
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
            let pt: ProposalType = b.get_u16().into();
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
                b.put_u16(self.cipher_suites[i].into());
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
    pub not_before: u64,
    pub not_after: u64,
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

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) LeafNodePayload
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct LeafNodePayload {
    pub encryption_key: HPKEPublicKey,
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub leaf_node_source: LeafNodeSource,
    pub extensions: Extensions,
}

impl Deserializer for LeafNodePayload {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let encryption_key = HPKEPublicKey::deserialize(buf)?;
        let signature_key = SignaturePublicKey::deserialize(buf)?;

        let credential = Credential::deserialize(buf)?;
        let capabilities = Capabilities::deserialize(buf)?;
        let leaf_node_source = LeafNodeSource::deserialize(buf)?;

        let extensions = Extensions::deserialize(buf)?;

        Ok(Self {
            encryption_key,
            signature_key,
            credential,
            capabilities,
            leaf_node_source,
            extensions,
        })
    }
}

impl Serializer for LeafNodePayload {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.encryption_key, buf)?;
        serialize_opaque_vec(&self.signature_key, buf)?;
        self.credential.serialize(buf)?;
        self.capabilities.serialize(buf)?;
        self.leaf_node_source.serialize(buf)?;
        self.extensions.serialize(buf)
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) LeafNode
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct LeafNode {
    pub payload: LeafNodePayload,
    pub signature: Bytes,
}

impl Deserializer for LeafNode {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let payload = LeafNodePayload::deserialize(buf)?;
        let signature = deserialize_opaque_vec(buf)?;

        Ok(Self { payload, signature })
    }
}

impl Serializer for LeafNode {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.payload.serialize(buf)?;
        serialize_opaque_vec(&self.signature, buf)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TreePosition {
    pub(crate) group_id: GroupID,
    pub(crate) leaf_index: LeafIndex,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum TreeInfoTBS {
    KeyPackage,
    UpdateOrCommit(TreePosition),
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) LeafNodeTBS
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LeafNodeTBS<'a> {
    payload: &'a LeafNodePayload,
    tree_info_tbs: TreeInfoTBS,
}

impl<'a> Serializer for LeafNodeTBS<'a> {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.payload.serialize(buf)?;

        match &self.payload.leaf_node_source {
            LeafNodeSource::Update | LeafNodeSource::Commit(_) => {
                if let TreeInfoTBS::UpdateOrCommit(tree_position) = &self.tree_info_tbs {
                    serialize_opaque_vec(&tree_position.group_id, buf)?;
                    buf.put_u32(tree_position.leaf_index.0);
                }
            }
            _ => {}
        }

        Ok(())
    }
}

impl LeafNode {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        crypto_provider: &impl CryptoProvider,
        crypto_config: CryptoConfig,
        credential: Credential,
        signature_key_pair: &SignatureKeyPair,
        leaf_node_source: LeafNodeSource,
        capabilities: Capabilities,
        extensions: Extensions,
        tree_info_tbs: TreeInfoTBS,
    ) -> Result<(Self, EncryptionKeyPair)> {
        let mut ikm = vec![0u8; crypto_provider.hash(crypto_config.cipher_suite)?.size()];
        crypto_provider.rand().fill(&mut ikm)?;
        let encryption_key_pair = crypto_provider
            .hpke(crypto_config.cipher_suite)?
            .kem_derive_key_pair(&ikm)?;

        let payload = LeafNodePayload {
            encryption_key: encryption_key_pair.public_key.clone(),
            signature_key: signature_key_pair.public_key.clone(),
            credential,
            capabilities,
            leaf_node_source,
            extensions,
        };

        let leaf_node_tbs = LeafNodeTBS {
            payload: &payload,
            tree_info_tbs,
        };

        let signature = crypto_provider.sign_with_label(
            crypto_config.cipher_suite,
            &signature_key_pair.public_key,
            LEAF_NODE_SIGNATURE_LABEL.as_bytes(),
            &leaf_node_tbs.serialize_detached()?,
        )?;

        Ok((Self { payload, signature }, encryption_key_pair))
    }

    /// Verify the signature of the leaf node.
    ///
    /// group_id and li can be left unspecified if the leaf node source is neither
    /// update nor commit.
    pub(crate) fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        tree_info_tbs: TreeInfoTBS,
    ) -> bool {
        let tbs = LeafNodeTBS {
            payload: &self.payload,
            tree_info_tbs,
        };
        let leaf_node_tbs = if let Ok(leaf_node_tbs) = tbs.serialize_detached() {
            leaf_node_tbs
        } else {
            return false;
        };
        crypto_provider
            .verify_with_label(
                cipher_suite,
                &self.payload.signature_key,
                LEAF_NODE_SIGNATURE_LABEL.as_bytes(),
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
        let leaf_index = options.leaf_index;
        let tree_info_tbs = TreeInfoTBS::UpdateOrCommit(TreePosition {
            group_id: options.group_id.clone(),
            leaf_index,
        });
        if !self.verify_signature(crypto_provider, options.cipher_suite, tree_info_tbs) {
            return Err(Error::LeafNodeSignatureVerificationFailed);
        }

        // TODO: check required_capabilities group extension

        if !options
            .supported_creds
            .contains(&self.payload.credential.credential_type())
        {
            return Err(Error::CredentialTypeUsedByLeafNodeNotSupportedByAllMembers(
                self.payload.credential.credential_type().into(),
            ));
        }

        if let LeafNodeSource::KeyPackage(lifetime) = &self.payload.leaf_node_source {
            let t = (options.now)();
            if t > UNIX_EPOCH && !lifetime.verify(t) {
                return Err(Error::LifetimeVerificationFailed);
            }
        }

        let mut supported_exts = HashSet::new();
        for et in &self.payload.capabilities.extensions {
            supported_exts.insert(*et);
        }
        for ext in self.payload.extensions.extensions() {
            if !supported_exts.contains(&ext.extension_type()) {
                return Err(
                    Error::ExtensionTypeUsedByLeafNodeNotSupportedByThatLeafNode(
                        ext.extension_type().into(),
                    ),
                );
            }
        }

        if options.signature_keys.contains(&self.payload.signature_key) {
            return Err(Error::DuplicateSignatureKeyInRatchetTree);
        }
        if options
            .encryption_keys
            .contains(&self.payload.encryption_key)
        {
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
    pub signature_keys: &'a HashSet<SignaturePublicKey>,
    pub encryption_keys: &'a HashSet<HPKEPublicKey>,
    pub now: &'a dyn Fn() -> SystemTime,
}
