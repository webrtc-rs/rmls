use bytes::{Buf, BufMut, Bytes};
use rand::Rng;

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::error::*;
use crate::key::schedule::{ConfirmedTranscriptHashInput, GroupContext};
use crate::message::{proposal::Proposal, Commit};
use crate::serde::*;
use crate::tree::math::LeafIndex;
use crate::tree::secret::RatchetSecret;

pub(crate) type ProtocolVersion = u16;

pub(crate) const PROTOCOL_VERSION_MLS10: ProtocolVersion = 1;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ContentType {
    #[default]
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

impl TryFrom<u8> for ContentType {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0x01 => Ok(ContentType::Application),
            0x02 => Ok(ContentType::Proposal),
            0x03 => Ok(ContentType::Commit),
            _ => Err(Error::InvalidContentTypeValue(v)),
        }
    }
}

impl Deserializer for ContentType {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        buf.get_u8().try_into()
    }
}
impl Serializer for ContentType {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Content {
    Application(Bytes),
    Proposal(Proposal),
    Commit(Commit),
}

impl Default for Content {
    fn default() -> Self {
        Content::Application(Bytes::new())
    }
}

impl Deserializer for Content {
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
            0x01 => Ok(Content::Application(deserialize_opaque_vec(buf)?)),
            0x02 => Ok(Content::Proposal(Proposal::deserialize(buf)?)),
            0x03 => Ok(Content::Commit(Commit::deserialize(buf)?)),
            _ => Err(Error::InvalidContentTypeValue(v)),
        }
    }
}
impl Serializer for Content {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Content::Application(application) => {
                buf.put_u8(1);
                serialize_opaque_vec(application, buf)?;
            }
            Content::Proposal(proposal) => {
                buf.put_u8(2);
                proposal.serialize(buf)?;
            }
            Content::Commit(commit) => {
                buf.put_u8(3);
                commit.serialize(buf)?
            }
        }

        Ok(())
    }
}

impl Content {
    pub(crate) fn content_type(&self) -> ContentType {
        match self {
            Content::Application(_) => ContentType::Application,
            Content::Proposal(_) => ContentType::Proposal,
            Content::Commit(_) => ContentType::Commit,
        }
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Sender {
    Member(LeafIndex),
    External(u32),
    NewMemberProposal,
    #[default]
    NewMemberCommit,
}

impl Deserializer for Sender {
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
            1 => {
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                Ok(Sender::Member(LeafIndex(buf.get_u32())))
            }
            2 => {
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                Ok(Sender::External(buf.get_u32()))
            }
            3 => Ok(Sender::NewMemberProposal),
            4 => Ok(Sender::NewMemberCommit),
            _ => Err(Error::InvalidSenderTypeValue(v)),
        }
    }
}

impl Serializer for Sender {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Sender::Member(leaf_index) => {
                buf.put_u8(1);
                buf.put_u32(leaf_index.0);
            }
            Sender::External(v) => {
                buf.put_u8(2);
                buf.put_u32(*v);
            }
            Sender::NewMemberProposal => {
                buf.put_u8(3);
            }
            Sender::NewMemberCommit => {
                buf.put_u8(4);
            }
        }
        Ok(())
    }
}

// http://www.iana.org/assignments/mls/mls.xhtml#mls-wire-formats
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum WireFormat {
    #[default]
    PublicMessage = 0x0001,
    PrivateMessage = 0x0002,
    Welcome = 0x0003,
    GroupInfo = 0x0004,
    KeyPackage = 0x0005,
}

impl TryFrom<u16> for WireFormat {
    type Error = Error;

    fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(WireFormat::PublicMessage),
            0x0002 => Ok(WireFormat::PrivateMessage),
            0x0003 => Ok(WireFormat::Welcome),
            0x0004 => Ok(WireFormat::GroupInfo),
            0x0005 => Ok(WireFormat::KeyPackage),
            _ => Err(Error::InvalidWireFormatValue(v)),
        }
    }
}

impl Deserializer for WireFormat {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }

        buf.get_u16().try_into()
    }
}

impl Serializer for WireFormat {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(*self as u16);

        Ok(())
    }
}

// GroupID is an application-specific group identifier.
pub(crate) type GroupID = Bytes;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct FramedContent {
    pub(crate) group_id: GroupID,
    pub(crate) epoch: u64,
    pub(crate) sender: Sender,
    pub(crate) authenticated_data: Bytes,
    pub(crate) content: Content,
}

impl Deserializer for FramedContent {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let group_id = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        let epoch = buf.get_u64();
        let sender = Sender::deserialize(buf)?;
        let authenticated_data = deserialize_opaque_vec(buf)?;
        let content = Content::deserialize(buf)?;

        Ok(Self {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content,
        })
    }
}

impl Serializer for FramedContent {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.sender.serialize(buf)?;
        serialize_opaque_vec(&self.authenticated_data, buf)?;
        self.content.serialize(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct AuthenticatedContent {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: FramedContent,
    pub(crate) auth: FramedContentAuthData,
}

impl Deserializer for AuthenticatedContent {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let wire_format = WireFormat::deserialize(buf)?;
        let content = FramedContent::deserialize(buf)?;
        let auth = FramedContentAuthData::deserialize(buf, content.content.content_type())?;

        Ok(Self {
            wire_format,
            content,
            auth,
        })
    }
}

impl Serializer for AuthenticatedContent {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.wire_format.serialize(buf)?;
        self.content.serialize(buf)?;
        self.auth
            .serialize(buf, self.content.content.content_type())
    }
}

fn sign_authenticated_content(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sign_key: &[u8],
    wf: WireFormat,
    content: &FramedContent,
    ctx: &GroupContext,
) -> Result<AuthenticatedContent> {
    let mut auth_content = AuthenticatedContent {
        wire_format: wf,
        content: content.clone(),
        auth: Default::default(),
    };
    let tbs = auth_content.framed_content_tbs(ctx);
    auth_content.auth.signature =
        sign_framed_content(crypto_provider, cipher_suite, sign_key, &tbs)?;

    Ok(auth_content)
}

impl AuthenticatedContent {
    pub(crate) fn confirmed_transcript_hash_input(&self) -> ConfirmedTranscriptHashInput {
        ConfirmedTranscriptHashInput {
            wire_format: self.wire_format,
            content: self.content.clone(),
            signature: self.auth.signature.clone(),
        }
    }

    fn framed_content_tbs(&self, ctx: &GroupContext) -> FramedContentTBS {
        FramedContentTBS {
            version: PROTOCOL_VERSION_MLS10,
            wire_format: self.wire_format,
            content: self.content.clone(),
            context: Some(ctx.clone()),
        }
    }

    pub(crate) fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        verif_key: &[u8],
        ctx: &GroupContext,
    ) -> Result<()> {
        self.auth.verify_signature(
            crypto_provider,
            cipher_suite,
            verif_key,
            &self.framed_content_tbs(ctx),
        )
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct FramedContentAuthData {
    signature: Bytes,
    pub(crate) confirmation_tag: Bytes, // for contentTypeCommit
}

impl FramedContentAuthData {
    fn deserialize<B>(buf: &mut B, ct: ContentType) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let signature = deserialize_opaque_vec(buf)?;
        let confirmation_tag = if ct == ContentType::Commit {
            deserialize_opaque_vec(buf)?
        } else {
            Bytes::new()
        };

        Ok(Self {
            signature,
            confirmation_tag,
        })
    }

    fn serialize<B>(&self, buf: &mut B, ct: ContentType) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.signature, buf)?;

        if ct == ContentType::Commit {
            serialize_opaque_vec(&self.confirmation_tag, buf)?;
        }
        Ok(())
    }

    pub(crate) fn verify_confirmation_tag(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        confirmation_key: &[u8],
        confirmed_transcript_hash: &[u8],
    ) -> bool {
        if self.confirmation_tag.is_empty() {
            false
        } else {
            crypto_provider.verify_mac(
                cipher_suite,
                confirmation_key,
                confirmed_transcript_hash,
                &self.confirmation_tag,
            )
        }
    }

    fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        verif_key: &[u8],
        content: &FramedContentTBS,
    ) -> Result<()> {
        let raw_content = serialize(content)?;
        crypto_provider.verify_with_label(
            cipher_suite,
            verif_key,
            b"FramedContentTBS",
            &raw_content,
            &self.signature,
        )
    }
}
fn sign_framed_content(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sign_key: &[u8],
    content: &FramedContentTBS,
) -> Result<Bytes> {
    let raw_content = serialize(content)?;
    crypto_provider.sign_with_label(cipher_suite, sign_key, b"FramedContentTBS", &raw_content)
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct FramedContentTBS {
    version: ProtocolVersion,
    wire_format: WireFormat,
    content: FramedContent,
    context: Option<GroupContext>, // for senderTypeMember and senderTypeNewMemberCommit
}

impl Deserializer for FramedContentTBS {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let version = buf.get_u16();
        let wire_format = WireFormat::deserialize(buf)?;
        let content = FramedContent::deserialize(buf)?;
        let context = match &content.sender {
            Sender::Member(_) | Sender::NewMemberCommit => Some(GroupContext::deserialize(buf)?),
            _ => None,
        };

        Ok(Self {
            version,
            wire_format,
            content,
            context,
        })
    }
}

impl Serializer for FramedContentTBS {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        self.wire_format.serialize(buf)?;
        self.content.serialize(buf)?;
        match &self.content.sender {
            Sender::Member(_) | Sender::NewMemberCommit => {
                if let Some(group_context) = &self.context {
                    group_context.serialize(buf)?;
                } else {
                    return Err(Error::SenderMemberAndNewMemberCommitNoGroupContext);
                }
            }
            _ => {}
        };

        Ok(())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PublicMessage {
    pub(crate) content: FramedContent,
    auth: FramedContentAuthData,
    membership_tag: Option<Bytes>, // for senderTypeMember
}

pub(crate) fn sign_public_message(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sign_key: &[u8],
    content: &FramedContent,
    ctx: &GroupContext,
) -> Result<PublicMessage> {
    let auth_content = sign_authenticated_content(
        crypto_provider,
        cipher_suite,
        sign_key,
        WireFormat::PublicMessage,
        content,
        ctx,
    )?;

    Ok(PublicMessage {
        content: auth_content.content,
        auth: auth_content.auth,
        membership_tag: None,
    })
}

impl Deserializer for PublicMessage {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let content = FramedContent::deserialize(buf)?;
        let auth = FramedContentAuthData::deserialize(buf, content.content.content_type())?;

        let membership_tag = if let Sender::Member(_) = &content.sender {
            Some(deserialize_opaque_vec(buf)?)
        } else {
            None
        };

        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}
impl Serializer for PublicMessage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.content.serialize(buf)?;
        self.auth
            .serialize(buf, self.content.content.content_type())?;

        if let Sender::Member(_) = &self.content.sender {
            if let Some(membership_tag) = &self.membership_tag {
                serialize_opaque_vec(membership_tag, buf)?;
            }
        }

        Ok(())
    }
}

impl PublicMessage {
    pub(crate) fn authenticated_content(&self) -> AuthenticatedContent {
        AuthenticatedContent {
            wire_format: WireFormat::PublicMessage,
            content: self.content.clone(),
            auth: self.auth.clone(),
        }
    }

    fn authenticated_content_tbm(&self, ctx: &GroupContext) -> AuthenticatedContentTBM {
        AuthenticatedContentTBM {
            content_tbs: self.authenticated_content().framed_content_tbs(ctx),
            auth: self.auth.clone(),
        }
    }

    pub(crate) fn sign_membership_tag(
        &mut self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        membership_key: &[u8],
        ctx: &GroupContext,
    ) -> Result<()> {
        match self.content.sender {
            Sender::External(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => {
                return Ok(())
            }
            _ => {}
        };
        let raw_auth_content_tbm = serialize(&self.authenticated_content_tbm(ctx))?;
        self.membership_tag =
            Some(crypto_provider.sign_mac(cipher_suite, membership_key, &raw_auth_content_tbm));
        Ok(())
    }

    pub(crate) fn verify_membership_tag(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        membership_key: &[u8],
        ctx: &GroupContext,
    ) -> bool {
        match self.content.sender {
            Sender::External(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => {
                return true;
            }
            _ => {}
        };
        if let Some(membership_tag) = &self.membership_tag {
            let raw_auth_content_tbm =
                if let Ok(raw) = serialize(&self.authenticated_content_tbm(ctx)) {
                    raw
                } else {
                    return false;
                };
            crypto_provider.verify_mac(
                cipher_suite,
                membership_key,
                &raw_auth_content_tbm,
                membership_tag,
            )
        } else {
            true
        }
    }
}
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct AuthenticatedContentTBM {
    content_tbs: FramedContentTBS,
    auth: FramedContentAuthData,
}

impl Serializer for AuthenticatedContentTBM {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.content_tbs.serialize(buf)?;
        self.auth
            .serialize(buf, self.content_tbs.content.content.content_type())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateMessage {
    group_id: GroupID,
    epoch: u64,
    pub(crate) content_type: ContentType,
    authenticated_data: Bytes,
    encrypted_sender_data: Bytes,
    ciphertext: Bytes,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_private_message(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sign_priv: &[u8],
    secret: &RatchetSecret,
    sender_data_secret: &[u8],
    content: &FramedContent,
    sender_data: &SenderData,
    ctx: &GroupContext,
) -> Result<PrivateMessage> {
    let ciphertext = encrypt_private_message_content(
        crypto_provider,
        cipher_suite,
        sign_priv,
        secret,
        content,
        ctx,
        &sender_data.reuse_guard,
    )?;
    let encrypted_sender_data = encrypt_sender_data(
        crypto_provider,
        cipher_suite,
        sender_data_secret,
        sender_data,
        content,
        &ciphertext,
    )?;

    Ok(PrivateMessage {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type: content.content.content_type(),
        authenticated_data: content.authenticated_data.clone(),
        encrypted_sender_data,
        ciphertext,
    })
}

impl Deserializer for PrivateMessage {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let group_id = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        let epoch = buf.get_u64();
        let content_type = ContentType::deserialize(buf)?;
        let authenticated_data = deserialize_opaque_vec(buf)?;
        let encrypted_sender_data = deserialize_opaque_vec(buf)?;
        let ciphertext = deserialize_opaque_vec(buf)?;

        Ok(Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

impl Serializer for PrivateMessage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.serialize(buf)?;
        serialize_opaque_vec(&self.authenticated_data, buf)?;
        serialize_opaque_vec(&self.encrypted_sender_data, buf)?;
        serialize_opaque_vec(&self.ciphertext, buf)
    }
}

impl PrivateMessage {
    pub(crate) fn decrypt_sender_data(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sender_data_secret: &[u8],
    ) -> Result<SenderData> {
        let key = expand_sender_data_key(
            crypto_provider,
            cipher_suite,
            sender_data_secret,
            &self.ciphertext,
        )?;
        let nonce = expand_sender_data_nonce(
            crypto_provider,
            cipher_suite,
            sender_data_secret,
            &self.ciphertext,
        )?;

        let aad = SenderDataAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
        };
        let raw_aad = serialize(&aad)?;

        let raw_sender_data = crypto_provider.hpke(cipher_suite).aead_open(
            &key,
            &nonce,
            &self.encrypted_sender_data,
            &raw_aad,
        )?;

        let mut buf = raw_sender_data.as_ref();
        SenderData::deserialize(&mut buf)
    }

    pub(crate) fn decrypt_content(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        secret: &RatchetSecret,
        reuse_guard: &[u8],
    ) -> Result<PrivateMessageContent> {
        let (key, nonce) = derive_private_message_key_and_nonce(
            crypto_provider,
            cipher_suite,
            secret,
            reuse_guard,
        )?;

        let aad = PrivateContentAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
        };

        let raw_aad = serialize(&aad)?;
        let raw_content = crypto_provider.hpke(cipher_suite).aead_open(
            &key,
            &nonce,
            &self.ciphertext,
            &raw_aad,
        )?;

        let mut buf = raw_content.as_ref();
        PrivateMessageContent::deserialize(&mut buf, self.content_type)
    }

    pub(crate) fn authenticated_content(
        &self,
        sender_data: &SenderData,
        content: &PrivateMessageContent,
    ) -> AuthenticatedContent {
        AuthenticatedContent {
            wire_format: WireFormat::PrivateMessage,
            content: FramedContent {
                group_id: self.group_id.clone(),
                epoch: self.epoch,
                sender: Sender::Member(sender_data.leaf_index),
                authenticated_data: self.authenticated_data.clone(),
                content: content.content.clone(),
            },
            auth: content.auth.clone(),
        }
    }
}
#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct SenderDataAAD {
    group_id: GroupID,
    epoch: u64,
    content_type: ContentType,
}

impl Serializer for SenderDataAAD {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.serialize(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct PrivateContentAAD {
    group_id: GroupID,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: Bytes,
}

impl Serializer for PrivateContentAAD {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.serialize(buf)?;
        serialize_opaque_vec(&self.authenticated_data, buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct PrivateMessageContent {
    pub(crate) content: Content,
    auth: FramedContentAuthData,
}

impl PrivateMessageContent {
    fn deserialize<B>(buf: &mut B, ct: ContentType) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let content = match ct {
            ContentType::Application => Content::Application(deserialize_opaque_vec(buf)?),
            ContentType::Proposal => Content::Proposal(Proposal::deserialize(buf)?),
            ContentType::Commit => Content::Commit(Commit::deserialize(buf)?),
        };

        let auth = FramedContentAuthData::deserialize(buf, ct)?;

        Ok(Self { content, auth })
    }
}

impl Serializer for PrivateMessageContent {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match &self.content {
            Content::Application(application) => serialize_opaque_vec(application, buf)?,
            Content::Proposal(proposal) => proposal.serialize(buf)?,
            Content::Commit(commit) => commit.serialize(buf)?,
        }

        self.auth.serialize(buf, self.content.content_type())
    }
}

fn derive_private_message_key_and_nonce(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    secret: &RatchetSecret,
    reuse_guard: &[u8],
) -> Result<(Bytes, Bytes)> {
    let key = secret.derive_key(crypto_provider, cipher_suite)?;
    let mut nonce = secret.derive_nonce(crypto_provider, cipher_suite)?.to_vec();
    if nonce.len() < reuse_guard.len() {
        return Err(Error::NonceAndReuseGuardLenNotMatch);
    }

    for i in 0..reuse_guard.len() {
        nonce[i] ^= reuse_guard[i];
    }

    Ok((key, nonce.into()))
}

pub(crate) fn encrypt_private_message_content(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sign_key: &[u8],
    secret: &RatchetSecret,
    content: &FramedContent,
    ctx: &GroupContext,
    reuse_guard: &[u8],
) -> Result<Bytes> {
    let auth_content = sign_authenticated_content(
        crypto_provider,
        cipher_suite,
        sign_key,
        WireFormat::PrivateMessage,
        content,
        ctx,
    )?;

    let priv_content = PrivateMessageContent {
        content: content.content.clone(),
        auth: auth_content.auth,
    };

    let plainttext = serialize(&priv_content)?;

    let (key, nonce) =
        derive_private_message_key_and_nonce(crypto_provider, cipher_suite, secret, reuse_guard)?;

    let aad = PrivateContentAAD {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type: content.content.content_type(),
        authenticated_data: content.authenticated_data.clone(),
    };
    let raw_aad = serialize(&aad)?;

    crypto_provider
        .hpke(cipher_suite)
        .aead_seal(&key, &nonce, &plainttext, &raw_aad)
}

fn encrypt_sender_data(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sender_data_secret: &[u8],
    sender_data: &SenderData,
    content: &FramedContent,
    ciphertext: &[u8],
) -> Result<Bytes> {
    let key = expand_sender_data_key(
        crypto_provider,
        cipher_suite,
        sender_data_secret,
        ciphertext,
    )?;
    let nonce = expand_sender_data_nonce(
        crypto_provider,
        cipher_suite,
        sender_data_secret,
        ciphertext,
    )?;

    let aad = SenderDataAAD {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type: content.content.content_type(),
    };
    let raw_aad = serialize(&aad)?;
    let raw_sender_data = serialize(sender_data)?;

    crypto_provider
        .hpke(cipher_suite)
        .aead_seal(&key, &nonce, &raw_sender_data, &raw_aad)
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct SenderData {
    leaf_index: LeafIndex,
    pub(crate) generation: u32,
    pub(crate) reuse_guard: [u8; 4],
}

impl SenderData {
    pub(crate) fn new(leaf_index: LeafIndex, generation: u32) -> Self {
        let mut reuse_guard: [u8; 4] = [0u8; 4];
        rand::thread_rng().fill(&mut reuse_guard[..]);
        Self {
            leaf_index,
            generation,
            reuse_guard,
        }
    }
}

impl Deserializer for SenderData {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 12 {
            return Err(Error::BufferTooSmall);
        }
        let leaf_index = LeafIndex(buf.get_u32());
        let generation = buf.get_u32();
        let mut reuse_guard = [0u8; 4];
        buf.copy_to_slice(&mut reuse_guard);

        Ok(Self {
            leaf_index,
            generation,
            reuse_guard,
        })
    }
}

impl Serializer for SenderData {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u32(self.leaf_index.0);
        buf.put_u32(self.generation);
        buf.put_slice(&self.reuse_guard);
        Ok(())
    }
}

pub(crate) fn expand_sender_data_key(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sender_data_secret: &[u8],
    ciphertext: &[u8],
) -> Result<Bytes> {
    let nk = crypto_provider.hpke(cipher_suite).aead_key_size() as u16;
    let ciphertext_sample = sample_ciphertext(crypto_provider, cipher_suite, ciphertext);
    crypto_provider.expand_with_label(
        cipher_suite,
        sender_data_secret,
        b"key",
        ciphertext_sample,
        nk,
    )
}

pub(crate) fn expand_sender_data_nonce(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sender_data_secret: &[u8],
    ciphertext: &[u8],
) -> Result<Bytes> {
    let nn = crypto_provider.hpke(cipher_suite).aead_nonce_size() as u16;
    let ciphertext_sample = sample_ciphertext(crypto_provider, cipher_suite, ciphertext);
    crypto_provider.expand_with_label(
        cipher_suite,
        sender_data_secret,
        b"nonce",
        ciphertext_sample,
        nn,
    )
}

pub(crate) fn sample_ciphertext<'a>(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    ciphertext: &'a [u8],
) -> &'a [u8] {
    let n = crypto_provider.hpke(cipher_suite).kdf_extract_size();
    if ciphertext.len() < n {
        ciphertext
    } else {
        &ciphertext[..n]
    }
}
