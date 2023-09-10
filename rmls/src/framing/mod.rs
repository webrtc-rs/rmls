//! [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Message Framing

#[cfg(test)]
mod framing_test;

use bytes::{Buf, BufMut, Bytes};

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::group::{info::*, proposal::*, *};
use crate::key_package::KeyPackage;
use crate::key_schedule::*;
use crate::secret_tree::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Protocol Version
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ProtocolVersion {
    /// Current supported version in *RMLS*
    #[default]
    MLS10 = 1,

    /// Unsupported version
    Unsupported(u16),
}

impl From<u16> for ProtocolVersion {
    fn from(v: u16) -> Self {
        match v {
            1 => ProtocolVersion::MLS10,
            _ => ProtocolVersion::Unsupported(v),
        }
    }
}

impl From<ProtocolVersion> for u16 {
    fn from(val: ProtocolVersion) -> u16 {
        match val {
            ProtocolVersion::MLS10 => 1,
            ProtocolVersion::Unsupported(v) => v,
        }
    }
}

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Content Type
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum ContentType {
    /// Application Content
    #[default]
    Application = 1,

    /// Proposal Content
    Proposal = 2,

    /// Commit Content
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

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Content
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Content {
    /// Application Content
    Application(Bytes),

    /// Proposal Content
    Proposal(Proposal),

    /// Commit Content
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
        let content_type = ContentType::deserialize(buf)?;
        match content_type {
            ContentType::Application => Ok(Content::Application(deserialize_opaque_vec(buf)?)),
            ContentType::Proposal => Ok(Content::Proposal(Proposal::deserialize(buf)?)),
            ContentType::Commit => Ok(Content::Commit(Commit::deserialize(buf)?)),
        }
    }
}
impl Serializer for Content {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.content_type().serialize(buf)?;
        match self {
            Content::Application(application) => {
                serialize_opaque_vec(application, buf)?;
            }
            Content::Proposal(proposal) => {
                proposal.serialize(buf)?;
            }
            Content::Commit(commit) => commit.serialize(buf)?,
        }

        Ok(())
    }
}

impl Content {
    /// Return ContentType of Content
    pub fn content_type(&self) -> ContentType {
        match self {
            Content::Application(_) => ContentType::Application,
            Content::Proposal(_) => ContentType::Proposal,
            Content::Commit(_) => ContentType::Commit,
        }
    }
}

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Sender Type
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum SenderType {
    /// Member Sender
    Member = 1,

    /// External Sender
    External = 2,

    /// New Member Proposal Sender
    NewMemberProposal = 3,

    /// New Member Commit Sender
    #[default]
    NewMemberCommit = 4,
}

impl TryFrom<u8> for SenderType {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0x01 => Ok(SenderType::Member),
            0x02 => Ok(SenderType::External),
            0x03 => Ok(SenderType::NewMemberProposal),
            0x04 => Ok(SenderType::NewMemberCommit),
            _ => Err(Error::InvalidSenderTypeValue(v)),
        }
    }
}

impl Deserializer for SenderType {
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
impl Serializer for SenderType {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Sender
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Sender {
    /// Member Sender
    Member(LeafIndex),

    /// External Sender
    External(u32),

    /// New Member Proposal Sender
    NewMemberProposal,

    /// New Member Commit Sender
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
        let sender_type = SenderType::deserialize(buf)?;
        match sender_type {
            SenderType::Member => {
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                Ok(Sender::Member(LeafIndex(buf.get_u32())))
            }
            SenderType::External => {
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                Ok(Sender::External(buf.get_u32()))
            }
            SenderType::NewMemberProposal => Ok(Sender::NewMemberProposal),
            SenderType::NewMemberCommit => Ok(Sender::NewMemberCommit),
        }
    }
}

impl Serializer for Sender {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.sender_type().serialize(buf)?;
        match self {
            Sender::Member(leaf_index) => {
                buf.put_u32(leaf_index.0);
            }
            Sender::External(v) => {
                buf.put_u32(*v);
            }
            Sender::NewMemberProposal | Sender::NewMemberCommit => {}
        }
        Ok(())
    }
}

impl Sender {
    pub fn sender_type(&self) -> SenderType {
        match self {
            Sender::Member(_) => SenderType::Member,
            Sender::External(_) => SenderType::External,
            Sender::NewMemberProposal => SenderType::NewMemberProposal,
            Sender::NewMemberCommit => SenderType::NewMemberCommit,
        }
    }
}

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Wire Format
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum WireFormat {
    /// Public Message Wire Format
    PublicMessage = 0x0001,

    /// Private Message Wire Format
    PrivateMessage = 0x0002,

    /// Welcome Wire Format
    #[default]
    Welcome = 0x0003,

    /// Group Info Wire Format
    GroupInfo = 0x0004,

    /// Key Package Wire Format
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

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Wire Message
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WireMessage {
    /// Public Message Wire Format
    PublicMessage(PublicMessage),

    /// Private Message Wire Format
    PrivateMessage(PrivateMessage),

    /// Welcome Wire Format
    Welcome(Welcome),

    /// Group Info Wire Format
    GroupInfo(GroupInfo),

    /// Key Package Wire Format
    KeyPackage(KeyPackage),
}

impl Default for WireMessage {
    fn default() -> Self {
        WireMessage::Welcome(Welcome::default())
    }
}

impl Deserializer for WireMessage {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let wire_format = WireFormat::deserialize(buf)?;
        match wire_format {
            WireFormat::PublicMessage => {
                Ok(WireMessage::PublicMessage(PublicMessage::deserialize(buf)?))
            }
            WireFormat::PrivateMessage => Ok(WireMessage::PrivateMessage(
                PrivateMessage::deserialize(buf)?,
            )),
            WireFormat::Welcome => Ok(WireMessage::Welcome(Welcome::deserialize(buf)?)),
            WireFormat::GroupInfo => Ok(WireMessage::GroupInfo(GroupInfo::deserialize(buf)?)),
            WireFormat::KeyPackage => Ok(WireMessage::KeyPackage(KeyPackage::deserialize(buf)?)),
        }
    }
}

impl Serializer for WireMessage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.wire_format().serialize(buf)?;
        match self {
            WireMessage::PublicMessage(message) => {
                message.serialize(buf)?;
            }
            WireMessage::PrivateMessage(message) => {
                message.serialize(buf)?;
            }
            WireMessage::Welcome(message) => {
                message.serialize(buf)?;
            }
            WireMessage::GroupInfo(message) => {
                message.serialize(buf)?;
            }
            WireMessage::KeyPackage(message) => {
                message.serialize(buf)?;
            }
        }
        Ok(())
    }
}

impl WireMessage {
    /// Return WireFormat of WireMessage
    pub fn wire_format(&self) -> WireFormat {
        match self {
            WireMessage::PublicMessage(_) => WireFormat::PublicMessage,
            WireMessage::PrivateMessage(_) => WireFormat::PrivateMessage,
            WireMessage::Welcome(_) => WireFormat::Welcome,
            WireMessage::GroupInfo(_) => WireFormat::GroupInfo,
            WireMessage::KeyPackage(_) => WireFormat::KeyPackage,
        }
    }
}

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) GroupID is an
/// application-specific group identifier.
pub type GroupID = Bytes;

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Framed Content
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct FramedContent {
    pub group_id: GroupID,
    pub epoch: u64,
    pub sender: Sender,
    pub authenticated_data: Bytes,
    pub content: Content,
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

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) MLS Message
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct MLSMessage {
    pub version: ProtocolVersion,
    pub wire_message: WireMessage,
}

impl Deserializer for MLSMessage {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let version: ProtocolVersion = buf.get_u16().into();
        if version != ProtocolVersion::MLS10 {
            return Err(Error::InvalidProtocolVersion(version.into()));
        }
        let wire_message = WireMessage::deserialize(buf)?;

        Ok(Self {
            version,
            wire_message,
        })
    }
}
impl Serializer for MLSMessage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version.into());
        self.wire_message.serialize(buf)
    }
}

/// [RFC9420 Sec.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-6) Authenticated Content
/// is used to fully describe the data transmitted in plaintexts or ciphertexts.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct AuthenticatedContent {
    pub wire_format: WireFormat,
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
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

impl AuthenticatedContent {
    /// Create a new AuthenticatedContent by signing FramedContent with GroupContext
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        wire_format: WireFormat,
        content: &FramedContent,
        ctx: &GroupContext,
    ) -> Result<Self> {
        let mut auth_content = Self {
            wire_format,
            content: content.clone(),
            auth: Default::default(),
        };
        let tbs = auth_content.framed_content_tbs(ctx);
        auth_content.auth.signature = FramedContentAuthData::sign_framed_content(
            crypto_provider,
            cipher_suite,
            sign_key,
            &tbs,
        )?;

        Ok(auth_content)
    }

    pub(crate) fn confirmed_transcript_hash_input(&self) -> ConfirmedTranscriptHashInput {
        ConfirmedTranscriptHashInput {
            wire_format: self.wire_format,
            content: self.content.clone(),
            signature: self.auth.signature.clone(),
        }
    }

    pub(crate) fn framed_content_tbs(&self, ctx: &GroupContext) -> FramedContentTBS {
        FramedContentTBS {
            version: ProtocolVersion::MLS10,
            wire_format: self.wire_format,
            content: self.content.clone(),
            context: Some(ctx.clone()),
        }
    }

    /// Verify the signature of FramedContentAuthData
    pub fn verify_signature(
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

/// [RFC9420 Sec.6.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1) FramedContentTBS
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct FramedContentTBS {
    pub version: ProtocolVersion,
    pub wire_format: WireFormat,
    pub content: FramedContent,
    pub context: Option<GroupContext>, // for SenderType::Member and SenderType::NewMemberCommit
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
        let version = buf.get_u16().into();
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
        buf.put_u16(self.version.into());
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

/// [RFC9420 Sec.6.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1) FramedContentAuthData
/// is used for authenticating FramedContent
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct FramedContentAuthData {
    pub signature: Bytes,
    pub confirmation_tag: Bytes, // for ContentType::Commit
}

impl FramedContentAuthData {
    pub fn deserialize<B>(buf: &mut B, content_type: ContentType) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let signature = deserialize_opaque_vec(buf)?;
        let confirmation_tag = if content_type == ContentType::Commit {
            deserialize_opaque_vec(buf)?
        } else {
            Bytes::new()
        };

        Ok(Self {
            signature,
            confirmation_tag,
        })
    }

    pub fn serialize<B>(&self, buf: &mut B, content_type: ContentType) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.signature, buf)?;

        if content_type == ContentType::Commit {
            serialize_opaque_vec(&self.confirmation_tag, buf)?;
        }
        Ok(())
    }

    /// [RFC9420 Sec.6.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1) Sign
    /// FramedContent to get the signature by computing using SignWithLabel with label "FramedContentTBS"
    /// and with a content that covers the message content and the wire format that will be used
    /// for this message.
    pub fn sign_framed_content(
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        tbs: &FramedContentTBS,
    ) -> Result<Bytes> {
        let raw_content = tbs.serialize_detached()?;
        crypto_provider.sign_with_label(cipher_suite, sign_key, b"FramedContentTBS", &raw_content)
    }

    /// [RFC9420 Sec.6.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1) Recipients of an
    /// MLSMessage MUST verify the signature with the key depending on the sender_type of the sender
    /// as described above.
    pub fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        verify_key: &[u8],
        tbs: &FramedContentTBS,
    ) -> Result<()> {
        let raw_content = tbs.serialize_detached()?;
        crypto_provider.verify_with_label(
            cipher_suite,
            verify_key,
            b"FramedContentTBS",
            &raw_content,
            &self.signature,
        )
    }

    /// [RFC9420 Sec.6.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1) The confirmation
    /// tag value confirms that the members of the group have arrived at the same state of the group.
    /// A FramedContentAuthData is said to be valid when both the signature and confirmation_tag
    /// fields are valid.
    pub fn verify_confirmation_tag(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        confirmation_key: &[u8],
        confirmed_transcript_hash: &[u8],
    ) -> Result<()> {
        if self.confirmation_tag.is_empty() {
            Err(Error::VerifyConfirmationTagFailed)
        } else {
            crypto_provider.verify_mac(
                cipher_suite,
                confirmation_key,
                confirmed_transcript_hash,
                &self.confirmation_tag,
            )
        }
    }
}

/// [RFC9420 Sec.6.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2) Messages that are
/// authenticated but not encrypted are encoded using the PublicMessage structure.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PublicMessage {
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
    pub membership_tag: Option<Bytes>, // for SenderType::Member
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
    /// Create a new PublicMessage by signing FramedContent with GroupContext to get
    /// FramedContentAuthData and setting membership_tag to None
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        content: &FramedContent,
        ctx: &GroupContext,
    ) -> Result<PublicMessage> {
        let auth_content = AuthenticatedContent::new(
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

    pub(crate) fn authenticated_content(&self) -> AuthenticatedContent {
        AuthenticatedContent {
            wire_format: WireFormat::PublicMessage,
            content: self.content.clone(),
            auth: self.auth.clone(),
        }
    }

    pub(crate) fn authenticated_content_tbm(&self, ctx: &GroupContext) -> AuthenticatedContentTBM {
        AuthenticatedContentTBM {
            content_tbs: self.authenticated_content().framed_content_tbs(ctx),
            auth: self.auth.clone(),
        }
    }

    /// [RFC9420 Sec.6.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2) The membership_tag
    /// field in the PublicMessage object authenticates the sender's membership in the group.
    pub fn sign_membership_tag(
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
        let raw_auth_content_tbm = self.authenticated_content_tbm(ctx).serialize_detached()?;
        self.membership_tag =
            Some(crypto_provider.sign_mac(cipher_suite, membership_key, &raw_auth_content_tbm)?);
        Ok(())
    }

    /// [RFC9420 Sec.6.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2) When decoding a
    /// PublicMessage into an AuthenticatedContent, the application MUST check
    /// membership_tag and MUST check that the FramedContentAuthData is valid.
    pub fn verify_membership_tag(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        membership_key: &[u8],
        ctx: &GroupContext,
    ) -> Result<()> {
        match self.content.sender {
            Sender::External(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => {
                return Ok(());
            }
            _ => {}
        };
        if let Some(membership_tag) = &self.membership_tag {
            let raw_auth_content_tbm =
                if let Ok(raw) = self.authenticated_content_tbm(ctx).serialize_detached() {
                    raw
                } else {
                    return Err(Error::VerifyConfirmationTagFailed);
                };
            crypto_provider.verify_mac(
                cipher_suite,
                membership_key,
                &raw_auth_content_tbm,
                membership_tag,
            )
        } else {
            Ok(())
        }
    }
}

/// [RFC9420 Sec.6.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2) For messages sent
/// by members, it MUST be set to AuthenticatedContentTBM
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct AuthenticatedContentTBM {
    pub content_tbs: FramedContentTBS,
    pub auth: FramedContentAuthData,
}

impl Deserializer for AuthenticatedContentTBM {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let content_tbs = FramedContentTBS::deserialize(buf)?;
        let auth =
            FramedContentAuthData::deserialize(buf, content_tbs.content.content.content_type())?;
        Ok(Self { content_tbs, auth })
    }
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

/// [RFC9420 Sec.6.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3) Authenticated and
/// encrypted messages are encoded using the PrivateMessage structure.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateMessage {
    pub group_id: GroupID,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Bytes,
    pub encrypted_sender_data: Bytes,
    pub ciphertext: Bytes,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        secret: &RatchetSecret,
        sender_data_secret: &[u8],
        content: &FramedContent,
        sender_data: &SenderData,
        ctx: &GroupContext,
    ) -> Result<PrivateMessage> {
        let ciphertext = encrypt_private_message_content(
            crypto_provider,
            cipher_suite,
            sign_key,
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
        let raw_aad = aad.serialize_detached()?;

        let raw_sender_data = crypto_provider.hpke(cipher_suite)?.aead_open(
            &key,
            &nonce,
            &self.encrypted_sender_data,
            &raw_aad,
        )?;

        SenderData::deserialize_exact(&raw_sender_data)
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

        let raw_aad = aad.serialize_detached()?;
        let raw_content = crypto_provider.hpke(cipher_suite)?.aead_open(
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

/// [RFC9420 Sec.6.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.1) Content to be
/// encrypted is encoded in a PrivateMessageContent structure.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateMessageContent {
    pub content: Content,
    pub auth: FramedContentAuthData,
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

        //FIXME(yngrtc): https://github.com/webrtc-rs/rmls/issues/5 fix padding check for RingCryptoProvider
        #[cfg(not(feature = "RingCryptoProvider"))]
        {
            while buf.has_remaining() {
                if buf.get_u8() != 0 {
                    return Err(Error::PaddingContainsNonZeroBytes);
                }
            }
        }

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

/// [RFC9420 Sec.6.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.1) The Additional
/// Authenticated Data (AAD) input to the encryption contains an object of the following form,
/// with the values used to identify the key and nonce
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateContentAAD {
    pub group_id: GroupID,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Bytes,
}

impl Deserializer for PrivateContentAAD {
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

        Ok(Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
        })
    }
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

/// [RFC9420 Sec.6.3.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.2) The SenderData
/// used to look up the key for content encryption is encrypted with the cipher suite's AEAD with
/// a key and nonce derived from both the sender_data_secret and a sample of the encrypted content.
/// Before being encrypted, the sender data is encoded as an object of the following form
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct SenderData {
    pub leaf_index: LeafIndex,
    pub generation: u32,
    pub reuse_guard: [u8; 4],
}

impl SenderData {
    /// Create a new SenderData
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        leaf_index: LeafIndex,
        generation: u32,
    ) -> Result<Self> {
        let mut reuse_guard: [u8; 4] = [0u8; 4];
        crypto_provider.rand().fill(&mut reuse_guard[..])?;
        Ok(Self {
            leaf_index,
            generation,
            reuse_guard,
        })
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

/// [RFC9420 Sec.6.3.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.2) The AAD for the
/// SenderData ciphertext is the first three fields of PrivateMessage.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SenderDataAAD {
    pub group_id: GroupID,
    pub epoch: u64,
    pub content_type: ContentType,
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
    let auth_content = AuthenticatedContent::new(
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

    let plainttext = priv_content.serialize_detached()?;

    let (key, nonce) =
        derive_private_message_key_and_nonce(crypto_provider, cipher_suite, secret, reuse_guard)?;

    let aad = PrivateContentAAD {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type: content.content.content_type(),
        authenticated_data: content.authenticated_data.clone(),
    };
    let raw_aad = aad.serialize_detached()?;

    crypto_provider
        .hpke(cipher_suite)?
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
    let raw_aad = aad.serialize_detached()?;
    let raw_sender_data = sender_data.serialize_detached()?;

    crypto_provider
        .hpke(cipher_suite)?
        .aead_seal(&key, &nonce, &raw_sender_data, &raw_aad)
}

pub(crate) fn expand_sender_data_key(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sender_data_secret: &[u8],
    ciphertext: &[u8],
) -> Result<Bytes> {
    let nk = crypto_provider.hpke(cipher_suite)?.aead_key_size() as u16;
    let ciphertext_sample = sample_ciphertext(crypto_provider, cipher_suite, ciphertext)?;
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
    let nn = crypto_provider.hpke(cipher_suite)?.aead_nonce_size() as u16;
    let ciphertext_sample = sample_ciphertext(crypto_provider, cipher_suite, ciphertext)?;
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
) -> Result<&'a [u8]> {
    let n = crypto_provider.hpke(cipher_suite)?.kdf_extract_size();
    if ciphertext.len() < n {
        Ok(ciphertext)
    } else {
        Ok(&ciphertext[..n])
    }
}
