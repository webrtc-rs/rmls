use bytes::{Buf, BufMut, Bytes};
use rand::Rng;

use crate::cipher_suite::CipherSuite;
use crate::codec::*;
use crate::crypto::provider::CryptoProvider;
use crate::error::*;
use crate::key_package::KeyPackage;
use crate::key_schedule::{ConfirmedTranscriptHashInput, GroupContext};
use crate::messages::group_info::GroupInfo;
use crate::messages::proposal::Proposal;
use crate::messages::{Commit, Welcome};
use crate::tree::secret_tree::RatchetSecret;
use crate::tree::tree_math::LeafIndex;

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

impl Reader for ContentType {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        *self = buf.get_u8().try_into()?;
        Ok(())
    }
}
impl Writer for ContentType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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

impl Reader for Content {
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
            0x01 => {
                *self = Content::Application(read_opaque_vec(buf)?);
            }
            0x02 => {
                let mut proposal = Proposal::default();
                proposal.read(buf)?;
                *self = Content::Proposal(proposal);
            }
            0x03 => {
                let mut commit = Commit::default();
                commit.read(buf)?;
                *self = Content::Commit(commit);
            }
            _ => return Err(Error::InvalidContentTypeValue(v)),
        }

        Ok(())
    }
}
impl Writer for Content {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Content::Application(application) => {
                buf.put_u8(1);
                write_opaque_vec(application, buf)?;
            }
            Content::Proposal(proposal) => {
                buf.put_u8(2);
                proposal.write(buf)?;
            }
            Content::Commit(commit) => {
                buf.put_u8(3);
                commit.write(buf)?
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

impl Reader for Sender {
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
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                *self = Sender::Member(LeafIndex(buf.get_u32()));
            }
            2 => {
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                *self = Sender::External(buf.get_u32());
            }
            3 => {
                *self = Sender::NewMemberProposal;
            }
            4 => {
                *self = Sender::NewMemberCommit;
            }
            _ => return Err(Error::InvalidSenderTypeValue(v)),
        }

        Ok(())
    }
}

impl Writer for Sender {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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

impl Reader for WireFormat {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }

        *self = buf.get_u16().try_into()?;

        Ok(())
    }
}

impl Writer for WireFormat {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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
    group_id: GroupID,
    epoch: u64,
    sender: Sender,
    authenticated_data: Bytes,
    pub(crate) content: Content,
}

impl Reader for FramedContent {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.group_id = read_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        self.epoch = buf.get_u64();
        self.sender.read(buf)?;
        self.authenticated_data = read_opaque_vec(buf)?;
        self.content.read(buf)
    }
}

impl Writer for FramedContent {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.sender.write(buf)?;
        write_opaque_vec(&self.authenticated_data, buf)?;
        self.content.write(buf)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WireFormatMessage {
    PublicMessage(PublicMessage),
    PrivateMessage(PrivateMessage),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}

impl Default for WireFormatMessage {
    fn default() -> Self {
        WireFormatMessage::Welcome(Welcome::default())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct MlsMessage {
    version: ProtocolVersion,
    pub(crate) wire_format: WireFormat,
    pub(crate) message: WireFormatMessage,
}

impl Reader for MlsMessage {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        self.version = buf.get_u16();

        if self.version != PROTOCOL_VERSION_MLS10 {
            return Err(Error::InvalidProtocolVersion(self.version));
        }

        self.wire_format.read(buf)?;

        match self.wire_format {
            WireFormat::PublicMessage => {
                let mut message = PublicMessage::default();
                message.read(buf)?;
                self.message = WireFormatMessage::PublicMessage(message);
            }
            WireFormat::PrivateMessage => {
                let mut message = PrivateMessage::default();
                message.read(buf)?;
                self.message = WireFormatMessage::PrivateMessage(message);
            }
            WireFormat::Welcome => {
                let mut message = Welcome::default();
                message.read(buf)?;
                self.message = WireFormatMessage::Welcome(message);
            }
            WireFormat::GroupInfo => {
                let mut message = GroupInfo::default();
                message.read(buf)?;
                self.message = WireFormatMessage::GroupInfo(message);
            }
            WireFormat::KeyPackage => {
                let mut message = KeyPackage::default();
                message.read(buf)?;
                self.message = WireFormatMessage::KeyPackage(message);
            }
        }
        Ok(())
    }
}
impl Writer for MlsMessage {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        self.wire_format.write(buf)?;
        match &self.message {
            WireFormatMessage::PublicMessage(message) => {
                message.write(buf)?;
            }
            WireFormatMessage::PrivateMessage(message) => {
                message.write(buf)?;
            }
            WireFormatMessage::Welcome(message) => {
                message.write(buf)?;
            }
            WireFormatMessage::GroupInfo(message) => {
                message.write(buf)?;
            }
            WireFormatMessage::KeyPackage(message) => {
                message.write(buf)?;
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct AuthenticatedContent {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: FramedContent,
    pub(crate) auth: FramedContentAuthData,
}

impl Reader for AuthenticatedContent {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.wire_format.read(buf)?;
        self.content.read(buf)?;
        self.auth.read(buf, self.content.content.content_type())
    }
}

impl Writer for AuthenticatedContent {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.wire_format.write(buf)?;
        self.content.write(buf)?;
        self.auth.write(buf, self.content.content.content_type())
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

    fn verify_signature(
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
    pub(crate) confirmation_tag: Option<Bytes>, // for contentTypeCommit
}

impl FramedContentAuthData {
    fn read<B>(&mut self, buf: &mut B, ct: ContentType) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.signature = read_opaque_vec(buf)?;
        if ct == ContentType::Commit {
            self.confirmation_tag = Some(read_opaque_vec(buf)?);
        } else {
            self.confirmation_tag = None;
        }

        Ok(())
    }

    fn write<B>(&self, buf: &mut B, ct: ContentType) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.signature, buf)?;

        if ct == ContentType::Commit {
            if let Some(confirmation_tag) = &self.confirmation_tag {
                write_opaque_vec(confirmation_tag, buf)?;
            }
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
        if let Some(confirmation_tag) = &self.confirmation_tag {
            if confirmation_tag.is_empty() {
                false
            } else {
                crypto_provider.verify_mac(
                    cipher_suite,
                    confirmation_key,
                    confirmed_transcript_hash,
                    confirmation_tag,
                )
            }
        } else {
            false
        }
    }

    fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        verif_key: &[u8],
        content: &FramedContentTBS,
    ) -> Result<()> {
        let raw_content = write(content)?;
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
    let raw_content = write(content)?;
    crypto_provider.sign_with_label(cipher_suite, sign_key, b"FramedContentTBS", &raw_content)
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct FramedContentTBS {
    version: ProtocolVersion,
    wire_format: WireFormat,
    content: FramedContent,
    context: Option<GroupContext>, // for senderTypeMember and senderTypeNewMemberCommit
}

impl Reader for FramedContentTBS {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        self.version = buf.get_u16();
        self.wire_format.read(buf)?;
        self.content.read(buf)?;

        let sender = self.content.sender;
        match sender {
            Sender::Member(_) | Sender::NewMemberCommit => {
                let mut group_context = GroupContext::default();
                group_context.read(buf)?;
                self.context = Some(group_context);
            }
            _ => self.context = None,
        }

        Ok(())
    }
}

impl Writer for FramedContentTBS {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        self.wire_format.write(buf)?;
        self.content.write(buf)?;
        match &self.content.sender {
            Sender::Member(_) | Sender::NewMemberCommit => {
                if let Some(group_context) = &self.context {
                    group_context.write(buf)?;
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
    content: FramedContent,
    auth: FramedContentAuthData,
    membership_tag: Option<Bytes>, // for senderTypeMember
}

fn sign_public_message(
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

impl Reader for PublicMessage {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.content.read(buf)?;
        self.auth.read(buf, self.content.content.content_type())?;

        if let Sender::Member(_) = &self.content.sender {
            self.membership_tag = Some(read_opaque_vec(buf)?);
        }

        Ok(())
    }
}
impl Writer for PublicMessage {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.content.write(buf)?;
        self.auth.write(buf, self.content.content.content_type())?;

        if let Sender::Member(_) = &self.content.sender {
            if let Some(membership_tag) = &self.membership_tag {
                write_opaque_vec(membership_tag, buf)?;
            }
        }

        Ok(())
    }
}

impl PublicMessage {
    fn authenticated_content(&self) -> AuthenticatedContent {
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

    fn sign_membership_tag(
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
        let raw_auth_content_tbm = write(&self.authenticated_content_tbm(ctx))?;
        self.membership_tag =
            Some(crypto_provider.sign_mac(cipher_suite, membership_key, &raw_auth_content_tbm));
        Ok(())
    }

    fn verify_membership_tag(
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
            let raw_auth_content_tbm = if let Ok(raw) = write(&self.authenticated_content_tbm(ctx))
            {
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

impl Writer for AuthenticatedContentTBM {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.content_tbs.write(buf)?;
        self.auth
            .write(buf, self.content_tbs.content.content.content_type())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateMessage {
    group_id: GroupID,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: Bytes,
    encrypted_sender_data: Bytes,
    ciphertext: Bytes,
}

#[allow(clippy::too_many_arguments)]
fn encrypt_private_message(
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

impl Reader for PrivateMessage {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.group_id = read_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        self.epoch = buf.get_u64();
        self.content_type.read(buf)?;
        self.authenticated_data = read_opaque_vec(buf)?;
        self.encrypted_sender_data = read_opaque_vec(buf)?;
        self.ciphertext = read_opaque_vec(buf)?;
        Ok(())
    }
}

impl Writer for PrivateMessage {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.write(buf)?;
        write_opaque_vec(&self.authenticated_data, buf)?;
        write_opaque_vec(&self.encrypted_sender_data, buf)?;
        write_opaque_vec(&self.ciphertext, buf)
    }
}

impl PrivateMessage {
    fn decrypt_sender_data(
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
        let raw_aad = write(&aad)?;

        let raw_sender_data = crypto_provider.hpke(cipher_suite).aead_open(
            &key,
            &nonce,
            &self.encrypted_sender_data,
            &raw_aad,
        )?;
        let mut sender_data = SenderData::default();
        let mut buf = raw_sender_data.as_ref();
        sender_data.read(&mut buf)?;
        Ok(sender_data)
    }

    fn decrypt_content(
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

        let raw_aad = write(&aad)?;
        let raw_content = crypto_provider.hpke(cipher_suite).aead_open(
            &key,
            &nonce,
            &self.ciphertext,
            &raw_aad,
        )?;

        let mut buf = raw_content.as_ref();
        let mut content = PrivateMessageContent::default();
        content.read(&mut buf, self.content_type)?;

        while buf.has_remaining() {
            if buf.get_u8() != 0 {
                return Err(Error::PaddingContainsNonZeroBytes);
            }
        }

        Ok(content)
    }

    fn authenticated_content(
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

impl Writer for SenderDataAAD {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.write(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct PrivateContentAAD {
    group_id: GroupID,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: Bytes,
}

impl Writer for PrivateContentAAD {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.write(buf)?;
        write_opaque_vec(&self.authenticated_data, buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct PrivateMessageContent {
    content: Content,
    auth: FramedContentAuthData,
}

impl PrivateMessageContent {
    fn read<B>(&mut self, buf: &mut B, ct: ContentType) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        match ct {
            ContentType::Application => {
                self.content = Content::Application(read_opaque_vec(buf)?);
            }
            ContentType::Proposal => {
                let mut proposal = Proposal::default();
                proposal.read(buf)?;
                self.content = Content::Proposal(proposal);
            }
            ContentType::Commit => {
                let mut commit = Commit::default();
                commit.read(buf)?;
                self.content = Content::Commit(commit);
            }
        };

        self.auth.read(buf, ct)
    }
}

impl Writer for PrivateMessageContent {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match &self.content {
            Content::Application(application) => write_opaque_vec(application, buf)?,
            Content::Proposal(proposal) => proposal.write(buf)?,
            Content::Commit(commit) => commit.write(buf)?,
        }

        self.auth.write(buf, self.content.content_type())
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

    let plainttext = write(&priv_content)?;

    let (key, nonce) =
        derive_private_message_key_and_nonce(crypto_provider, cipher_suite, secret, reuse_guard)?;

    let aad = PrivateContentAAD {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type: content.content.content_type(),
        authenticated_data: content.authenticated_data.clone(),
    };
    let raw_aad = write(&aad)?;

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
    let raw_aad = write(&aad)?;
    let raw_sender_data = write(sender_data)?;

    crypto_provider
        .hpke(cipher_suite)
        .aead_seal(&key, &nonce, &raw_sender_data, &raw_aad)
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct SenderData {
    leaf_index: LeafIndex,
    generation: u32,
    reuse_guard: [u8; 4],
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

impl Reader for SenderData {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 12 {
            return Err(Error::BufferTooSmall);
        }
        self.leaf_index = LeafIndex(buf.get_u32());
        self.generation = buf.get_u32();
        buf.copy_to_slice(&mut self.reuse_guard);
        Ok(())
    }
}

impl Writer for SenderData {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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
