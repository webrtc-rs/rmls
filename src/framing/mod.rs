use bytes::{Buf, BufMut, Bytes};

use crate::cipher_suite::CipherSuite;
use crate::codec::*;
use crate::crypto::provider::CryptoProvider;
use crate::error::*;
use crate::key_schedule::{ConfirmedTranscriptHashInput, GroupContext};
use crate::messages::proposal::Proposal;
use crate::messages::Commit;
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

/*
type mlsMessage struct {
    version        protocolVersion
    wire_format     wire_format
    publicMessage  *publicMessage  // for wireFormatMLSPublicMessage
    privateMessage *privateMessage // for wireFormatMLSPrivateMessage
    welcome        *welcome        // for wireFormatMLSWelcome
    groupInfo      *groupInfo      // for wireFormatMLSGroupInfo
    keyPackage     *keyPackage     // for wireFormatMLSKeyPackage
}

func (msg *mlsMessage) unmarshal(s *cryptobyte.String) error {
    *msg = mlsMessage{}

    if !s.ReadUint16((*uint16)(&msg.version)) {
        return io.ErrUnexpectedEOF
    }
    if msg.version != protocolVersionMLS10 {
        return fmt.Errorf("mls: invalid protocol version %d", msg.version)
    }

    if err := msg.wire_format.unmarshal(s); err != nil {
        return err
    }

    switch msg.wire_format {
    case wireFormatMLSPublicMessage:
        msg.publicMessage = new(publicMessage)
        return msg.publicMessage.unmarshal(s)
    case wireFormatMLSPrivateMessage:
        msg.privateMessage = new(privateMessage)
        return msg.privateMessage.unmarshal(s)
    case wireFormatMLSWelcome:
        msg.welcome = new(welcome)
        return msg.welcome.unmarshal(s)
    case wireFormatMLSGroupInfo:
        msg.groupInfo = new(groupInfo)
        return msg.groupInfo.unmarshal(s)
    case wireFormatMLSKeyPackage:
        msg.keyPackage = new(keyPackage)
        return msg.keyPackage.unmarshal(s)
    default:
        panic("unreachable")
    }
}

func (msg *mlsMessage) marshal(b *cryptobyte.Builder) {
    b.AddUint16(uint16(msg.version))
    msg.wire_format.marshal(b)
    switch msg.wire_format {
    case wireFormatMLSPublicMessage:
        msg.publicMessage.marshal(b)
    case wireFormatMLSPrivateMessage:
        msg.privateMessage.marshal(b)
    case wireFormatMLSWelcome:
        msg.welcome.marshal(b)
    case wireFormatMLSGroupInfo:
        msg.groupInfo.marshal(b)
    case wireFormatMLSKeyPackage:
        msg.keyPackage.marshal(b)
    default:
        panic("unreachable")
    }
}*/

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct AuthenticatedContent {
    wire_format: WireFormat,
    content: FramedContent,
    auth: FramedContentAuthData,
}

impl Reader for AuthenticatedContent {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.wire_format.read(buf)?;
        self.content.read(buf)?;
        self.auth.read(buf, &self.content.content)
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
        self.auth.write(buf, &self.content.content)
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
    fn confirmed_transcript_hash_input(&self) -> ConfirmedTranscriptHashInput {
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
    confirmation_tag: Option<Bytes>, // for contentTypeCommit
}

impl FramedContentAuthData {
    fn read<B>(&mut self, buf: &mut B, content: &Content) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.signature = read_opaque_vec(buf)?;
        if let Content::Commit(_) = content {
            self.confirmation_tag = Some(read_opaque_vec(buf)?);
        } else {
            self.confirmation_tag = None;
        }

        Ok(())
    }

    fn write<B>(&self, buf: &mut B, content: &Content) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.signature, buf)?;

        if let Content::Commit(_) = content {
            if let Some(confirmation_tag) = &self.confirmation_tag {
                write_opaque_vec(confirmation_tag, buf)?;
            }
        }
        Ok(())
    }

    fn verify_confirmation_tag(
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

/*
type publicMessage struct {
    content       framedContent
    auth          framedContentAuthData
    membershipTag []byte // for senderTypeMember
}

func signPublicMessage(cs cipherSuite, signKey []byte, content *framedContent, ctx *groupContext) (*publicMessage, error) {
    authContent, err := sign_authenticated_content(cs, signKey, wireFormatMLSPublicMessage, content, ctx)
    if err != nil {
        return nil, err
    }
    return &publicMessage{
        content: authContent.content,
        auth:    authContent.auth,
    }, nil
}

func (msg *publicMessage) unmarshal(s *cryptobyte.String) error {
    *msg = publicMessage{}

    if err := msg.content.unmarshal(s); err != nil {
        return err
    }
    if err := msg.auth.unmarshal(s, msg.content.contentType); err != nil {
        return err
    }

    if msg.content.sender.senderType == senderTypeMember {
        if !readOpaqueVec(s, &msg.membershipTag) {
            return io.ErrUnexpectedEOF
        }
    }

    return nil
}

func (msg *publicMessage) marshal(b *cryptobyte.Builder) {
    msg.content.marshal(b)
    msg.auth.marshal(b, msg.content.contentType)

    if msg.content.sender.senderType == senderTypeMember {
        writeOpaqueVec(b, msg.membershipTag)
    }
}

func (msg *publicMessage) authenticatedContent() *authenticatedContent {
    return &authenticatedContent{
        wire_format: wireFormatMLSPublicMessage,
        content:    msg.content,
        auth:       msg.auth,
    }
}

func (msg *publicMessage) authenticatedContentTBM(ctx *groupContext) *authenticatedContentTBM {
    return &authenticatedContentTBM{
        contentTBS: *msg.authenticatedContent().framed_content_tbs(ctx),
        auth:       msg.auth,
    }
}

func (msg *publicMessage) signMembershipTag(cs cipherSuite, membershipKey []byte, ctx *groupContext) error {
    if msg.content.sender.senderType != senderTypeMember {
        return nil
    }
    rawAuthContentTBM, err := marshal(msg.authenticatedContentTBM(ctx))
    if err != nil {
        return err
    }
    msg.membershipTag = cs.signMAC(membershipKey, rawAuthContentTBM)
    return nil
}

func (msg *publicMessage) verifyMembershipTag(cs cipherSuite, membershipKey []byte, ctx *groupContext) bool {
    if msg.content.sender.senderType != senderTypeMember {
        return true // there is no membership tag
    }
    rawAuthContentTBM, err := marshal(msg.authenticatedContentTBM(ctx))
    if err != nil {
        return false
    }
    return cs.verifyMAC(membershipKey, rawAuthContentTBM, msg.membershipTag)
}

type authenticatedContentTBM struct {
    contentTBS framed_content_tbs
    auth       framedContentAuthData
}

func (tbm *authenticatedContentTBM) marshal(b *cryptobyte.Builder) {
    tbm.contentTBS.marshal(b)
    tbm.auth.marshal(b, tbm.contentTBS.content.contentType)
}

type privateMessage struct {
    groupID             GroupID
    epoch               uint64
    contentType         contentType
    authenticatedData   []byte
    encryptedSenderData []byte
    ciphertext          []byte
}

func encryptPrivateMessage(cs cipherSuite, signPriv []byte, secret ratchetSecret, senderDataSecret []byte, content *framedContent, senderData *senderData, ctx *groupContext) (*privateMessage, error) {
    ciphertext, err := encryptPrivateMessageContent(cs, signPriv, secret, content, ctx, senderData.reuseGuard)
    if err != nil {
        return nil, err
    }
    encryptedSenderData, err := encryptSenderData(cs, senderDataSecret, senderData, content, ciphertext)
    if err != nil {
        return nil, err
    }
    return &privateMessage{
        groupID:             content.groupID,
        epoch:               content.epoch,
        contentType:         content.contentType,
        authenticatedData:   content.authenticatedData,
        encryptedSenderData: encryptedSenderData,
        ciphertext:          ciphertext,
    }, nil
}

func (msg *privateMessage) unmarshal(s *cryptobyte.String) error {
    *msg = privateMessage{}
    ok := readOpaqueVec(s, (*[]byte)(&msg.groupID)) &&
        s.ReadUint64(&msg.epoch)
    if !ok {
        return io.ErrUnexpectedEOF
    }
    if err := msg.contentType.unmarshal(s); err != nil {
        return err
    }
    ok = readOpaqueVec(s, &msg.authenticatedData) &&
        readOpaqueVec(s, &msg.encryptedSenderData) &&
        readOpaqueVec(s, &msg.ciphertext)
    if !ok {
        return io.ErrUnexpectedEOF
    }
    return nil
}

func (msg *privateMessage) marshal(b *cryptobyte.Builder) {
    writeOpaqueVec(b, []byte(msg.groupID))
    b.AddUint64(msg.epoch)
    msg.contentType.marshal(b)
    writeOpaqueVec(b, msg.authenticatedData)
    writeOpaqueVec(b, msg.encryptedSenderData)
    writeOpaqueVec(b, msg.ciphertext)
}

func (msg *privateMessage) decryptSenderData(cs cipherSuite, senderDataSecret []byte) (*senderData, error) {
    key, err := expandSenderDataKey(cs, senderDataSecret, msg.ciphertext)
    if err != nil {
        return nil, err
    }
    nonce, err := expandSenderDataNonce(cs, senderDataSecret, msg.ciphertext)
    if err != nil {
        return nil, err
    }

    aad := senderDataAAD{
        groupID:     msg.groupID,
        epoch:       msg.epoch,
        contentType: msg.contentType,
    }
    rawAAD, err := marshal(&aad)
    if err != nil {
        return nil, err
    }

    _, _, aead := cs.hpke().Params()
    cipher, err := aead.New(key)
    if err != nil {
        return nil, err
    }

    rawSenderData, err := cipher.Open(nil, nonce, msg.encryptedSenderData, rawAAD)
    if err != nil {
        return nil, err
    }

    var senderData senderData
    if err := unmarshal(rawSenderData, &senderData); err != nil {
        return nil, err
    }

    return &senderData, nil
}

func (msg *privateMessage) decryptContent(cs cipherSuite, secret ratchetSecret, reuseGuard [4]byte) (*privateMessageContent, error) {
    key, nonce, err := derivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
    if err != nil {
        return nil, err
    }

    aad := privateContentAAD{
        groupID:           msg.groupID,
        epoch:             msg.epoch,
        contentType:       msg.contentType,
        authenticatedData: msg.authenticatedData,
    }
    rawAAD, err := marshal(&aad)
    if err != nil {
        return nil, err
    }

    _, _, aead := cs.hpke().Params()
    cipher, err := aead.New(key)
    if err != nil {
        return nil, err
    }

    rawContent, err := cipher.Open(nil, nonce, msg.ciphertext, rawAAD)
    if err != nil {
        return nil, err
    }

    s := cryptobyte.String(rawContent)
    var content privateMessageContent
    if err := content.unmarshal(&s, msg.contentType); err != nil {
        return nil, err
    }

    for _, v := range s {
        if v != 0 {
            return nil, fmt.Errorf("mls: padding contains non-zero bytes")
        }
    }

    return &content, nil
}

func derivePrivateMessageKeyAndNonce(cs cipherSuite, secret ratchetSecret, reuseGuard [4]byte) (key, nonce []byte, err error) {
    key, err = secret.deriveKey(cs)
    if err != nil {
        return nil, nil, err
    }
    nonce, err = secret.deriveNonce(cs)
    if err != nil {
        return nil, nil, err
    }

    for i := range reuseGuard {
        nonce[i] = nonce[i] ^ reuseGuard[i]
    }

    return key, nonce, nil
}

func (msg *privateMessage) authenticatedContent(senderData *senderData, content *privateMessageContent) *authenticatedContent {
    return &authenticatedContent{
        wire_format: wireFormatMLSPrivateMessage,
        content: framedContent{
            groupID: msg.groupID,
            epoch:   msg.epoch,
            sender: sender{
                senderType: senderTypeMember,
                leafIndex:  senderData.leafIndex,
            },
            authenticatedData: msg.authenticatedData,
            contentType:       msg.contentType,
            applicationData:   content.applicationData,
            proposal:          content.proposal,
            commit:            content.commit,
        },
        auth: content.auth,
    }
}

type senderDataAAD struct {
    groupID     GroupID
    epoch       uint64
    contentType contentType
}

func (aad *senderDataAAD) marshal(b *cryptobyte.Builder) {
    writeOpaqueVec(b, []byte(aad.groupID))
    b.AddUint64(aad.epoch)
    aad.contentType.marshal(b)
}

type privateContentAAD struct {
    groupID           GroupID
    epoch             uint64
    contentType       contentType
    authenticatedData []byte
}

func (aad *privateContentAAD) marshal(b *cryptobyte.Builder) {
    writeOpaqueVec(b, []byte(aad.groupID))
    b.AddUint64(aad.epoch)
    aad.contentType.marshal(b)
    writeOpaqueVec(b, aad.authenticatedData)
}

type privateMessageContent struct {
    applicationData []byte    // for contentTypeApplication
    proposal        *proposal // for contentTypeProposal
    commit          *commit   // for contentTypeCommit

    auth framedContentAuthData
}

func (content *privateMessageContent) unmarshal(s *cryptobyte.String, ct contentType) error {
    *content = privateMessageContent{}

    var err error
    switch ct {
    case contentTypeApplication:
        if !readOpaqueVec(s, &content.applicationData) {
            err = io.ErrUnexpectedEOF
        }
    case contentTypeProposal:
        content.proposal = new(proposal)
        err = content.proposal.unmarshal(s)
    case contentTypeCommit:
        content.commit = new(commit)
        err = content.commit.unmarshal(s)
    default:
        panic("unreachable")
    }
    if err != nil {
        return err
    }

    return content.auth.unmarshal(s, ct)
}

func (content *privateMessageContent) marshal(b *cryptobyte.Builder, ct contentType) {
    switch ct {
    case contentTypeApplication:
        writeOpaqueVec(b, content.applicationData)
    case contentTypeProposal:
        content.proposal.marshal(b)
    case contentTypeCommit:
        content.commit.marshal(b)
    default:
        panic("unreachable")
    }
    content.auth.marshal(b, ct)
}

func encryptPrivateMessageContent(cs cipherSuite, signKey []byte, secret ratchetSecret, content *framedContent, ctx *groupContext, reuseGuard [4]byte) ([]byte, error) {
    authContent, err := sign_authenticated_content(cs, signKey, wireFormatMLSPrivateMessage, content, ctx)
    if err != nil {
        return nil, err
    }

    privContent := privateMessageContent{
        applicationData: content.applicationData,
        proposal:        content.proposal,
        commit:          content.commit,
        auth:            authContent.auth,
    }
    var b cryptobyte.Builder
    privContent.marshal(&b, content.contentType)
    plaintext, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    key, nonce, err := derivePrivateMessageKeyAndNonce(cs, secret, reuseGuard)
    if err != nil {
        return nil, err
    }

    aad := privateContentAAD{
        groupID:           content.groupID,
        epoch:             content.epoch,
        contentType:       content.contentType,
        authenticatedData: content.authenticatedData,
    }
    rawAAD, err := marshal(&aad)
    if err != nil {
        return nil, err
    }

    _, _, aead := cs.hpke().Params()
    cipher, err := aead.New(key)
    if err != nil {
        return nil, err
    }

    return cipher.Seal(nil, nonce, plaintext, rawAAD), nil
}

func encryptSenderData(cs cipherSuite, senderDataSecret []byte, senderData *senderData, content *framedContent, ciphertext []byte) ([]byte, error) {
    key, err := expandSenderDataKey(cs, senderDataSecret, ciphertext)
    if err != nil {
        return nil, err
    }
    nonce, err := expandSenderDataNonce(cs, senderDataSecret, ciphertext)
    if err != nil {
        return nil, err
    }

    aad := senderDataAAD{
        groupID:     content.groupID,
        epoch:       content.epoch,
        contentType: content.contentType,
    }
    rawAAD, err := marshal(&aad)
    if err != nil {
        return nil, err
    }

    _, _, aead := cs.hpke().Params()
    cipher, err := aead.New(key)
    if err != nil {
        return nil, err
    }

    rawSenderData, err := marshal(senderData)
    if err != nil {
        return nil, err
    }

    return cipher.Seal(nil, nonce, rawSenderData, rawAAD), nil
}

type senderData struct {
    leafIndex  leafIndex
    generation uint32
    reuseGuard [4]byte
}

func newSenderData(leafIndex leafIndex, generation uint32) (*senderData, error) {
    data := senderData{
        leafIndex:  leafIndex,
        generation: generation,
    }
    if _, err := rand.Read(data.reuseGuard[:]); err != nil {
        return nil, err
    }
    return &data, nil
}

func (data *senderData) unmarshal(s *cryptobyte.String) error {
    if !s.ReadUint32((*uint32)(&data.leafIndex)) || !s.ReadUint32(&data.generation) || !s.CopyBytes(data.reuseGuard[:]) {
        return io.ErrUnexpectedEOF
    }
    return nil
}

func (data *senderData) marshal(b *cryptobyte.Builder) {
    b.AddUint32(uint32(data.leafIndex))
    b.AddUint32(data.generation)
    b.AddBytes(data.reuseGuard[:])
}

*/

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
