use crate::framing::*;

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
