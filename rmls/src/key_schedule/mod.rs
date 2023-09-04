//! [RFC9420 Sec.8](https://www.rfc-editor.org/rfc/rfc9420.html#section-8) Key Schedule
//!
//! Given these inputs, the derivation of secrets for an epoch proceeds as shown in the following diagram:
//! ```text
//!                     init_secret_[n-1]
//!                           |
//!                           |
//!                           V
//!     commit_secret --> KDF.Extract
//!                           |
//!                           |
//!                           V
//!                   ExpandWithLabel(., "joiner", GroupContext_[n], KDF.Nh)
//!                           |
//!                           |
//!                           V
//!                      joiner_secret
//!                           |
//!                           |
//!                           V
//!      pks_secret(or 0)-->KDF.Extract
//!                           |
//!                           |
//!                           +--> DeriveSecret(., "welcome")
//!                           |    = welcome_secret
//!                           |
//!                           V
//!                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//!                           |
//!                           |
//!                           V
//!                      epoch_secret
//!   
//!                  The MLS Key Schedule
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::extensibility::Extensions;
use crate::framing::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;

#[cfg(test)]
mod key_schedule_test;

/// [RFC9420 Sec.8.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.1) Group Context
/// Each member of the group maintains a GroupContext object that summarizes the state of the group:
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupContext {
    /// The version is the protocol version
    pub version: ProtocolVersion,
    /// The cipher_suite is the cipher suite used by the group
    pub cipher_suite: CipherSuite,
    /// The group_id field is an application-defined identifier for the group
    pub group_id: GroupID,
    /// The epoch field represents the current version of the group
    pub epoch: u64,
    /// The tree_hash field contains a commitment to the contents of the group's ratchet tree and
    /// the credentials for the members of the group, as described in
    /// [RFC9420 Sec.7.8](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8)
    pub tree_hash: Bytes,
    /// The confirmed_transcript_hash field contains a running hash over the messages that led to this state
    pub confirmed_transcript_hash: Bytes,
    /// The extensions field contains the details of any protocol extensions that apply to the group
    pub extensions: Extensions,
}

impl Deserializer for GroupContext {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }

        let version: ProtocolVersion = buf.get_u16().into();
        let cipher_suite = buf.get_u16().try_into()?;
        let group_id = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        let epoch = buf.get_u64();
        let tree_hash = deserialize_opaque_vec(buf)?;
        let confirmed_transcript_hash = deserialize_opaque_vec(buf)?;

        if version != ProtocolVersion::MLS10 {
            return Err(Error::InvalidProposalTypeValue(version.into()));
        }

        let extensions = Extensions::deserialize(buf)?;

        Ok(Self {
            version,
            cipher_suite,
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
        })
    }
}
impl Serializer for GroupContext {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version.into());
        buf.put_u16(self.cipher_suite as u16);
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        serialize_opaque_vec(&self.tree_hash, buf)?;
        serialize_opaque_vec(&self.confirmed_transcript_hash, buf)?;
        self.extensions.serialize(buf)
    }
}

impl GroupContext {
    pub(crate) fn extract_joiner_secret(
        &self,
        crypto_provider: &impl CryptoProvider,
        prev_init_secret: &[u8],
        commit_secret: &[u8],
    ) -> Result<Bytes> {
        let cipher_suite = self.cipher_suite;
        let extracted = crypto_provider
            .hpke(cipher_suite)
            .kdf_extract(commit_secret, prev_init_secret)?;

        let raw_group_context = self.serialize_detached()?;
        let extract_size = crypto_provider.hpke(cipher_suite).kdf_extract_size() as u16;

        crypto_provider.expand_with_label(
            cipher_suite,
            &extracted,
            b"joiner",
            &raw_group_context,
            extract_size,
        )
    }

    pub(crate) fn extract_epoch_secret(
        &self,
        crypto_provider: &impl CryptoProvider,
        joiner_secret: &[u8],
        psk_secret: &[u8],
    ) -> Result<Bytes> {
        let kdf_extract_size = crypto_provider.hpke(self.cipher_suite).kdf_extract_size();
        let zero = vec![0u8; kdf_extract_size];

        // TODO de-duplicate with extract_welcome_secret

        let extracted = crypto_provider.hpke(self.cipher_suite).kdf_extract(
            if psk_secret.is_empty() {
                &zero
            } else {
                psk_secret
            },
            joiner_secret,
        )?;

        let raw_group_context = self.serialize_detached()?;
        let extract_size = crypto_provider.hpke(self.cipher_suite).kdf_extract_size() as u16;

        crypto_provider.expand_with_label(
            self.cipher_suite,
            &extracted,
            b"epoch",
            &raw_group_context,
            extract_size,
        )
    }
}

pub(crate) fn extract_welcome_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    joiner_secret: &[u8],
    psk_secret: &[u8],
) -> Result<Bytes> {
    let kdf_extract_size = crypto_provider.hpke(cipher_suite).kdf_extract_size();
    let zero = vec![0u8; kdf_extract_size];
    let extracted = crypto_provider.hpke(cipher_suite).kdf_extract(
        if psk_secret.is_empty() {
            &zero
        } else {
            psk_secret
        },
        joiner_secret,
    )?;

    crypto_provider.derive_secret(cipher_suite, &extracted, b"welcome")
}

pub(crate) const SECRET_LABEL_INIT: &[u8] = b"init";
pub(crate) const SECRET_LABEL_SENDER_DATA: &[u8] = b"sender data";
pub(crate) const SECRET_LABEL_ENCRYPTION: &[u8] = b"encryption";
pub(crate) const SECRET_LABEL_EXPORTER: &[u8] = b"exporter";
pub(crate) const SECRET_LABEL_EXTERNAL: &[u8] = b"external";
pub(crate) const SECRET_LABEL_CONFIRM: &[u8] = b"confirm";
pub(crate) const SECRET_LABEL_MEMBERSHIP: &[u8] = b"membership";
pub(crate) const SECRET_LABEL_RESUMPTION: &[u8] = b"resumption";
pub(crate) const SECRET_LABEL_AUTHENTICATION: &[u8] = b"authentication";

/// [RFC9420 Sec.8.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.2) The AuthenticatedContent
/// struct is split into ConfirmedTranscriptHashInput and InterimTranscriptHashInput.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ConfirmedTranscriptHashInput {
    pub wire_format: WireFormat,
    pub content: FramedContent,
    pub signature: Bytes,
}

impl Deserializer for ConfirmedTranscriptHashInput {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let wire_format = WireFormat::deserialize(buf)?;
        let content = FramedContent::deserialize(buf)?;
        match &content.content {
            Content::Application(_) | Content::Proposal(_) => {
                return Err(Error::ConfirmedTranscriptHashInputContainContentCommitOnly)
            }
            Content::Commit(_) => {}
        };
        let signature = deserialize_opaque_vec(buf)?;

        Ok(Self {
            wire_format,
            content,
            signature,
        })
    }
}

impl Serializer for ConfirmedTranscriptHashInput {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self.content.content {
            Content::Application(_) | Content::Proposal(_) => {
                return Err(Error::ConfirmedTranscriptHashInputContainContentCommitOnly)
            }
            Content::Commit(_) => {}
        };

        self.wire_format.serialize(buf)?;
        self.content.serialize(buf)?;
        serialize_opaque_vec(&self.signature, buf)
    }
}

impl ConfirmedTranscriptHashInput {
    /// [RFC9420 Sec.8.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.2) update the confirmed transcript hash
    ///
    /// ```text
    /// confirmed_transcript_hash_[0] = ""; /* zero-length octet string */
    /// interim_transcript_hash_[0] = ""; /* zero-length octet string */
    /// confirmed_transcript_hash_[epoch] =
    ///     Hash(interim_transcript_hash_[epoch - 1] ||
    ///         ConfirmedTranscriptHashInput_[epoch]);
    /// ```
    pub fn hash(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        interim_transcript_hash_before: &[u8],
    ) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        let raw_input = self.serialize_detached()?;

        buf.extend_from_slice(interim_transcript_hash_before);
        buf.put(raw_input);

        Ok(crypto_provider.hash(cipher_suite).digest(&buf.freeze()))
    }
}

/// [RFC9420 Sec.8.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.2) The AuthenticatedContent
/// struct is split into ConfirmedTranscriptHashInput and InterimTranscriptHashInput.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct InterimTranscriptHashInput {
    pub confirmation_tag: Bytes,
}

/// [RFC9420 Sec.8.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.2) update the interim transcript hash
///
/// ```text
/// confirmed_transcript_hash_[0] = ""; /* zero-length octet string */
/// interim_transcript_hash_[0] = ""; /* zero-length octet string */
/// interim_transcript_hash_[epoch] =
///     Hash(confirmed_transcript_hash_[epoch] ||
///         InterimTranscriptHashInput_[epoch]);
/// ```
pub fn next_interim_transcript_hash(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    confirmed_transcript_hash: &[u8],
    confirmation_tag: &[u8],
) -> Result<Bytes> {
    let mut buf = BytesMut::new();
    serialize_opaque_vec(confirmation_tag, &mut buf)?;
    let raw_input = buf.freeze();

    let mut buf = BytesMut::new();
    buf.extend_from_slice(confirmed_transcript_hash);
    buf.put(raw_input);

    Ok(crypto_provider.hash(cipher_suite).digest(&buf.freeze()))
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4) PSKType
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum PSKType {
    #[default]
    External = 1,
    Resumption = 2,
}

impl TryFrom<u8> for PSKType {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            1 => Ok(PSKType::External),
            2 => Ok(PSKType::Resumption),
            _ => Err(Error::InvalidPskTypeValue(v)),
        }
    }
}

impl Deserializer for PSKType {
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
impl Serializer for PSKType {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4) PSK
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PSK {
    External(Bytes),        //  = 1,
    Resumption(Resumption), //  = 2,
}

impl Default for PSK {
    fn default() -> Self {
        PSK::External(Bytes::new())
    }
}

impl Deserializer for PSK {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let psk_type = PSKType::deserialize(buf)?;

        match psk_type {
            PSKType::External => Ok(PSK::External(deserialize_opaque_vec(buf)?)),
            PSKType::Resumption => Ok(PSK::Resumption(Resumption::deserialize(buf)?)),
        }
    }
}

impl Serializer for PSK {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.psk_type().serialize(buf)?;
        match self {
            PSK::External(identity) => serialize_opaque_vec(identity, buf),
            PSK::Resumption(resumption) => resumption.serialize(buf),
        }
    }
}

impl PSK {
    pub fn psk_type(&self) -> PSKType {
        match self {
            PSK::External(_) => PSKType::External,
            PSK::Resumption(_) => PSKType::Resumption,
        }
    }
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4) ResumptionPSKUsage
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum ResumptionPSKUsage {
    #[default]
    Application = 1,
    Reinit = 2,
    Branch = 3,
}

impl TryFrom<u8> for ResumptionPSKUsage {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0x01 => Ok(ResumptionPSKUsage::Application),
            0x02 => Ok(ResumptionPSKUsage::Reinit),
            0x03 => Ok(ResumptionPSKUsage::Branch),
            _ => Err(Error::InvalidResumptionPSKUsageValue(v)),
        }
    }
}

impl Deserializer for ResumptionPSKUsage {
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
impl Serializer for ResumptionPSKUsage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4) Resumption
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Resumption {
    pub usage: ResumptionPSKUsage,
    pub psk_group_id: GroupID,
    pub psk_epoch: u64,
}

impl Deserializer for Resumption {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let usage = ResumptionPSKUsage::deserialize(buf)?;
        let psk_group_id = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        let psk_epoch = buf.get_u64();
        Ok(Self {
            usage,
            psk_group_id,
            psk_epoch,
        })
    }
}

impl Serializer for Resumption {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.usage.serialize(buf)?;
        serialize_opaque_vec(&self.psk_group_id, buf)?;
        buf.put_u64(self.psk_epoch);
        Ok(())
    }
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4) PreSharedKeyID
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PreSharedKeyID {
    pub psk: PSK,
    pub psk_nonce: Bytes,
}

impl Deserializer for PreSharedKeyID {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let psk = PSK::deserialize(buf)?;
        let psk_nonce = deserialize_opaque_vec(buf)?;

        Ok(Self { psk, psk_nonce })
    }
}
impl Serializer for PreSharedKeyID {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.psk.serialize(buf)?;
        serialize_opaque_vec(&self.psk_nonce, buf)
    }
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4) PSKLabel
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PSKLabel {
    pub id: PreSharedKeyID,
    pub index: u16,
    pub count: u16,
}

impl Deserializer for PSKLabel {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let id = PreSharedKeyID::deserialize(buf)?;
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        let index = buf.get_u16();
        let count = buf.get_u16();

        Ok(Self { id, index, count })
    }
}

impl Serializer for PSKLabel {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.id.serialize(buf)?;
        buf.put_u16(self.index);
        buf.put_u16(self.count);
        Ok(())
    }
}

/// [RFC9420 Sec.8.4](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4)
/// Computation of a PSK Secret from a Set of PSKs
pub fn extract_psk_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    psk_ids: &[PreSharedKeyID],
    psks: &[Bytes],
) -> Result<Bytes> {
    if psk_ids.len() != psks.len() {
        return Err(Error::PskIDsAndPskLenNotMatch);
    }

    let kdf_extract_size = crypto_provider.hpke(cipher_suite).kdf_extract_size();
    let zero = vec![0u8; kdf_extract_size];

    let mut psk_secret = Bytes::from(zero.clone());
    for i in 0..psk_ids.len() {
        let psk_extracted = crypto_provider
            .hpke(cipher_suite)
            .kdf_extract(&psks[i], &zero)?;

        let psk_label = PSKLabel {
            id: psk_ids[i].clone(),
            index: i as u16,
            count: psk_ids.len() as u16,
        };
        let raw_psklabel = psk_label.serialize_detached()?;

        let psk_input = crypto_provider.expand_with_label(
            cipher_suite,
            &psk_extracted,
            b"derived psk",
            &raw_psklabel,
            kdf_extract_size as u16,
        )?;

        psk_secret = crypto_provider
            .hpke(cipher_suite)
            .kdf_extract(&psk_secret, &psk_input)?;
    }

    Ok(psk_secret)
}
