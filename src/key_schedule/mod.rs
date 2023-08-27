#[cfg(test)]
mod key_schedule_test;

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::error::*;
use crate::messages::framing::{
    Content, FramedContent, GroupID, ProtocolVersion, WireFormat, PROTOCOL_VERSION_MLS10,
};
use crate::serde::*;
use crate::tree::{deserialize_extensions, serialize_extensions, Extension};

use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct GroupContext {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) group_id: GroupID,
    pub(crate) epoch: u64,
    pub(crate) tree_hash: Bytes,
    pub(crate) confirmed_transcript_hash: Bytes,
    pub(crate) extensions: Vec<Extension>,
}

impl Deserializer for GroupContext {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }

        self.version = buf.get_u16();
        self.cipher_suite = buf.get_u16().try_into()?;
        self.group_id = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        self.epoch = buf.get_u64();
        self.tree_hash = deserialize_opaque_vec(buf)?;
        self.confirmed_transcript_hash = deserialize_opaque_vec(buf)?;

        if self.version != PROTOCOL_VERSION_MLS10 {
            return Err(Error::InvalidProposalTypeValue(self.version));
        }

        self.extensions = deserialize_extensions(buf)?;

        Ok(())
    }
}
impl Serializer for GroupContext {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        buf.put_u16(self.cipher_suite as u16);
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        serialize_opaque_vec(&self.tree_hash, buf)?;
        serialize_opaque_vec(&self.confirmed_transcript_hash, buf)?;
        serialize_extensions(&self.extensions, buf)
    }
}

impl GroupContext {
    fn extract_joiner_secret(
        &self,
        crypto_provider: &impl CryptoProvider,
        prev_init_secret: &[u8],
        commit_secret: &[u8],
    ) -> Result<Bytes> {
        let cipher_suite = self.cipher_suite;
        let extracted = crypto_provider
            .hpke(cipher_suite)
            .kdf_extract(commit_secret, prev_init_secret)?;

        let raw_group_context = serialize(self)?;
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

        let raw_group_context = serialize(self)?;
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

pub const SECRET_LABEL_INIT: &[u8] = b"init";
pub const SECRET_LABEL_SENDER_DATA: &[u8] = b"sender data";
pub const SECRET_LABEL_ENCRYPTION: &[u8] = b"encryption";
pub const SECRET_LABEL_EXPORTER: &[u8] = b"exporter";
pub const SECRET_LABEL_EXTERNAL: &[u8] = b"external";
pub const SECRET_LABEL_CONFIRM: &[u8] = b"confirm";
pub const SECRET_LABEL_MEMBERSHIP: &[u8] = b"membership";
pub const SECRET_LABEL_RESUMPTION: &[u8] = b"resumption";
pub const SECRET_LABEL_AUTHENTICATION: &[u8] = b"authentication";

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct ConfirmedTranscriptHashInput {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: FramedContent,
    pub(crate) signature: Bytes,
}

impl Deserializer for ConfirmedTranscriptHashInput {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.wire_format.deserialize(buf)?;
        self.content.deserialize(buf)?;
        match self.content.content {
            Content::Application(_) | Content::Proposal(_) => {
                return Err(Error::ConfirmedTranscriptHashInputContainContentCommitOnly)
            }
            Content::Commit(_) => {}
        };
        self.signature = deserialize_opaque_vec(buf)?;
        Ok(())
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
    fn hash(
        &self,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        interim_transcript_hash_before: &[u8],
    ) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        let raw_input = serialize(self)?;

        buf.extend_from_slice(interim_transcript_hash_before);
        buf.put(raw_input);

        Ok(crypto_provider.hash(cipher_suite).digest(&buf.freeze()))
    }
}

pub(crate) fn next_interim_transcript_hash(
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
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Resumption {
    pub(crate) usage: ResumptionPSKUsage,
    psk_group_id: GroupID,
    psk_epoch: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Psk {
    External(Bytes),        //  = 1,
    Resumption(Resumption), //  = 2,
}

impl Default for Psk {
    fn default() -> Self {
        Psk::External(Bytes::new())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct PreSharedKeyID {
    pub(crate) psk: Psk,
    psk_nonce: Bytes,
}

impl Deserializer for PreSharedKeyID {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
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
                self.psk = Psk::External(deserialize_opaque_vec(buf)?);
            }
            2 => {
                let mut resumption = Resumption::default();
                resumption.usage.deserialize(buf)?;
                resumption.psk_group_id = deserialize_opaque_vec(buf)?;
                if buf.remaining() < 8 {
                    return Err(Error::BufferTooSmall);
                }
                resumption.psk_epoch = buf.get_u64();
                self.psk = Psk::Resumption(resumption);
            }
            _ => return Err(Error::InvalidPskTypeValue(v)),
        }

        self.psk_nonce = deserialize_opaque_vec(buf)?;

        Ok(())
    }
}
impl Serializer for PreSharedKeyID {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match &self.psk {
            Psk::External(psk_id) => {
                buf.put_u8(1);
                serialize_opaque_vec(psk_id, buf)?;
            }
            Psk::Resumption(resumption) => {
                buf.put_u8(2);

                resumption.usage.serialize(buf)?;
                serialize_opaque_vec(&resumption.psk_group_id, buf)?;
                buf.put_u64(resumption.psk_epoch);
            }
        }

        serialize_opaque_vec(&self.psk_nonce, buf)
    }
}

fn extract_psk_secret(
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

        let psk_label = PskLabel {
            id: psk_ids[i].clone(),
            index: i as u16,
            count: psk_ids.len() as u16,
        };
        let raw_psklabel = serialize(&psk_label)?;

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

#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct PskLabel {
    id: PreSharedKeyID,
    index: u16,
    count: u16,
}

impl Deserializer for PskLabel {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.id.deserialize(buf)?;
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        self.index = buf.get_u16();
        self.count = buf.get_u16();

        Ok(())
    }
}

impl Serializer for PskLabel {
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
