use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::crypto::provider::CryptoProvider;
use crate::key_schedule::*;
use crate::ratchet_tree::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupInfo {
    pub(crate) group_context: GroupContext,
    pub(crate) extensions: Extensions,
    confirmation_tag: Bytes,
    pub(crate) signer: LeafIndex,
    signature: Bytes,
}

impl Deserializer for GroupInfo {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let group_context = GroupContext::deserialize(buf)?;
        let extensions = Extensions::deserialize(buf)?;
        let confirmation_tag = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        let signer = LeafIndex(buf.get_u32());
        let signature = deserialize_opaque_vec(buf)?;

        Ok(Self {
            group_context,
            extensions,
            confirmation_tag,
            signer,
            signature,
        })
    }
}

impl Serializer for GroupInfo {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.serialize_base(buf)?;
        serialize_opaque_vec(&self.signature, buf)
    }
}

impl GroupInfo {
    fn serialize_base<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.group_context.serialize(buf)?;
        self.extensions.serialize(buf)?;
        serialize_opaque_vec(&self.confirmation_tag, buf)?;
        buf.put_u32(self.signer.0);
        Ok(())
    }

    pub(crate) fn verify_signature(
        &self,
        crypto_provider: &impl CryptoProvider,
        signer_pub: &[u8],
    ) -> Result<()> {
        let cipher_suite = self.group_context.cipher_suite;
        let mut buf = BytesMut::new();
        self.serialize_base(&mut buf)?;
        let tbs = buf.freeze();

        crypto_provider.verify_with_label(
            cipher_suite,
            signer_pub,
            b"GroupInfoTBS",
            &tbs,
            &self.signature,
        )
    }

    pub(crate) fn verify_confirmation_tag(
        &self,
        crypto_provider: &impl CryptoProvider,
        joiner_secret: &[u8],
        psk_secret: &[u8],
    ) -> Result<()> {
        let cipher_suite = self.group_context.cipher_suite;
        let epoch_secret =
            self.group_context
                .extract_epoch_secret(crypto_provider, joiner_secret, psk_secret)?;
        let confirmation_key =
            crypto_provider.derive_secret(cipher_suite, &epoch_secret, SECRET_LABEL_CONFIRM)?;

        if crypto_provider.verify_mac(
            cipher_suite,
            &confirmation_key,
            &self.group_context.confirmed_transcript_hash,
            &self.confirmation_tag,
        ) {
            Ok(())
        } else {
            Err(Error::VerifyConfirmationTagFailed)
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupSecrets {
    pub(crate) joiner_secret: Bytes,
    pub(crate) path_secret: Option<Bytes>,
    pub(crate) psk_ids: Vec<PreSharedKeyID>,
}

impl Deserializer for GroupSecrets {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let joiner_secret = deserialize_opaque_vec(buf)?;

        let has_path_secret = deserialize_optional(buf)?;
        let path_secret = if has_path_secret {
            Some(deserialize_opaque_vec(buf)?)
        } else {
            None
        };

        let mut psk_ids = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            psk_ids.push(PreSharedKeyID::deserialize(b)?);
            Ok(())
        })?;

        Ok(Self {
            joiner_secret,
            path_secret,
            psk_ids,
        })
    }
}

impl Serializer for GroupSecrets {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.joiner_secret, buf)?;

        serialize_optional(self.path_secret.is_some(), buf)?;
        if let Some(path_secret) = &self.path_secret {
            serialize_opaque_vec(path_secret, buf)?;
        }

        serialize_vector(
            self.psk_ids.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.psk_ids[i].serialize(b) },
        )
    }
}

impl GroupSecrets {
    // verifySingleReInitOrBranchPSK verifies that at most one key has type
    // resumption with usage reinit or branch.
    pub(crate) fn verify_single_reinit_or_branch_psk(&self) -> bool {
        let mut n = 0;
        for psk in &self.psk_ids {
            if let Psk::Resumption(resumption) = &psk.psk {
                match resumption.usage {
                    ResumptionPSKUsage::Reinit | ResumptionPSKUsage::Branch => n += 1,
                    _ => {}
                }
            }
        }
        n <= 1
    }
}
