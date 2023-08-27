use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::crypto::provider::CryptoProvider;
use crate::error::*;
use crate::key::schedule::{
    GroupContext, PreSharedKeyID, Psk, ResumptionPSKUsage, SECRET_LABEL_CONFIRM,
};
use crate::serde::*;
use crate::tree::math::LeafIndex;
use crate::tree::{deserialize_extensions, serialize_extensions, Extension};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupInfo {
    group_context: GroupContext,
    extensions: Vec<Extension>,
    confirmation_tag: Bytes,
    signer: LeafIndex,
    signature: Bytes,
}

impl Deserializer for GroupInfo {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.group_context.deserialize(buf)?;
        self.extensions = deserialize_extensions(buf)?;
        self.confirmation_tag = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        self.signer = LeafIndex(buf.get_u32());
        self.signature = deserialize_opaque_vec(buf)?;

        Ok(())
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
        serialize_extensions(&self.extensions, buf)?;
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
    path_secret: Option<Bytes>,
    psk_ids: Vec<PreSharedKeyID>,
}

impl Deserializer for GroupSecrets {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.joiner_secret = deserialize_opaque_vec(buf)?;

        let has_path_secret = deserialize_optional(buf)?;
        if has_path_secret {
            self.path_secret = Some(deserialize_opaque_vec(buf)?);
        } else {
            self.path_secret = None;
        }

        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            let mut psk = PreSharedKeyID::default();
            psk.deserialize(b)?;
            self.psk_ids.push(psk);
            Ok(())
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
    fn verify_single_reinit_or_branch_psk(&self) -> bool {
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
