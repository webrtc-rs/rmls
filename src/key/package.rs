use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::crypto::{cipher_suite::*, provider::CryptoProvider, *};
use crate::error::*;
use crate::key::schedule::*;
use crate::message::framing::*;
use crate::serde::*;
use crate::tree::*;

pub type KeyPackageRef = Bytes;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct KeyPackage {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    init_key: HpkePublicKey,
    pub(crate) leaf_node: LeafNode,
    extensions: Vec<Extension>,
    signature: Bytes,
}

impl Deserializer for KeyPackage {
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
        self.init_key = deserialize_opaque_vec(buf)?;
        self.leaf_node.deserialize(buf)?;
        self.extensions = deserialize_extensions(buf)?;
        self.signature = deserialize_opaque_vec(buf)?;

        Ok(())
    }
}

impl Serializer for KeyPackage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.serialize_base(buf)?;
        serialize_opaque_vec(&self.signature, buf)
    }
}

impl KeyPackage {
    fn serialize_base<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        buf.put_u16(self.cipher_suite as u16);
        serialize_opaque_vec(&self.init_key, buf)?;
        self.leaf_node.serialize(buf)?;
        serialize_extensions(&self.extensions, buf)
    }

    fn verify_signature(&self, crypto_provider: &impl CryptoProvider) -> Result<()> {
        let mut buf = BytesMut::new();
        self.serialize_base(&mut buf)?;
        let raw = buf.freeze();
        crypto_provider.verify_with_label(
            self.cipher_suite,
            &self.leaf_node.signature_key,
            b"KeyPackageTBS",
            &raw,
            &self.signature,
        )
    }

    // verify performs KeyPackage verification as described in RFC 9420 section 10.1.
    pub(crate) fn verify(
        &self,
        crypto_provider: &impl CryptoProvider,
        ctx: &GroupContext,
    ) -> Result<()> {
        if self.version != ctx.version {
            return Err(Error::KeyPackageVersionNotMatchGroupContext);
        }
        if self.cipher_suite != ctx.cipher_suite {
            return Err(Error::CipherSuiteNotMatchGroupContext);
        }
        if let LeafNodeSource::KeyPackage(_) = &self.leaf_node.leaf_node_source {
        } else {
            return Err(Error::KeyPackageContainsLeafNodeWithInvalidSource);
        }
        if self.verify_signature(crypto_provider).is_err() {
            return Err(Error::InvalidKeyPackageSignature);
        }
        if self.leaf_node.encryption_key == self.init_key {
            return Err(Error::KeyPackageEncryptionKeyAndInitKeyIdentical);
        }
        Ok(())
    }

    pub(crate) fn generate_ref(
        &self,
        crypto_provider: &impl CryptoProvider,
    ) -> Result<KeyPackageRef> {
        let mut buf = BytesMut::new();
        self.serialize(&mut buf)?;
        let raw = buf.freeze();

        crypto_provider.ref_hash(self.cipher_suite, b"MLS 1.0 KeyPackage Reference", &raw)
    }
}
