use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::framing::{GroupInfo, GroupSecrets};
use crate::key_package::KeyPackageRef;
use crate::key_schedule::extract_welcome_secret;
use crate::ratchet_tree::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Welcome {
    cipher_suite: CipherSuite,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: Bytes,
}

impl Deserializer for Welcome {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let cipher_suite = buf.get_u16().into();

        let mut secrets = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            secrets.push(EncryptedGroupSecrets::deserialize(b)?);
            Ok(())
        })?;

        let encrypted_group_info = deserialize_opaque_vec(buf)?;

        Ok(Self {
            cipher_suite,
            secrets,
            encrypted_group_info,
        })
    }
}

impl Serializer for Welcome {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.cipher_suite.into());
        serialize_vector(
            self.secrets.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.secrets[i].serialize(b) },
        )?;
        serialize_opaque_vec(&self.encrypted_group_info, buf)
    }
}

impl Welcome {
    fn find_secret(&self, r: &KeyPackageRef) -> Option<&EncryptedGroupSecrets> {
        for (i, sec) in self.secrets.iter().enumerate() {
            if &sec.new_member == r {
                return Some(&self.secrets[i]);
            }
        }
        None
    }

    pub(crate) fn decrypt_group_secrets(
        &self,
        crypto_provider: &impl CryptoProvider,
        r: &KeyPackageRef,
        init_key_priv: &[u8],
    ) -> Result<GroupSecrets> {
        if let Some(sec) = self.find_secret(r) {
            let raw_group_secrets = crypto_provider.decrypt_with_label(
                self.cipher_suite,
                init_key_priv,
                b"Welcome",
                &self.encrypted_group_info,
                &sec.encrypted_group_secrets.kem_output,
                &sec.encrypted_group_secrets.ciphertext,
            )?;

            Ok(GroupSecrets::deserialize_exact(&raw_group_secrets)?)
        } else {
            Err(Error::EncryptedGroupSecretsNotFoundForProvidedKeyPackageRef)
        }
    }

    pub(crate) fn decrypt_group_info(
        &self,
        crypto_provider: &impl CryptoProvider,
        joiner_secret: &[u8],
        psk_secret: &[u8],
    ) -> Result<GroupInfo> {
        let welcome_secret = extract_welcome_secret(
            crypto_provider,
            self.cipher_suite,
            joiner_secret,
            psk_secret,
        )?;

        let aead_nonce_size = crypto_provider.hpke(self.cipher_suite)?.aead_nonce_size() as u16;
        let welcome_nonce = crypto_provider.expand_with_label(
            self.cipher_suite,
            &welcome_secret,
            b"nonce",
            &[],
            aead_nonce_size,
        )?;

        let aead_key_size = crypto_provider.hpke(self.cipher_suite)?.aead_key_size() as u16;
        let welcome_key = crypto_provider.expand_with_label(
            self.cipher_suite,
            &welcome_secret,
            b"key",
            &[],
            aead_key_size,
        )?;

        let raw_group_info = crypto_provider.hpke(self.cipher_suite)?.aead_open(
            &welcome_key,
            &welcome_nonce,
            &self.encrypted_group_info,
            &[],
        )?;

        GroupInfo::deserialize_exact(&raw_group_info)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EncryptedGroupSecrets {
    new_member: KeyPackageRef,
    encrypted_group_secrets: HPKECiphertext,
}

impl Deserializer for EncryptedGroupSecrets {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let new_member = KeyPackageRef::deserialize(buf)?;
        let encrypted_group_secrets = HPKECiphertext::deserialize(buf)?;

        Ok(Self {
            new_member,
            encrypted_group_secrets,
        })
    }
}

impl Serializer for EncryptedGroupSecrets {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.new_member.serialize(buf)?;
        self.encrypted_group_secrets.serialize(buf)
    }
}
