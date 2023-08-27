#[cfg(test)]
mod crypto_test;

use crate::error::*;
use crate::serde::*;

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub mod cipher_suite;
pub mod provider;

pub(crate) type HpkePublicKey = Bytes;
pub(crate) type SignaturePublicKey = Bytes;

// https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum CredentialType {
    #[default]
    Basic = 0x0001,
    X509 = 0x0002,
    Unknown(u16),
}

impl From<u16> for CredentialType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => CredentialType::Basic,
            0x0002 => CredentialType::X509,
            _ => CredentialType::Unknown(v),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(val: CredentialType) -> u16 {
        match val {
            CredentialType::Basic => 0x0001,
            CredentialType::X509 => 0x0002,
            CredentialType::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Credential {
    Basic(Bytes),
    X509(Vec<Bytes>),
}

impl Default for Credential {
    fn default() -> Self {
        Self::Basic(Bytes::new())
    }
}

impl Deserializer for Credential {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let credential_type = buf.get_u16().into();
        let mut certificates = vec![];

        match credential_type {
            CredentialType::Basic => Ok(Self::Basic(deserialize_opaque_vec(buf)?)),
            CredentialType::X509 => {
                deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
                    let cert = deserialize_opaque_vec(b)?;
                    certificates.push(cert);
                    Ok(())
                })?;

                Ok(Self::X509(certificates))
            }
            _ => Err(Error::InvalidCredentialTypeValue),
        }
    }
}

impl Serializer for Credential {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.credential_type().into());
        match self {
            Credential::Basic(identity) => serialize_opaque_vec(identity, buf),
            Credential::X509(certificates) => serialize_vector(
                certificates.len(),
                buf,
                |i: usize, b: &mut BytesMut| -> Result<()> {
                    serialize_opaque_vec(&certificates[i], b)
                },
            ),
        }
    }
}

impl Credential {
    pub fn credential_type(&self) -> CredentialType {
        match self {
            Credential::Basic(_) => CredentialType::Basic,
            Credential::X509(_) => CredentialType::X509,
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct HpkeCiphertext {
    pub(crate) kem_output: Bytes,
    pub(crate) ciphertext: Bytes,
}

impl Deserializer for HpkeCiphertext {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let kem_output = deserialize_opaque_vec(buf)?;
        let ciphertext = deserialize_opaque_vec(buf)?;

        Ok(Self {
            kem_output,
            ciphertext,
        })
    }
}

impl Serializer for HpkeCiphertext {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.kem_output, buf)?;
        serialize_opaque_vec(&self.ciphertext, buf)?;
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Kem {
    #[default]
    // KEM_P256_HKDF_SHA256 is a KEM using P256 curve and HKDF with SHA-256.
    KEM_P256_HKDF_SHA256 = 0x10,
    // KEM_P384_HKDF_SHA384 is a KEM using P384 curve and HKDF with SHA-384.
    KEM_P384_HKDF_SHA384 = 0x11,
    // KEM_P521_HKDF_SHA512 is a KEM using P521 curve and HKDF with SHA-512.
    KEM_P521_HKDF_SHA512 = 0x12,
    // KEM_X25519_HKDF_SHA256 is a KEM using X25519 Diffie-Hellman function
    // and HKDF with SHA-256.
    KEM_X25519_HKDF_SHA256 = 0x20,
    // KEM_X448_HKDF_SHA512 is a KEM using X448 Diffie-Hellman function and
    // HKDF with SHA-512.
    KEM_X448_HKDF_SHA512 = 0x21,
    // KEM_X25519_KYBER768_DRAFT00 is a hybrid KEM built on DHKEM(X25519, HKDF-SHA256)
    // and Kyber768Draft00
    KEM_X25519_KYBER768_DRAFT00 = 0x30,
}

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Kdf {
    #[default]
    // KDF_HKDF_SHA256 is a KDF using HKDF with SHA-256.
    KDF_HKDF_SHA256 = 0x01,
    // KDF_HKDF_SHA384 is a KDF using HKDF with SHA-384.
    KDF_HKDF_SHA384 = 0x02,
    // KDF_HKDF_SHA512 is a KDF using HKDF with SHA-512.
    KDF_HKDF_SHA512 = 0x03,
}

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Aead {
    #[default]
    // AEAD_AES128GCM is AES-128 block cipher in Galois Counter Mode (GCM).
    AEAD_AES128GCM = 0x01,
    // AEAD_AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
    AEAD_AES256GCM = 0x02,
    // AEAD_ChaCha20Poly1305 is ChaCha20 stream cipher and Poly1305 MAC.
    AEAD_ChaCha20Poly1305 = 0x03,
}
