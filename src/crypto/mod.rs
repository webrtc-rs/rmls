use crate::codec::*;
use crate::error::*;

use bytes::{Buf, BufMut, Bytes, BytesMut};

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
}

impl TryFrom<u16> for CredentialType {
    type Error = Error;

    fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CredentialType::Basic),
            0x0002 => Ok(CredentialType::X509),
            _ => Err(Error::InvalidCredentialTypeValue(v)),
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Credential {
    pub(crate) credential_type: CredentialType,
    identity: Bytes,          // for credentialTypeBasic
    certificates: Vec<Bytes>, // for credentialTypeX509
}

impl Reader for Credential {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        *self = Credential::default();

        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        self.credential_type = buf.get_u16().try_into()?;

        match self.credential_type {
            CredentialType::Basic => {
                self.identity = read_opaque_vec(buf)?;
                Ok(())
            }
            CredentialType::X509 => read_vector(buf, |b: &mut Bytes| -> Result<()> {
                let cert = read_opaque_vec(b)?;
                self.certificates.push(cert);
                Ok(())
            }),
        }
    }
}

impl Writer for Credential {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.credential_type as u16);
        match self.credential_type {
            CredentialType::Basic => write_opaque_vec(&self.identity, buf),
            CredentialType::X509 => write_vector(
                self.certificates.len(),
                buf,
                |i: usize, b: &mut BytesMut| -> Result<()> {
                    write_opaque_vec(&self.certificates[i], b)
                },
            ),
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct HpkeCiphertext {
    kem_output: Bytes,
    ciphertext: Bytes,
}

impl Reader for HpkeCiphertext {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.kem_output = read_opaque_vec(buf)?;
        self.ciphertext = read_opaque_vec(buf)?;

        Ok(())
    }
}

impl Writer for HpkeCiphertext {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.kem_output, buf)?;
        write_opaque_vec(&self.ciphertext, buf)?;
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
