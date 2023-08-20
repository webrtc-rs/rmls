use crate::codec::*;
use crate::error::*;

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub mod crypto_provider;
pub mod hash;
pub mod hpke;
pub mod signature;

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
