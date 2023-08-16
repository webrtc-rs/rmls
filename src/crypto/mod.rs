use crate::codec::{read_opaque_vec, read_vector, write_opaque_vec, write_vector, Reader, Writer};
use crate::error::*;

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub(crate) mod hash;

pub(crate) type HpkePublicKey = Bytes;
pub(crate) type SignaturePublicKey = Bytes;

pub(crate) type CredentialType = u16;

// https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types

pub(crate) const CREDENTIAL_TYPE_BASIC: CredentialType = 0x0001;
pub(crate) const CREDENTIAL_TYPE_X509: CredentialType = 0x0002;

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
        self.credential_type = buf.get_u16();

        match self.credential_type {
            CREDENTIAL_TYPE_BASIC => {
                self.identity = read_opaque_vec(buf)?;
                Ok(())
            }
            CREDENTIAL_TYPE_X509 => read_vector(buf, |b: &mut Bytes| -> Result<()> {
                let cert = read_opaque_vec(b)?;
                self.certificates.push(cert);
                Ok(())
            }),
            _ => Err(Error::InvalidCredentialType(self.credential_type)),
        }
    }
}

impl Writer for Credential {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.credential_type);
        match self.credential_type {
            CREDENTIAL_TYPE_BASIC => write_opaque_vec(&self.identity, buf),
            CREDENTIAL_TYPE_X509 => write_vector(
                self.certificates.len(),
                buf,
                |i: usize, b: &mut BytesMut| -> Result<()> {
                    write_opaque_vec(&self.certificates[i], b)
                },
            ),
            _ => Err(Error::InvalidCredentialType(self.credential_type)),
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
