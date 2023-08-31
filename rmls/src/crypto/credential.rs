//! [RFC9420 Sec.5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) Each member of a group
//! presents a credential that provides one or more identities for the member and associates them
//! with the member's signing key.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::utilities::error::*;
use crate::utilities::serde::*;

/// [RFC9420 Sec.5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) Enum type of Credential
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum CredentialType {
    #[default]
    /// A "basic" credential type
    Basic = 0x0001,
    /// An X.509 credential type
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

/// [RFC9420 Sec.5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) Credential provides
/// "presented identifiers"
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Credential {
    /// A "basic" credential is a bare assertion of an identity, without any additional information.
    /// The format of the encoded identity is defined by the application.
    Basic(Bytes),
    /// For an X.509 credential, each entry in the certificates field represents a single
    /// DER-encoded X.509 certificate.
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
