use bytes::Bytes;

pub(crate) mod hash;

pub(crate) type HpkePublicKey = Bytes;
pub(crate) type SignaturePublicKey = Bytes;

pub(crate) type CredentialType = u16;

// https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types

pub(crate) const CREDENTIAL_TYPE_BASIC: CredentialType = 0x0001;
pub(crate) const CREDENTIAL_TYPE_X509: CredentialType = 0x0002;
