//! [RFC9420 Sec.13](https://www.rfc-editor.org/rfc/rfc9420.html#section-13) Extensibility
//!
//! The base MLS protocol can be extended in a few ways. New cipher suites can be added to enable
//! the use of new cryptographic algorithms. New types of proposals can be used to perform new
//! actions within an epoch. Extension fields can be used to add additional information
//! to the protocol.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::ops::Deref;

use crate::crypto::credential::{Credential, CredentialType};
use crate::crypto::{HPKEPublicKey, SignaturePublicKey};
use crate::framing::proposal::ProposalType;
use crate::ratchet_tree::RatchetTree;
use crate::utilities::error::*;
use crate::utilities::serde::*;

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) ExtensionType
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    #[default]
    ApplicationId = 0x0001,
    RatchetTree = 0x0002,
    RequiredCapabilities = 0x0003,
    ExternalPub = 0x0004,
    ExternalSenders = 0x0005,
    /// A currently unknown extension type.
    Unknown(u16),
}

impl From<u16> for ExtensionType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => ExtensionType::ApplicationId,
            0x0002 => ExtensionType::RatchetTree,
            0x0003 => ExtensionType::RequiredCapabilities,
            0x0004 => ExtensionType::ExternalPub,
            0x0005 => ExtensionType::ExternalSenders,
            _ => ExtensionType::Unknown(v),
        }
    }
}

impl From<ExtensionType> for u16 {
    fn from(val: ExtensionType) -> Self {
        match val {
            ExtensionType::ApplicationId => 0x0001,
            ExtensionType::RatchetTree => 0x0002,
            ExtensionType::RequiredCapabilities => 0x0003,
            ExtensionType::ExternalPub => 0x0004,
            ExtensionType::ExternalSenders => 0x0005,
            ExtensionType::Unknown(v) => v,
        }
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: Bytes,
}

impl Extension {
    pub fn new(extension_type: ExtensionType, extension_data: Bytes) -> Self {
        Self {
            extension_type,
            extension_data,
        }
    }

    pub fn extension_type(&self) -> ExtensionType {
        self.extension_type
    }

    pub fn extension_data(&self) -> &Bytes {
        &self.extension_data
    }
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Extensions
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    pub fn new(extensions: Vec<Extension>) -> Self {
        Self(extensions)
    }

    pub fn extensions(&self) -> &[Extension] {
        self.0.as_ref()
    }
}

impl Deserializer for Extensions {
    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self> {
        let mut extensions = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let extension_type: ExtensionType = b.get_u16().into();
            let extension_data = deserialize_opaque_vec(b)?;
            extensions.push(Extension {
                extension_type,
                extension_data,
            });
            Ok(())
        })?;
        Ok(Extensions(extensions))
    }
}

impl Serializer for Extensions {
    fn serialize<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        serialize_vector(
            self.0.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.0[i].extension_type.into());
                serialize_opaque_vec(&self.0[i].extension_data, b)
            },
        )
    }
}

impl Extensions {
    pub(crate) fn find_extension_data(&self, t: ExtensionType) -> Option<Bytes> {
        for ext in &self.0 {
            if ext.extension_type == t {
                return Some(ext.extension_data.clone());
            }
        }
        None
    }
}

/// Application Id Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ApplicationIdExtension(Bytes);

impl ApplicationIdExtension {
    /// Creates a new ApplicationIdExtension
    pub fn new(id: Bytes) -> Self {
        Self(id)
    }
}

impl Deref for ApplicationIdExtension {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializer for ApplicationIdExtension {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(ApplicationIdExtension(deserialize_opaque_vec(buf)?))
    }
}

impl Serializer for ApplicationIdExtension {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.0, buf)
    }
}

/// Ratchet Tree Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct RatchetTreeExtension {
    ratchet_tree: RatchetTree,
}

impl RatchetTreeExtension {
    /// Creates a new RatchetTreeExtension
    pub fn new(ratchet_tree: RatchetTree) -> Self {
        Self { ratchet_tree }
    }

    /// Returns the RatchetTree from this extension
    pub fn ratchet_tree(&self) -> &RatchetTree {
        &self.ratchet_tree
    }
}

//FIXME(yngrtc): RatchetTreeExtension deserialize failed framing_test and serde_test
impl Deserializer for RatchetTreeExtension {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(RatchetTreeExtension {
            ratchet_tree: RatchetTree::deserialize(buf)?,
        })
    }
}

impl Serializer for RatchetTreeExtension {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.ratchet_tree.serialize(buf)
    }
}

/// Required Capabilities Extension.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct RequiredCapabilitiesExtension {
    extension_types: Vec<ExtensionType>,
    proposal_types: Vec<ProposalType>,
    credential_types: Vec<CredentialType>,
}

impl RequiredCapabilitiesExtension {
    /// Creates a new RequiredCapabilitiesExtension
    pub fn new(
        extension_types: Vec<ExtensionType>,
        proposal_types: Vec<ProposalType>,
        credential_types: Vec<CredentialType>,
    ) -> Self {
        Self {
            extension_types,
            proposal_types,
            credential_types,
        }
    }

    /// Returns the extension_types from this extension
    pub fn extension_types(&self) -> &[ExtensionType] {
        &self.extension_types
    }

    /// Returns the proposal_types from this extension
    pub fn proposal_types(&self) -> &[ProposalType] {
        &self.proposal_types
    }

    /// Returns the credential_types from this extension
    pub fn credential_types(&self) -> &[CredentialType] {
        &self.credential_types
    }
}

impl Deserializer for RequiredCapabilitiesExtension {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let mut extension_types = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let extension_type: ExtensionType = b.get_u16().into();
            extension_types.push(extension_type);
            Ok(())
        })?;

        let mut proposal_types = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let proposal_type: ProposalType = b.get_u16().into();
            proposal_types.push(proposal_type);
            Ok(())
        })?;

        let mut credential_types = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let credential_type: CredentialType = b.get_u16().into();
            credential_types.push(credential_type);
            Ok(())
        })?;

        Ok(RequiredCapabilitiesExtension {
            extension_types,
            proposal_types,
            credential_types,
        })
    }
}

impl Serializer for RequiredCapabilitiesExtension {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_vector(
            self.extension_types.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.extension_types[i].into());
                Ok(())
            },
        )?;

        serialize_vector(
            self.proposal_types.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.proposal_types[i].into());
                Ok(())
            },
        )?;

        serialize_vector(
            self.credential_types.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> {
                b.put_u16(self.credential_types[i].into());
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// ExternalPub Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ExternalPubExtension {
    external_pub: HPKEPublicKey,
}

impl ExternalPubExtension {
    /// Creates a new ExternalPubExtension
    pub fn new(external_pub: HPKEPublicKey) -> Self {
        Self { external_pub }
    }

    /// Returns the HPKEPublicKey from this extension
    pub fn external_pub(&self) -> &HPKEPublicKey {
        &self.external_pub
    }
}

impl Deserializer for ExternalPubExtension {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(ExternalPubExtension {
            external_pub: HPKEPublicKey::deserialize(buf)?,
        })
    }
}

impl Serializer for ExternalPubExtension {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.external_pub.serialize(buf)
    }
}

/// ExternalSenders Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ExternalSendersExtension {
    signature_key: SignaturePublicKey,
    credential: Credential,
}

impl ExternalSendersExtension {
    /// Creates a new ExternalSendersExtension
    pub fn new(signature_key: SignaturePublicKey, credential: Credential) -> Self {
        Self {
            signature_key,
            credential,
        }
    }

    /// Returns the SignaturePublicKey from this extension
    pub fn signature_key(&self) -> &SignaturePublicKey {
        &self.signature_key
    }

    /// Returns the Credential from this extension
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
}

impl Deserializer for ExternalSendersExtension {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let signature_key = SignaturePublicKey::deserialize(buf)?;
        let credential = Credential::deserialize(buf)?;

        Ok(ExternalSendersExtension {
            signature_key,
            credential,
        })
    }
}

impl Serializer for ExternalSendersExtension {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.signature_key.serialize(buf)?;
        self.credential.serialize(buf)
    }
}

/// ExternalSenders Extension
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UnknownExtension(Bytes);

impl UnknownExtension {
    /// Creates a new UnknownExtension
    pub fn new(unknown: Bytes) -> Self {
        Self(unknown)
    }
}

impl Deref for UnknownExtension {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializer for UnknownExtension {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(UnknownExtension(deserialize_opaque_vec(buf)?))
    }
}

impl Serializer for UnknownExtension {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.0, buf)
    }
}
