use crate::crypto::cipher_suite::CipherSuite;
use crate::framing::{GroupID, ProtocolVersion};
use crate::key_package::KeyPackage;
use crate::key_schedule::PreSharedKeyID;
use crate::ratchet_tree::*;
use crate::utilities::error::*;
use crate::utilities::serde::*;
use crate::utilities::tree_math::*;

use bytes::{Buf, BufMut, Bytes};

// http://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum ProposalTypeCapability {
    #[default]
    Add = 0x0001,
    Update = 0x0002,
    Remove = 0x0003,
    PreSharedKey = 0x0004,
    ReInit = 0x0005,
    ExternalInit = 0x0006,
    GroupContextExtensions = 0x0007,
    Unknown(u16),
}

impl From<u16> for ProposalTypeCapability {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => ProposalTypeCapability::Add,
            0x0002 => ProposalTypeCapability::Update,
            0x0003 => ProposalTypeCapability::Remove,
            0x0004 => ProposalTypeCapability::PreSharedKey,
            0x0005 => ProposalTypeCapability::ReInit,
            0x0006 => ProposalTypeCapability::ExternalInit,
            0x0007 => ProposalTypeCapability::GroupContextExtensions,
            _ => ProposalTypeCapability::Unknown(v),
        }
    }
}

impl From<ProposalTypeCapability> for u16 {
    fn from(val: ProposalTypeCapability) -> Self {
        match val {
            ProposalTypeCapability::Add => 0x0001,
            ProposalTypeCapability::Update => 0x0002,
            ProposalTypeCapability::Remove => 0x0003,
            ProposalTypeCapability::PreSharedKey => 0x0004,
            ProposalTypeCapability::ReInit => 0x0005,
            ProposalTypeCapability::ExternalInit => 0x0006,
            ProposalTypeCapability::GroupContextExtensions => 0x0007,
            ProposalTypeCapability::Unknown(v) => v,
        }
    }
}

impl Deserializer for ProposalTypeCapability {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        Ok(buf.get_u16().into())
    }
}

impl Serializer for ProposalTypeCapability {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16((*self).into());
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    PreSharedKey(PreSharedKeyProposal),
    ReInit(ReInitProposal),
    ExternalInit(ExternalInitProposal),
    GroupContextExtensions(GroupContextExtensionsProposal),
}

impl Default for Proposal {
    fn default() -> Self {
        Proposal::Remove(RemoveProposal::default())
    }
}

impl Deserializer for Proposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let proposal = buf.get_u16().into();

        match proposal {
            ProposalTypeCapability::Add => Ok(Proposal::Add(AddProposal::deserialize(buf)?)),
            ProposalTypeCapability::Update => {
                Ok(Proposal::Update(UpdateProposal::deserialize(buf)?))
            }
            ProposalTypeCapability::Remove => {
                Ok(Proposal::Remove(RemoveProposal::deserialize(buf)?))
            }
            ProposalTypeCapability::PreSharedKey => Ok(Proposal::PreSharedKey(
                PreSharedKeyProposal::deserialize(buf)?,
            )),
            ProposalTypeCapability::ReInit => {
                Ok(Proposal::ReInit(ReInitProposal::deserialize(buf)?))
            }
            ProposalTypeCapability::ExternalInit => Ok(Proposal::ExternalInit(
                ExternalInitProposal::deserialize(buf)?,
            )),
            ProposalTypeCapability::GroupContextExtensions => Ok(Proposal::GroupContextExtensions(
                GroupContextExtensionsProposal::deserialize(buf)?,
            )),
            ProposalTypeCapability::Unknown(v) => Err(Error::InvalidProposalTypeValue(v)),
        }
    }
}

impl Serializer for Proposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Proposal::Add(proposal) => {
                buf.put_u16(ProposalTypeCapability::Add.into());
                proposal.serialize(buf)
            }
            Proposal::Update(proposal) => {
                buf.put_u16(ProposalTypeCapability::Update.into());
                proposal.serialize(buf)
            }
            Proposal::Remove(proposal) => {
                buf.put_u16(ProposalTypeCapability::Remove.into());
                proposal.serialize(buf)
            }
            Proposal::PreSharedKey(proposal) => {
                buf.put_u16(ProposalTypeCapability::PreSharedKey.into());
                proposal.serialize(buf)
            }
            Proposal::ReInit(proposal) => {
                buf.put_u16(ProposalTypeCapability::ReInit.into());
                proposal.serialize(buf)
            }
            Proposal::ExternalInit(proposal) => {
                buf.put_u16(ProposalTypeCapability::ExternalInit.into());
                proposal.serialize(buf)
            }
            Proposal::GroupContextExtensions(proposal) => {
                buf.put_u16(ProposalTypeCapability::GroupContextExtensions.into());
                proposal.serialize(buf)
            }
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl Deserializer for AddProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let key_package = KeyPackage::deserialize(buf)?;
        Ok(Self { key_package })
    }
}

impl Serializer for AddProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.key_package.serialize(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UpdateProposal {
    pub(crate) leaf_node: LeafNode,
}

impl Deserializer for UpdateProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let leaf_node = LeafNode::deserialize(buf)?;
        Ok(Self { leaf_node })
    }
}

impl Serializer for UpdateProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.leaf_node.serialize(buf)
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct RemoveProposal {
    pub(crate) removed: LeafIndex,
}

impl Deserializer for RemoveProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        let removed = LeafIndex(buf.get_u32());
        Ok(Self { removed })
    }
}

impl Serializer for RemoveProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u32(self.removed.0);

        Ok(())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PreSharedKeyProposal {
    pub(crate) psk: PreSharedKeyID,
}

impl Deserializer for PreSharedKeyProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let psk = PreSharedKeyID::deserialize(buf)?;
        Ok(Self { psk })
    }
}
impl Serializer for PreSharedKeyProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.psk.serialize(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ReInitProposal {
    group_id: GroupID,
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    extensions: Extensions,
}

impl Deserializer for ReInitProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let group_id = deserialize_opaque_vec(buf)?;

        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        let version = buf.get_u16().into();
        let cipher_suite = buf.get_u16().try_into()?;

        let extensions = Extensions::deserialize(buf)?;

        Ok(Self {
            group_id,
            version,
            cipher_suite,
            extensions,
        })
    }
}
impl Serializer for ReInitProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u16(self.version.into());
        buf.put_u16(self.cipher_suite as u16);
        self.extensions.serialize(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ExternalInitProposal {
    kem_output: Bytes,
}

impl Deserializer for ExternalInitProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let kem_output = deserialize_opaque_vec(buf)?;
        Ok(Self { kem_output })
    }
}
impl Serializer for ExternalInitProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.kem_output, buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupContextExtensionsProposal {
    extensions: Extensions,
}

impl Deserializer for GroupContextExtensionsProposal {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(Self {
            extensions: Extensions::deserialize(buf)?,
        })
    }
}
impl Serializer for GroupContextExtensionsProposal {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.extensions.serialize(buf)
    }
}

pub type ProposalRef = Bytes;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProposalOrRef {
    Proposal(Proposal),     // = 1,
    Reference(ProposalRef), // = 2,
}

impl Default for ProposalOrRef {
    fn default() -> Self {
        ProposalOrRef::Reference(Bytes::new())
    }
}

impl Deserializer for ProposalOrRef {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let v = buf.get_u8();
        match v {
            1 => Ok(ProposalOrRef::Proposal(Proposal::deserialize(buf)?)),
            2 => Ok(ProposalOrRef::Reference(deserialize_opaque_vec(buf)?)),
            _ => Err(Error::InvalidProposalOrRefValue(v)),
        }
    }
}
impl Serializer for ProposalOrRef {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            ProposalOrRef::Proposal(proposal) => {
                buf.put_u8(1);
                proposal.serialize(buf)
            }
            ProposalOrRef::Reference(proposal_ref) => {
                buf.put_u8(2);
                serialize_opaque_vec(proposal_ref, buf)
            }
        }
    }
}
