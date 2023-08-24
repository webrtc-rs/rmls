use crate::cipher_suite::CipherSuite;
use crate::codec::{read_opaque_vec, write_opaque_vec, Reader, Writer};
use crate::error::*;
use crate::framing::{GroupID, ProtocolVersion};
use crate::key_package::KeyPackage;
use crate::key_schedule::PreSharedKeyID;
use crate::tree::tree_math::LeafIndex;
use crate::tree::{read_extensions, write_extensions, Extension, LeafNode};

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

impl Reader for ProposalTypeCapability {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        *self = buf.get_u16().into();
        Ok(())
    }
}

impl Writer for ProposalTypeCapability {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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

impl Reader for Proposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let proposal = buf.get_u16().into();

        match proposal {
            ProposalTypeCapability::Add => {
                let mut proposal = AddProposal::default();
                proposal.read(buf)?;
                *self = Proposal::Add(proposal);
            }
            ProposalTypeCapability::Update => {
                let mut proposal = UpdateProposal::default();
                proposal.read(buf)?;
                *self = Proposal::Update(proposal);
            }
            ProposalTypeCapability::Remove => {
                let mut proposal = RemoveProposal::default();
                proposal.read(buf)?;
                *self = Proposal::Remove(proposal);
            }
            ProposalTypeCapability::PreSharedKey => {
                let mut proposal = PreSharedKeyProposal::default();
                proposal.read(buf)?;
                *self = Proposal::PreSharedKey(proposal);
            }
            ProposalTypeCapability::ReInit => {
                let mut proposal = ReInitProposal::default();
                proposal.read(buf)?;
                *self = Proposal::ReInit(proposal);
            }
            ProposalTypeCapability::ExternalInit => {
                let mut proposal = ExternalInitProposal::default();
                proposal.read(buf)?;
                *self = Proposal::ExternalInit(proposal);
            }
            ProposalTypeCapability::GroupContextExtensions => {
                let mut proposal = GroupContextExtensionsProposal::default();
                proposal.read(buf)?;
                *self = Proposal::GroupContextExtensions(proposal);
            }
            ProposalTypeCapability::Unknown(v) => return Err(Error::InvalidProposalTypeValue(v)),
        };

        Ok(())
    }
}

impl Writer for Proposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Proposal::Add(proposal) => {
                buf.put_u16(ProposalTypeCapability::Add.into());
                proposal.write(buf)
            }
            Proposal::Update(proposal) => {
                buf.put_u16(ProposalTypeCapability::Update.into());
                proposal.write(buf)
            }
            Proposal::Remove(proposal) => {
                buf.put_u16(ProposalTypeCapability::Remove.into());
                proposal.write(buf)
            }
            Proposal::PreSharedKey(proposal) => {
                buf.put_u16(ProposalTypeCapability::PreSharedKey.into());
                proposal.write(buf)
            }
            Proposal::ReInit(proposal) => {
                buf.put_u16(ProposalTypeCapability::ReInit.into());
                proposal.write(buf)
            }
            Proposal::ExternalInit(proposal) => {
                buf.put_u16(ProposalTypeCapability::ExternalInit.into());
                proposal.write(buf)
            }
            Proposal::GroupContextExtensions(proposal) => {
                buf.put_u16(ProposalTypeCapability::GroupContextExtensions.into());
                proposal.write(buf)
            }
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl Reader for AddProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.key_package.read(buf)
    }
}

impl Writer for AddProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.key_package.write(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UpdateProposal {
    pub(crate) leaf_node: LeafNode,
}

impl Reader for UpdateProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.leaf_node.read(buf)
    }
}

impl Writer for UpdateProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.leaf_node.write(buf)
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct RemoveProposal {
    pub(crate) removed: LeafIndex,
}

impl Reader for RemoveProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        self.removed = LeafIndex(buf.get_u32());
        Ok(())
    }
}

impl Writer for RemoveProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
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
    psk: PreSharedKeyID,
}

impl Reader for PreSharedKeyProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.psk.read(buf)
    }
}
impl Writer for PreSharedKeyProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.psk.write(buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ReInitProposal {
    group_id: GroupID,
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    extensions: Vec<Extension>,
}

impl Reader for ReInitProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.group_id = read_opaque_vec(buf)?;

        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }
        self.version = buf.get_u16();
        self.cipher_suite = buf.get_u16().try_into()?;

        self.extensions = read_extensions(buf)?;

        Ok(())
    }
}
impl Writer for ReInitProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u16(self.version);
        buf.put_u16(self.cipher_suite as u16);
        write_extensions(&self.extensions, buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct ExternalInitProposal {
    kem_output: Bytes,
}

impl Reader for ExternalInitProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.kem_output = read_opaque_vec(buf)?;

        Ok(())
    }
}
impl Writer for ExternalInitProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.kem_output, buf)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupContextExtensionsProposal {
    extensions: Vec<Extension>,
}

impl Reader for GroupContextExtensionsProposal {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.extensions = read_extensions(buf)?;

        Ok(())
    }
}
impl Writer for GroupContextExtensionsProposal {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_extensions(&self.extensions, buf)
    }
}

pub type ProposalRef = Bytes;

#[derive(Debug, Clone, Eq, PartialEq)]
enum ProposalOrRef {
    Proposal(Proposal),     // = 1,
    Reference(ProposalRef), // = 2,
}

impl Reader for ProposalOrRef {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let v = buf.get_u8();
        match v {
            1 => {
                let mut proposal = Proposal::default();
                proposal.read(buf)?;
                *self = ProposalOrRef::Proposal(proposal);
            }
            2 => {
                let proposal_ref = read_opaque_vec(buf)?;
                *self = ProposalOrRef::Reference(proposal_ref);
            }
            _ => return Err(Error::InvalidProposalOrRefValue(v)),
        }

        Ok(())
    }
}
impl Writer for ProposalOrRef {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            ProposalOrRef::Proposal(proposal) => {
                buf.put_u16(1);
                proposal.write(buf)
            }
            ProposalOrRef::Reference(proposal_ref) => {
                buf.put_u16(2);
                write_opaque_vec(proposal_ref, buf)
            }
        }
    }
}
