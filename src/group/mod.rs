use crate::codec::{Reader, Writer};
use crate::error::*;
use bytes::{Buf, BufMut};

// http://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum ProposalType {
    #[default]
    Add = 0x0001,
    Update = 0x0002,
    Remove = 0x0003,
    Psk = 0x0004,
    Reinit = 0x0005,
    ExternalInit = 0x0006,
    GroupContextExtensions = 0x0007,
    Unknown(u16),
}

impl From<u16> for ProposalType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => ProposalType::Add,
            0x0002 => ProposalType::Update,
            0x0003 => ProposalType::Remove,
            0x0004 => ProposalType::Psk,
            0x0005 => ProposalType::Reinit,
            0x0006 => ProposalType::ExternalInit,
            0x0007 => ProposalType::GroupContextExtensions,
            _ => ProposalType::Unknown(v),
        }
    }
}

impl From<ProposalType> for u16 {
    fn from(val: ProposalType) -> Self {
        match val {
            ProposalType::Add => 0x0001,
            ProposalType::Update => 0x0002,
            ProposalType::Remove => 0x0003,
            ProposalType::Psk => 0x0004,
            ProposalType::Reinit => 0x0005,
            ProposalType::ExternalInit => 0x0006,
            ProposalType::GroupContextExtensions => 0x0007,
            ProposalType::Unknown(v) => v,
        }
    }
}

impl Reader for ProposalType {
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

impl Writer for ProposalType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16((*self).into());
        Ok(())
    }
}
