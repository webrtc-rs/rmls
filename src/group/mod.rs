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
}

impl TryFrom<u16> for ProposalType {
    type Error = Error;

    fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(ProposalType::Add),
            0x0002 => Ok(ProposalType::Update),
            0x0003 => Ok(ProposalType::Remove),
            0x0004 => Ok(ProposalType::Psk),
            0x0005 => Ok(ProposalType::Reinit),
            0x0006 => Ok(ProposalType::ExternalInit),
            0x0007 => Ok(ProposalType::GroupContextExtensions),
            _ => Err(Error::InvalidProposalTypeValue(v)),
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
        *self = buf.get_u16().try_into()?;
        Ok(())
    }
}

impl Writer for ProposalType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(*self as u16);
        Ok(())
    }
}
