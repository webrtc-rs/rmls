use bytes::{Buf, BufMut, Bytes};

use crate::codec::*;
use crate::error::*;

pub(crate) type ProtocolVersion = u16;

// GroupID is an application-specific group identifier.
pub(crate) type GroupID = Bytes;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum ContentType {
    #[default]
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

impl TryFrom<u8> for ContentType {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0x01 => Ok(ContentType::Application),
            0x02 => Ok(ContentType::Proposal),
            0x03 => Ok(ContentType::Commit),
            _ => Err(Error::InvalidContentType(v)),
        }
    }
}

impl Reader for ContentType {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        *self = buf.get_u8().try_into()?;
        Ok(())
    }
}
impl Writer for ContentType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(*self as u8);
        Ok(())
    }
}
