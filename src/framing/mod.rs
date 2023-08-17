use bytes::{Buf, BufMut, Bytes};

use crate::codec::*;
use crate::error::*;

pub(crate) type ProtocolVersion = u16;

// GroupID is an application-specific group identifier.
pub(crate) type GroupID = Bytes;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct ContentType(pub(crate) u8);

pub(crate) const CONTENT_TYPE_APPLICATION: ContentType = ContentType(1);
pub(crate) const CONTENT_TYPE_PROPOSAL: ContentType = ContentType(2);
pub(crate) const CONTENT_TYPE_COMMIT: ContentType = ContentType(3);

impl Reader for ContentType {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        self.0 = buf.get_u8();

        match *self {
            CONTENT_TYPE_APPLICATION | CONTENT_TYPE_PROPOSAL | CONTENT_TYPE_COMMIT => Ok(()),

            _ => Err(Error::InvalidContentType(self.0)),
        }
    }
}
impl Writer for ContentType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(self.0);
        Ok(())
    }
}
