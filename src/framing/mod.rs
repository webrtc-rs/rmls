use bytes::Bytes;

pub(crate) type ProtocolVersion = u16;

// GroupID is an application-specific group identifier.
pub(crate) type GroupID = Bytes;
