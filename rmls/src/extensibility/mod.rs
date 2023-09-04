//! [RFC9420 Sec.13](https://www.rfc-editor.org/rfc/rfc9420.html#section-13) Extensibility
//!
//! The base MLS protocol can be extended in a few ways. New cipher suites can be added to enable
//! the use of new cryptographic algorithms. New types of proposals can be used to perform new
//! actions within an epoch. Extension fields can be used to add additional information
//! to the protocol.

use bytes::{Buf, BufMut, Bytes, BytesMut};

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
    pub extension_type: ExtensionType,
    pub extension_data: Bytes,
}

/// [RFC9420 Sec.7.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2) Extensions
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Extensions(pub Vec<Extension>);

impl Deserializer for Extensions {
    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self> {
        let mut exts = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            if b.remaining() < 2 {
                return Err(Error::BufferTooSmall);
            }
            let extension_type: ExtensionType = b.get_u16().into();
            let extension_data = deserialize_opaque_vec(b)?;
            exts.push(Extension {
                extension_type,
                extension_data,
            });
            Ok(())
        })?;
        Ok(Extensions(exts))
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
