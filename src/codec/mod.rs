#[cfg(test)]
pub(crate) mod codec_test;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

pub(crate) fn read_varint<B: Buf>(buf: &mut B) -> Result<u32> {
    if !buf.has_remaining() {
        return Err(Error::BufferTooSmall);
    }
    let b = buf.get_u8();

    let prefix = b >> 6;
    if prefix == 3 {
        return Err(Error::InvalidVariableLengthIntegerPrefix);
    }

    let n = 1 << prefix;
    let mut v = (b & 0x3F) as u32;
    for _ in 0..n - 1 {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let b = buf.get_u8();
        v = (v << 8) + b as u32;
    }

    if prefix >= 1 && v < 1u32 << (8 * (n / 2) - 2) {
        return Err(Error::MinimumEncodingWasNotUsed);
    }

    Ok(v)
}

pub(crate) fn write_varint<B: BufMut>(n: u32, buf: &mut B) -> Result<()> {
    if n < (1 << 6) {
        buf.put_u8(n as u8);
    } else if n < (1 << 14) {
        buf.put_u16(0b01 << 14 | (n as u16));
    } else if n < (1 << 30) {
        buf.put_u32(0b10 << 30 | n);
    } else {
        return Err(Error::VarintExceeds30Bits);
    }
    Ok(())
}

pub(crate) fn read_opaque_vec<B: Buf>(buf: &mut B) -> Result<Bytes> {
    let n = read_varint(buf)? as usize;
    if buf.remaining() < n {
        return Err(Error::BufferTooSmall);
    }

    Ok(buf.copy_to_bytes(n))
}

pub(crate) fn write_opaque_vec<B: BufMut>(v: &[u8], buf: &mut B) -> Result<()> {
    if v.len() >= 1 << 32 {
        return Err(Error::OpaqueSizeExceedsMaximumValueOfU32);
    }

    write_varint(v.len() as u32, buf)?;

    buf.put(v);

    Ok(())
}

pub(crate) fn read_vector<B: Buf>(
    buf: &mut B,
    mut f: impl FnMut(&mut Bytes) -> Result<()>,
) -> Result<()> {
    let n = read_varint(buf)? as usize;
    if buf.remaining() < n {
        return Err(Error::BufferTooSmall);
    }

    let mut v = buf.copy_to_bytes(n);
    let ss = &mut v;
    while !ss.has_remaining() {
        f(ss)?
    }
    Ok(())
}

pub(crate) fn write_vector<B: BufMut>(
    n: usize,
    buf: &mut B,
    mut f: impl FnMut(usize, &mut BytesMut) -> Result<()>,
) -> Result<()> {
    // We don't know the total size in advance, and the vector is prefixed with
    // a varint, so we can't avoid the temporary buffer here
    let mut child = BytesMut::new();
    for i in 0..n {
        f(i, &mut child)?;
    }

    let raw = child.freeze();

    write_opaque_vec(&raw, buf)
}

pub(crate) fn read_optional<B: Buf>(buf: &mut B) -> Result<bool> {
    if !buf.has_remaining() {
        return Err(Error::BufferTooSmall);
    }
    let b = buf.get_u8();

    match b {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::InvalidOptionalValue),
    }
}

pub(crate) fn write_optional<B: BufMut>(present: bool, buf: &mut B) -> Result<()> {
    let n: u8 = if present { 1 } else { 0 };
    buf.put_u8(n);
    Ok(())
}

pub(crate) trait Reader {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf;
}

pub(crate) trait Writer {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut;
}

pub(crate) fn read<B: Buf, V: Reader>(v: &mut V, buf: &mut B) -> Result<()> {
    v.read(buf)?;
    if buf.has_remaining() {
        Err(Error::InputContainsExcessBytes(buf.remaining()))
    } else {
        Ok(())
    }
}

pub(crate) fn write<V: Writer>(v: &V) -> Result<Bytes> {
    let mut b = BytesMut::new();
    v.write(&mut b)?;
    Ok(b.freeze())
}
