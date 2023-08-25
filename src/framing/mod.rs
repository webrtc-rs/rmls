use bytes::{Buf, BufMut, Bytes};

use crate::cipher_suite::CipherSuite;
use crate::codec::*;
use crate::crypto::provider::CryptoProvider;
use crate::error::*;
use crate::messages::proposal::Proposal;
use crate::messages::Commit;
use crate::tree::tree_math::LeafIndex;

pub(crate) type ProtocolVersion = u16;

pub(crate) const PROTOCOL_VERSION_MLS10: ProtocolVersion = 1;

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
            _ => Err(Error::InvalidContentTypeValue(v)),
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Content {
    Application(Bytes),
    Proposal(Proposal),
    Commit(Commit),
}

impl Default for Content {
    fn default() -> Self {
        Content::Application(Bytes::new())
    }
}

impl Reader for Content {
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
            0x01 => {
                *self = Content::Application(read_opaque_vec(buf)?);
            }
            0x02 => {
                let mut proposal = Proposal::default();
                proposal.read(buf)?;
                *self = Content::Proposal(proposal);
            }
            0x03 => {
                let mut commit = Commit::default();
                commit.read(buf)?;
                *self = Content::Commit(commit);
            }
            _ => return Err(Error::InvalidContentTypeValue(v)),
        }

        Ok(())
    }
}
impl Writer for Content {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Content::Application(application) => {
                buf.put_u8(1);
                write_opaque_vec(application, buf)?;
            }
            Content::Proposal(proposal) => {
                buf.put_u8(2);
                proposal.write(buf)?;
            }
            Content::Commit(commit) => {
                buf.put_u8(3);
                commit.write(buf)?
            }
        }

        Ok(())
    }
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Sender {
    Member(LeafIndex),
    External(u32),
    NewMemberProposal,
    #[default]
    NewMemberCommit,
}

impl Reader for Sender {
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
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                *self = Sender::Member(LeafIndex(buf.get_u32()));
            }
            2 => {
                if buf.remaining() < 4 {
                    return Err(Error::BufferTooSmall);
                }
                *self = Sender::External(buf.get_u32());
            }
            3 => {
                *self = Sender::NewMemberProposal;
            }
            4 => {
                *self = Sender::NewMemberCommit;
            }
            _ => return Err(Error::InvalidSenderTypeValue(v)),
        }

        Ok(())
    }
}

impl Writer for Sender {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match self {
            Sender::Member(leaf_index) => {
                buf.put_u8(1);
                buf.put_u32(leaf_index.0);
            }
            Sender::External(v) => {
                buf.put_u8(2);
                buf.put_u32(*v);
            }
            Sender::NewMemberProposal => {
                buf.put_u8(3);
            }
            Sender::NewMemberCommit => {
                buf.put_u8(4);
            }
        }
        Ok(())
    }
}

// http://www.iana.org/assignments/mls/mls.xhtml#mls-wire-formats
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub(crate) enum WireFormat {
    #[default]
    PublicMessage = 0x0001,
    PrivateMessage = 0x0002,
    Welcome = 0x0003,
    GroupInfo = 0x0004,
    KeyPackage = 0x0005,
}

impl TryFrom<u16> for WireFormat {
    type Error = Error;

    fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(WireFormat::PublicMessage),
            0x0002 => Ok(WireFormat::PrivateMessage),
            0x0003 => Ok(WireFormat::Welcome),
            0x0004 => Ok(WireFormat::GroupInfo),
            0x0005 => Ok(WireFormat::KeyPackage),
            _ => Err(Error::InvalidWireFormatValue(v)),
        }
    }
}

impl Reader for WireFormat {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }

        *self = buf.get_u16().try_into()?;

        Ok(())
    }
}

impl Writer for WireFormat {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(*self as u16);

        Ok(())
    }
}

// GroupID is an application-specific group identifier.
pub(crate) type GroupID = Bytes;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct FramedContent {
    group_id: GroupID,
    epoch: u64,
    sender: Sender,
    authenticated_data: Bytes,
    pub(crate) content: Content,
}

impl Reader for FramedContent {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.group_id = read_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        self.epoch = buf.get_u64();
        self.sender.read(buf)?;
        self.authenticated_data = read_opaque_vec(buf)?;
        self.content.read(buf)
    }
}

impl Writer for FramedContent {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.sender.write(buf)?;
        write_opaque_vec(&self.authenticated_data, buf)?;
        self.content.write(buf)
    }
}

pub(crate) fn expand_sender_data_key(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sender_data_secret: &[u8],
    ciphertext: &[u8],
) -> Result<Bytes> {
    let nk = crypto_provider.hpke(cipher_suite).aead_key_size() as u16;
    let ciphertext_sample = sample_ciphertext(crypto_provider, cipher_suite, ciphertext);
    crypto_provider.expand_with_label(
        cipher_suite,
        sender_data_secret,
        b"key",
        ciphertext_sample,
        nk,
    )
}

pub(crate) fn expand_sender_data_nonce(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sender_data_secret: &[u8],
    ciphertext: &[u8],
) -> Result<Bytes> {
    let nn = crypto_provider.hpke(cipher_suite).aead_nonce_size() as u16;
    let ciphertext_sample = sample_ciphertext(crypto_provider, cipher_suite, ciphertext);
    crypto_provider.expand_with_label(
        cipher_suite,
        sender_data_secret,
        b"nonce",
        ciphertext_sample,
        nn,
    )
}

pub(crate) fn sample_ciphertext<'a>(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    ciphertext: &'a [u8],
) -> &'a [u8] {
    let n = crypto_provider.hpke(cipher_suite).kdf_extract_size();
    if ciphertext.len() < n {
        ciphertext
    } else {
        &ciphertext[..n]
    }
}
