use crate::cipher_suite::CipherSuite;
use crate::codec::*;
use crate::crypto::provider::CryptoProvider;
use crate::error::*;

use bytes::{Buf, BufMut, Bytes};

pub(crate) type ProtocolVersion = u16;

pub(crate) const PROTOCOL_VERSION_MLS10: ProtocolVersion = 1;

// GroupID is an application-specific group identifier.
pub(crate) type GroupID = Bytes;

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
