use ring::digest::{self, digest, SHA256, SHA384, SHA512};
use ring::hmac;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Hash {
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

impl Hash {
    pub(crate) fn digest(&self, data: &[u8]) -> digest::Digest {
        match *self {
            Hash::SHA256 => digest(&SHA256, data),
            Hash::SHA384 => digest(&SHA384, data),
            Hash::SHA512 => digest(&SHA512, data),
        }
    }

    pub(crate) fn sign_mac(&self, key: &[u8], message: &[u8]) -> hmac::Tag {
        let hmac_key = match *self {
            Hash::SHA256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            Hash::SHA384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            Hash::SHA512 => hmac::Key::new(hmac::HMAC_SHA512, key),
        };
        hmac::sign(&hmac_key, message)
    }
}
