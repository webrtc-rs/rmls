use bytes::Bytes;
use ring::{
    digest::{digest, SHA256, SHA384, SHA512},
    hmac,
};

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum HashScheme {
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

impl crate::crypto::provider::Hash for HashScheme {
    fn digest(&self, data: &[u8]) -> Bytes {
        let d = match *self {
            HashScheme::SHA256 => digest(&SHA256, data),
            HashScheme::SHA384 => digest(&SHA384, data),
            HashScheme::SHA512 => digest(&SHA512, data),
        };
        Bytes::from(d.as_ref().to_vec())
    }

    fn sign(&self, key: &[u8], message: &[u8]) -> Bytes {
        let hmac_key = match *self {
            HashScheme::SHA256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            HashScheme::SHA384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            HashScheme::SHA512 => hmac::Key::new(hmac::HMAC_SHA512, key),
        };
        Bytes::from(hmac::sign(&hmac_key, message).as_ref().to_vec())
    }
}
