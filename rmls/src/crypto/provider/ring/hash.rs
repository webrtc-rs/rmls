use bytes::Bytes;
use ring::{
    digest::{digest, SHA256, SHA384, SHA512},
    hmac,
};

use crate::crypto::provider::HashScheme;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct HashSchemeWrapper(pub(super) HashScheme);

impl crate::crypto::provider::Hash for HashSchemeWrapper {
    fn size(&self) -> usize {
        match self.0 {
            HashScheme::SHA256 => 32,
            HashScheme::SHA384 => 48,
            HashScheme::SHA512 => 64,
        }
    }

    fn digest(&self, data: &[u8]) -> Bytes {
        let d = match self.0 {
            HashScheme::SHA256 => digest(&SHA256, data),
            HashScheme::SHA384 => digest(&SHA384, data),
            HashScheme::SHA512 => digest(&SHA512, data),
        };
        Bytes::from(d.as_ref().to_vec())
    }

    fn mac(&self, key: &[u8], message: &[u8]) -> Bytes {
        let hmac_key = match self.0 {
            HashScheme::SHA256 => hmac::Key::new(hmac::HMAC_SHA256, key),
            HashScheme::SHA384 => hmac::Key::new(hmac::HMAC_SHA384, key),
            HashScheme::SHA512 => hmac::Key::new(hmac::HMAC_SHA512, key),
        };
        Bytes::from(hmac::sign(&hmac_key, message).as_ref().to_vec())
    }
}
