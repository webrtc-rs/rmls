use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

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
        match self.0 {
            HashScheme::SHA256 => {
                let mut h = Sha256::new();
                h.update(data);
                Bytes::from(h.finalize().to_vec())
            }
            HashScheme::SHA384 => {
                let mut h = Sha384::new();
                h.update(data);
                Bytes::from(h.finalize().to_vec())
            }
            HashScheme::SHA512 => {
                let mut h = Sha512::new();
                h.update(data);
                Bytes::from(h.finalize().to_vec())
            }
        }
    }

    fn mac(&self, key: &[u8], message: &[u8]) -> Bytes {
        match self.0 {
            HashScheme::SHA256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(key).unwrap();
                m.update(message);
                Bytes::from(m.finalize().into_bytes().to_vec())
            }
            HashScheme::SHA384 => {
                let mut m = Hmac::<Sha384>::new_from_slice(key).unwrap();
                m.update(message);
                Bytes::from(m.finalize().into_bytes().to_vec())
            }
            HashScheme::SHA512 => {
                let mut m = Hmac::<Sha512>::new_from_slice(key).unwrap();
                m.update(message);
                Bytes::from(m.finalize().into_bytes().to_vec())
            }
        }
    }
}
