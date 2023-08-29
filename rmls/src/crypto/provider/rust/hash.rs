use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum HashScheme {
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

impl crate::crypto::provider::Hash for HashScheme {
    fn digest(&self, data: &[u8]) -> Bytes {
        match *self {
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
        match *self {
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
