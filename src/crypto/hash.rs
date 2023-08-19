use ring::digest::{digest, Digest, SHA256, SHA384, SHA512};

pub(crate) trait Digester {
    fn digest(&self, data: &[u8]) -> Digest;
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Hash {
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

impl Digester for Hash {
    fn digest(&self, data: &[u8]) -> Digest {
        match *self {
            Hash::SHA256 => digest(&SHA256, data),
            Hash::SHA384 => digest(&SHA384, data),
            Hash::SHA512 => digest(&SHA512, data),
        }
    }
}
