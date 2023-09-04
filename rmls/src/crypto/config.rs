use crate::crypto::cipher_suite::CipherSuite;
use crate::framing::ProtocolVersion;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct CryptoConfig {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct CryptoConfigBuilder {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
}

impl CryptoConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    pub fn build(self) -> CryptoConfig {
        CryptoConfig {
            version: self.version,
            cipher_suite: self.cipher_suite,
        }
    }
}
