use crate::crypto::cipher_suite::CipherSuite;
use crate::framing::ProtocolVersion;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct CryptoConfig {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
}

impl CryptoConfig {
    /// Create a crypto config builder
    pub fn builder() -> CryptoConfigBuilder {
        CryptoConfigBuilder::new()
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct CryptoConfigBuilder {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
}

impl CryptoConfigBuilder {
    /// Create a crypto config
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with version
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = version;
        self
    }

    /// Build with cipher suite
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    /// Finalize and build the crypto config
    pub fn build(self) -> CryptoConfig {
        CryptoConfig {
            version: self.version,
            cipher_suite: self.cipher_suite,
        }
    }
}
