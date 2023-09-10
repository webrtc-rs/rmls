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
    crypto_config: CryptoConfig,
}

impl CryptoConfigBuilder {
    /// Create a crypto config
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with version
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.crypto_config.version = version;
        self
    }

    /// Build with cipher suite
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.crypto_config.cipher_suite = cipher_suite;
        self
    }

    /// Finalize and build the crypto config
    pub fn build(self) -> CryptoConfig {
        self.crypto_config
    }
}
