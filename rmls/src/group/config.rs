use crate::crypto::config::CryptoConfig;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct GroupConfig {
    pub(crate) crypto_config: CryptoConfig,
}

impl GroupConfig {
    /// Create a group config builder
    pub fn builder() -> GroupConfigBuilder {
        GroupConfigBuilder::new()
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct GroupConfigBuilder {
    group_config: GroupConfig,
}

impl GroupConfigBuilder {
    /// Create a group config
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with crypto config
    pub fn with_crypto_config(mut self, crypto_config: CryptoConfig) -> Self {
        self.group_config.crypto_config = crypto_config;
        self
    }

    /// Finalize and build the group config
    pub fn build(self) -> GroupConfig {
        self.group_config
    }
}
