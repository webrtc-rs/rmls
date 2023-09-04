use super::*;

/// [RFC9420 Sec.10](https://www.rfc-editor.org/rfc/rfc9420.html#section-10) KeyPackage
#[derive(Default, Debug, Clone)]
pub struct KeyPackageBuilder {
    key_package_lifetime: Option<Lifetime>,
    key_package_extensions: Option<Extensions>,
    leaf_node_capabilities: Option<Capabilities>,
    leaf_node_extensions: Option<Extensions>,
}

impl KeyPackageBuilder {
    /// Create a key packet builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with the key package lifetime.
    pub fn with_key_package_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.key_package_lifetime.replace(lifetime);
        self
    }

    /// Build with the key package extensions.
    pub fn with_key_package_extensions(mut self, extensions: Extensions) -> Self {
        self.key_package_extensions.replace(extensions);
        self
    }

    /// Build with the leaf node capabilities.
    pub fn with_leaf_node_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.leaf_node_capabilities.replace(capabilities);
        self
    }

    /// Build with the leaf node extensions.
    pub fn with_leaf_node_extensions(mut self, extensions: Extensions) -> Self {
        self.leaf_node_extensions.replace(extensions);
        self
    }

    /*TODO(yngrtc): pub fn build(self) -> Result<KeyPackage> {

    }*/
}
