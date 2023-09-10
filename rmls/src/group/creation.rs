use crate::crypto::credential::Credential;
use crate::crypto::key_pair::SignatureKeyPair;
use crate::crypto::provider::CryptoProvider;
use crate::framing::welcome::Welcome;
use crate::framing::GroupID;
use crate::group::config::GroupConfig;
use crate::group::*;
use crate::key_package::KeyPackage;
use crate::ratchet_tree::RatchetTree;
use crate::utilities::error::*;
use crate::utilities::serde::*;

use crate::crypto::{HPKEPrivateKey, SecretKey};
use bytes::Bytes;

impl Group {
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        group_config: GroupConfig,
        credential: Credential,
        signature_key_pair: &SignatureKeyPair,
        group_id: Option<GroupID>,
    ) -> Result<Self> {
        let group_id = if let Some(group_id) = group_id {
            group_id
        } else {
            let mut group_id = vec![0u8; 16];
            crypto_provider.rand().fill(&mut group_id)?;
            Bytes::from(group_id)
        };

        Ok(Self {
            group_config,
            credential,
            signature_key: signature_key_pair.public_key.clone(),
            group_id,
        })
    }

    pub fn from_welcome(
        crypto_provider: &impl CryptoProvider,
        _group_config: GroupConfig,
        welcome: Welcome,
        _ratchet_tree: Option<RatchetTree>,
    ) -> Result<Self> {
        let key_package = KeyPackage::deserialize_exact(
            &welcome
                .secrets()
                .iter()
                .find_map(|egs| crypto_provider.key_store().retrieve(egs.new_member()))
                .ok_or(Error::NoMatchingKeyPackage)?,
        )?;
        crypto_provider
            .key_store()
            .delete(&*key_package.generate_ref(crypto_provider)?);

        let _private_key: HPKEPrivateKey = SecretKey::deserialize_exact(
            &crypto_provider
                .key_store()
                .retrieve(&key_package.payload.init_key)
                .ok_or(Error::NoMatchingKeyPackage)?,
        )?;
        crypto_provider
            .key_store()
            .delete(&key_package.payload.init_key);

        Ok(Self::default())
    }
}
