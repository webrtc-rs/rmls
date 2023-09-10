use crate::crypto::credential::Credential;
use crate::crypto::key_pair::SignatureKeyPair;
use crate::crypto::provider::CryptoProvider;
use crate::framing::welcome::Welcome;
use crate::framing::GroupID;
use crate::group::config::GroupConfig;
use crate::group::*;
use crate::ratchet_tree::RatchetTree;
use crate::utilities::error::*;
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
        _crypto_provider: &impl CryptoProvider,
        _group_config: GroupConfig,
        _welcome: Welcome,
        _ratchet_tree: Option<RatchetTree>,
    ) -> Result<Self> {
        Ok(Self::default())
    }
}
