#[cfg(test)]
mod messages_test;

pub mod external;
pub mod group_info;
pub mod proposal;

use crate::error::*;
use crate::serde::*;
use crate::tree::*;
use proposal::*;
use std::collections::HashSet;
use std::iter::zip;

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider, HpkeCiphertext};
use crate::key_package::KeyPackageRef;
use crate::key_schedule::extract_welcome_secret;
use crate::messages::group_info::*;
use crate::tree::tree_math::LeafIndex;

use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Commit {
    proposals: Vec<ProposalOrRef>,
    path: Option<UpdatePath>,
}

impl Deserializer for Commit {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            let mut prop_or_ref = ProposalOrRef::default();
            prop_or_ref.deserialize(b)?;
            self.proposals.push(prop_or_ref);
            Ok(())
        })?;

        let has_path = deserialize_optional(buf)?;
        if has_path {
            let mut update_path = UpdatePath::default();
            update_path.deserialize(buf)?;
            self.path = Some(update_path);
        }

        Ok(())
    }
}

impl Serializer for Commit {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_vector(
            self.proposals.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.proposals[i].serialize(b) },
        )?;
        serialize_optional(self.path.is_some(), buf)?;
        if let Some(update_path) = &self.path {
            update_path.serialize(buf)?;
        }

        Ok(())
    }
}

// verifyProposalList ensures that a list of proposals passes the checks for a
// regular commit described in section 12.2.
//
// It does not perform all checks:
//
//   - It does not check the validity of individual proposals (section 12.1).
//   - It does not check whether members in add proposals are already part of
//     the group.
//   - It does not check whether non-default proposal types are supported by
//     all members of the group who will process the commit.
//   - It does not check whether the ratchet tree is valid after processing the
//     commit.
pub fn verify_proposal_list(
    proposals: &[Proposal],
    senders: &[LeafIndex],
    committer: LeafIndex,
) -> Result<()> {
    if proposals.len() != senders.len() {
        return Err(Error::ProposalsLenNotMatchSendersLen);
    }

    let mut add_proposals = HashSet::new();
    let mut update_or_remove_proposals = HashSet::new();
    let mut psk_proposals = HashSet::new();

    let mut group_context_extensions = false;
    for (prop, sender) in zip(proposals, senders) {
        match prop {
            Proposal::Add(proposal) => {
                if add_proposals.contains(&proposal.key_package.leaf_node.signature_key) {
                    return Err(Error::MultipleAddProposalsHaveTheSameSignatureKey);
                }
                add_proposals.insert(proposal.key_package.leaf_node.signature_key.clone());
                //TODO:(yngrtc) optimize it
            }

            Proposal::Update(_) => {
                if sender == &committer {
                    return Err(Error::UpdateProposalGeneratedByTheCommitter);
                }
                if update_or_remove_proposals.contains(sender) {
                    return Err(Error::MultipleUpdateRemoveProposalsApplyToTheSameLeaf);
                }
                update_or_remove_proposals.insert(*sender);
            }
            Proposal::Remove(proposal) => {
                if proposal.removed == committer {
                    return Err(Error::RemoveProposalRemovesTheCommitter);
                }
                if update_or_remove_proposals.contains(&proposal.removed) {
                    return Err(Error::MultipleUpdateRemoveProposalsApplyToTheSameLeaf);
                }
                update_or_remove_proposals.insert(proposal.removed);
            }
            Proposal::PreSharedKey(proposal) => {
                let psk = serialize(&proposal.psk)?;
                if psk_proposals.contains(&psk) {
                    return Err(Error::MultiplePSKProposalsReferenceTheSamePSKId);
                }
                psk_proposals.insert(psk);
            }
            Proposal::GroupContextExtensions(_) => {
                if group_context_extensions {
                    return Err(Error::MultipleGroupContextExtensionsProposals);
                }
                group_context_extensions = true;
            }
            Proposal::ReInit(_) => {
                if proposals.len() > 1 {
                    return Err(Error::ReinitProposalTogetherWithAnyOtherProposal);
                }
            }
            Proposal::ExternalInit(_) => {
                return Err(Error::ExternalInitProposalNotAllowed);
            }
        }
    }
    Ok(())
}

fn proposal_list_needs_path(proposals: &[Proposal]) -> bool {
    if proposals.is_empty() {
        return true;
    }

    for prop in proposals {
        match prop {
            Proposal::Update(_)
            | Proposal::Remove(_)
            | Proposal::ExternalInit(_)
            | Proposal::GroupContextExtensions(_) => {
                return true;
            }
            _ => {}
        }
    }

    false
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Welcome {
    cipher_suite: CipherSuite,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: Bytes,
}

impl Deserializer for Welcome {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        self.cipher_suite = buf.get_u16().try_into()?;

        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            let mut secret = EncryptedGroupSecrets::default();
            secret.deserialize(b)?;
            self.secrets.push(secret);
            Ok(())
        })?;

        self.encrypted_group_info = deserialize_opaque_vec(buf)?;

        Ok(())
    }
}

impl Serializer for Welcome {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.cipher_suite as u16);
        serialize_vector(
            self.secrets.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.secrets[i].serialize(b) },
        )?;
        serialize_opaque_vec(&self.encrypted_group_info, buf)
    }
}

impl Welcome {
    fn find_secret(&self, r: &KeyPackageRef) -> Option<&EncryptedGroupSecrets> {
        for (i, sec) in self.secrets.iter().enumerate() {
            if sec.new_member == r {
                return Some(&self.secrets[i]);
            }
        }
        None
    }

    fn decrypt_group_secrets(
        &self,
        crypto_provider: &impl CryptoProvider,
        r: &KeyPackageRef,
        init_key_priv: &[u8],
    ) -> Result<GroupSecrets> {
        if let Some(sec) = self.find_secret(r) {
            let mut raw_group_secrets = crypto_provider.decrypt_with_label(
                self.cipher_suite,
                init_key_priv,
                b"Welcome",
                &self.encrypted_group_info,
                &sec.encrypted_group_secrets.kem_output,
                &sec.encrypted_group_secrets.ciphertext,
            )?;

            let mut group_secrets = GroupSecrets::default();
            group_secrets.deserialize(&mut raw_group_secrets)?;

            Ok(group_secrets)
        } else {
            Err(Error::EncryptedGroupSecretsNotFoundForProvidedKeyPackageRef)
        }
    }

    fn decrypt_group_info(
        &self,
        crypto_provider: &impl CryptoProvider,
        joiner_secret: &[u8],
        psk_secret: &[u8],
    ) -> Result<GroupInfo> {
        let welcome_secret = extract_welcome_secret(
            crypto_provider,
            self.cipher_suite,
            joiner_secret,
            psk_secret,
        )?;

        let aead_nonce_size = crypto_provider.hpke(self.cipher_suite).aead_nonce_size() as u16;
        let welcome_nonce = crypto_provider.expand_with_label(
            self.cipher_suite,
            &welcome_secret,
            b"nonce",
            &[],
            aead_nonce_size,
        )?;

        let aead_key_size = crypto_provider.hpke(self.cipher_suite).aead_key_size() as u16;
        let welcome_key = crypto_provider.expand_with_label(
            self.cipher_suite,
            &welcome_secret,
            b"key",
            &[],
            aead_key_size,
        )?;

        let mut raw_group_info = crypto_provider.hpke(self.cipher_suite).aead_open(
            &welcome_key,
            &welcome_nonce,
            &self.encrypted_group_info,
            &[],
        )?;

        let mut group_info = GroupInfo::default();
        group_info.deserialize(&mut raw_group_info)?;

        Ok(group_info)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EncryptedGroupSecrets {
    new_member: KeyPackageRef,
    encrypted_group_secrets: HpkeCiphertext,
}

impl Deserializer for EncryptedGroupSecrets {
    fn deserialize<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        self.new_member = deserialize_opaque_vec(buf)?;
        self.encrypted_group_secrets.deserialize(buf)
    }
}

impl Serializer for EncryptedGroupSecrets {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.new_member, buf)?;
        self.encrypted_group_secrets.serialize(buf)
    }
}
