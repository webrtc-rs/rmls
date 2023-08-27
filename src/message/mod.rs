#[cfg(test)]
mod message_test;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashSet;
use std::iter::zip;

pub mod external;
pub mod framing;
pub mod group_info;
pub mod proposal;

use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider, HpkeCiphertext};
use crate::error::*;
use crate::key::{
    package::{KeyPackage, KeyPackageRef},
    schedule::extract_welcome_secret,
};
use crate::message::{
    framing::{PrivateMessage, ProtocolVersion, PublicMessage, WireFormat, PROTOCOL_VERSION_MLS10},
    group_info::*,
    proposal::*,
};
use crate::serde::*;
use crate::tree::math::LeafIndex;
use crate::tree::*;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Commit {
    proposals: Vec<ProposalOrRef>,
    path: Option<UpdatePath>,
}

impl Deserializer for Commit {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let mut proposals = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            proposals.push(ProposalOrRef::deserialize(b)?);
            Ok(())
        })?;

        let has_path = deserialize_optional(buf)?;
        let path = if has_path {
            Some(UpdatePath::deserialize(buf)?)
        } else {
            None
        };

        Ok(Self { proposals, path })
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
                let psk = proposal.psk.serialize_detached()?;
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
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let cipher_suite = buf.get_u16().try_into()?;

        let mut secrets = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            secrets.push(EncryptedGroupSecrets::deserialize(b)?);
            Ok(())
        })?;

        let encrypted_group_info = deserialize_opaque_vec(buf)?;

        Ok(Self {
            cipher_suite,
            secrets,
            encrypted_group_info,
        })
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
            let raw_group_secrets = crypto_provider.decrypt_with_label(
                self.cipher_suite,
                init_key_priv,
                b"Welcome",
                &self.encrypted_group_info,
                &sec.encrypted_group_secrets.kem_output,
                &sec.encrypted_group_secrets.ciphertext,
            )?;

            Ok(GroupSecrets::deserialize_exact(&raw_group_secrets)?)
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

        let raw_group_info = crypto_provider.hpke(self.cipher_suite).aead_open(
            &welcome_key,
            &welcome_nonce,
            &self.encrypted_group_info,
            &[],
        )?;

        GroupInfo::deserialize_exact(&raw_group_info)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EncryptedGroupSecrets {
    new_member: KeyPackageRef,
    encrypted_group_secrets: HpkeCiphertext,
}

impl Deserializer for EncryptedGroupSecrets {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let new_member = deserialize_opaque_vec(buf)?;
        let encrypted_group_secrets = HpkeCiphertext::deserialize(buf)?;

        Ok(Self {
            new_member,
            encrypted_group_secrets,
        })
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WireFormatMessage {
    PublicMessage(PublicMessage),
    PrivateMessage(PrivateMessage),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}

impl Default for WireFormatMessage {
    fn default() -> Self {
        WireFormatMessage::Welcome(Welcome::default())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Message {
    version: ProtocolVersion,
    pub(crate) wire_format: WireFormat,
    pub(crate) message: WireFormatMessage,
}

impl Deserializer for Message {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let version = buf.get_u16();

        if version != PROTOCOL_VERSION_MLS10 {
            return Err(Error::InvalidProtocolVersion(version));
        }

        let wire_format = WireFormat::deserialize(buf)?;

        let message = match wire_format {
            WireFormat::PublicMessage => {
                WireFormatMessage::PublicMessage(PublicMessage::deserialize(buf)?)
            }
            WireFormat::PrivateMessage => {
                WireFormatMessage::PrivateMessage(PrivateMessage::deserialize(buf)?)
            }
            WireFormat::Welcome => WireFormatMessage::Welcome(Welcome::deserialize(buf)?),
            WireFormat::GroupInfo => WireFormatMessage::GroupInfo(GroupInfo::deserialize(buf)?),
            WireFormat::KeyPackage => WireFormatMessage::KeyPackage(KeyPackage::deserialize(buf)?),
        };

        Ok(Self {
            version,
            wire_format,
            message,
        })
    }
}
impl Serializer for Message {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        self.wire_format.serialize(buf)?;
        match &self.message {
            WireFormatMessage::PublicMessage(message) => {
                message.serialize(buf)?;
            }
            WireFormatMessage::PrivateMessage(message) => {
                message.serialize(buf)?;
            }
            WireFormatMessage::Welcome(message) => {
                message.serialize(buf)?;
            }
            WireFormatMessage::GroupInfo(message) => {
                message.serialize(buf)?;
            }
            WireFormatMessage::KeyPackage(message) => {
                message.serialize(buf)?;
            }
        }
        Ok(())
    }
}
