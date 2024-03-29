//! [RFC9420 Sec.11](https://www.rfc-editor.org/rfc/rfc9420.html#section-11) Group Creation and
//! [RFC9420 Sec.12](https://www.rfc-editor.org/rfc/rfc9420.html#section-12) Group Evolution
//!
//! A group is always created with a single member, the "creator". Other members are then added to
//! the group using the usual Add/Commit mechanism.
//!
//! Over the lifetime of a group, its membership can change, and existing members might want to
//! change their keys in order to achieve post-compromise security.

use crate::crypto::credential::Credential;
use crate::crypto::SignaturePublicKey;
use crate::framing::GroupID;
use crate::group::config::GroupConfig;

#[cfg(test)]
mod group_test;

pub mod config;
pub mod creation;
pub mod evolution;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Group {
    group_config: GroupConfig,
    credential: Credential,
    signature_key: SignaturePublicKey,
    group_id: GroupID,
}
