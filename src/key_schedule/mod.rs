use crate::cipher_suite::CipherSuite;
use crate::framing::{GroupID, ProtocolVersion};
use crate::tree::Extension;

use bytes::Bytes;

pub(crate) struct GroupContext {
    version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) group_id: GroupID,
    epoch: u64,
    pub(crate) tree_hash: Bytes,
    confirmed_transcript_hash: Bytes,
    extensions: Vec<Extension>,
}