use crate::cipher_suite::CipherSuite;
use crate::framing::{GroupID, ProtocolVersion};
use crate::tree::Extension;

use bytes::Bytes;

pub(crate) struct GroupContext {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) group_id: GroupID,
    pub(crate) epoch: u64,
    pub(crate) tree_hash: Bytes,
    pub(crate) confirmed_transcript_hash: Bytes,
    pub(crate) extensions: Vec<Extension>,
}
