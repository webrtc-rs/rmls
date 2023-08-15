use crate::codec::{Reader, Writer};
use crate::error::*;
use bytes::{Buf, BufMut};

// http://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct ProposalType(pub(crate) u16);

pub(crate) const PROPOSAL_TYPE_ADD: ProposalType = ProposalType(0x0001);
pub(crate) const PROPOSAL_TYPE_UPDATE: ProposalType = ProposalType(0x0002);
pub(crate) const PROPOSAL_TYPE_REMOVE: ProposalType = ProposalType(0x0003);
pub(crate) const PROPOSAL_TYPE_PSK: ProposalType = ProposalType(0x0004);
pub(crate) const PROPOSAL_TYPE_REINIT: ProposalType = ProposalType(0x0005);
pub(crate) const PROPOSAL_TYPE_EXTERNAL_INIT: ProposalType = ProposalType(0x0006);
pub(crate) const PROPOSAL_TYPE_GROUP_CONTEXT_EXTENSIONS: ProposalType = ProposalType(0x0007);

impl Reader for ProposalType {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        self.0 = buf.get_u16();

        match *self {
            PROPOSAL_TYPE_ADD
            | PROPOSAL_TYPE_UPDATE
            | PROPOSAL_TYPE_REMOVE
            | PROPOSAL_TYPE_PSK
            | PROPOSAL_TYPE_REINIT
            | PROPOSAL_TYPE_EXTERNAL_INIT
            | PROPOSAL_TYPE_GROUP_CONTEXT_EXTENSIONS => Ok(()),
            _ => Err(Error::InvalidProposalType(self.0)),
        }
    }
}

impl Writer for ProposalType {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.0);
        Ok(())
    }
}
