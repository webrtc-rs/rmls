use serde::{Deserialize, Serialize};

use crate::framing::MLSMessage;
use crate::group::{info::*, proposal::*, Commit};
use crate::ratchet_tree::RatchetTree;
use crate::utilities::error::*;
use crate::utilities::serde::{serde_test::load_test_vector, *};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MessagesTest {
    #[serde(with = "hex")]
    mls_welcome: Vec<u8>,
    #[serde(with = "hex")]
    mls_group_info: Vec<u8>,
    #[serde(with = "hex")]
    mls_key_package: Vec<u8>,

    #[serde(with = "hex")]
    ratchet_tree: Vec<u8>,
    #[serde(with = "hex")]
    group_secrets: Vec<u8>,

    #[serde(with = "hex")]
    add_proposal: Vec<u8>,
    #[serde(with = "hex")]
    update_proposal: Vec<u8>,
    #[serde(with = "hex")]
    remove_proposal: Vec<u8>,
    #[serde(with = "hex")]
    pre_shared_key_proposal: Vec<u8>,
    #[serde(with = "hex")]
    re_init_proposal: Vec<u8>,
    #[serde(with = "hex")]
    external_init_proposal: Vec<u8>,
    #[serde(with = "hex")]
    group_context_extensions_proposal: Vec<u8>,

    #[serde(with = "hex")]
    commit: Vec<u8>,

    #[serde(with = "hex")]
    public_message_application: Vec<u8>,
    #[serde(with = "hex")]
    public_message_proposal: Vec<u8>,
    #[serde(with = "hex")]
    public_message_commit: Vec<u8>,
    #[serde(with = "hex")]
    private_message: Vec<u8>,
}

//fn message_test<T>()

fn messages_test(tc: MessagesTest) -> Result<()> {
    // Welcome
    let my_mls_welcome = MLSMessage::deserialize_exact(&tc.mls_welcome)?.serialize_detached()?;
    assert_eq!(&tc.mls_welcome, my_mls_welcome.as_ref());

    // (Verifiable)GroupInfo
    let my_mls_group_info =
        MLSMessage::deserialize_exact(&tc.mls_group_info)?.serialize_detached()?;
    assert_eq!(&tc.mls_group_info, my_mls_group_info.as_ref());

    // KeyPackage
    let my_key_package =
        MLSMessage::deserialize_exact(&tc.mls_key_package)?.serialize_detached()?;
    assert_eq!(&tc.mls_key_package, my_key_package.as_ref());

    // RatchetTree
    let my_ratchet_tree = RatchetTree::deserialize_exact(&tc.ratchet_tree)?.serialize_detached()?;
    assert_eq!(&tc.ratchet_tree, my_ratchet_tree.as_ref());

    // GroupSecrets
    let my_group_secrets =
        GroupSecrets::deserialize_exact(&tc.group_secrets)?.serialize_detached()?;
    assert_eq!(&tc.group_secrets, my_group_secrets.as_ref());

    // AddProposal
    let my_add_proposal = AddProposal::deserialize_exact(&tc.add_proposal)?.serialize_detached()?;
    assert_eq!(&tc.add_proposal, my_add_proposal.as_ref());

    //update_proposal: String,         /* serialized Update */
    // UpdateProposal
    let my_update_proposal =
        UpdateProposal::deserialize_exact(&tc.update_proposal)?.serialize_detached()?;
    assert_eq!(&tc.update_proposal, my_update_proposal.as_ref());

    //remove_proposal: String,         /* serialized Remove */
    // RemoveProposal
    let my_remove_proposal =
        RemoveProposal::deserialize_exact(&tc.remove_proposal)?.serialize_detached()?;
    assert_eq!(&tc.remove_proposal, my_remove_proposal.as_ref());

    // PreSharedKeyProposal
    let my_pre_shared_key_proposal =
        PreSharedKeyProposal::deserialize_exact(&tc.pre_shared_key_proposal)?
            .serialize_detached()?;
    assert_eq!(
        &tc.pre_shared_key_proposal,
        my_pre_shared_key_proposal.as_ref()
    );

    // Re-Init, External Init and App-Ack Proposals go here...

    // Commit
    let my_commit = Commit::deserialize_exact(&tc.commit)?.serialize_detached()?;
    assert_eq!(&tc.commit, my_commit.as_ref());

    // MlsPlaintextApplication
    let my_public_message_application =
        MLSMessage::deserialize_exact(&tc.public_message_application)?.serialize_detached()?;
    assert_eq!(
        &tc.public_message_application,
        my_public_message_application.as_ref()
    );

    // PublicMessage(Proposal)
    let my_public_message_proposal =
        MLSMessage::deserialize_exact(&tc.public_message_proposal)?.serialize_detached()?;
    assert_eq!(
        &tc.public_message_proposal,
        my_public_message_proposal.as_ref()
    );

    // PublicMessage(Commit)
    let my_public_message_commit =
        MLSMessage::deserialize_exact(&tc.public_message_commit)?.serialize_detached()?;
    assert_eq!(&tc.public_message_commit, my_public_message_commit.as_ref());

    // PrivateMessage
    let my_private_message =
        MLSMessage::deserialize_exact(&tc.private_message)?.serialize_detached()?;
    assert_eq!(&tc.private_message, my_private_message.as_ref());

    Ok(())
}

#[test]
fn test_messages() -> Result<()> {
    let tests: Vec<MessagesTest> = load_test_vector("test-vectors/messages.json")?;

    for tc in tests {
        messages_test(tc)?;
    }

    Ok(())
}
