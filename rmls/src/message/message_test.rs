use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[cfg(feature = "RingCryptoProvider")]
use crate::crypto::provider::RingCryptoProvider;
#[cfg(feature = "RustCryptoProvider")]
use crate::crypto::provider::RustCryptoProvider;
use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::error::*;
use crate::key::schedule::GroupContext;
use crate::message::{
    framing::{
        encrypt_private_message, sign_public_message, Content, FramedContent, PrivateMessage,
        PrivateMessageContent, PublicMessage, Sender, SenderData, WireFormat,
        PROTOCOL_VERSION_MLS10,
    },
    group_info::*,
    proposal::*,
    Commit, Message, WireFormatMessage,
};
use crate::serde::{serde_test::load_test_vector, *};
use crate::tree::{math::*, ratchet::RatchetTree, secret::*};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct WelcomeTest {
    cipher_suite: u16,
    #[serde(with = "hex")]
    init_priv: Vec<u8>,
    #[serde(with = "hex")]
    signer_pub: Vec<u8>,
    #[serde(with = "hex")]
    key_package: Vec<u8>,
    #[serde(with = "hex")]
    welcome: Vec<u8>,
}

fn welcome_test(
    crypto_provider: &impl CryptoProvider,
    _cipher_suite: CipherSuite,
    tc: &WelcomeTest,
) -> Result<()> {
    let welcome_msg = Message::deserialize_exact(&tc.welcome)?;
    assert_eq!(welcome_msg.wire_format, WireFormat::Welcome);
    let welcome = if let WireFormatMessage::Welcome(welcome) = welcome_msg.message {
        welcome
    } else {
        return Err(Error::Other("unreachable".to_string()));
    };

    let key_package_msg = Message::deserialize_exact(&tc.key_package)?;
    assert_eq!(key_package_msg.wire_format, WireFormat::KeyPackage);
    let key_package = if let WireFormatMessage::KeyPackage(key_package) = key_package_msg.message {
        key_package
    } else {
        return Err(Error::Other("unreachable".to_string()));
    };

    let key_package_ref = key_package.generate_ref(crypto_provider)?;

    let group_secrets =
        welcome.decrypt_group_secrets(crypto_provider, &key_package_ref, &tc.init_priv)?;

    let group_info =
        welcome.decrypt_group_info(crypto_provider, &group_secrets.joiner_secret, &[])?;

    assert!(group_info
        .verify_signature(crypto_provider, &tc.signer_pub)
        .is_ok());

    assert!(group_info
        .verify_confirmation_tag(crypto_provider, &group_secrets.joiner_secret, &[])
        .is_ok());

    Ok(())
}

fn test_welcome_with_crypto_provider(
    tests: &[WelcomeTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_welcome {}:{}", cipher_suite, cipher_suite as u16);

        if crypto_provider.supports(cipher_suite) {
            welcome_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_welcome() -> Result<()> {
    let tests: Vec<WelcomeTest> = load_test_vector("test-vectors/welcome.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_welcome_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_welcome_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct MessageProtectionTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    group_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex")]
    tree_hash: Vec<u8>,
    #[serde(with = "hex")]
    confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex")]
    signature_priv: Vec<u8>,
    #[serde(with = "hex")]
    signature_pub: Vec<u8>,

    #[serde(with = "hex")]
    encryption_secret: Vec<u8>,
    #[serde(with = "hex")]
    sender_data_secret: Vec<u8>,
    #[serde(with = "hex")]
    membership_key: Vec<u8>,

    #[serde(with = "hex")]
    proposal: Vec<u8>,
    #[serde(with = "hex")]
    proposal_pub: Vec<u8>,
    #[serde(with = "hex")]
    proposal_priv: Vec<u8>,

    #[serde(with = "hex")]
    commit: Vec<u8>,
    #[serde(with = "hex")]
    commit_pub: Vec<u8>,
    #[serde(with = "hex")]
    commit_priv: Vec<u8>,

    #[serde(with = "hex")]
    application: Vec<u8>,
    #[serde(with = "hex")]
    application_priv: Vec<u8>,
}

fn test_message_protection_pub(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    want_raw: &[u8],
    raw_pub: &[u8],
) -> Result<()> {
    let msg = Message::deserialize_exact(raw_pub)?;
    assert_eq!(msg.wire_format, WireFormat::PublicMessage);
    let pub_msg = if let WireFormatMessage::PublicMessage(pub_msg) = msg.message {
        pub_msg
    } else {
        return Err(Error::Other("unreachable".to_string()));
    };

    verify_public_message(crypto_provider, cipher_suite, tc, ctx, &pub_msg, want_raw)?;

    let mut pub_msg = sign_public_message(
        crypto_provider,
        cipher_suite,
        &tc.signature_priv,
        &pub_msg.content,
        ctx,
    )?;

    pub_msg.sign_membership_tag(crypto_provider, cipher_suite, &tc.membership_key, ctx)?;

    verify_public_message(crypto_provider, cipher_suite, tc, ctx, &pub_msg, want_raw)
}

fn verify_public_message(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    pub_msg: &PublicMessage,
    want_raw: &[u8],
) -> Result<()> {
    let auth_content = pub_msg.authenticated_content();
    assert!(auth_content
        .verify_signature(crypto_provider, cipher_suite, &tc.signature_pub, ctx)
        .is_ok());
    assert!(pub_msg.verify_membership_tag(crypto_provider, cipher_suite, &tc.membership_key, ctx));

    let raw = match &pub_msg.content.content {
        Content::Application(application) => application.clone(),
        Content::Proposal(proposal) => proposal.serialize_detached()?,
        Content::Commit(commit) => commit.serialize_detached()?,
    };
    assert_eq!(raw.as_ref(), want_raw);

    Ok(())
}

fn test_message_protection_priv(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    want_raw: &[u8],
    raw_priv: &[u8],
) -> Result<()> {
    let msg = Message::deserialize_exact(raw_priv)?;
    assert_eq!(msg.wire_format, WireFormat::PrivateMessage);
    let priv_msg = if let WireFormatMessage::PrivateMessage(priv_msg) = msg.message {
        priv_msg
    } else {
        return Err(Error::Other("unreachable".to_string()));
    };

    let tree = derive_secret_tree(
        crypto_provider,
        cipher_suite,
        NumLeaves(2),
        &tc.encryption_secret,
    )?;

    let label = ratchet_label_from_content_type(priv_msg.content_type)?;
    let li = LeafIndex(1);
    let secret = tree.derive_ratchet_root(crypto_provider, cipher_suite, li.node_index(), label)?;

    let content = decrypt_private_message(
        crypto_provider,
        cipher_suite,
        tc,
        ctx,
        secret.clone(),
        &priv_msg,
        want_raw,
    )?;

    // TODO: set generation > 0
    let sender_data = SenderData::new(li, 0);
    let framed_content = FramedContent {
        group_id: tc.group_id.clone().into(),
        epoch: tc.epoch,
        sender: Sender::Member(li),
        authenticated_data: Bytes::new(),
        content: content.content.clone(),
    };

    let priv_msg = encrypt_private_message(
        crypto_provider,
        cipher_suite,
        &tc.signature_priv,
        &secret,
        &tc.sender_data_secret,
        &framed_content,
        &sender_data,
        ctx,
    )?;

    decrypt_private_message(
        crypto_provider,
        cipher_suite,
        tc,
        ctx,
        secret.clone(),
        &priv_msg,
        want_raw,
    )?;

    Ok(())
}

fn decrypt_private_message(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    mut secret: RatchetSecret,
    priv_msg: &PrivateMessage,
    want_raw: &[u8],
) -> Result<PrivateMessageContent> {
    let sender_data =
        priv_msg.decrypt_sender_data(crypto_provider, cipher_suite, &tc.sender_data_secret)?;

    while secret.generation != sender_data.generation {
        secret = secret.derive_next(crypto_provider, cipher_suite)?;
    }

    let content = priv_msg.decrypt_content(
        crypto_provider,
        cipher_suite,
        &secret,
        &sender_data.reuse_guard,
    )?;

    let auth_content = priv_msg.authenticated_content(&sender_data, &content);
    assert!(auth_content
        .verify_signature(crypto_provider, cipher_suite, &tc.signature_pub, ctx)
        .is_ok());

    let raw = match &content.content {
        Content::Application(application) => application.clone(),
        Content::Proposal(proposal) => proposal.serialize_detached()?,
        Content::Commit(commit) => commit.serialize_detached()?,
    };
    assert_eq!(raw.as_ref(), want_raw);

    Ok(content)
}

fn message_protection_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
) -> Result<()> {
    let ctx = GroupContext {
        version: PROTOCOL_VERSION_MLS10,
        cipher_suite,
        group_id: tc.group_id.clone().into(),
        epoch: tc.epoch,
        tree_hash: tc.tree_hash.clone().into(),
        confirmed_transcript_hash: tc.confirmed_transcript_hash.clone().into(),
        extensions: vec![],
    };

    let wire_formats = vec![
        (
            "proposal",
            tc.proposal.clone(),
            tc.proposal_pub.clone(),
            tc.proposal_priv.clone(),
        ),
        (
            "commit",
            tc.commit.clone(),
            tc.commit_pub.clone(),
            tc.commit_priv.clone(),
        ),
        (
            "application",
            tc.application.clone(),
            vec![],
            tc.application_priv.clone(),
        ),
    ];
    for wf in wire_formats {
        println!("testing {}", wf.0);
        if !wf.2.is_empty() {
            test_message_protection_pub(crypto_provider, cipher_suite, tc, &ctx, &wf.1, &wf.2)?;
        }
        test_message_protection_priv(crypto_provider, cipher_suite, tc, &ctx, &wf.1, &wf.3)?;
    }

    Ok(())
}

fn test_message_protection_with_crypto_provider(
    tests: &[MessageProtectionTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!(
            "test_message_protection {}:{}",
            cipher_suite, cipher_suite as u16
        );

        if crypto_provider.supports(cipher_suite) {
            message_protection_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_message_protection() -> Result<()> {
    let tests: Vec<MessageProtectionTest> =
        load_test_vector("test-vectors/message-protection.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_message_protection_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_message_protection_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

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
    let my_mls_welcome = Message::deserialize_exact(&tc.mls_welcome)?.serialize_detached()?;
    assert_eq!(&tc.mls_welcome, my_mls_welcome.as_ref());

    // (Verifiable)GroupInfo
    let my_mls_group_info = Message::deserialize_exact(&tc.mls_group_info)?.serialize_detached()?;
    assert_eq!(&tc.mls_group_info, my_mls_group_info.as_ref());

    // KeyPackage
    let my_key_package = Message::deserialize_exact(&tc.mls_key_package)?.serialize_detached()?;
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
        Message::deserialize_exact(&tc.public_message_application)?.serialize_detached()?;
    assert_eq!(
        &tc.public_message_application,
        my_public_message_application.as_ref()
    );

    // PublicMessage(Proposal)
    let my_public_message_proposal =
        Message::deserialize_exact(&tc.public_message_proposal)?.serialize_detached()?;
    assert_eq!(
        &tc.public_message_proposal,
        my_public_message_proposal.as_ref()
    );

    // PublicMessage(Commit)
    let my_public_message_commit =
        Message::deserialize_exact(&tc.public_message_commit)?.serialize_detached()?;
    assert_eq!(&tc.public_message_commit, my_public_message_commit.as_ref());

    // PrivateMessage
    let my_private_message =
        Message::deserialize_exact(&tc.private_message)?.serialize_detached()?;
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
