/*use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;
use crate::codec::codec_test::load_test_vector;
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct WelcomeTest {
    cipher_suite: u16,
    #[serde(with = "hex::serde")]
    init_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    signer_pub: Vec<u8>,
    #[serde(with = "hex::serde")]
    key_package: Vec<u8>,
    #[serde(with = "hex::serde")]
    welcome: Vec<u8>,
}

fn welcome_test( crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite, tc:&WelcomeTest) -> Result<()> {
    let mut welcomeMsg = mlsMessage
    if err := welcomeMsg.unmarshal(tc.Welcome.ByteString()); err != nil {
        t.Fatalf("unmarshal(welcome) = %v", err)
    } else if welcomeMsg.wireFormat != wireFormatMLSWelcome {
        t.Fatalf("wireFormat = %v, want %v", welcomeMsg.wireFormat, wireFormatMLSWelcome)
    }
    welcome := welcomeMsg.welcome

    var keyPackageMsg mlsMessage
    if err := keyPackageMsg.unmarshal(tc.KeyPackage.ByteString()); err != nil {
        t.Fatalf("unmarshal(keyPackage) = %v", err)
    } else if keyPackageMsg.wireFormat != wireFormatMLSKeyPackage {
        t.Fatalf("wireFormat = %v, want %v", keyPackageMsg.wireFormat, wireFormatMLSKeyPackage)
    }
    keyPackage := keyPackageMsg.keyPackage

    keyPackageRef, err := keyPackage.generateRef()
    if err != nil {
        t.Fatalf("keyPackage.generateRef() = %v", err)
    }

    groupSecrets, err := welcome.decryptGroupSecrets(keyPackageRef, []byte(tc.InitPriv))
    if err != nil {
        t.Fatalf("welcome.decryptGroupSecrets() = %v", err)
    }

    groupInfo, err := welcome.decryptGroupInfo(groupSecrets.joinerSecret, nil)
    if err != nil {
        t.Fatalf("welcome.decryptGroupInfo() = %v", err)
    }
    if !groupInfo.verifySignature(signaturePublicKey(tc.SignerPub)) {
        t.Errorf("groupInfo.verifySignature() failed")
    }
    if !groupInfo.verifyConfirmationTag(groupSecrets.joinerSecret, nil) {
        t.Errorf("groupInfo.verifyConfirmationTag() failed")
    }

    Ok(())
}

fn test_welcome_with_crypto_provider(
    tests: &[WelcomeTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!(
            "test_welcome {}:{}",
            cipher_suite, cipher_suite as u16
        );

        if crypto_provider.supports(cipher_suite).is_ok() {
            welcome_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_welcome() -> Result<()> {
    let tests: Vec<WelcomeTest>= load_test_vector( "test-vectors/welcome.json")?;

    test_welcome_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    //TODO:test_welcome_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

type messageProtectionTest struct {
    CipherSuite cipherSuite `json:"cipher_suite"`

    GroupID                 testBytes `json:"group_id"`
    Epoch                   uint64    `json:"epoch"`
    TreeHash                testBytes `json:"tree_hash"`
    ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

    SignaturePriv testBytes `json:"signature_priv"`
    SignaturePub  testBytes `json:"signature_pub"`

    EncryptionSecret testBytes `json:"encryption_secret"`
    SenderDataSecret testBytes `json:"sender_data_secret"`
    MembershipKey    testBytes `json:"membership_key"`

    Proposal     testBytes `json:"proposal"`
    ProposalPub  testBytes `json:"proposal_pub"`
    ProposalPriv testBytes `json:"proposal_priv"`

    Commit     testBytes `json:"commit"`
    CommitPub  testBytes `json:"commit_pub"`
    CommitPriv testBytes `json:"commit_priv"`

    Application     testBytes `json:"application"`
    ApplicationPriv testBytes `json:"application_priv"`
}

func testMessageProtectionPub(t *testing.T, tc *messageProtectionTest, ctx *groupContext, wantRaw, rawPub []byte) {
    var msg mlsMessage
    if err := unmarshal(rawPub, &msg); err != nil {
        t.Fatalf("unmarshal() = %v", err)
    } else if msg.wireFormat != wireFormatMLSPublicMessage {
        t.Fatalf("unmarshal(): wireFormat = %v, want %v", msg.wireFormat, wireFormatMLSPublicMessage)
    }
    pubMsg := msg.publicMessage

    verifyPublicMessage(t, tc, ctx, pubMsg, wantRaw)

    pubMsg, err := signPublicMessage(tc.CipherSuite, []byte(tc.SignaturePriv), &pubMsg.content, ctx)
    if err != nil {
        t.Errorf("signPublicMessage() = %v", err)
    }
    if err := pubMsg.signMembershipTag(tc.CipherSuite, []byte(tc.MembershipKey), ctx); err != nil {
        t.Errorf("signMembershipTag() = %v", err)
    }
    verifyPublicMessage(t, tc, ctx, pubMsg, wantRaw)
}

func verifyPublicMessage(t *testing.T, tc *messageProtectionTest, ctx *groupContext, pubMsg *publicMessage, wantRaw []byte) {
    authContent := pubMsg.authenticatedContent()
    if !authContent.verifySignature(tc.CipherSuite, []byte(tc.SignaturePub), ctx) {
        t.Errorf("verifySignature() failed")
    }
    if !pubMsg.verifyMembershipTag(tc.CipherSuite, []byte(tc.MembershipKey), ctx) {
        t.Errorf("verifyMembershipTag() failed")
    }

    var (
        raw []byte
        err error
    )
    switch pubMsg.content.contentType {
    case contentTypeApplication:
        raw = pubMsg.content.applicationData
    case contentTypeProposal:
        raw, err = marshal(pubMsg.content.proposal)
    case contentTypeCommit:
        raw, err = marshal(pubMsg.content.commit)
    default:
        t.Errorf("unexpected content type %v", pubMsg.content.contentType)
    }
    if err != nil {
        t.Errorf("marshal() = %v", err)
    } else if !bytes.Equal(raw, wantRaw) {
        t.Errorf("marshal() = %v, want %v", raw, wantRaw)
    }
}

func testMessageProtectionPriv(t *testing.T, tc *messageProtectionTest, ctx *groupContext, wantRaw, rawPriv []byte) {
    var msg mlsMessage
    if err := unmarshal(rawPriv, &msg); err != nil {
        t.Fatalf("unmarshal() = %v", err)
    } else if msg.wireFormat != wireFormatMLSPrivateMessage {
        t.Fatalf("unmarshal(): wireFormat = %v, want %v", msg.wireFormat, wireFormatMLSPrivateMessage)
    }
    privMsg := msg.privateMessage

    tree, err := deriveSecretTree(tc.CipherSuite, numLeaves(2), []byte(tc.EncryptionSecret))
    if err != nil {
        t.Fatalf("deriveSecretTree() = %v", err)
    }

    label := ratchetLabelFromContentType(privMsg.contentType)
    li := leafIndex(1)
    secret, err := tree.deriveRatchetRoot(tc.CipherSuite, li.nodeIndex(), label)
    if err != nil {
        t.Fatalf("deriveRatchetRoot() = %v", err)
    }

    content := decryptPrivateMessage(t, tc, ctx, secret, privMsg, wantRaw)

    senderData, err := newSenderData(li, 0) // TODO: set generation > 0
    if err != nil {
        t.Fatalf("newSenderData() = %v", err)
    }
    framedContent := framedContent{
        groupID: GroupID(tc.GroupID),
        epoch:   tc.Epoch,
        sender: sender{
            senderType: senderTypeMember,
            leafIndex:  li,
        },
        contentType:     privMsg.contentType,
        applicationData: content.applicationData,
        proposal:        content.proposal,
        commit:          content.commit,
    }
    privMsg, err = encryptPrivateMessage(tc.CipherSuite, []byte(tc.SignaturePriv), secret, []byte(tc.SenderDataSecret), &framedContent, senderData, ctx)
    if err != nil {
        t.Fatalf("encryptPrivateMessage() = %v", err)
    }
    decryptPrivateMessage(t, tc, ctx, secret, privMsg, wantRaw)
}

func decryptPrivateMessage(t *testing.T, tc *messageProtectionTest, ctx *groupContext, secret ratchetSecret, privMsg *privateMessage, wantRaw []byte) *privateMessageContent {
    senderData, err := privMsg.decryptSenderData(tc.CipherSuite, []byte(tc.SenderDataSecret))
    if err != nil {
        t.Fatalf("decryptSenderData() = %v", err)
    }

    for secret.generation != senderData.generation {
        secret, err = secret.deriveNext(tc.CipherSuite)
        if err != nil {
            t.Fatalf("deriveNext() = %v", err)
        }
    }

    content, err := privMsg.decryptContent(tc.CipherSuite, secret, senderData.reuseGuard)
    if err != nil {
        t.Fatalf("decryptContent() = %v", err)
    }

    authContent := privMsg.authenticatedContent(senderData, content)
    if !authContent.verifySignature(tc.CipherSuite, []byte(tc.SignaturePub), ctx) {
        t.Errorf("verifySignature() failed")
    }

    var raw []byte
    switch privMsg.contentType {
    case contentTypeApplication:
        raw = content.applicationData
    case contentTypeProposal:
        raw, err = marshal(content.proposal)
    case contentTypeCommit:
        raw, err = marshal(content.commit)
    default:
        t.Errorf("unexpected content type %v", privMsg.contentType)
    }
    if err != nil {
        t.Errorf("marshal() = %v", err)
    } else if !bytes.Equal(raw, wantRaw) {
        t.Errorf("marshal() = %v, want %v", raw, wantRaw)
    }

    return content
}

func testMessageProtection(t *testing.T, tc *messageProtectionTest) {
    ctx := groupContext{
        version:                 protocolVersionMLS10,
        cipherSuite:             tc.CipherSuite,
        groupID:                 GroupID(tc.GroupID),
        epoch:                   tc.Epoch,
        treeHash:                []byte(tc.TreeHash),
        confirmedTranscriptHash: []byte(tc.ConfirmedTranscriptHash),
    }

    wireFormats := []struct {
        name           string
        raw, pub, priv testBytes
    }{
        {"proposal", tc.Proposal, tc.ProposalPub, tc.ProposalPriv},
        {"commit", tc.Commit, tc.CommitPub, tc.CommitPriv},
        {"application", tc.Application, nil, tc.ApplicationPriv},
    }
    for _, wireFormat := range wireFormats {
        t.Run(wireFormat.name, func(t *testing.T) {
            raw := []byte(wireFormat.raw)
            pub := []byte(wireFormat.pub)
            priv := []byte(wireFormat.priv)
            if wireFormat.pub != nil {
                t.Run("pub", func(t *testing.T) {
                    testMessageProtectionPub(t, tc, &ctx, raw, pub)
                })
            }
            t.Run("priv", func(t *testing.T) {
                testMessageProtectionPriv(t, tc, &ctx, raw, priv)
            })
        })
    }
}

func TestMessageProtection(t *testing.T) {
    var tests []messageProtectionTest
    loadTestVector(t, "testdata/message-protection.json", &tests)

    for i, tc := range tests {
        t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
            testMessageProtection(t, &tc)
        })
    }
}
 */
