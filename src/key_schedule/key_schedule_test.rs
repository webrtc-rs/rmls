use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;
use crate::codec::codec_test::load_test_vector;
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;
use crate::key_schedule::{extract_psk_secret, PreSharedKeyID, Psk};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct PSK {
    #[serde(with = "hex")]
    psk_id: Vec<u8>,
    #[serde(with = "hex")]
    psk: Vec<u8>,
    #[serde(with = "hex")]
    psk_nonce: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct PskSecretTest {
    cipher_suite: u16,
    psks: Vec<PSK>,
    #[serde(with = "hex")]
    psk_secret: Vec<u8>,
}

fn psk_secret_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &PskSecretTest,
) -> Result<()> {
    let mut psk_ids = vec![];
    let mut psks: Vec<Bytes> = vec![];

    for psk in &tc.psks {
        psk_ids.push(PreSharedKeyID {
            psk: Psk::External(psk.psk_id.clone().into()),
            psk_nonce: psk.psk_nonce.clone().into(),
        });
        psks.push(psk.psk.clone().into());
    }

    let psk_secret = extract_psk_secret(crypto_provider, cipher_suite, &psk_ids, &psks)?;

    assert_eq!(&psk_secret, &tc.psk_secret);

    Ok(())
}

fn test_psk_secret_with_crypto_provider(
    tests: &[PskSecretTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_psk_secret {}:{}", cipher_suite, cipher_suite as u16);

        if crypto_provider.supports(cipher_suite).is_ok() {
            psk_secret_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_psk_secret() -> Result<()> {
    let tests: Vec<PskSecretTest> = load_test_vector("test-vectors/psk_secret.json")?;

    test_psk_secret_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    test_psk_secret_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}
/*
type keyScheduleTest struct {
    CipherSuite cipherSuite `json:"cipher_suite"`

    GroupID           testBytes `json:"group_id"`
    InitialInitSecret testBytes `json:"initial_init_secret"`

    Epochs []struct {
        TreeHash                testBytes `json:"tree_hash"`
        CommitSecret            testBytes `json:"commit_secret"`
        PSKSecret               testBytes `json:"psk_secret"`
        ConfirmedTranscriptHash testBytes `json:"confirmed_transcript_hash"`

        GroupContext testBytes `json:"group_context"`

        JoinerSecret  testBytes `json:"joiner_secret"`
        WelcomeSecret testBytes `json:"welcome_secret"`
        InitSecret    testBytes `json:"init_secret"`

        SenderDataSecret   testBytes `json:"sender_data_secret"`
        EncryptionSecret   testBytes `json:"encryption_secret"`
        ExporterSecret     testBytes `json:"exporter_secret"`
        EpochAuthenticator testBytes `json:"epoch_authenticator"`
        ExternalSecret     testBytes `json:"external_secret"`
        ConfirmationKey    testBytes `json:"confirmation_key"`
        MembershipKey      testBytes `json:"membership_key"`
        ResumptionPSK      testBytes `json:"resumption_psk"`

        ExternalPub testBytes `json:"external_pub"`
        Exporter    struct {
            Label   string    `json:"label"`
            Context testBytes `json:"context"`
            Length  uint32    `json:"length"`
            Secret  testBytes `json:"secret"`
        } `json:"exporter"`
    } `json:"epochs"`
}

func testKeySchedule(t *testing.T, tc *keyScheduleTest) {
    initSecret := []byte(tc.InitialInitSecret)
    for i, epoch := range tc.Epochs {
        t.Logf("epoch %d", i)

        ctx := groupContext{
            version:                 protocolVersionMLS10,
            cipherSuite:             tc.CipherSuite,
            groupID:                 GroupID(tc.GroupID),
            epoch:                   uint64(i),
            treeHash:                []byte(epoch.TreeHash),
            confirmedTranscriptHash: []byte(epoch.ConfirmedTranscriptHash),
        }
        rawCtx, err := marshal(&ctx)
        if err != nil {
            t.Fatalf("marshal(groupContext) = %v", err)
        } else if !bytes.Equal(rawCtx, []byte(epoch.GroupContext)) {
            t.Errorf("marshal(groupContext) = %v, want %v", rawCtx, epoch.GroupContext)
        }

        joinerSecret, err := ctx.extractJoinerSecret(initSecret, []byte(epoch.CommitSecret))
        if err != nil {
            t.Errorf("extractJoinerSecret() = %v", err)
        } else if !bytes.Equal(joinerSecret, []byte(epoch.JoinerSecret)) {
            t.Errorf("extractJoinerSecret() = %v, want %v", joinerSecret, epoch.JoinerSecret)
        }

        welcomeSecret, err := extractWelcomeSecret(ctx.cipherSuite, joinerSecret, []byte(epoch.PSKSecret))
        if err != nil {
            t.Errorf("extractWelcomeSecret() = %v", err)
        } else if !bytes.Equal(welcomeSecret, []byte(epoch.WelcomeSecret)) {
            t.Errorf("extractWelcomeSecret() = %v, want %v", welcomeSecret, epoch.WelcomeSecret)
        }

        epochSecret, err := ctx.extractEpochSecret(joinerSecret, []byte(epoch.PSKSecret))
        if err != nil {
            t.Fatalf("extractEpochSecret() = %v", err)
        }

        initSecret, err = ctx.cipherSuite.deriveSecret(epochSecret, secretLabelInit)
        if err != nil {
            t.Errorf("deriveSecret(init) = %v", err)
        } else if !bytes.Equal(initSecret, []byte(epoch.InitSecret)) {
            t.Errorf("deriveSecret(init) = %v, want %v", initSecret, epoch.InitSecret)
        }

        secrets := []struct {
            label []byte
            want  testBytes
        }{
            {secretLabelSenderData, epoch.SenderDataSecret},
            {secretLabelEncryption, epoch.EncryptionSecret},
            {secretLabelExporter, epoch.ExporterSecret},
            {secretLabelExternal, epoch.ExternalSecret},
            {secretLabelConfirm, epoch.ConfirmationKey},
            {secretLabelMembership, epoch.MembershipKey},
            {secretLabelResumption, epoch.ResumptionPSK},
        }
        for _, secret := range secrets {
            sec, err := ctx.cipherSuite.deriveSecret(epochSecret, secret.label)
            if err != nil {
                t.Errorf("deriveSecret(%v) = %v", string(secret.label), err)
            } else if !bytes.Equal(sec, []byte(secret.want)) {
                t.Errorf("deriveSecret(%v) = %v, want %v", string(secret.label), sec, secret.want)
            }
        }

        // TODO: verify external pub, exporter secret
    }
}

func TestKeySchedule(t *testing.T) {
    var tests []keyScheduleTest
    loadTestVector(t, "testdata/key-schedule.json", &tests)

    for i, tc := range tests {
        t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
            testKeySchedule(t, &tc)
        })
    }
}

type transcriptHashesTest struct {
    CipherSuite cipherSuite `json:"cipher_suite"`

    ConfirmationKey             testBytes `json:"confirmation_key"`
    AuthenticatedContent        testBytes `json:"authenticated_content"`
    InterimTranscriptHashBefore testBytes `json:"interim_transcript_hash_before"`

    ConfirmedTranscriptHashAfter testBytes `json:"confirmed_transcript_hash_after"`
    InterimTranscriptHashAfter   testBytes `json:"interim_transcript_hash_after"`
}

func testTranscriptHashes(t *testing.T, tc *transcriptHashesTest) {
    cs := tc.CipherSuite

    var authContent authenticatedContent
    if err := unmarshal([]byte(tc.AuthenticatedContent), &authContent); err != nil {
        t.Fatalf("unmarshal() = %v", err)
    } else if authContent.content.contentType != contentTypeCommit {
        t.Fatalf("contentType = %v, want %v", authContent.content.contentType, contentTypeCommit)
    }

    if !authContent.auth.verifyConfirmationTag(cs, []byte(tc.ConfirmationKey), []byte(tc.ConfirmedTranscriptHashAfter)) {
        t.Errorf("verifyConfirmationTag() failed")
    }

    confirmedTranscriptHashAfter, err := authContent.confirmedTranscriptHashInput().hash(cs, []byte(tc.InterimTranscriptHashBefore))
    if err != nil {
        t.Fatalf("confirmedTranscriptHashInput.hash() = %v", err)
    } else if !bytes.Equal(confirmedTranscriptHashAfter, []byte(tc.ConfirmedTranscriptHashAfter)) {
        t.Errorf("confirmedTranscriptHashInput.hash() = %v, want %v", confirmedTranscriptHashAfter, tc.ConfirmedTranscriptHashAfter)
    }

    interimTranscriptHashAfter, err := nextInterimTranscriptHash(cs, confirmedTranscriptHashAfter, authContent.auth.confirmationTag)
    if err != nil {
        t.Fatalf("nextInterimTranscriptHash() = %v", err)
    } else if !bytes.Equal(interimTranscriptHashAfter, []byte(tc.InterimTranscriptHashAfter)) {
        t.Errorf("nextInterimTranscriptHash() = %v, want %v", interimTranscriptHashAfter, tc.InterimTranscriptHashAfter)
    }
}

func TestTranscriptHashes(t *testing.T) {
    var tests []transcriptHashesTest
    loadTestVector(t, "testdata/transcript-hashes.json", &tests)

    for i, tc := range tests {
        t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
            testTranscriptHashes(t, &tc)
        })
    }
}
*/
