use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::cipher_suite::CipherSuite;
use crate::codec::codec_test::load_test_vector;
use crate::codec::write;
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;
use crate::framing::PROTOCOL_VERSION_MLS10;
use crate::key_schedule::{
    extract_psk_secret, extract_welcome_secret, GroupContext, PreSharedKeyID, Psk,
    SECRET_LABEL_CONFIRM, SECRET_LABEL_ENCRYPTION, SECRET_LABEL_EXPORTER, SECRET_LABEL_EXTERNAL,
    SECRET_LABEL_INIT, SECRET_LABEL_MEMBERSHIP, SECRET_LABEL_RESUMPTION, SECRET_LABEL_SENDER_DATA,
};

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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Exporter {
    #[serde(with = "hex")]
    label: Vec<u8>,
    #[serde(with = "hex")]
    context: Vec<u8>,
    length: u32,
    #[serde(with = "hex")]
    secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Epoch {
    // Chosen by the generator
    #[serde(with = "hex")]
    tree_hash: Vec<u8>,
    #[serde(with = "hex")]
    commit_secret: Vec<u8>,
    #[serde(with = "hex")]
    psk_secret: Vec<u8>,
    #[serde(with = "hex")]
    confirmed_transcript_hash: Vec<u8>,

    // Computed values
    #[serde(with = "hex")]
    group_context: Vec<u8>,
    #[serde(with = "hex")]
    joiner_secret: Vec<u8>,
    #[serde(with = "hex")]
    welcome_secret: Vec<u8>,
    #[serde(with = "hex")]
    init_secret: Vec<u8>,
    #[serde(with = "hex")]
    sender_data_secret: Vec<u8>,
    #[serde(with = "hex")]
    encryption_secret: Vec<u8>,
    #[serde(with = "hex")]
    exporter_secret: Vec<u8>,
    #[serde(with = "hex")]
    epoch_authenticator: Vec<u8>,
    #[serde(with = "hex")]
    external_secret: Vec<u8>,
    #[serde(with = "hex")]
    confirmation_key: Vec<u8>,
    #[serde(with = "hex")]
    membership_key: Vec<u8>,
    #[serde(with = "hex")]
    resumption_psk: Vec<u8>,

    #[serde(with = "hex")]
    external_pub: Vec<u8>,
    exporter: Exporter,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct KeyScheduleTest {
    cipher_suite: u16,
    #[serde(with = "hex")]
    group_id: Vec<u8>,
    #[serde(with = "hex")]
    initial_init_secret: Vec<u8>,
    epochs: Vec<Epoch>,
}

fn key_schedule_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &KeyScheduleTest,
) -> Result<()> {
    let mut init_secret: Bytes = tc.initial_init_secret.clone().into();
    for (i, epoch) in tc.epochs.iter().enumerate() {
        println!("epoch {}", i);

        let ctx = GroupContext {
            version: PROTOCOL_VERSION_MLS10,
            cipher_suite,
            group_id: tc.group_id.clone().into(),
            epoch: i as u64,
            tree_hash: epoch.tree_hash.clone().into(),
            confirmed_transcript_hash: epoch.confirmed_transcript_hash.clone().into(),
            extensions: vec![],
        };

        let raw_ctx = write(&ctx)?;
        assert_eq!(raw_ctx.as_ref(), &epoch.group_context);

        let joiner_secret =
            ctx.extract_joiner_secret(crypto_provider, &init_secret, &epoch.commit_secret)?;
        assert_eq!(joiner_secret.as_ref(), &epoch.joiner_secret);

        let welcome_secret = extract_welcome_secret(
            crypto_provider,
            cipher_suite,
            &joiner_secret,
            &epoch.psk_secret,
        )?;
        assert_eq!(welcome_secret.as_ref(), &epoch.welcome_secret);

        let epoch_secret =
            ctx.extract_epoch_secret(crypto_provider, &joiner_secret, &epoch.psk_secret)?;

        init_secret =
            crypto_provider.derive_secret(cipher_suite, &epoch_secret, SECRET_LABEL_INIT)?;
        assert_eq!(init_secret.as_ref(), &epoch.init_secret);

        let secrets: Vec<(&[u8], &[u8])> = vec![
            (SECRET_LABEL_SENDER_DATA, &epoch.sender_data_secret),
            (SECRET_LABEL_ENCRYPTION, &epoch.encryption_secret),
            (SECRET_LABEL_EXPORTER, &epoch.exporter_secret),
            (SECRET_LABEL_EXTERNAL, &epoch.external_secret),
            (SECRET_LABEL_CONFIRM, &epoch.confirmation_key),
            (SECRET_LABEL_MEMBERSHIP, &epoch.membership_key),
            (SECRET_LABEL_RESUMPTION, &epoch.resumption_psk),
        ];

        for secret in secrets {
            let sec = crypto_provider.derive_secret(cipher_suite, &epoch_secret, secret.0)?;
            assert_eq!(sec.as_ref(), secret.1);
        }

        // TODO: verify external pub, exporter secret
    }

    Ok(())
}

fn test_key_schedule_with_crypto_provider(
    tests: &[KeyScheduleTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_key_schedule {}:{}", cipher_suite, cipher_suite as u16);

        if crypto_provider.supports(cipher_suite).is_ok() {
            key_schedule_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_key_schedule() -> Result<()> {
    let tests: Vec<KeyScheduleTest> = load_test_vector("test-vectors/key-schedule.json")?;

    test_key_schedule_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    test_key_schedule_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}
/*
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
