use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[cfg(feature = "RingCryptoProvider")]
use crate::crypto::provider::ring::RingCryptoProvider;
#[cfg(feature = "RustCryptoProvider")]
use crate::crypto::provider::rust::RustCryptoProvider;
use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::error::*;
use crate::key::schedule::{
    extract_psk_secret, extract_welcome_secret, next_interim_transcript_hash, GroupContext,
    PreSharedKeyID, Psk, SECRET_LABEL_CONFIRM, SECRET_LABEL_ENCRYPTION, SECRET_LABEL_EXPORTER,
    SECRET_LABEL_EXTERNAL, SECRET_LABEL_INIT, SECRET_LABEL_MEMBERSHIP, SECRET_LABEL_RESUMPTION,
    SECRET_LABEL_SENDER_DATA,
};
use crate::message::framing::{AuthenticatedContent, Content, PROTOCOL_VERSION_MLS10};
use crate::serde::{serde_test::load_test_vector, serialize, Deserializer};

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

        if crypto_provider.supports(cipher_suite) {
            psk_secret_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_psk_secret() -> Result<()> {
    let tests: Vec<PskSecretTest> = load_test_vector("test-vectors/psk_secret.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_psk_secret_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
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

        let raw_ctx = serialize(&ctx)?;
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

        if crypto_provider.supports(cipher_suite) {
            key_schedule_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_key_schedule() -> Result<()> {
    let tests: Vec<KeyScheduleTest> = load_test_vector("test-vectors/key-schedule.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_key_schedule_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_key_schedule_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TranscriptHashesTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    pub confirmation_key: Vec<u8>,
    #[serde(with = "hex")]
    pub authenticated_content: Vec<u8>,
    #[serde(with = "hex")]
    pub interim_transcript_hash_before: Vec<u8>,

    #[serde(with = "hex")]
    pub confirmed_transcript_hash_after: Vec<u8>,
    #[serde(with = "hex")]
    pub interim_transcript_hash_after: Vec<u8>,
}

fn transcript_hashes_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TranscriptHashesTest,
) -> Result<()> {
    let mut buf = tc.authenticated_content.as_ref();
    let auth_content = AuthenticatedContent::deserialize(&mut buf)?;
    match auth_content.content.content {
        Content::Commit(_) => {}
        _ => assert!(
            false,
            "content type want Commit, but got {:?}",
            auth_content.content.content
        ),
    };

    assert!(auth_content.auth.verify_confirmation_tag(
        crypto_provider,
        cipher_suite,
        &tc.confirmation_key,
        &tc.confirmed_transcript_hash_after
    ));

    let confirmed_transcript_hash_after = auth_content.confirmed_transcript_hash_input().hash(
        crypto_provider,
        cipher_suite,
        &tc.interim_transcript_hash_before,
    )?;
    assert_eq!(
        confirmed_transcript_hash_after.as_ref(),
        &tc.confirmed_transcript_hash_after
    );

    let interim_transcript_hash_after = next_interim_transcript_hash(
        crypto_provider,
        cipher_suite,
        &confirmed_transcript_hash_after,
        &auth_content.auth.confirmation_tag,
    )?;
    assert_eq!(
        interim_transcript_hash_after.as_ref(),
        &tc.interim_transcript_hash_after
    );

    Ok(())
}

fn test_transcript_hashes_with_crypto_provider(
    tests: &[TranscriptHashesTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!(
            "test_transcript_hashes {}:{}",
            cipher_suite, cipher_suite as u16
        );

        if crypto_provider.supports(cipher_suite) {
            transcript_hashes_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_transcript_hashes() -> Result<()> {
    let tests: Vec<TranscriptHashesTest> = load_test_vector("test-vectors/transcript-hashes.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_transcript_hashes_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_transcript_hashes_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}
