use super::*;
use crate::codec::codec_test::{hex_to_bytes, load_test_vector};
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SenderData {
    sender_data_secret: String,
    ciphertext: String,
    key: String,
    nonce: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct Leaf {
    generation: u32,
    handshake_key: String,
    handshake_nonce: String,
    application_key: String,
    application_nonce: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SecretTreeTest {
    cipher_suite: u16,
    sender_data: SenderData,
    encryption_secret: String,
    leaves: Vec<Vec<Leaf>>,
}

fn secret_tree_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &SecretTreeTest,
) -> Result<()> {
    let sender_data_secret = hex_to_bytes(&tc.sender_data.sender_data_secret);
    let ciphertext = hex_to_bytes(&tc.sender_data.ciphertext);
    let encryption_secret = hex_to_bytes(&tc.encryption_secret);
    let expect_key = hex_to_bytes(&tc.sender_data.key);
    let expect_nonce = hex_to_bytes(&tc.sender_data.nonce);

    let key = expand_sender_data_key(
        crypto_provider,
        cipher_suite,
        &sender_data_secret,
        &ciphertext,
    )?;
    assert_eq!(
        &key, &expect_key,
        "expand_sender_data_key() = {:?}, want {:?}",
        key, expect_key
    );

    let nonce = expand_sender_data_nonce(
        crypto_provider,
        cipher_suite,
        &sender_data_secret,
        &ciphertext,
    )?;
    assert_eq!(
        &nonce, &expect_nonce,
        "expand_sender_data_nonce() = {:?}, want {:?}",
        nonce, expect_nonce
    );

    let tree = derive_secret_tree(
        crypto_provider,
        cipher_suite,
        NumLeaves(tc.leaves.len() as u32),
        &encryption_secret,
    )?;

    for (i, gens) in tc.leaves.iter().enumerate() {
        let li = LeafIndex(i as u32);
        test_ratchet_secret(
            crypto_provider,
            cipher_suite,
            &tree,
            li,
            RatchetLabel::Handshake,
            gens,
        )?;

        test_ratchet_secret(
            crypto_provider,
            cipher_suite,
            &tree,
            li,
            RatchetLabel::Application,
            gens,
        )?;
    }

    Ok(())
}

fn test_ratchet_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tree: &SecretTree,
    li: LeafIndex,
    label: RatchetLabel,
    gens: &[Leaf],
) -> Result<()> {
    let mut secret =
        tree.derive_ratchet_root(crypto_provider, cipher_suite, li.node_index(), label)?;

    for gen in gens {
        assert!(!(gen.generation < secret.generation));

        while secret.generation != gen.generation {
            secret = secret.derive_next(crypto_provider, cipher_suite)?;
        }

        let (want_key, want_nonce) = match label {
            RatchetLabel::Handshake => (
                hex_to_bytes(&gen.handshake_key),
                hex_to_bytes(&gen.handshake_nonce),
            ),
            RatchetLabel::Application => (
                hex_to_bytes(&gen.application_key),
                hex_to_bytes(&gen.application_nonce),
            ),
        };

        let key = secret.derive_key(crypto_provider, cipher_suite)?;
        assert_eq!(
            &key, &want_key,
            "deriveKey() = {:?}, want {:?}",
            key, want_key
        );

        let nonce = secret.derive_nonce(crypto_provider, cipher_suite)?;
        assert_eq!(
            &nonce, &want_nonce,
            "deriveNonce() = {:?}, want {:?}",
            nonce, want_nonce
        );
    }

    Ok(())
}

fn test_secret_tree_with_crypto_provider(
    tests: &[SecretTreeTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_secret_tree {}", cipher_suite);

        secret_tree_test(crypto_provider, cipher_suite, tc)?;
    }

    Ok(())
}

#[test]
fn test_secret_tree() -> Result<()> {
    let tests: Vec<SecretTreeTest> = load_test_vector("test-vectors/secret-tree.json")?;

    test_secret_tree_with_crypto_provider(&tests, &RingCryptoProvider {})?;

    test_secret_tree_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}
