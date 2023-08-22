use super::*;
use crate::codec::codec_test::*;
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;
use crate::tree::secret_tree::derive_tree_secret;

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct CryptoBasicsTest {
    cipher_suite: u16,
    ref_hash: RefHashTest,
    expand_with_label: ExpandWithLabelTest,
    derive_secret: DeriveSecretTest,
    derive_tree_secret: DeriveTreeSecretTest,
    sign_with_label: SignWithLabelTest,
    encrypt_with_label: EncryptWithLabelTest,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct RefHashTest {
    label: String,
    out: String,
    value: String,
}

fn test_ref_hash(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &RefHashTest,
) -> Result<()> {
    let label = tc.label.as_bytes();
    let value = hex_to_bytes(&tc.value);
    let expect_out = hex_to_bytes(&tc.out);
    let actual_out = crypto_provider.ref_hash(cipher_suite, label, &value)?;

    assert_eq!(
        actual_out.as_ref(),
        &expect_out,
        "got {:?}, want {:?}",
        actual_out.as_ref(),
        &expect_out,
    );

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ExpandWithLabelTest {
    secret: String,
    label: String,
    context: String,
    length: u16,
    out: String,
}

fn test_expand_with_label(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &ExpandWithLabelTest,
) -> Result<()> {
    let secret = hex_to_bytes(&tc.secret);
    let label = tc.label.as_bytes();
    let context = hex_to_bytes(&tc.context);
    let expect_out = hex_to_bytes(&tc.out);
    let actual_out =
        crypto_provider.expand_with_label(cipher_suite, &secret, &label, &context, tc.length)?;

    assert_eq!(
        actual_out.as_ref(),
        &expect_out,
        "got {:?}, want {:?}",
        actual_out.as_ref(),
        &expect_out,
    );

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DeriveSecretTest {
    label: String,
    out: String,
    secret: String,
}

fn test_derive_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &DeriveSecretTest,
) -> Result<()> {
    let label = tc.label.as_bytes();
    let secret = hex_to_bytes(&tc.secret);
    let expect_out = hex_to_bytes(&tc.out);
    let actual_out = crypto_provider.derive_secret(cipher_suite, &secret, label)?;
    assert_eq!(
        actual_out.as_ref(),
        &expect_out,
        "got {:?}, want {:?}",
        actual_out.as_ref(),
        &expect_out,
    );

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DeriveTreeSecretTest {
    secret: String,
    label: String,
    generation: u32,
    length: u16,
    out: String,
}

fn test_derive_tree_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &DeriveTreeSecretTest,
) -> Result<()> {
    let secret = hex_to_bytes(&tc.secret);
    let label = tc.label.as_bytes();
    let expect_out = hex_to_bytes(&tc.out);
    let actual_out = derive_tree_secret(
        crypto_provider,
        cipher_suite,
        &secret,
        label,
        tc.generation,
        tc.length,
    )?;

    assert_eq!(
        actual_out.as_ref(),
        &expect_out,
        "got {:?}, want {:?}",
        actual_out.as_ref(),
        &expect_out,
    );

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SignWithLabelTest {
    r#priv: String,
    r#pub: String,
    content: String,
    label: String,
    signature: String,
}

fn test_sign_with_label(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &SignWithLabelTest,
) -> Result<()> {
    if cipher_suite == CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        || cipher_suite == CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        || cipher_suite == CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
    {
        //TODO(yngrtc): implement ECDSA_P521_SHA512 and Ed448
        println!("\t test_sign_with_label {:?} skipped", cipher_suite);
        return Ok(());
    }
    let private = hex_to_bytes(&tc.r#priv);
    let public = hex_to_bytes(&tc.r#pub);
    let content = hex_to_bytes(&tc.content);
    let label = tc.label.as_bytes();
    let signature = hex_to_bytes(&tc.signature);

    assert!(
        crypto_provider
            .verify_with_label(cipher_suite, &public, label, &content, &signature)
            .is_ok(),
        "reference signature did not verify"
    );

    let sign_value = crypto_provider.sign_with_label(cipher_suite, &private, label, &content)?;

    assert!(
        crypto_provider
            .verify_with_label(cipher_suite, &public, label, &content, &sign_value)
            .is_ok(),
        "generated signature did not verify"
    );

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct EncryptWithLabelTest {
    r#priv: String,
    r#pub: String,
    label: String,
    context: String,
    plaintext: String,
    kem_output: String,
    ciphertext: String,
}

fn test_encrypt_with_label(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &EncryptWithLabelTest,
) -> Result<()> {
    if !(cipher_suite == CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        || cipher_suite == CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        || cipher_suite == CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
    {
        //TODO(yngrtc): implement other CipherSuite
        println!("\t test_encrypt_with_label {:?} skipped", cipher_suite);
        return Ok(());
    }

    let private_key = hex_to_bytes(&tc.r#priv);
    let public_key = hex_to_bytes(&tc.r#pub);
    let label = tc.label.as_bytes();
    let context = hex_to_bytes(&tc.context);
    let expect_kem_output = hex_to_bytes(&tc.kem_output);
    let expect_plaintext = hex_to_bytes(&tc.plaintext);
    let expect_ciphertext = hex_to_bytes(&tc.ciphertext);

    let actual_plaintext = crypto_provider.decrypt_with_label(
        cipher_suite,
        &private_key,
        label,
        &context,
        &expect_kem_output,
        &expect_ciphertext,
    )?;
    assert_eq!(
        &actual_plaintext, &expect_plaintext,
        "decrypting reference ciphertext: got {:?}, want {:?}",
        &actual_plaintext, &expect_plaintext
    );

    let (actual_kem_output, actual_ciphertext) = crypto_provider.encrypt_with_label(
        cipher_suite,
        &public_key,
        label,
        &context,
        &expect_plaintext,
    )?;

    let actual_plaintext = crypto_provider.decrypt_with_label(
        cipher_suite,
        &private_key,
        label,
        &context,
        &actual_kem_output,
        &actual_ciphertext,
    )?;

    assert_eq!(
        &actual_plaintext, &expect_plaintext,
        "decrypting reference ciphertext: got {:?}, want {:?}",
        &actual_plaintext, &expect_plaintext
    );

    Ok(())
}

fn test_crypto_basics_with_crypto_provider(
    tests: &[CryptoBasicsTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_crypto_basics {}", cipher_suite);

        test_ref_hash(crypto_provider, cipher_suite, &tc.ref_hash)?;

        test_expand_with_label(crypto_provider, cipher_suite, &tc.expand_with_label)?;

        test_derive_secret(crypto_provider, cipher_suite, &tc.derive_secret)?;

        test_derive_tree_secret(crypto_provider, cipher_suite, &tc.derive_tree_secret)?;

        test_sign_with_label(crypto_provider, cipher_suite, &tc.sign_with_label)?;

        test_encrypt_with_label(crypto_provider, cipher_suite, &tc.encrypt_with_label)?;
    }

    Ok(())
}

#[test]
fn test_crypto_basics() -> Result<()> {
    let tests: Vec<CryptoBasicsTest> = load_test_vector("test-vectors/crypto-basics.json")?;

    test_crypto_basics_with_crypto_provider(&tests, &RingCryptoProvider {})?;

    test_crypto_basics_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}
