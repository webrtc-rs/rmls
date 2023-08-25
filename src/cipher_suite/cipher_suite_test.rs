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
    #[serde(with = "hex")]
    out: Vec<u8>,
    #[serde(with = "hex")]
    value: Vec<u8>,
}

fn test_ref_hash(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &RefHashTest,
) -> Result<()> {
    let out = crypto_provider.ref_hash(cipher_suite, tc.label.as_bytes(), &tc.value)?;
    assert_eq!(out.as_ref(), &tc.out);
    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ExpandWithLabelTest {
    #[serde(with = "hex")]
    secret: Vec<u8>,
    label: String,
    #[serde(with = "hex")]
    context: Vec<u8>,
    length: u16,
    #[serde(with = "hex")]
    out: Vec<u8>,
}

fn test_expand_with_label(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &ExpandWithLabelTest,
) -> Result<()> {
    let out = crypto_provider.expand_with_label(
        cipher_suite,
        &tc.secret,
        tc.label.as_bytes(),
        &tc.context,
        tc.length,
    )?;
    assert_eq!(out.as_ref(), &tc.out);
    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DeriveSecretTest {
    label: String,
    #[serde(with = "hex")]
    out: Vec<u8>,
    #[serde(with = "hex")]
    secret: Vec<u8>,
}

fn test_derive_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &DeriveSecretTest,
) -> Result<()> {
    let out = crypto_provider.derive_secret(cipher_suite, &tc.secret, tc.label.as_bytes())?;
    assert_eq!(out.as_ref(), &tc.out,);
    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DeriveTreeSecretTest {
    #[serde(with = "hex")]
    secret: Vec<u8>,
    label: String,
    generation: u32,
    length: u16,
    #[serde(with = "hex")]
    out: Vec<u8>,
}

fn test_derive_tree_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &DeriveTreeSecretTest,
) -> Result<()> {
    let out = derive_tree_secret(
        crypto_provider,
        cipher_suite,
        &tc.secret,
        tc.label.as_bytes(),
        tc.generation,
        tc.length,
    )?;
    assert_eq!(out.as_ref(), &tc.out,);
    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SignWithLabelTest {
    #[serde(with = "hex")]
    r#priv: Vec<u8>,
    #[serde(with = "hex")]
    r#pub: Vec<u8>,
    #[serde(with = "hex")]
    content: Vec<u8>,
    label: String,
    #[serde(with = "hex")]
    signature: Vec<u8>,
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

    assert!(
        crypto_provider
            .verify_with_label(
                cipher_suite,
                &tc.r#pub,
                tc.label.as_bytes(),
                &tc.content,
                &tc.signature
            )
            .is_ok(),
        "reference signature did not verify"
    );

    let out = crypto_provider.sign_with_label(
        cipher_suite,
        &tc.r#priv,
        tc.label.as_bytes(),
        &tc.content,
    )?;

    assert!(
        crypto_provider
            .verify_with_label(
                cipher_suite,
                &tc.r#pub,
                tc.label.as_bytes(),
                &tc.content,
                &out
            )
            .is_ok(),
        "generated signature did not verify"
    );

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct EncryptWithLabelTest {
    #[serde(with = "hex")]
    r#priv: Vec<u8>,
    #[serde(with = "hex")]
    r#pub: Vec<u8>,
    label: String,
    #[serde(with = "hex")]
    context: Vec<u8>,
    #[serde(with = "hex")]
    plaintext: Vec<u8>,
    #[serde(with = "hex")]
    kem_output: Vec<u8>,
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
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

    let plaintext = crypto_provider.decrypt_with_label(
        cipher_suite,
        &tc.r#priv,
        tc.label.as_bytes(),
        &tc.context,
        &tc.kem_output,
        &tc.ciphertext,
    )?;
    assert_eq!(plaintext.as_ref(), &tc.plaintext);

    let (kem_output, ciphertext) = crypto_provider.encrypt_with_label(
        cipher_suite,
        &tc.r#pub,
        tc.label.as_bytes(),
        &tc.context,
        &tc.plaintext,
    )?;

    let plaintext = crypto_provider.decrypt_with_label(
        cipher_suite,
        &tc.r#priv,
        tc.label.as_bytes(),
        &tc.context,
        &kem_output,
        &ciphertext,
    )?;

    assert_eq!(plaintext.as_ref(), &tc.plaintext);

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
