use super::*;
use crate::codec::codec_test::*;
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;

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
/*
func testExpandWithLabel(t *testing.T, cs cipherSuite, tc *expandWithLabelTest) {
    out, err := cs.expandWithLabel([]byte(tc.secret), []byte(tc.label), []byte(tc.context), tc.length)
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal([]byte(tc.out), out) {
        t.Errorf("got %v, want %v", out, tc.out)
    }
}
*/
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DeriveSecretTest {
    label: String,
    out: String,
    secret: String,
}
/*
func testDeriveSecret(t *testing.T, cs cipherSuite, tc *deriveSecretTest) {
    out, err := cs.deriveSecret([]byte(tc.secret), []byte(tc.label))
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal([]byte(tc.out), out) {
        t.Errorf("got %v, want %v", out, tc.out)
    }
}
*/
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DeriveTreeSecretTest {
    secret: String,
    label: String,
    generation: u32,
    length: u16,
    out: String,
}
/*
func testDeriveTreeSecret(t *testing.T, cs cipherSuite, tc *deriveTreeSecretTest) {
    out, err := deriveTreeSecret(cs, []byte(tc.secret), []byte(tc.label), tc.generation, tc.length)
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal([]byte(tc.out), out) {
        t.Errorf("got %v, want %v", out, tc.out)
    }
}
*/
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
/*
func testEncryptWithLabel(t *testing.T, cs cipherSuite, tc *encryptWithLabelTest) {
    plaintext, err := cs.decryptWithLabel([]byte(tc.Priv), []byte(tc.Label), []byte(tc.Context), []byte(tc.KEMOutput), []byte(tc.Ciphertext))
    if err != nil {
        t.Fatalf("decryptWithLabel() = %v", err)
    }
    if !bytes.Equal([]byte(tc.Plaintext), plaintext) {
        t.Fatalf("decrypting reference ciphertext: got %v, want %v", plaintext, tc.Plaintext)
    }

    kemOutput, ciphertext, err := cs.encryptWithLabel([]byte(tc.Pub), []byte(tc.Label), []byte(tc.Context), []byte(tc.Plaintext))
    if err != nil {
        t.Fatalf("encryptWithLabel() = %v", err)
    }
    plaintext, err = cs.decryptWithLabel([]byte(tc.Priv), []byte(tc.Label), []byte(tc.Context), kemOutput, ciphertext)
    if err != nil {
        t.Fatalf("decryptWithLabel() = %v", err)
    }
    if !bytes.Equal([]byte(tc.Plaintext), plaintext) {
        t.Fatalf("decrypting reference ciphertext: got %v, want %v", plaintext, tc.Plaintext)
    }
}
*/

fn test_crypto_basics_with_crypto_provider(
    tests: &[CryptoBasicsTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("testing {}:\n\t {:?}", cipher_suite, tc);

        test_ref_hash(crypto_provider, cipher_suite, &tc.ref_hash)?;
        /*
        t.Run("expand_with_label", func(t *testing.T) {
            testExpandWithLabel(t, tc.CipherSuite, &tc.ExpandWithLabel)
        })
        t.Run("derive_secret", func(t *testing.T) {
            testDeriveSecret(t, tc.CipherSuite, &tc.DeriveSecret)
        })
        t.Run("derive_tree_secret", func(t *testing.T) {
            testDeriveTreeSecret(t, tc.CipherSuite, &tc.DeriveTreeSecret)
        })*/
        test_sign_with_label(crypto_provider, cipher_suite, &tc.sign_with_label)?;
        /*
        t.Run("encrypt_with_label", func(t *testing.T) {
            testEncryptWithLabel(t, tc.CipherSuite, &tc.EncryptWithLabel)
        })*/
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
