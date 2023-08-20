use super::*;
use crate::codec::codec_test::*;
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

fn test_ref_hash(cs: u16, tc: &RefHashTest) -> Result<()> {
    let cs: CipherSuite = cs.try_into()?;
    let label = tc.label.as_bytes();
    let value = hex_to_bytes(&tc.value);
    let expect_out = hex_to_bytes(&tc.out);
    let actual_out = cs.ref_hash(label, &value)?;

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
/*
func testSignWithLabel(t *testing.T, cs cipherSuite, tc *signWithLabelTest) {
    if !cs.verifyWithLabel([]byte(tc.Pub), []byte(tc.label), []byte(tc.Content), []byte(tc.Signature)) {
        t.Error("reference signature did not verify")
    }

    signValue, err := cs.signWithLabel([]byte(tc.Priv), []byte(tc.label), []byte(tc.Content))
    if err != nil {
        t.Fatalf("signWithLabel() = %v", err)
    }
    if !cs.verifyWithLabel([]byte(tc.Pub), []byte(tc.label), []byte(tc.Content), signValue) {
        t.Error("generated signature did not verify")
    }
}
*/
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

#[test]
fn test_crypto_basics() -> Result<()> {
    let tests: Vec<CryptoBasicsTest> = load_test_vector("test-vectors/crypto-basics.json")?;

    for tc in tests {
        test_ref_hash(tc.cipher_suite, &tc.ref_hash)?;
        /*
        t.Run("expand_with_label", func(t *testing.T) {
            testExpandWithLabel(t, tc.CipherSuite, &tc.ExpandWithLabel)
        })
        t.Run("derive_secret", func(t *testing.T) {
            testDeriveSecret(t, tc.CipherSuite, &tc.DeriveSecret)
        })
        t.Run("derive_tree_secret", func(t *testing.T) {
            testDeriveTreeSecret(t, tc.CipherSuite, &tc.DeriveTreeSecret)
        })
        t.Run("sign_with_label", func(t *testing.T) {
            testSignWithLabel(t, tc.CipherSuite, &tc.SignWithLabel)
        })
        t.Run("encrypt_with_label", func(t *testing.T) {
            testEncryptWithLabel(t, tc.CipherSuite, &tc.EncryptWithLabel)
        })*/
    }

    Ok(())
}
