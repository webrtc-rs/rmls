use bytes::Bytes;
use ed25519_dalek::{Signer, Verifier};

use crate::error::*;

pub(crate) trait SignatureScheme {
    fn sign(&self, secret_key: &Bytes, message: &Bytes) -> Result<Bytes>;
    fn verify(&self, public_key: &Bytes, message: &Bytes, sig: &Bytes) -> Result<bool>;
}

pub(crate) struct Ed25519SignatureScheme;

impl SignatureScheme for Ed25519SignatureScheme {
    fn sign(&self, secret_key: &Bytes, message: &Bytes) -> Result<Bytes> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            secret_key
                .iter()
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidEd25519PrivateKeySize)?,
        );

        Ok(signing_key.sign(message).to_vec().into())
    }

    fn verify(&self, public_key: &Bytes, message: &Bytes, signature: &Bytes) -> Result<bool> {
        let verify_key = ed25519_dalek::VerifyingKey::from_bytes(
            public_key
                .iter()
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidEd25519PublicKeySize)?,
        )
        .map_err(|_| Error::InvalidEd25519PublicKeySize)?;

        Ok(verify_key
            .verify(
                message,
                &ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| Error::InvalidEd25519SignatureSize)?,
            )
            .is_ok())
    }
}

/*
type ecdsaSignatureScheme struct {
    curve elliptic.Curve
    hash  crypto.Hash
}


func (scheme ecdsaSignatureScheme) hashSum(message []byte) []byte {
    h := scheme.hash.New()
    h.Write(message)
    return h.Sum(nil)
}
impl SignatureScheme for ecdsaSignatureScheme{
fn sign(&self, sign_key: &Bytes, message: &Bytes) -> Result<Bytes> {
    d := new(big.Int).SetBytes(signKey)
    x, y := scheme.curve.ScalarBaseMult(signKey)
    priv := &ecdsa.PrivateKey{
        PublicKey: ecdsa.PublicKey{Curve: scheme.curve, X: x, Y: y},
        D:         d,
    }
    return ecdsa.SignASN1(rand.Reader, priv, scheme.hashSum(message))
}

fn verify(&self, public_key: &Bytes, message: &Bytes, sig: &Bytes) -> bool{
    x, y := elliptic.Unmarshal(scheme.curve, publicKey)
    pub := &ecdsa.PublicKey{Curve: scheme.curve, X: x, Y: y}
    return ecdsa.VerifyASN1(pub, scheme.hashSum(message), sig)
}
}
type ed448SignatureScheme struct{}

impl SignatureScheme for ed448SignatureScheme{
fn sign(&self, sign_key: &Bytes, message: &Bytes) -> Result<Bytes> {
    if len(signKey) != ed448.SeedSize {
        return nil, fmt.Errorf("mls: invalid Ed448 private key size")
    }
    priv := ed448.NewKeyFromSeed(signKey)
    return ed448.Sign(priv, message, ""), nil
}

fn verify(&self, public_key: &Bytes, message: &Bytes, sig: &Bytes) -> bool {
    if len(publicKey) != ed448.PublicKeySize {
        return false
    }
    return ed448.Verify(ed448.PublicKey(publicKey), message, sig, "")
}
}
*/
