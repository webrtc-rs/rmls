use bytes::Bytes;
use ring::signature::{Ed25519KeyPair, VerificationAlgorithm, ED25519};

use crate::error::*;

pub(crate) trait SignatureScheme {
    fn sign(&self, sign_key: &Bytes, message: &Bytes) -> Result<Bytes>;
    fn verify(&self, public_key: &Bytes, message: &Bytes, sig: &Bytes) -> Result<bool>;
}

pub(crate) struct Ed25519SignatureScheme;

impl SignatureScheme for Ed25519SignatureScheme {
    fn sign(&self, sign_key: &Bytes, message: &Bytes) -> Result<Bytes> {
        let private_key = Ed25519KeyPair::from_seed_unchecked(sign_key)
            .map_err(|_| Error::InvalidEd25519PrivateKeySize)?;

        Ok(Bytes::from(private_key.sign(message).as_ref().to_vec()))
    }

    fn verify(&self, public_key: &Bytes, message: &Bytes, signature: &Bytes) -> Result<bool> {
        Ok(ED25519
            .verify(
                public_key.as_ref().into(),
                message.as_ref().into(),
                signature.as_ref().into(),
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
