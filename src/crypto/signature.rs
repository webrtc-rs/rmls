use bytes::Bytes;
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use ring::signature::{Ed25519KeyPair, VerificationAlgorithm, ED25519};

use crate::error::*;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SignatureScheme {
    #[default]
    Ed25519,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P521_SHA512,
    Ed448,
}

impl SignatureScheme {
    pub(crate) fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes> {
        match *self {
            SignatureScheme::Ed25519 => {
                let private_key = Ed25519KeyPair::from_seed_unchecked(sign_key)
                    .map_err(|_| Error::InvalidEd25519PrivateKey)?;
                Ok(Bytes::from(private_key.sign(message).as_ref().to_vec()))
            }
            SignatureScheme::ECDSA_P256_SHA256 => {
                let private_key = SigningKey::from_bytes(sign_key.into())
                    .map_err(|_| Error::InvalidECDSAPrivateKey)?;
                let signature: Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_der().to_bytes().to_vec()))
            }
            SignatureScheme::ECDSA_P384_SHA384 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ECDSA_P521_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::Ed448 => Err(Error::UnsupportedEd448),
        }
    }

    pub(crate) fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match *self {
            SignatureScheme::Ed25519 => ED25519
                .verify(public_key.into(), message.into(), signature.into())
                .is_ok(),
            SignatureScheme::ECDSA_P256_SHA256 => {
                let encoded_point = if let Ok(encoded_point) = EncodedPoint::from_bytes(public_key)
                {
                    encoded_point
                } else {
                    return false;
                };
                let verifying_key =
                    if let Ok(verifying_key) = VerifyingKey::from_encoded_point(&encoded_point) {
                        verifying_key
                    } else {
                        return false;
                    };
                let signature = if let Ok(signature) = Signature::from_der(signature) {
                    signature
                } else {
                    return false;
                };
                verifying_key.verify(message, &signature).is_ok()
            }
            SignatureScheme::ECDSA_P384_SHA384 => false,
            SignatureScheme::ECDSA_P521_SHA512 => false,
            SignatureScheme::Ed448 => false,
        }
    }
}
