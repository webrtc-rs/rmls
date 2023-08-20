use ring::signature::{Ed25519KeyPair, Signature, VerificationAlgorithm, ED25519};

use crate::error::*;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SignatureScheme {
    #[default]
    Ed25519,
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P521_SHA512_ASN1, // https://github.com/briansmith/ring/issues/824
    Ed448,
}

impl SignatureScheme {
    pub(crate) fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Signature> {
        match *self {
            SignatureScheme::Ed25519 => {
                let private_key = Ed25519KeyPair::from_seed_unchecked(sign_key)
                    .map_err(|_| Error::InvalidEd25519PrivateKeySize)?;
                Ok(private_key.sign(message))
            }
            SignatureScheme::ECDSA_P256_SHA256_ASN1 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ECDSA_P384_SHA384_ASN1 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ECDSA_P521_SHA512_ASN1 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::Ed448 => Err(Error::UnsupportedEd448),
        }
    }

    pub(crate) fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match *self {
            SignatureScheme::Ed25519 => ED25519
                .verify(public_key.into(), message.into(), signature.into())
                .is_ok(),
            SignatureScheme::ECDSA_P256_SHA256_ASN1 => false,
            SignatureScheme::ECDSA_P384_SHA384_ASN1 => false,
            SignatureScheme::ECDSA_P521_SHA512_ASN1 => false,
            SignatureScheme::Ed448 => false,
        }
    }
}
