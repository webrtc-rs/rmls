use ring::signature::{
    Ed25519KeyPair, Signature,
    VerificationAlgorithm, /*ECDSA_P256_SHA256_ASN1,
                           ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,*/
    ED25519,
};

use crate::error::*;

pub(crate) trait SignatureScheme {
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Signature>;
    fn verify(&self, public_key: &[u8], message: &[u8], sig: &[u8]) -> Result<bool>;
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Ed25519SignatureScheme;

impl SignatureScheme for Ed25519SignatureScheme {
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Signature> {
        let private_key = Ed25519KeyPair::from_seed_unchecked(sign_key)
            .map_err(|_| Error::InvalidEd25519PrivateKeySize)?;

        Ok(private_key.sign(message))
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        Ok(ED25519
            .verify(public_key.into(), message.into(), signature.into())
            .is_ok())
    }
}

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum EcdsaSignatureScheme {
    #[default]
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P521_SHA512_ASN1, // https://github.com/briansmith/ring/issues/824
}

impl SignatureScheme for EcdsaSignatureScheme {
    fn sign(&self, _sign_key: &[u8], _message: &[u8]) -> Result<Signature> {
        match *self {
            EcdsaSignatureScheme::ECDSA_P256_SHA256_ASN1 => {
                Err(Error::UnsupportedEcdsaP521Sha512) //TODO(yngrtc):ECDSA_P256_SHA256_ASN1_SIGNING.sign(message)
            }
            EcdsaSignatureScheme::ECDSA_P384_SHA384_ASN1 => {
                Err(Error::UnsupportedEcdsaP521Sha512) //TODO(yngrtc):ECDSA_P384_SHA384_ASN1_SIGNING.sign(message)
            }
            EcdsaSignatureScheme::ECDSA_P521_SHA512_ASN1 => Err(Error::UnsupportedEcdsaP521Sha512),
        }
    }

    fn verify(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<bool> {
        match *self {
            EcdsaSignatureScheme::ECDSA_P256_SHA256_ASN1 => Err(Error::UnsupportedEcdsaP521Sha512) /*TODO(yngrtc):ECDSA_P256_SHA256_ASN1
                .verify(public_key.into(), message.into(), signature.into())
                .is_ok()*/,
            EcdsaSignatureScheme::ECDSA_P384_SHA384_ASN1 => Err(Error::UnsupportedEcdsaP521Sha512) /*TODO(yngrtc):ECDSA_P384_SHA384_ASN1
                .verify(public_key.into(), message.into(), signature.into())
                .is_ok()*/,
            EcdsaSignatureScheme::ECDSA_P521_SHA512_ASN1 => Err(Error::UnsupportedEcdsaP521Sha512),
        }
    }
}

pub(crate) struct Ed448SignatureScheme;

impl SignatureScheme for Ed448SignatureScheme {
    fn sign(&self, _sign_key: &[u8], _message: &[u8]) -> Result<Signature> {
        Err(Error::UnsupportedEd448SignatureScheme)
    }

    fn verify(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<bool> {
        Ok(false)
    }
}
