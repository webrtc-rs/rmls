use bytes::Bytes;
use ring::signature::{
    Ed25519KeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519,
};
use signature::Signer;

use crate::error::*;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum SignatureScheme {
    #[default]
    Ed25519,
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P521_SHA512,
    Ed448,
}

impl crate::crypto::provider::Signature for SignatureScheme {
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes> {
        match *self {
            SignatureScheme::Ed25519 => {
                let private_key = Ed25519KeyPair::from_seed_unchecked(sign_key)
                    .map_err(|_| Error::InvalidEd25519PrivateKey)?;
                Ok(Bytes::from(private_key.sign(message).as_ref().to_vec()))
            }
            SignatureScheme::ECDSA_P256_SHA256 => {
                let private_key = ecdsa::SigningKey::from_bytes(sign_key.into())
                    .map_err(|_| Error::InvalidECDSAPrivateKey)?;
                let signature: p256::ecdsa::Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_der().to_bytes().to_vec()))
            }
            SignatureScheme::ECDSA_P384_SHA384 => {
                let private_key = ecdsa::SigningKey::from_bytes(sign_key.into())
                    .map_err(|_| Error::InvalidECDSAPrivateKey)?;
                let signature: p384::ecdsa::Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_der().to_bytes().to_vec()))
            }
            SignatureScheme::ECDSA_P521_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::Ed448 => Err(Error::UnsupportedEd448),
        }
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        match *self {
            SignatureScheme::Ed25519 => {
                ED25519
                    .verify(public_key.into(), message.into(), signature.into())
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                Ok(())
            }
            SignatureScheme::ECDSA_P256_SHA256 => {
                ECDSA_P256_SHA256_ASN1
                    .verify(public_key.into(), message.into(), signature.into())
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                Ok(())
            }
            SignatureScheme::ECDSA_P384_SHA384 => {
                ECDSA_P384_SHA384_ASN1
                    .verify(public_key.into(), message.into(), signature.into())
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                Ok(())
            }
            SignatureScheme::ECDSA_P521_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::Ed448 => Err(Error::UnsupportedEd448),
        }
    }
}
