use bytes::Bytes;
use signature::{Signer, Verifier};

use crate::crypto::provider::SignatureScheme;
use crate::utilities::error::*;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct SignatureSchemeWrapper(pub(super) SignatureScheme);

impl crate::crypto::provider::Signature for SignatureSchemeWrapper {
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes> {
        match self.0 {
            SignatureScheme::ED25519 => {
                let private_key = ed25519_dalek::SigningKey::from_bytes(
                    &sign_key
                        .try_into()
                        .map_err(|_| Error::InvalidEd25519PrivateKey)?,
                );
                let signature: ed25519_dalek::Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_vec()))
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let private_key = ecdsa::SigningKey::from_bytes(sign_key.into())
                    .map_err(|_| Error::InvalidECDSAPrivateKey)?;
                let signature: p256::ecdsa::Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_der().to_bytes().to_vec()))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let private_key = ecdsa::SigningKey::from_bytes(sign_key.into())
                    .map_err(|_| Error::InvalidECDSAPrivateKey)?;
                let signature: p384::ecdsa::Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_der().to_bytes().to_vec()))
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ED448 => Err(Error::UnsupportedEd448),
        }
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        match self.0 {
            SignatureScheme::ED25519 => {
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                    &public_key
                        .try_into()
                        .map_err(|_| Error::InvalidEd25519PrivateKey)?,
                )?;
                let signature = ed25519_dalek::Signature::from_slice(signature)?;
                verifying_key.verify(message, &signature)?;
                Ok(())
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let encoded_point = p256::EncodedPoint::from_bytes(public_key)?;
                let verifying_key: ecdsa::VerifyingKey<p256::NistP256> =
                    ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
                let signature = ecdsa::Signature::from_der(signature)?;
                verifying_key.verify(message, &signature)?;
                Ok(())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let encoded_point = p384::EncodedPoint::from_bytes(public_key)?;
                let verifying_key: ecdsa::VerifyingKey<p384::NistP384> =
                    ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
                let signature = ecdsa::Signature::from_der(signature)?;
                verifying_key.verify(message, &signature)?;
                Ok(())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ED448 => Err(Error::UnsupportedEd448),
        }
    }
}
