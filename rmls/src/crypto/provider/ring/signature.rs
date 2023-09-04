use bytes::Bytes;
use rand_core::{RngCore, SeedableRng};
use ring::signature::{
    Ed25519KeyPair, KeyPair, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    ED25519,
};
use signature::Signer;

use crate::crypto::{key_pair::SignatureKeyPair, provider::SignatureScheme, SignaturePublicKey};
use crate::utilities::error::*;

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct SignatureSchemeWrapper(pub(super) SignatureScheme);

impl crate::crypto::provider::Signature for SignatureSchemeWrapper {
    fn signature_key_pair(&self) -> Result<SignatureKeyPair> {
        match self.0 {
            SignatureScheme::ED25519 => {
                const SEED_LEN: usize = 32;
                let mut seed = [0u8; SEED_LEN];
                let mut rand = rand_chacha::ChaCha20Rng::from_entropy();
                rand.fill_bytes(&mut seed);
                let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
                    .map_err(|_| Error::InvalidEd25519PrivateKey)?;
                Ok(SignatureKeyPair {
                    private_key: Bytes::from(seed.to_vec()),
                    public_key: SignaturePublicKey(Bytes::from(
                        key_pair.public_key().as_ref().to_vec(),
                    )),
                    signature_scheme: self.0,
                })
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let signing_key: ecdsa::SigningKey<p256::NistP256> =
                    ecdsa::SigningKey::random(&mut rand_chacha::ChaCha20Rng::from_entropy());
                let (private_key, public_key) = (
                    signing_key.to_bytes(),
                    signing_key.verifying_key().to_sec1_bytes(),
                );
                Ok(SignatureKeyPair {
                    private_key: Bytes::from(private_key.to_vec()),
                    public_key: SignaturePublicKey(Bytes::from(public_key.to_vec())),
                    signature_scheme: self.0,
                })
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let signing_key: ecdsa::SigningKey<p384::NistP384> =
                    ecdsa::SigningKey::random(&mut rand_chacha::ChaCha20Rng::from_entropy());
                let (private_key, public_key) = (
                    signing_key.to_bytes(),
                    signing_key.verifying_key().to_sec1_bytes(),
                );
                Ok(SignatureKeyPair {
                    private_key: Bytes::from(private_key.to_vec()),
                    public_key: SignaturePublicKey(Bytes::from(public_key.to_vec())),
                    signature_scheme: self.0,
                })
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ED448 => Err(Error::UnsupportedEd448),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.0
    }

    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes> {
        match self.0 {
            SignatureScheme::ED25519 => {
                let private_key = Ed25519KeyPair::from_seed_unchecked(sign_key)
                    .map_err(|_| Error::InvalidEd25519PrivateKey)?;
                Ok(Bytes::from(private_key.sign(message).as_ref().to_vec()))
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
                ED25519
                    .verify(public_key.into(), message.into(), signature.into())
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                Ok(())
            }
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                ECDSA_P256_SHA256_ASN1
                    .verify(public_key.into(), message.into(), signature.into())
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                Ok(())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                ECDSA_P384_SHA384_ASN1
                    .verify(public_key.into(), message.into(), signature.into())
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                Ok(())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => Err(Error::UnsupportedEcdsa),
            SignatureScheme::ED448 => Err(Error::UnsupportedEd448),
        }
    }
}
