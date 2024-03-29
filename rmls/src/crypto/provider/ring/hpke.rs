use bytes::Bytes;
use hpke::{Kem, Serializable};
use ring::aead::{self, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use ring::digest::{SHA256_OUTPUT_LEN, SHA384_OUTPUT_LEN, SHA512_OUTPUT_LEN};
use ring::hkdf::{KeyType, Prk, HKDF_SHA256, HKDF_SHA384, HKDF_SHA512};
use ring::hmac;

use crate::crypto::key_pair::HPKEKeyPair;
use crate::crypto::provider::HpkeSuite;
use crate::crypto::*;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct HpkeSuiteWrapper(pub(super) HpkeSuite);

/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.
#[derive(Debug, PartialEq)]
struct MyKeyType<T: core::fmt::Debug + PartialEq>(T);

impl KeyType for MyKeyType<u16> {
    fn len(&self) -> usize {
        self.0 as usize
    }
}

impl provider::Hpke for HpkeSuiteWrapper {
    fn hpke_suite(&self) -> HpkeSuite {
        self.0
    }

    fn kem_derive_key_pair(&self, ikm: &[u8]) -> Result<HPKEKeyPair> {
        match self.0.kem {
            provider::Kem::KEM_X25519_HKDF_SHA256 => {
                let (private_key, public_key) = hpke::kem::X25519HkdfSha256::derive_keypair(ikm);
                Ok(HPKEKeyPair {
                    private_key: SecretKey(Bytes::from(private_key.to_bytes().to_vec())),
                    public_key: SecretKey(Bytes::from(public_key.to_bytes().to_vec())),
                })
            }
            provider::Kem::KEM_P256_HKDF_SHA256 => {
                let (private_key, public_key) = hpke::kem::DhP256HkdfSha256::derive_keypair(ikm);
                Ok(HPKEKeyPair {
                    private_key: SecretKey(Bytes::from(private_key.to_bytes().to_vec())),
                    public_key: SecretKey(Bytes::from(public_key.to_bytes().to_vec())),
                })
            }
            _ => Err(Error::UnsupportedKem),
        }
    }

    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes> {
        let prk = match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => Prk::new_less_safe(HKDF_SHA256, secret),
            Kdf::KDF_HKDF_SHA384 => Prk::new_less_safe(HKDF_SHA384, secret),
            Kdf::KDF_HKDF_SHA512 => Prk::new_less_safe(HKDF_SHA512, secret),
        };

        let infos = [info];
        let okm = prk
            .expand(&infos, MyKeyType(length))
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;

        let mut out = vec![0u8; length as usize];
        okm.fill(&mut out)
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;

        Ok(Bytes::from(out))
    }

    fn kdf_extract(&self, secret: &[u8], salt: &[u8]) -> Result<Bytes> {
        let salt = match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => hmac::Key::new(hmac::HMAC_SHA256, salt),
            Kdf::KDF_HKDF_SHA384 => hmac::Key::new(hmac::HMAC_SHA384, salt),
            Kdf::KDF_HKDF_SHA512 => hmac::Key::new(hmac::HMAC_SHA512, salt),
        };
        Ok(Bytes::from(hmac::sign(&salt, secret).as_ref().to_vec()))
    }

    fn kdf_extract_size(&self) -> usize {
        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => SHA256_OUTPUT_LEN,
            Kdf::KDF_HKDF_SHA384 => SHA384_OUTPUT_LEN,
            Kdf::KDF_HKDF_SHA512 => SHA512_OUTPUT_LEN,
        }
    }

    // key_size returns the size in bytes of the keys used by the AEAD cipher.
    fn aead_key_size(&self) -> usize {
        match self.0.aead {
            Aead::AEAD_AES128GCM => 16,
            Aead::AEAD_AES256GCM => 32,
            Aead::AEAD_ChaCha20Poly1305 => 32,
        }
    }

    // nonce_size returns the size in bytes of the nonce used by the AEAD cipher.
    fn aead_nonce_size(&self) -> usize {
        match self.0.aead {
            Aead::AEAD_AES128GCM | Aead::AEAD_AES256GCM | Aead::AEAD_ChaCha20Poly1305 => 12,
        }
    }

    fn aead_open(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes> {
        let key = match self.0.aead {
            Aead::AEAD_AES128GCM => {
                let key = aead::UnboundKey::new(&AES_128_GCM, key)
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                aead::LessSafeKey::new(key)
            }
            Aead::AEAD_AES256GCM => {
                let key = aead::UnboundKey::new(&AES_256_GCM, key)
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                aead::LessSafeKey::new(key)
            }
            Aead::AEAD_ChaCha20Poly1305 => {
                let key = aead::UnboundKey::new(&CHACHA20_POLY1305, key)
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                aead::LessSafeKey::new(key)
            }
        };

        let mut in_out = ciphertext.to_vec();
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;
        let aad = aead::Aad::from(additional_data);

        key.open_in_place(nonce, aad, &mut in_out)
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;

        Ok(Bytes::from(in_out))
    }

    fn aead_seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes> {
        let key = match self.0.aead {
            Aead::AEAD_AES128GCM => {
                let key = aead::UnboundKey::new(&AES_128_GCM, key)
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                aead::LessSafeKey::new(key)
            }
            Aead::AEAD_AES256GCM => {
                let key = aead::UnboundKey::new(&AES_256_GCM, key)
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                aead::LessSafeKey::new(key)
            }
            Aead::AEAD_ChaCha20Poly1305 => {
                let key = aead::UnboundKey::new(&CHACHA20_POLY1305, key)
                    .map_err(|err| Error::RingCryptoError(err.to_string()))?;
                aead::LessSafeKey::new(key)
            }
        };

        let mut in_out = plaintext.to_vec();
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;
        let aad = aead::Aad::from(additional_data);

        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|err| Error::RingCryptoError(err.to_string()))?;

        Ok(Bytes::from(in_out))
    }
}
