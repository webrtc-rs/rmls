use aes_gcm::{
    aead::{consts::U12, AeadInPlace},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{Kem, Serializable};
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::key_pair::HPKEKeyPair;
use crate::crypto::provider::HpkeSuite;
use crate::crypto::*;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct HpkeSuiteWrapper(pub(super) HpkeSuite);

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
        let mut out = vec![0u8; length as usize];

        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
            Kdf::KDF_HKDF_SHA384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
            Kdf::KDF_HKDF_SHA512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
        };

        Ok(Bytes::from(out))
    }

    fn kdf_extract(&self, secret: &[u8], salt: &[u8]) -> Result<Bytes> {
        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(salt)?;
                m.update(secret);
                Ok(Bytes::from(m.finalize().into_bytes().to_vec()))
            }
            Kdf::KDF_HKDF_SHA384 => {
                let mut m = Hmac::<Sha384>::new_from_slice(salt)?;
                m.update(secret);
                Ok(Bytes::from(m.finalize().into_bytes().to_vec()))
            }
            Kdf::KDF_HKDF_SHA512 => {
                let mut m = Hmac::<Sha512>::new_from_slice(salt)?;
                m.update(secret);
                Ok(Bytes::from(m.finalize().into_bytes().to_vec()))
            }
        }
    }

    fn kdf_extract_size(&self) -> usize {
        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => 32,
            Kdf::KDF_HKDF_SHA384 => 48,
            Kdf::KDF_HKDF_SHA512 => 64,
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
        use aes_gcm::KeyInit;
        match self.0.aead {
            Aead::AEAD_AES128GCM => {
                let key: &Key<Aes128Gcm> = key.try_into().map_err(|_| {
                    Error::RustCryptoError("key error due to try into Key<Aes128Gcm>".to_string())
                })?;
                let nonce: &Nonce<U12> = nonce.try_into().map_err(|_| {
                    Error::RustCryptoError("nonce error due to try into Nonce<16>".to_string())
                })?;

                let cipher = Aes128Gcm::new(key);
                let mut in_out = ciphertext.to_vec();
                cipher
                    .decrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
            Aead::AEAD_AES256GCM => {
                let key: &Key<Aes256Gcm> = key.try_into().map_err(|_| {
                    Error::RustCryptoError("key error due to try into Key<Aes128Gcm>".to_string())
                })?;
                let nonce: &Nonce<U12> = nonce.try_into().map_err(|_| {
                    Error::RustCryptoError("nonce error due to try into Nonce<16>".to_string())
                })?;

                let cipher = Aes256Gcm::new(key);
                let mut in_out = ciphertext.to_vec();
                cipher
                    .decrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
            Aead::AEAD_ChaCha20Poly1305 => {
                let key: &Key<ChaCha20Poly1305> = key.try_into().map_err(|_| {
                    Error::RustCryptoError("key error due to try into Key<Aes128Gcm>".to_string())
                })?;
                let nonce: &Nonce<U12> = nonce.try_into().map_err(|_| {
                    Error::RustCryptoError("nonce error due to try into Nonce<16>".to_string())
                })?;

                let cipher = ChaCha20Poly1305::new(key);
                let mut in_out = ciphertext.to_vec();
                cipher
                    .decrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
        }
    }

    fn aead_seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes> {
        use aes_gcm::KeyInit;
        match self.0.aead {
            Aead::AEAD_AES128GCM => {
                let key: &Key<Aes128Gcm> = key.try_into().map_err(|_| {
                    Error::RustCryptoError("key error due to try into Key<Aes128Gcm>".to_string())
                })?;
                let nonce: &Nonce<U12> = nonce.try_into().map_err(|_| {
                    Error::RustCryptoError("nonce error due to try into Nonce<16>".to_string())
                })?;

                let cipher = Aes128Gcm::new(key);
                let mut in_out = plaintext.to_vec();
                cipher
                    .encrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
            Aead::AEAD_AES256GCM => {
                let key: &Key<Aes256Gcm> = key.try_into().map_err(|_| {
                    Error::RustCryptoError("key error due to try into Key<Aes128Gcm>".to_string())
                })?;
                let nonce: &Nonce<U12> = nonce.try_into().map_err(|_| {
                    Error::RustCryptoError("nonce error due to try into Nonce<16>".to_string())
                })?;

                let cipher = Aes256Gcm::new(key);
                let mut in_out = plaintext.to_vec();
                cipher
                    .encrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
            Aead::AEAD_ChaCha20Poly1305 => {
                let key: &Key<ChaCha20Poly1305> = key.try_into().map_err(|_| {
                    Error::RustCryptoError("key error due to try into Key<Aes128Gcm>".to_string())
                })?;
                let nonce: &Nonce<U12> = nonce.try_into().map_err(|_| {
                    Error::RustCryptoError("nonce error due to try into Nonce<16>".to_string())
                })?;

                let cipher = ChaCha20Poly1305::new(key);
                let mut in_out = plaintext.to_vec();
                cipher
                    .encrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
        }
    }
}
