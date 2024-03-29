//! [RFC9420 Sec.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-5) Cryptographic Objects
#[cfg(test)]
mod crypto_test;

use bytes::{Buf, BufMut, Bytes};
use std::ops::Deref;

use crate::utilities::{error::*, serde::*};

pub mod cipher_suite;
pub mod config;
pub mod credential;
pub mod key_pair;
pub mod provider;

#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
pub struct SecretKey(Bytes);

impl Deref for SecretKey {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializer for SecretKey {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(SecretKey(deserialize_opaque_vec(buf)?))
    }
}

impl Serializer for SecretKey {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.0, buf)
    }
}

/// [RFC9420 Sec.5.1.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.1) HPKE public keys are
/// opaque values in a format defined by the underlying protocol (see Section 4 of
/// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html) for more information).
pub type HPKEPublicKey = SecretKey;
pub type HPKEPrivateKey = SecretKey;

/// [RFC9420 Sec.5.1.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.1) Signature public keys
/// are likewise represented as opaque values in a format defined by the cipher suite's signature scheme.
pub type SignaturePublicKey = SecretKey;
pub type SignaturePrivateKey = SecretKey;

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Key Encapsulation
/// Mechanism (KEM) of HPKE parameters
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Kem {
    #[default]
    /// KEM_P256_HKDF_SHA256 is a KEM using P256 curve and HKDF with SHA-256.
    KEM_P256_HKDF_SHA256 = 0x10,
    /// KEM_P384_HKDF_SHA384 is a KEM using P384 curve and HKDF with SHA-384.
    KEM_P384_HKDF_SHA384 = 0x11,
    /// KEM_P521_HKDF_SHA512 is a KEM using P521 curve and HKDF with SHA-512.
    KEM_P521_HKDF_SHA512 = 0x12,
    /// KEM_X25519_HKDF_SHA256 is a KEM using X25519 Diffie-Hellman function
    /// and HKDF with SHA-256.
    KEM_X25519_HKDF_SHA256 = 0x20,
    /// KEM_X448_HKDF_SHA512 is a KEM using X448 Diffie-Hellman function and
    /// HKDF with SHA-512.
    KEM_X448_HKDF_SHA512 = 0x21,
    /// KEM_X25519_KYBER768_DRAFT00 is a hybrid KEM built on DHKEM(X25519, HKDF-SHA256)
    /// and Kyber768Draft00
    KEM_X25519_KYBER768_DRAFT00 = 0x30,
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Key Derivation Function
/// (KDF) of HPKE parameters
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Kdf {
    #[default]
    /// KDF_HKDF_SHA256 is a KDF using HKDF with SHA-256.
    KDF_HKDF_SHA256 = 0x01,
    /// KDF_HKDF_SHA384 is a KDF using HKDF with SHA-384.
    KDF_HKDF_SHA384 = 0x02,
    /// KDF_HKDF_SHA512 is a KDF using HKDF with SHA-512.
    KDF_HKDF_SHA512 = 0x03,
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1)  Authenticated Encryption
/// with Associated Data (AEAD) encryption algorithm of HPKE parameters
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Aead {
    #[default]
    /// AEAD_AES128GCM is AES-128 block cipher in Galois Counter Mode (GCM).
    AEAD_AES128GCM = 0x01,
    /// AEAD_AES256GCM is AES-256 block cipher in Galois Counter Mode (GCM).
    AEAD_AES256GCM = 0x02,
    /// AEAD_ChaCha20Poly1305 is ChaCha20 stream cipher and Poly1305 MAC.
    AEAD_ChaCha20Poly1305 = 0x03,
}
