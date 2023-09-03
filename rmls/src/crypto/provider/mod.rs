//! [RFC9420 Sec.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-5) CryptoProvider trait and
//! implementations that provide the cryptographic primitives to be used in group key computations.

#[cfg(feature = "RingCryptoProvider")]
mod ring;
#[cfg(feature = "RingCryptoProvider")]
pub use self::ring::RingCryptoProvider;
#[cfg(feature = "RustCryptoProvider")]
mod rust;
#[cfg(feature = "RustCryptoProvider")]
pub use self::rust::RustCryptoProvider;

use crate::crypto::{cipher_suite::CipherSuite, *};

use bytes::{BufMut, Bytes, BytesMut};
use hpke::{Deserializable, Serializable};
use rand_core::SeedableRng;

/// [RFC9420 Sec.5.1.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2) MLS prefix string - "MLS 1.0 "
const MLS_PREFIX: &str = "MLS 1.0 ";

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) HashScheme
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashScheme {
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) HpkeSuite
///
/// It is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct HpkeSuite {
    pub(super) kem: Kem,
    pub(super) kdf: Kdf,
    pub(super) aead: Aead,
}

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) SignatureScheme
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum SignatureScheme {
    /// ECDSA_SECP256R1_SHA256
    #[default]
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA_SECP384R1_SHA384
    ECDSA_SECP384R1_SHA384 = 0x0503,
    /// ECDSA_SECP521R1_SHA512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// ED25519
    ED25519 = 0x0807,
    /// ED448
    ED448 = 0x0808,
}

/// SignatureKeyPair is a wrapper CryptoProvider's signature key pair
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SignatureKeyPair {
    private_key: Bytes,
    public_key: Bytes,
    signature_scheme: SignatureScheme,
}

impl SignatureKeyPair {
    /// Returns private key
    pub fn private_key(&self) -> &[u8] {
        self.private_key.as_ref()
    }

    /// Returns public key
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// Returns signature scheme
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

/// Rand trait provides randomness
pub trait Rand: Send + Sync {
    fn fill(&self, buf: &mut [u8]) -> Result<()>;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Hash trait provides
/// hash algorithm and Message Authentication Code (MAC) algorithm
pub trait Hash: Send + Sync {
    /// A hash algorithm
    fn digest(&self, data: &[u8]) -> Bytes;

    /// A Message Authentication Code (MAC) algorithm
    fn mac(&self, key: &[u8], message: &[u8]) -> Bytes;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Hpke trait provides
/// Key Derivation Function (KDF) algorithm and Authenticated Encryption with Associated Data (AEAD)
/// algorithm
pub trait Hpke: Send + Sync {
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Expand a pseudorandom key
    /// using optional string info into length bytes of output keying material.
    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes>;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Extract a pseudorandom key
    /// of fixed length Nh bytes from input keying material and an optional byte string salt.
    fn kdf_extract(&self, secret: &[u8], salt: &[u8]) -> Result<Bytes>;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) The output size of the
    /// Extract function in bytes.
    fn kdf_extract_size(&self) -> usize;

    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) The length in bytes of
    /// a nonce for this algorithm.
    fn aead_nonce_size(&self) -> usize;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) The length in bytes of
    /// a key for this algorithm.
    fn aead_key_size(&self) -> usize;

    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Decrypt ciphertext using
    /// associated data with symmetric key and nonce, returning plaintext message
    fn aead_open(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes>;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Encrypt and authenticate
    /// plaintext with associated data aad using symmetric key and nonce, yielding ciphertext
    fn aead_seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes>;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Signature trait provides
/// signature algorithm
pub trait Signature: Send + Sync {
    /// Generate a new signature key pair
    fn generate_key_pair(&self) -> Result<SignatureKeyPair>;

    /// Returns signature scheme
    fn signature_scheme(&self) -> SignatureScheme;

    /// Sign the message with the provided sign_key
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes>;

    /// Verify the message with the provided public key and signature
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) CryptoProvider trait
/// specifies the cryptographic primitives to be used in group key computations
pub trait CryptoProvider {
    /// Check whether the cipher suite is supported or not
    fn supports(&self, cipher_suite: CipherSuite) -> bool;

    /// Return supported cipher suites
    fn supported(&self) -> Vec<CipherSuite>;

    ///
    fn rand(&self) -> &dyn Rand;

    /// Derive Hash trait object based on the given cipher suite
    fn hash(&self, cipher_suite: CipherSuite) -> &dyn Hash;

    /// Derive Hpke trait object based on the given cipher suite
    fn hpke(&self, cipher_suite: CipherSuite) -> &dyn Hpke;

    /// Derive Signature trait object based on the given cipher suite
    fn signature(&self, cipher_suite: CipherSuite) -> &dyn Signature;

    /// HMAC based sign based on the given cipher suite
    fn sign_mac(&self, cipher_suite: CipherSuite, key: &[u8], message: &[u8]) -> Bytes {
        // All cipher suites use HMAC
        self.hash(cipher_suite).mac(key, message)
    }

    /// HMAC based verify based on the given cipher suite
    fn verify_mac(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        message: &[u8],
        tag: &[u8],
    ) -> bool {
        tag == self.sign_mac(cipher_suite, key, message).as_ref()
    }

    /// [RFC9420 Sec.5.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2) Hash-Based Identifiers
    fn ref_hash(&self, cipher_suite: CipherSuite, label: &[u8], value: &[u8]) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        serialize_opaque_vec(label, &mut buf)?;
        serialize_opaque_vec(value, &mut buf)?;
        let input = buf.freeze();
        let h = self.hash(cipher_suite);
        Ok(h.digest(&input))
    }

    /// Expand secret with label
    fn expand_with_label(
        &self,
        cipher_suite: CipherSuite,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: u16,
    ) -> Result<Bytes> {
        let mut mls_label = MLS_PREFIX.as_bytes().to_vec();
        mls_label.extend_from_slice(label);

        let mut buf = BytesMut::new();
        buf.put_u16(length);
        serialize_opaque_vec(&mls_label, &mut buf)?;
        serialize_opaque_vec(context, &mut buf)?;
        let info = buf.freeze();
        self.hpke(cipher_suite).kdf_expand(secret, &info, length)
    }

    /// Derive secret with label
    fn derive_secret(
        &self,
        cipher_suite: CipherSuite,
        secret: &[u8],
        label: &[u8],
    ) -> Result<Bytes> {
        let length = self.hpke(cipher_suite).kdf_extract_size();
        self.expand_with_label(cipher_suite, secret, label, &[], length as u16)
    }

    /// [RFC9420 Sec.5.1.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2) Sign message with label
    fn sign_with_label(
        &self,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        label: &[u8],
        content: &[u8],
    ) -> Result<Bytes> {
        let sign_content = mls_prefix_label_data(label, content)?;
        self.signature(cipher_suite).sign(sign_key, &sign_content)
    }

    /// [RFC9420 Sec.5.1.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2) Verify message with label
    fn verify_with_label(
        &self,
        cipher_suite: CipherSuite,
        verify_key: &[u8],
        label: &[u8],
        content: &[u8],
        sign_value: &[u8],
    ) -> Result<()> {
        let sign_content = mls_prefix_label_data(label, content)?;
        self.signature(cipher_suite)
            .verify(verify_key, &sign_content, sign_value)
    }

    /// [RFC9420 Sec.5.1.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3) Encrypt message with label
    fn encrypt_with_label(
        &self,
        cipher_suite: CipherSuite,
        public_key: &[u8],
        label: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<(Bytes, Bytes)> {
        let info = mls_prefix_label_data(label, context)?;
        match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                let public_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let (kem_output, mut encryption_context) = hpke::setup_sender::<
                    hpke::aead::AesGcm128,
                    hpke::kdf::HkdfSha256,
                    hpke::kem::X25519HkdfSha256,
                    _,
                >(
                    &hpke::OpModeS::Base,
                    &public_key,
                    &info,
                    &mut rand_chacha::ChaCha20Rng::from_entropy(),
                )
                .map_err(|err| Error::HpkeError(err.to_string()))?;

                let ciphertext = encryption_context
                    .seal(plaintext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;
                Ok((
                    Bytes::from(kem_output.to_bytes().to_vec()),
                    Bytes::from(ciphertext),
                ))
            }
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let public_key =
                    <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let (kem_output, mut encryption_context) = hpke::setup_sender::<
                    hpke::aead::AesGcm128,
                    hpke::kdf::HkdfSha256,
                    hpke::kem::DhP256HkdfSha256,
                    _,
                >(
                    &hpke::OpModeS::Base,
                    &public_key,
                    &info,
                    &mut rand_chacha::ChaCha20Rng::from_entropy(),
                )
                .map_err(|err| Error::HpkeError(err.to_string()))?;

                let ciphertext = encryption_context
                    .seal(plaintext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;
                Ok((
                    Bytes::from(kem_output.to_bytes().to_vec()),
                    Bytes::from(ciphertext),
                ))
            }
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                let public_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let (kem_output, mut encryption_context) = hpke::setup_sender::<
                    hpke::aead::ChaCha20Poly1305,
                    hpke::kdf::HkdfSha256,
                    hpke::kem::X25519HkdfSha256,
                    _,
                >(
                    &hpke::OpModeS::Base,
                    &public_key,
                    &info,
                    &mut rand_chacha::ChaCha20Rng::from_entropy(),
                )
                .map_err(|err| Error::HpkeError(err.to_string()))?;

                let ciphertext = encryption_context
                    .seal(plaintext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;
                Ok((
                    Bytes::from(kem_output.to_bytes().to_vec()),
                    Bytes::from(ciphertext),
                ))
            }
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                Err(Error::UnsupportedCipherSuite)
            }
        }
    }

    /// [RFC9420 Sec.5.1.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3) Decrypt message with label
    fn decrypt_with_label(
        &self,
        cipher_suite: CipherSuite,
        private_key: &[u8],
        label: &[u8],
        context: &[u8],
        kem_output: &[u8],
        ciphertext: &[u8],
    ) -> Result<Bytes> {
        let info = mls_prefix_label_data(label, context)?;
        match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                let private_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(private_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;
                let encapped_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(kem_output)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let mut decryption_context =
                    hpke::setup_receiver::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(&hpke::OpModeR::Base, &private_key, &encapped_key, &info)
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                let plaintext = decryption_context
                    .open(ciphertext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                Ok(Bytes::from(plaintext))
            }
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                let private_key =
                    <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(private_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;
                let encapped_key =
                    <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(kem_output)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let mut decryption_context =
                    hpke::setup_receiver::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::DhP256HkdfSha256,
                    >(&hpke::OpModeR::Base, &private_key, &encapped_key, &info)
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                let plaintext = decryption_context
                    .open(ciphertext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                Ok(Bytes::from(plaintext))
            }
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                let private_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(private_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;
                let encapped_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(kem_output)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let mut decryption_context =
                    hpke::setup_receiver::<
                        hpke::aead::ChaCha20Poly1305,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(&hpke::OpModeR::Base, &private_key, &encapped_key, &info)
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                let plaintext = decryption_context
                    .open(ciphertext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                Ok(Bytes::from(plaintext))
            }
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                Err(Error::UnsupportedCipherSuite)
            }
        }
    }
}

fn mls_prefix_label_data(label: &[u8], data: &[u8]) -> Result<Bytes> {
    let mut mls_label = MLS_PREFIX.as_bytes().to_vec();
    mls_label.extend_from_slice(label);

    let mut buf = BytesMut::new();
    serialize_opaque_vec(&mls_label, &mut buf)?;
    serialize_opaque_vec(data, &mut buf)?;
    Ok(buf.freeze())
}
