pub mod ring;
pub mod rust;

use crate::cipher_suite::CipherSuite;
use crate::codec::*;
use crate::error::*;

use bytes::{BufMut, Bytes, BytesMut};
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeS, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};

pub const MLS_PREFIX: &str = "MLS 1.0 ";

pub trait Hash: Send + Sync {
    fn digest(&self, data: &[u8]) -> Bytes;

    fn sign(&self, key: &[u8], message: &[u8]) -> Bytes;
}

pub trait Hpke: Send + Sync {
    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes>;
    fn kdf_extract_size(&self) -> usize;
}

pub trait Signature: Send + Sync {
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes>;

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;
}

pub trait CryptoProvider {
    fn supports(&self, cipher_suite: CipherSuite) -> Result<()>;

    fn supported(&self) -> Vec<CipherSuite>;

    fn hash(&self, cipher_suite: CipherSuite) -> &dyn Hash;

    fn hpke(&self, cipher_suite: CipherSuite) -> &dyn Hpke;

    fn signature(&self, cipher_suite: CipherSuite) -> &dyn Signature;

    fn sign_mac(&self, cipher_suite: CipherSuite, key: &[u8], message: &[u8]) -> Bytes {
        // All cipher suites use HMAC
        self.hash(cipher_suite).sign(key, message)
    }

    fn verify_mac(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        message: &[u8],
        tag: &[u8],
    ) -> bool {
        tag == self.sign_mac(cipher_suite, key, message).as_ref()
    }

    fn ref_hash(&self, cipher_suite: CipherSuite, label: &[u8], value: &[u8]) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        write_opaque_vec(label, &mut buf)?;
        write_opaque_vec(value, &mut buf)?;
        let input = buf.freeze();
        let h = self.hash(cipher_suite);
        Ok(h.digest(&input))
    }

    fn expand_with_label(
        &self,
        cipher_suite: CipherSuite,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: u16,
    ) -> Result<Bytes> {
        let mut mls_label = "MLS 1.0 ".as_bytes().to_vec();
        mls_label.extend_from_slice(label);

        let mut buf = BytesMut::new();
        buf.put_u16(length);
        write_opaque_vec(&mls_label, &mut buf)?;
        write_opaque_vec(context, &mut buf)?;
        let info = buf.freeze();
        self.hpke(cipher_suite).kdf_expand(secret, &info, length)
    }

    fn derive_secret(
        &self,
        cipher_suite: CipherSuite,
        secret: &[u8],
        label: &[u8],
    ) -> Result<Bytes> {
        let length = self.hpke(cipher_suite).kdf_extract_size();
        self.expand_with_label(cipher_suite, secret, label, &[], length as u16)
    }

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
                let x25519_public_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let (kem_output, mut encryption_context) =
                    hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
                        &OpModeS::Base,
                        &x25519_public_key,
                        &info,
                        &mut StdRng::from_entropy(),
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
                Ok((Bytes::new(), Bytes::new()))
            }
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Ok((Bytes::new(), Bytes::new()))
            }
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                Err(Error::UnsupportedCipherSuite)
            }
        }
    }

    fn decrypt_with_label(
        &self,
        cipher_suite: CipherSuite,
        private_key: &[u8],
        label: &[u8],
        context: &[u8],
        kem_output: &[u8],
        ciphertext: &[u8],
    ) -> Result<Bytes> {
        let _encrypt_context = mls_prefix_label_data(label, context)?;
        match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => Ok(Bytes::new()),
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(Bytes::new()),
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => Ok(Bytes::new()),
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                Err(Error::UnsupportedCipherSuite)
            }
        }
        /*TODO(yngrtc):
        hpke := cs.hpke()
        kem, _, _ := hpke.Params()
        priv, err := kem.Scheme().UnmarshalBinaryPrivateKey(private_key)
        if err != nil {
            return nil, err
        }

        receiver, err := hpke.NewReceiver(priv, encrypt_context)
        if err != nil {
            return nil, err
        }

        opener, err := receiver.Setup(kem_output)
        if err != nil {
            return nil, err
        }

        return opener.Open(ciphertext, nil)*/
    }
}

fn mls_prefix_label_data(label: &[u8], data: &[u8]) -> Result<Bytes> {
    let mut mls_label = MLS_PREFIX.as_bytes().to_vec();
    mls_label.extend_from_slice(label);

    let mut buf = BytesMut::new();
    write_opaque_vec(&mls_label, &mut buf)?;
    write_opaque_vec(data, &mut buf)?;
    Ok(buf.freeze())
}
