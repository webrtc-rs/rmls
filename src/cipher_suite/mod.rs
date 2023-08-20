#[cfg(test)]
mod cipher_suite_test;

use crate::codec::*;
use crate::crypto::{
    hash::Hash,
    hpke::{
        algs::{Aead, Kdf, Kem},
        HpkeSuite,
    },
    signature::SignatureScheme,
};
use crate::error::*;

use bytes::{BufMut, Bytes, BytesMut};
use ring::{digest, hmac};
use std::fmt::{Display, Formatter};

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum CipherSuite {
    #[default]
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;

    fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            0x0007 => Ok(CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
            _ => Err(Error::InvalidCipherSuiteValue(v)),
        }
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl CipherSuite {
    pub(crate) fn hash(&self) -> Hash {
        match *self {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => Hash::SHA256,
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Hash::SHA384,
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => Hash::SHA512,
        }
    }

    pub(crate) fn hpke(&self) -> HpkeSuite {
        match *self {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => HpkeSuite::new(
                Kem::KEM_X25519_HKDF_SHA256,
                Kdf::KDF_HKDF_SHA256,
                Aead::AEAD_AES128GCM,
            ),
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeSuite::new(
                Kem::KEM_P256_HKDF_SHA256,
                Kdf::KDF_HKDF_SHA256,
                Aead::AEAD_AES128GCM,
            ),
            CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => HpkeSuite::new(
                Kem::KEM_X25519_HKDF_SHA256,
                Kdf::KDF_HKDF_SHA256,
                Aead::AEAD_ChaCha20Poly1305,
            ),
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => HpkeSuite::new(
                Kem::KEM_X448_HKDF_SHA512,
                Kdf::KDF_HKDF_SHA512,
                Aead::AEAD_AES256GCM,
            ),
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeSuite::new(
                Kem::KEM_P521_HKDF_SHA512,
                Kdf::KDF_HKDF_SHA512,
                Aead::AEAD_AES256GCM,
            ),
            CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HpkeSuite::new(
                Kem::KEM_X448_HKDF_SHA512,
                Kdf::KDF_HKDF_SHA512,
                Aead::AEAD_ChaCha20Poly1305,
            ),
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => HpkeSuite::new(
                Kem::KEM_P384_HKDF_SHA384,
                Kdf::KDF_HKDF_SHA384,
                Aead::AEAD_AES256GCM,
            ),
        }
    }

    pub(crate) fn signature(&self) -> SignatureScheme {
        match *self {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureScheme::Ed25519
            }
            CipherSuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                SignatureScheme::ECDSA_P256_SHA256
            }
            CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => {
                SignatureScheme::ECDSA_P384_SHA384
            }
            CipherSuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                SignatureScheme::ECDSA_P521_SHA512
            }
            CipherSuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
            | CipherSuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureScheme::Ed448
            }
        }
    }

    fn sign_mac(&self, key: &[u8], message: &[u8]) -> hmac::Tag {
        // All cipher suites use HMAC
        self.hash().sign_mac(key, message)
    }

    fn verify_mac(&self, key: &[u8], message: &[u8], tag: &[u8]) -> bool {
        tag == self.sign_mac(key, message).as_ref()
    }

    fn ref_hash(&self, label: &[u8], value: &[u8]) -> Result<digest::Digest> {
        let mut buf = BytesMut::new();
        write_opaque_vec(label, &mut buf)?;
        write_opaque_vec(value, &mut buf)?;
        let input = buf.freeze();
        let h = self.hash();
        Ok(h.digest(&input))
    }

    fn expand_with_label(
        &self,
        _secret: &[u8],
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
        let kdf_label = buf.freeze();
        //TODO(yngrtc):_, kdf, _ := cs.hpke().Params()
        //TODO(yngrtc):return kdf.Expand(secret, kdfLabel, uint(length)), nil
        Ok(kdf_label)
    }

    fn derive_secret(&self, _secret: &[u8], _label: &[u8]) -> Result<Bytes> {
        //TODO(yngrtc):_, kdf, _ := cs.hpke().Params()
        //TODO(yngrtc):return cs.expandWithLabel(secret, label, nil, uint16(kdf.ExtractSize()))
        Ok(Bytes::new())
    }

    fn sign_with_label(&self, sign_key: &[u8], label: &[u8], content: &[u8]) -> Result<Bytes> {
        let sign_content = marshal_sign_content(label, content)?;
        self.signature().sign(sign_key, &sign_content)
    }

    pub(crate) fn verify_with_label(
        &self,
        verify_key: &[u8],
        label: &[u8],
        content: &[u8],
        sign_value: &[u8],
    ) -> bool {
        let sign_content = if let Ok(sign_content) = marshal_sign_content(label, content) {
            sign_content
        } else {
            return false;
        };
        self.signature()
            .verify(verify_key, &sign_content, sign_value)
    }

    fn encrypt_with_label(
        &self,
        _public_key: &[u8],
        label: &[u8],
        context: &[u8],
        _plaintext: &[u8],
    ) -> Result<(Bytes, Bytes)> {
        let encrypt_context = marshal_encrypt_context(label, context)?;

        /*TODO(yngrtc):
        hpke := cs.hpke()
        kem, _, _ := hpke.Params()
        pub, err := kem.Scheme().UnmarshalBinaryPublicKey(public_key)
        if err != nil {
            return nil, nil, err
        }

        sender, err := hpke.NewSender(pub , encrypt_context)
        if err != nil {
            return nil, nil, err
        }

        kemOutput, sealer, err := sender.Setup(rand.Reader)
        if err != nil {
            return nil, nil, err
        }

        ciphertext, err = sealer.Seal(plaintext, nil)
        return kemOutput, ciphertext, err*/
        Ok((encrypt_context.clone(), encrypt_context))
    }

    fn decrypt_with_label(
        &self,
        _private_key: &[u8],
        label: &[u8],
        context: &[u8],
        _kem_output: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Bytes> {
        let encrypt_context = marshal_encrypt_context(label, context)?;

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
        Ok(encrypt_context)
    }
}

fn marshal_sign_content(label: &[u8], content: &[u8]) -> Result<Bytes> {
    let mut mls_label = "MLS 1.0 ".as_bytes().to_vec();
    mls_label.extend_from_slice(label);

    let mut buf = BytesMut::new();
    write_opaque_vec(&mls_label, &mut buf)?;
    write_opaque_vec(content, &mut buf)?;
    Ok(buf.freeze())
}

fn marshal_encrypt_context(label: &[u8], context: &[u8]) -> Result<Bytes> {
    let mut mls_label = "MLS 1.0 ".as_bytes().to_vec();
    mls_label.extend_from_slice(label);

    let mut buf = BytesMut::new();
    write_opaque_vec(&mls_label, &mut buf)?;
    write_opaque_vec(context, &mut buf)?;
    Ok(buf.freeze())
}
