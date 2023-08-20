pub mod ring;
pub mod rust;

use crate::cipher_suite::CipherSuite;
use crate::crypto::{hash::Hash, hpke::Hpke, signature::Signature};
use crate::error::*;

use crate::codec::write_opaque_vec;
use bytes::{BufMut, Bytes, BytesMut};
use std::sync::Arc;

pub const MLS_PREFIX: &str = "MLS 1.0 ";

pub trait CryptoProvider {
    fn supports(&self, cipher_suite: CipherSuite) -> Result<()>;

    fn supported(&self) -> Vec<CipherSuite>;

    fn hash(&self, cipher_suite: CipherSuite) -> Arc<dyn Hash>;

    fn hpke(&self, cipher_suite: CipherSuite) -> Arc<dyn Hpke>;

    fn signature(&self, cipher_suite: CipherSuite) -> Arc<dyn Signature>;

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
        _cipher_suite: CipherSuite,
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

    fn derive_secret(
        &self,
        _cipher_suite: CipherSuite,
        _secret: &[u8],
        _label: &[u8],
    ) -> Result<Bytes> {
        //TODO(yngrtc):_, kdf, _ := cs.hpke().Params()
        //TODO(yngrtc):return cs.expandWithLabel(secret, label, nil, uint16(kdf.ExtractSize()))
        Ok(Bytes::new())
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
        _cipher_suite: CipherSuite,
        _public_key: &[u8],
        label: &[u8],
        context: &[u8],
        _plaintext: &[u8],
    ) -> Result<(Bytes, Bytes)> {
        let encrypt_context = mls_prefix_label_data(label, context)?;

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
        _cipher_suite: CipherSuite,
        _private_key: &[u8],
        label: &[u8],
        context: &[u8],
        _kem_output: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Bytes> {
        let encrypt_context = mls_prefix_label_data(label, context)?;

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

fn mls_prefix_label_data(label: &[u8], data: &[u8]) -> Result<Bytes> {
    let mut mls_label = MLS_PREFIX.as_bytes().to_vec();
    mls_label.extend_from_slice(label);

    let mut buf = BytesMut::new();
    write_opaque_vec(&mls_label, &mut buf)?;
    write_opaque_vec(data, &mut buf)?;
    Ok(buf.freeze())
}
