use super::*;

const PLAINTEXT: &[u8] = b"38a6b327573639d654b5b729336cf74d01728cf4fa9af81a0ef1814ffc1d492f";

fn test_signature_key_pair_with_crypto_provider(
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for c in 1..=7u16 {
        let cipher_suite: CipherSuite = c.into();
        if crypto_provider.supports(cipher_suite) {
            let signature = crypto_provider.signature(cipher_suite)?;
            let key_pair = signature.generate_key_pair()?;
            let out = signature.sign(key_pair.private_key(), PLAINTEXT)?;
            assert!(signature
                .verify(key_pair.public_key(), PLAINTEXT, &out)
                .is_ok());
        }
    }

    Ok(())
}

#[test]
fn test_signature_key_pair() -> Result<()> {
    #[cfg(feature = "RingCryptoProvider")]
    test_signature_key_pair_with_crypto_provider(&RingCryptoProvider::default())?;
    #[cfg(feature = "RustCryptoProvider")]
    test_signature_key_pair_with_crypto_provider(&RustCryptoProvider::default())?;

    Ok(())
}
