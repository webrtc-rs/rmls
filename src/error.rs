#![allow(dead_code)]

use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("invalid variable length integer prefix")]
    InvalidVariableLengthIntegerPrefix,
    #[error("minimum encoding was not used")]
    MinimumEncodingWasNotUsed,
    #[error("varint exceeds 30 bits")]
    VarintExceeds30Bits,
    #[error("opaque size exceeds maximum value of uint32")]
    OpaqueSizeExceedsMaximumValueOfU32,
    #[error("invalid optional value")]
    InvalidOptionalValue,
    #[error("input contains {0} excess bytes")]
    InputContainsExcessBytes(usize),
    #[error("invalid sibling")]
    InvalidSibling,
    #[error("invalid leaf node source value {0}")]
    InvalidLeafNodeSourceValue(u8),
    #[error("invalid extension type value {0}")]
    InvalidExtensionTypeValue(u16),
    #[error("invalid proposal type value {0}")]
    InvalidProposalTypeValue(u16),
    #[error("invalid credential type value")]
    InvalidCredentialTypeValue,
    #[error("invalid content type value {0}")]
    InvalidContentTypeValue(u8),
    #[error("invalid resumption PSK usage value {0}")]
    InvalidResumptionPSKUsageValue(u8),
    #[error("invalid PSK type value {0}")]
    InvalidPskTypeValue(u8),
    #[error("invalid sender type value {0}")]
    InvalidSenderTypeValue(u8),
    #[error("invalid wire format value {0}")]
    InvalidWireFormatValue(u16),
    #[error("invalid cipher suite value {0}")]
    InvalidCipherSuiteValue(u16),
    #[error("leaf node signature verification failed")]
    LeafNodeSignatureVerificationFailed,
    #[error("credential type {0} used by leaf node not supported by all members")]
    CredentialTypeUsedByLeafNodeNotSupportedByAllMembers(u16),
    #[error("lifetime verification failed")]
    LifetimeVerificationFailed,
    #[error("extension type {0} used by leaf node not supported by that leaf node")]
    ExtensionTypeUsedByLeafNodeNotSupportedByThatLeafNode(u16),
    #[error("duplicate signature key in ratchet tree")]
    DuplicateSignatureKeyInRatchetTree,
    #[error("duplicate encryption key in ratchet tree")]
    DuplicateEncryptionKeyInRatchetTree,
    #[error("invalid node type value {0}")]
    InvalidNodeTypeValue(u8),
    #[error("invalid leaf node")]
    InvalidLeafNode,
    #[error("invalid parent node")]
    InvalidParentNode,
    #[error("invalid children")]
    InvalidChildren,
    #[error("tree hash verification failed")]
    TreeHashVerificationFailed,
    #[error("parent hashes verification failed")]
    ParentHashesVerificationFailed,
    #[error("unmerged leaf is not a descendant of the parent node")]
    UnmergedLeafIsNotDescendantOfTheParentNode,
    #[error("non-blank intermediate node is missing unmerged leaf")]
    NonBlankIntermediateNodeMissingUnmergedLeaf,
    #[error("updatePath and filtered direct path has different node")]
    UpdatePathAndFilteredDirectPathHasDifferentNode,
    #[error("parent hash mismatch for update path's leaf node")]
    ParentHashMismatchForUpdatePathLeafNode,
    #[error("invalid Ed25519 private key")]
    InvalidEd25519PrivateKey,
    #[error("invalid ECDSA private key")]
    InvalidECDSAPrivateKey,
    #[error("unsupported Ecdsa")]
    UnsupportedEcdsa,
    #[error("unsupported Ed448")]
    UnsupportedEd448,
    #[error("RingCrypto error {0}")]
    RingCryptoError(String),
    #[error("RustCrypto error {0}")]
    RustCryptoError(String),
    #[error("Hpke error {0}")]
    HpkeError(String),
    #[error("unsupported CipherSuite")]
    UnsupportedCipherSuite,
    #[error("unsupported HKPE KEM")]
    UnsupportedHkpeKem,
    #[error("key package version doesn't match group context")]
    KeyPackageVersionNotMatchGroupContext,
    #[error("cipher suite doesn't match group context")]
    CipherSuiteNotMatchGroupContext,
    #[error("key package contains a leaf node with an invalid source")]
    KeyPackageContainsLeafNodeWithInvalidSource,
    #[error("invalid key package signature")]
    InvalidKeyPackageSignature,
    #[error("key package encryption key and init key are identical")]
    KeyPackageEncryptionKeyAndInitKeyIdentical,

    #[error("parse int: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("{0}")]
    Io(#[source] IoError),
    #[error("utf8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("{0}")]
    Std(#[source] StdError),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("{0}")]
    Sec1(#[source] sec1::Error),
    #[error("{0}")]
    Ecdsa(#[source] ecdsa::Error),
    #[error("{0}")]
    SignatureDigest(#[source] signature::digest::InvalidLength),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(IoError(e))
    }
}

/// An escape hatch to preserve stack traces when we don't know the error.
///
/// This crate exports some traits such as `Conn` and `Listener`. The trait functions
/// produce the local error `util::Error`. However when used in crates higher up the stack,
/// we are forced to handle errors that are local to that crate. For example we use
/// `Listener` the `dtls` crate and it needs to handle `dtls::Error`.
///
/// By using `util::Error::from_std` we can preserve the underlying error (and stack trace!).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StdError(pub Box<dyn std::error::Error + Send + Sync>);

impl From<sec1::Error> for Error {
    fn from(e: sec1::Error) -> Self {
        Error::Sec1(e)
    }
}

impl From<ecdsa::Error> for Error {
    fn from(e: ecdsa::Error) -> Self {
        Error::Ecdsa(e)
    }
}

impl From<signature::digest::InvalidLength> for Error {
    fn from(e: signature::digest::InvalidLength) -> Self {
        Error::SignatureDigest(e)
    }
}
