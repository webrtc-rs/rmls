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
    #[error("invalid leaf node source {0}")]
    InvalidLeafNodeSource(u8),
    #[error("invalid proposal type {0}")]
    InvalidProposalType(u16),
    #[error("invalid credential type {0}")]
    InvalidCredentialType(u16),
    #[error("invalid content type {0}")]
    InvalidContentType(u8),
    #[error("invalid leaf node source with null lifetime")]
    InvalidLeafNodeSourceWithNullLifetime,
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
    #[error("invalid node type {0}")]
    InvalidNodeType(u8),
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
    #[error("invalid Ed25519 private key size")]
    InvalidEd25519PrivateKeySize,
    #[error("invalid Ed25519 public key size")]
    InvalidEd25519PublicKeySize,
    #[error("invalid Ed25519 signature size")]
    InvalidEd25519SignatureSize,

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
