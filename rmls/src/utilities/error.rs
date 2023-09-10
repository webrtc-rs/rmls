//! RMLS Errors

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
    #[error("invalid signature scheme value {0}")]
    InvalidSignatureSchemeValue(u16),
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
    #[error("invalid ProposalOrRef value {0}")]
    InvalidProposalOrRefValue(u8),
    #[error("invalid wire format value {0}")]
    InvalidWireFormatValue(u16),
    #[error("invalid cipher suite value {0}")]
    InvalidCipherSuiteValue(u16),
    #[error("leaf node signature verification failed")]
    LeafNodeSignatureVerificationFailed,
    #[error("verify confirmation tag failed")]
    VerifyConfirmationTagFailed,
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
    #[error("unsupported Kem")]
    UnsupportedKem,
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
    #[error("cipher suite doesn't match signature scheme")]
    CipherSuiteNotMatchSignatureScheme,
    #[error("key package contains a leaf node with an invalid source")]
    KeyPackageContainsLeafNodeWithInvalidSource,
    #[error("invalid key package signature")]
    InvalidKeyPackageSignature,
    #[error("key package encryption key and init key are identical")]
    KeyPackageEncryptionKeyAndInitKeyIdentical,
    #[error("Proposals len not match senders len")]
    ProposalsLenNotMatchSendersLen,
    #[error("multiple add proposals have the same signature key")]
    MultipleAddProposalsHaveTheSameSignatureKey,
    #[error("update proposal generated by the committer")]
    UpdateProposalGeneratedByTheCommitter,
    #[error("multiple update and/or remove proposals apply to the same leaf")]
    MultipleUpdateRemoveProposalsApplyToTheSameLeaf,
    #[error("remove proposal removes the committer")]
    RemoveProposalRemovesTheCommitter,
    #[error("multiple PSK proposals reference the same PSK ID")]
    MultiplePSKProposalsReferenceTheSamePSKId,
    #[error("multiple group context extensions proposals")]
    MultipleGroupContextExtensionsProposals,
    #[error("reinit proposal together with any other proposal")]
    ReinitProposalTogetherWithAnyOtherProposal,
    #[error("external init proposal is not allowed")]
    ExternalInitProposalNotAllowed,
    #[error("encrypted group secrets not found for provided key package ref")]
    EncryptedGroupSecretsNotFoundForProvidedKeyPackageRef,
    #[error("PSK IDs and PSKs len doesn't match")]
    PskIDsAndPskLenNotMatch,
    #[error("ConfirmedTranscriptHashInput can only contain Content::Commit")]
    ConfirmedTranscriptHashInputContainContentCommitOnly,
    #[error("senderTypeMember and senderTypeNewMemberCommit should have GroupContext")]
    SenderMemberAndNewMemberCommitNoGroupContext,
    #[error("nonce and reuse_guard len not match")]
    NonceAndReuseGuardLenNotMatch,
    #[error("padding contains non-zero bytes")]
    PaddingContainsNonZeroBytes,
    #[error("invalid protocol version {0}")]
    InvalidProtocolVersion(u16),

    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[cfg(feature = "RustCryptoProvider")]
    #[error("{0}")]
    Sec1(#[source] sec1::Error),
    #[cfg(feature = "RustCryptoProvider")]
    #[error("{0}")]
    Ecdsa(#[source] ecdsa::Error),
    #[cfg(feature = "RustCryptoProvider")]
    #[error("{0}")]
    SignatureDigest(#[source] signature::digest::InvalidLength),

    #[error("{0}")]
    Other(String),
}

#[cfg(feature = "RustCryptoProvider")]
impl From<sec1::Error> for Error {
    fn from(e: sec1::Error) -> Self {
        Error::Sec1(e)
    }
}

#[cfg(feature = "RustCryptoProvider")]
impl From<ecdsa::Error> for Error {
    fn from(e: ecdsa::Error) -> Self {
        Error::Ecdsa(e)
    }
}

#[cfg(feature = "RustCryptoProvider")]
impl From<signature::digest::InvalidLength> for Error {
    fn from(e: signature::digest::InvalidLength) -> Self {
        Error::SignatureDigest(e)
    }
}
