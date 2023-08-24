use crate::cipher_suite::CipherSuite;
use crate::codec::*;
use crate::error::*;
use crate::framing::{GroupID, ProtocolVersion, PROTOCOL_VERSION_MLS10};
use crate::tree::{read_extensions, write_extensions, Extension};

use crate::crypto::provider::CryptoProvider;
use bytes::{Buf, BufMut, Bytes};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct GroupContext {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) group_id: GroupID,
    pub(crate) epoch: u64,
    pub(crate) tree_hash: Bytes,
    pub(crate) confirmed_transcript_hash: Bytes,
    pub(crate) extensions: Vec<Extension>,
}

impl Reader for GroupContext {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }

        self.version = buf.get_u16();
        self.cipher_suite = buf.get_u16().try_into()?;
        self.group_id = read_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        self.epoch = buf.get_u64();
        self.tree_hash = read_opaque_vec(buf)?;
        self.confirmed_transcript_hash = read_opaque_vec(buf)?;

        if self.version != PROTOCOL_VERSION_MLS10 {
            return Err(Error::InvalidProposalTypeValue(self.version));
        }

        self.extensions = read_extensions(buf)?;

        Ok(())
    }
}
impl Writer for GroupContext {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version);
        buf.put_u16(self.cipher_suite as u16);
        write_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        write_opaque_vec(&self.tree_hash, buf)?;
        write_opaque_vec(&self.confirmed_transcript_hash, buf)?;
        write_extensions(&self.extensions, buf)
    }
}

impl GroupContext {
    fn extract_joiner_secret(
        &self,
        crypto_provider: &impl CryptoProvider,
        prev_init_secret: &[u8],
        commit_secret: &[u8],
    ) -> Result<Bytes> {
        let cipher_suite = self.cipher_suite;
        let extracted = crypto_provider
            .hpke(cipher_suite)
            .kdf_extract(commit_secret, prev_init_secret)?;

        let raw_group_context = write(self)?;
        let extract_size = crypto_provider.hpke(cipher_suite).kdf_extract_size() as u16;

        crypto_provider.expand_with_label(
            cipher_suite,
            &extracted,
            b"joiner",
            &raw_group_context,
            extract_size,
        )
    }

    fn extract_epoch_secret(
        &self,
        crypto_provider: &impl CryptoProvider,
        joiner_secret: &[u8],
        psk_secret: &[u8],
    ) -> Result<Bytes> {
        let cipher_suite = self.cipher_suite;

        // TODO de-duplicate with extractWelcomeSecret
        if psk_secret.is_empty() {
            //psk_secret = make([]byte, kdf.ExtractSize())
        }
        let extracted = crypto_provider
            .hpke(cipher_suite)
            .kdf_extract(psk_secret, joiner_secret)?;

        let raw_group_context = write(self)?;
        let extract_size = crypto_provider.hpke(cipher_suite).kdf_extract_size() as u16;

        crypto_provider.expand_with_label(
            cipher_suite,
            &extracted,
            b"epoch",
            &raw_group_context,
            extract_size,
        )
    }
}
/*
func extractWelcomeSecret(cs cipherSuite, joinerSecret, pskSecret []byte) ([]byte, error) {
    _, kdf, _ := cs.hpke().Params()

    if pskSecret == nil {
        pskSecret = make([]byte, kdf.ExtractSize())
    }
    extracted := kdf.Extract(pskSecret, joinerSecret)

    return cs.deriveSecret(extracted, []byte("welcome"))
}

var (
    secretLabelInit           = []byte("init")
    secretLabelSenderData     = []byte("sender data")
    secretLabelEncryption     = []byte("encryption")
    secretLabelExporter       = []byte("exporter")
    secretLabelExternal       = []byte("external")
    secretLabelConfirm        = []byte("confirm")
    secretLabelMembership     = []byte("membership")
    secretLabelResumption     = []byte("resumption")
    secretLabelAuthentication = []byte("authentication")
)

type confirmedTranscriptHashInput struct {
    wireFormat wireFormat
    content    framedContent
    signature  []byte
}

func (input *confirmedTranscriptHashInput) marshal(b *cryptobyte.Builder) {
    if input.content.contentType != contentTypeCommit {
        b.SetError(fmt.Errorf("mls: confirmedTranscriptHashInput can only contain contentTypeCommit"))
        return
    }
    input.wireFormat.marshal(b)
    input.content.marshal(b)
    writeOpaqueVec(b, input.signature)
}

func (input *confirmedTranscriptHashInput) hash(cs cipherSuite, interimTranscriptHashBefore []byte) ([]byte, error) {
    rawInput, err := marshal(input)
    if err != nil {
        return nil, err
    }

    h := cs.hash().New()
    h.Write(interimTranscriptHashBefore)
    h.Write(rawInput)
    return h.Sum(nil), nil
}

func nextInterimTranscriptHash(cs cipherSuite, confirmedTranscriptHash, confirmationTag []byte) ([]byte, error) {
    var b cryptobyte.Builder
    writeOpaqueVec(&b, confirmationTag)
    rawInput, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    h := cs.hash().New()
    h.Write(confirmedTranscriptHash)
    h.Write(rawInput)
    return h.Sum(nil), nil
}

type pskType uint8

const (
    pskTypeExternal   pskType = 1
    pskTypeResumption pskType = 2
)

func (t *pskType) unmarshal(s *cryptobyte.String) error {
    if !s.ReadUint8((*uint8)(t)) {
        return io.ErrUnexpectedEOF
    }
    switch *t {
    case pskTypeExternal, pskTypeResumption:
        return nil
    default:
        return fmt.Errorf("mls: invalid PSK type %d", *t)
    }
}

func (t pskType) marshal(b *cryptobyte.Builder) {
    b.AddUint8(uint8(t))
}

type resumptionPSKUsage uint8

const (
    resumptionPSKUsageApplication resumptionPSKUsage = 1
    resumptionPSKUsageReinit      resumptionPSKUsage = 2
    resumptionPSKUsageBranch      resumptionPSKUsage = 3
)

func (usage *resumptionPSKUsage) unmarshal(s *cryptobyte.String) error {
    if !s.ReadUint8((*uint8)(usage)) {
        return io.ErrUnexpectedEOF
    }
    switch *usage {
    case resumptionPSKUsageApplication, resumptionPSKUsageReinit, resumptionPSKUsageBranch:
        return nil
    default:
        return fmt.Errorf("mls: invalid resumption PSK usage %d", *usage)
    }
}

func (usage resumptionPSKUsage) marshal(b *cryptobyte.Builder) {
    b.AddUint8(uint8(usage))
}

type preSharedKeyID struct {
    pskType pskType

    // for pskTypeExternal
    pskID []byte

    // for pskTypeResumption
    usage      resumptionPSKUsage
    pskGroupID GroupID
    pskEpoch   uint64

    pskNonce []byte
}

func (id *preSharedKeyID) unmarshal(s *cryptobyte.String) error {
    *id = preSharedKeyID{}

    if err := id.pskType.unmarshal(s); err != nil {
        return err
    }

    switch id.pskType {
    case pskTypeExternal:
        if !readOpaqueVec(s, &id.pskID) {
            return io.ErrUnexpectedEOF
        }
    case pskTypeResumption:
        if err := id.usage.unmarshal(s); err != nil {
            return err
        }
        if !readOpaqueVec(s, (*[]byte)(&id.pskGroupID)) || !s.ReadUint64(&id.pskEpoch) {
            return io.ErrUnexpectedEOF
        }
    default:
        panic("unreachable")
    }

    if !readOpaqueVec(s, &id.pskNonce) {
        return io.ErrUnexpectedEOF
    }

    return nil
}

func (id *preSharedKeyID) marshal(b *cryptobyte.Builder) {
    id.pskType.marshal(b)
    switch id.pskType {
    case pskTypeExternal:
        writeOpaqueVec(b, id.pskID)
    case pskTypeResumption:
        id.usage.marshal(b)
        writeOpaqueVec(b, []byte(id.pskGroupID))
        b.AddUint64(id.pskEpoch)
    default:
        panic("unreachable")
    }
    writeOpaqueVec(b, id.pskNonce)
}

func extractPSKSecret(cs cipherSuite, pskIDs []preSharedKeyID, psks [][]byte) ([]byte, error) {
    if len(pskIDs) != len(psks) {
        return nil, fmt.Errorf("mls: got %v PSK IDs and %v PSKs, want same number", len(pskIDs), len(psks))
    }

    _, kdf, _ := cs.hpke().Params()
    zero := make([]byte, kdf.ExtractSize())

    pskSecret := zero
    for i := range pskIDs {
        pskExtracted := kdf.Extract(psks[i], zero)

        pskLabel := pskLabel{
            id:    pskIDs[i],
            index: uint16(i),
            count: uint16(len(pskIDs)),
        }
        rawPSKLabel, err := marshal(&pskLabel)
        if err != nil {
            return nil, err
        }

        pskInput, err := cs.expandWithLabel(pskExtracted, []byte("derived psk"), rawPSKLabel, uint16(kdf.ExtractSize()))
        if err != nil {
            return nil, err
        }

        pskSecret = kdf.Extract(pskSecret, pskInput)
    }

    return pskSecret, nil
}

type pskLabel struct {
    id    preSharedKeyID
    index uint16
    count uint16
}

func (label *pskLabel) marshal(b *cryptobyte.Builder) {
    label.id.marshal(b)
    b.AddUint16(label.index)
    b.AddUint16(label.count)
}
*/
