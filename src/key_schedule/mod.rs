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

        // TODO de-duplicate with extract_welcome_secret

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

fn extract_welcome_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    joiner_secret: &[u8],
    psk_secret: &[u8],
) -> Result<Bytes> {
    let extracted = crypto_provider
        .hpke(cipher_suite)
        .kdf_extract(psk_secret, joiner_secret)?;

    crypto_provider.derive_secret(cipher_suite, &extracted, b"welcome")
}

const SECRET_LABEL_INIT: &[u8] = b"init";
const SECRET_LABEL_SENDER_DATA: &[u8] = b"sender data";
const SECRET_LABEL_ENCRYPTION: &[u8] = b"encryption";
const SECRET_LABEL_EXPORTER: &[u8] = b"exporter";
const SECRET_LABEL_EXTERNAL: &[u8] = b"external";
const SECRET_LABEL_CONFIRM: &[u8] = b"confirm";
const SECRET_LABEL_MEMBERSHIP: &[u8] = b"membership";
const SECRET_LABEL_RESUMPTION: &[u8] = b"resumption";
const SECRET_LABEL_AUTHENTICATION: &[u8] = b"authentication";
/*
struct confirmedTranscriptHashInput {
    WireFormat: WireFormat,
    content: FramedContent,
    signature: Bytes,
}

impl Writer for confirmedTranscriptHashInput {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
    if input.content.contentType != contentTypeCommit {
        b.SetError(fmt.Errorf("mls: confirmedTranscriptHashInput can only contain contentTypeCommit"))
        return
    }
    input.WireFormat.marshal(b)
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
}*/

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
enum ResumptionPSKUsage {
    #[default]
    Application = 1,
    Reinit = 2,
    Branch = 3,
}

impl TryFrom<u8> for ResumptionPSKUsage {
    type Error = Error;

    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        match v {
            0x01 => Ok(ResumptionPSKUsage::Application),
            0x02 => Ok(ResumptionPSKUsage::Reinit),
            0x03 => Ok(ResumptionPSKUsage::Branch),
            _ => Err(Error::InvalidResumptionPSKUsageValue(v)),
        }
    }
}

impl Reader for ResumptionPSKUsage {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        *self = buf.get_u8().try_into()?;
        Ok(())
    }
}
impl Writer for ResumptionPSKUsage {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u8(*self as u8);
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
struct Resumption {
    usage: ResumptionPSKUsage,
    psk_group_id: GroupID,
    psk_epoch: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Psk {
    External(Bytes),        //  = 1,
    Resumption(Resumption), //  = 2,
}

impl Default for Psk {
    fn default() -> Self {
        Psk::External(Bytes::new())
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct PreSharedKeyID {
    psk: Psk,
    psk_nonce: Bytes,
}

impl Reader for PreSharedKeyID {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let v = buf.get_u8();
        match v {
            1 => {
                self.psk = Psk::External(read_opaque_vec(buf)?);
            }
            2 => {
                let mut resumption = Resumption::default();
                resumption.usage.read(buf)?;
                resumption.psk_group_id = read_opaque_vec(buf)?;
                if buf.remaining() < 8 {
                    return Err(Error::BufferTooSmall);
                }
                resumption.psk_epoch = buf.get_u64();
                self.psk = Psk::Resumption(resumption);
            }
            _ => return Err(Error::InvalidPskTypeValue(v)),
        }

        self.psk_nonce = read_opaque_vec(buf)?;

        Ok(())
    }
}
impl Writer for PreSharedKeyID {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match &self.psk {
            Psk::External(psk_id) => {
                buf.put_u8(1);
                write_opaque_vec(psk_id, buf)?;
            }
            Psk::Resumption(resumption) => {
                buf.put_u8(2);

                resumption.usage.write(buf)?;
                write_opaque_vec(&resumption.psk_group_id, buf)?;
                buf.put_u64(resumption.psk_epoch);
            }
        }

        write_opaque_vec(&self.psk_nonce, buf)
    }
}

/*
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
}*/
/*
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
