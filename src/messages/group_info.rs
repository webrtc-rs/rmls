/*
type groupInfo struct {
    groupContext    groupContext
    extensions      []extension
    confirmationTag []byte
    signer          leafIndex
    signature       []byte
}

func (info *groupInfo) unmarshal(s *cryptobyte.String) error {
    *info = groupInfo{}

    if err := info.groupContext.unmarshal(s); err != nil {
        return err
    }

    exts, err := unmarshalExtensionVec(s)
    if err != nil {
        return err
    }
    info.extensions = exts

    if !readOpaqueVec(s, &info.confirmationTag) || !s.ReadUint32((*uint32)(&info.signer)) || !readOpaqueVec(s, &info.signature) {
        return err
    }

    return nil
}

func (info *groupInfo) marshal(b *cryptobyte.Builder) {
    (*groupInfoTBS)(info).marshal(b)
    writeOpaqueVec(b, info.signature)
}

func (info *groupInfo) verifySignature(signerPub signaturePublicKey) bool {
    cs := info.groupContext.cipher_suite
    tbs, err := marshal((*groupInfoTBS)(info))
    if err != nil {
        return false
    }
    return cs.verifyWithLabel([]byte(signerPub), []byte("GroupInfoTBS"), tbs, info.signature)
}

func (info *groupInfo) verifyConfirmationTag(joinerSecret, pskSecret []byte) bool {
    cs := info.groupContext.cipher_suite
    epochSecret, err := info.groupContext.extractEpochSecret(joinerSecret, pskSecret)
    if err != nil {
        return false
    }
    confirmationKey, err := cs.deriveSecret(epochSecret, secretLabelConfirm)
    if err != nil {
        return false
    }
    return cs.verifyMAC(confirmationKey, info.groupContext.confirmedTranscriptHash, info.confirmationTag)
}

type groupInfoTBS groupInfo

func (info *groupInfoTBS) marshal(b *cryptobyte.Builder) {
    info.groupContext.marshal(b)
    marshalExtensionVec(b, info.extensions)
    writeOpaqueVec(b, info.confirmationTag)
    b.AddUint32(uint32(info.signer))
}

type groupSecrets struct {
    joinerSecret []byte
    pathSecret   []byte // optional
    psks         []preSharedKeyID
}

func (sec *groupSecrets) unmarshal(s *cryptobyte.String) error {
    *sec = groupSecrets{}

    if !readOpaqueVec(s, &sec.joinerSecret) {
        return io.ErrUnexpectedEOF
    }

    var hasPathSecret bool
    if !readOptional(s, &hasPathSecret) {
        return io.ErrUnexpectedEOF
    } else if hasPathSecret && !readOpaqueVec(s, &sec.pathSecret) {
        return io.ErrUnexpectedEOF
    }

    return readVector(s, func(s *cryptobyte.String) error {
        var psk preSharedKeyID
        if err := psk.unmarshal(s); err != nil {
            return err
        }
        sec.psks = append(sec.psks, psk)
        return nil
    })
}

func (sec *groupSecrets) marshal(b *cryptobyte.Builder) {
    writeOpaqueVec(b, sec.joinerSecret)

    writeOptional(b, sec.pathSecret != nil)
    if sec.pathSecret != nil {
        writeOpaqueVec(b, sec.pathSecret)
    }

    writeVector(b, len(sec.psks), func(b *cryptobyte.Builder, i int) {
        sec.psks[i].marshal(b)
    })
}

// verifySingleReInitOrBranchPSK verifies that at most one key has type
// resumption with usage reinit or branch.
func (sec *groupSecrets) verifySingleReinitOrBranchPSK() bool {
    n := 0
    for _, pskID := range sec.psks {
        if pskID.pskType != pskTypeResumption {
            continue
        }
        switch pskID.usage {
        case resumptionPSKUsageReinit, resumptionPSKUsageBranch:
            n++
        }
    }
    return n <= 1
}
*/
