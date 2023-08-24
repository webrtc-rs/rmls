pub mod external;
mod group_info;
pub mod proposal;

/*

type commit struct {
    proposals []proposalOrRef
    path      *updatePath // optional
}

func (c *commit) unmarshal(s *cryptobyte.String) error {
    *c = commit{}

    err := readVector(s, func(s *cryptobyte.String) error {
        var propOrRef proposalOrRef
        if err := propOrRef.unmarshal(s); err != nil {
            return err
        }
        c.proposals = append(c.proposals, propOrRef)
        return nil
    })
    if err != nil {
        return err
    }

    var hasPath bool
    if !readOptional(s, &hasPath) {
        return io.ErrUnexpectedEOF
    } else if hasPath {
        c.path = new(updatePath)
        if err := c.path.unmarshal(s); err != nil {
            return err
        }
    }

    return nil
}

func (c *commit) marshal(b *cryptobyte.Builder) {
    writeVector(b, len(c.proposals), func(b *cryptobyte.Builder, i int) {
        c.proposals[i].marshal(b)
    })
    writeOptional(b, c.path != nil)
    if c.path != nil {
        c.path.marshal(b)
    }
}

// verifyProposalList ensures that a list of proposals passes the checks for a
// regular commit described in section 12.2.
//
// It does not perform all checks:
//
//   - It does not check the validity of individual proposals (section 12.1).
//   - It does not check whether members in add proposals are already part of
//     the group.
//   - It does not check whether non-default proposal types are supported by
//     all members of the group who will process the commit.
//   - It does not check whether the ratchet tree is valid after processing the
//     commit.
func verifyProposalList(proposals []proposal, senders []leafIndex, committer leafIndex) error {
    if len(proposals) != len(senders) {
        panic("unreachable")
    }

    add := make(map[string]struct{})
    updateOrRemove := make(map[leafIndex]struct{})
    psk := make(map[string]struct{})
    groupContextExtensions := false
    for i, prop := range proposals {
        sender := senders[i]

        switch prop.proposalType {
        case proposalTypeAdd:
            k := string(prop.add.key_package.leaf_node.signatureKey)
            if _, dup := add[k]; dup {
                return fmt.Errorf("mls: multiple add proposals have the same signature key")
            }
            add[k] = struct{}{}
        case proposalTypeUpdate:
            if sender == committer {
                return fmt.Errorf("mls: update proposal generated by the committer")
            }
            if _, dup := updateOrRemove[sender]; dup {
                return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
            }
            updateOrRemove[sender] = struct{}{}
        case proposalTypeRemove:
            if prop.remove.removed == committer {
                return fmt.Errorf("mls: remove proposal removes the committer")
            }
            if _, dup := updateOrRemove[prop.remove.removed]; dup {
                return fmt.Errorf("mls: multiple update and/or remove proposals apply to the same leaf")
            }
            updateOrRemove[prop.remove.removed] = struct{}{}
        case proposalTypePSK:
            b, err := marshal(&prop.preSharedKey.psk)
            if err != nil {
                return err
            }
            k := string(b)
            if _, dup := psk[k]; dup {
                return fmt.Errorf("mls: multiple PSK proposals reference the same PSK ID")
            }
            psk[k] = struct{}{}
        case proposalTypeGroupContextExtensions:
            if groupContextExtensions {
                return fmt.Errorf("mls: multiple group context extensions proposals")
            }
            groupContextExtensions = true
        case proposalTypeReinit:
            if len(proposals) > 1 {
                return fmt.Errorf("mls: reinit proposal together with any other proposal")
            }
        case proposalTypeExternalInit:
            return fmt.Errorf("mls: external init proposal is not allowed")
        }
    }
    return nil
}

func proposalListNeedsPath(proposals []proposal) bool {
    if len(proposals) == 0 {
        return true
    }

    for _, prop := range proposals {
        switch prop.proposalType {
        case proposalTypeUpdate, proposalTypeRemove, proposalTypeExternalInit, proposalTypeGroupContextExtensions:
            return true
        }
    }

    return false
}


type welcome struct {
    cipher_suite        cipher_suite
    secrets            []encryptedGroupSecrets
    encryptedGroupInfo []byte
}

func (w *welcome) unmarshal(s *cryptobyte.String) error {
    *w = welcome{}

    if !s.ReadUint16((*uint16)(&w.cipher_suite)) {
        return io.ErrUnexpectedEOF
    }

    err := readVector(s, func(s *cryptobyte.String) error {
        var sec encryptedGroupSecrets
        if err := sec.unmarshal(s); err != nil {
            return err
        }
        w.secrets = append(w.secrets, sec)
        return nil
    })
    if err != nil {
        return err
    }

    if !readOpaqueVec(s, &w.encryptedGroupInfo) {
        return io.ErrUnexpectedEOF
    }

    return nil
}

func (w *welcome) marshal(b *cryptobyte.Builder) {
    b.AddUint16(uint16(w.cipher_suite))
    writeVector(b, len(w.secrets), func(b *cryptobyte.Builder, i int) {
        w.secrets[i].marshal(b)
    })
    writeOpaqueVec(b, w.encryptedGroupInfo)
}

func (w *welcome) findSecret(ref keyPackageRef) *encryptedGroupSecrets {
    for i, sec := range w.secrets {
        if sec.newMember.Equal(ref) {
            return &w.secrets[i]
        }
    }
    return nil
}

func (w *welcome) decryptGroupSecrets(ref keyPackageRef, initKeyPriv []byte) (*groupSecrets, error) {
    cs := w.cipher_suite

    sec := w.findSecret(ref)
    if sec == nil {
        return nil, fmt.Errorf("mls: encrypted group secrets not found for provided key package ref")
    }

    rawGroupSecrets, err := cs.decryptWithLabel(initKeyPriv, []byte("Welcome"), w.encryptedGroupInfo, sec.encryptedGroupSecrets.kem_output, sec.encryptedGroupSecrets.ciphertext)
    if err != nil {
        return nil, err
    }
    var groupSecrets groupSecrets
    if err := unmarshal(rawGroupSecrets, &groupSecrets); err != nil {
        return nil, err
    }

    return &groupSecrets, err
}

func (w *welcome) decryptGroupInfo(joinerSecret, pskSecret []byte) (*groupInfo, error) {
    cs := w.cipher_suite
    _, _, aead := cs.hpke().Params()

    welcomeSecret, err := extractWelcomeSecret(cs, joinerSecret, pskSecret)
    if err != nil {
        return nil, err
    }

    welcomeNonce, err := cs.expandWithLabel(welcomeSecret, []byte("nonce"), nil, uint16(aead.NonceSize()))
    if err != nil {
        return nil, err
    }
    welcomeKey, err := cs.expandWithLabel(welcomeSecret, []byte("key"), nil, uint16(aead.KeySize()))
    if err != nil {
        return nil, err
    }

    welcomeCipher, err := aead.New(welcomeKey)
    if err != nil {
        return nil, err
    }
    rawGroupInfo, err := welcomeCipher.Open(nil, welcomeNonce, w.encryptedGroupInfo, nil)
    if err != nil {
        return nil, err
    }

    var groupInfo groupInfo
    if err := unmarshal(rawGroupInfo, &groupInfo); err != nil {
        return nil, err
    }

    return &groupInfo, nil
}

type encryptedGroupSecrets struct {
    newMember             keyPackageRef
    encryptedGroupSecrets hpkeCiphertext
}

func (sec *encryptedGroupSecrets) unmarshal(s *cryptobyte.String) error {
    *sec = encryptedGroupSecrets{}
    if !readOpaqueVec(s, (*[]byte)(&sec.newMember)) {
        return io.ErrUnexpectedEOF
    }
    if err := sec.encryptedGroupSecrets.unmarshal(s); err != nil {
        return err
    }
    return nil
}

func (sec *encryptedGroupSecrets) marshal(b *cryptobyte.Builder) {
    writeOpaqueVec(b, []byte(sec.newMember))
    sec.encryptedGroupSecrets.marshal(b)
}
*/
