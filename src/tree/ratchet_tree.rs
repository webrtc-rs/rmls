/*
type ratchetTree []*node

func (tree *ratchetTree) unmarshal(s *cryptobyte.String) error {
    *tree = ratchetTree{}
    err := readVector(s, func(s *cryptobyte.String) error {
        var n *node
        var hasNode bool
        if !readOptional(s, &hasNode) {
            return io.ErrUnexpectedEOF
        } else if hasNode {
            n = new(node)
            if err := n.unmarshal(s); err != nil {
                return err
            }
        }
        *tree = append(*tree, n)
        return nil
    })
    if err != nil {
        return err
    }

    // The raw tree doesn't include blank nodes at the end, fill it until next
    // power of 2
    for !isPowerOf2(uint32(len(*tree) + 1)) {
        *tree = append(*tree, nil)
    }

    return nil
}

func (tree ratchetTree) marshal(b *cryptobyte.Builder) {
    end := len(tree)
    for end > 0 && tree[end-1] == nil {
        end--
    }

    writeVector(b, len(tree[:end]), func(b *cryptobyte.Builder, i int) {
        n := tree[i]
        writeOptional(b, n != nil)
        if n != nil {
            n.marshal(b)
        }
    })
}

// get returns the node at the provided index.
//
// nil is returned for blank nodes. get panics if the index is out of range.
func (tree ratchetTree) get(i nodeIndex) *node {
    return tree[int(i)]
}

func (tree ratchetTree) set(i nodeIndex, node *node) {
    tree[int(i)] = node
}

func (tree ratchetTree) getLeaf(li leaf_index) *leaf_node {
    node := tree.get(li.nodeIndex())
    if node == nil {
        return nil
    }
    if node.node_type != nodeTypeLeaf {
        panic("unreachable")
    }
    return node.leaf_node
}

// resolve computes the resolution of a node.
func (tree ratchetTree) resolve(x nodeIndex) []nodeIndex {
    n := tree.get(x)
    if n == nil {
        l, r, ok := x.children()
        if !ok {
            return nil // leaf
        }
        return append(tree.resolve(l), tree.resolve(r)...)
    } else {
        res := []nodeIndex{x}
        if n.node_type == nodeTypeParent {
            for _, leaf_index := range n.parent_node.unmerged_leaves {
                res = append(res, leaf_index.nodeIndex())
            }
        }
        return res
    }
}

func (tree ratchetTree) supported_creds() map[credentialType]struct{} {
    numMembers := 0
    supportedCredsCount := make(map[credentialType]int)
    for li := leaf_index(0); li < leaf_index(tree.numLeaves()); li++ {
        node := tree.getLeaf(li)
        if node == nil {
            continue
        }

        numMembers++
        for _, ct := range node.capabilities.credentials {
            supportedCredsCount[ct]++
        }
    }

    supported_creds := make(map[credentialType]struct{})
    for ct, n := range supportedCredsCount {
        if n == numMembers {
            supported_creds[ct] = struct{}{}
        }
    }

    return supported_creds
}

func (tree ratchetTree) keys() (signature_keys, encryption_keys map[string]struct{}) {
    signature_keys = make(map[string]struct{})
    encryption_keys = make(map[string]struct{})
    for li := leaf_index(0); li < leaf_index(tree.numLeaves()); li++ {
        node := tree.getLeaf(li)
        if node == nil {
            continue
        }
        signature_keys[string(node.signature_key)] = struct{}{}
        encryption_keys[string(node.encryption_key)] = struct{}{}
    }
    return signature_keys, encryption_keys
}

// verifyIntegrity verifies the integrity of the ratchet tree, as described in
// section 12.4.3.1.
//
// This function does not perform full leaf node validation. In particular:
//
//   - It doesn't check that credentials are valid.
//   - It doesn't check the lifetime field.
func (tree ratchetTree) verifyIntegrity(ctx *groupContext, now func() time.Time) error {
    cs := ctx.cipher_suite
    numLeaves := tree.numLeaves()

    if h, err := tree.computeRootTreeHash(cs); err != nil {
        return err
    } else if !bytes.Equal(h, ctx.treeHash) {
        return fmt.Errorf("mls: tree hash verification failed")
    }

    if !tree.verifyParentHashes(cs) {
        return fmt.Errorf("mls: parent hashes verification failed")
    }

    supported_creds := tree.supported_creds()
    signature_keys := make(map[string]struct{})
    encryption_keys := make(map[string]struct{})
    for li := leaf_index(0); li < leaf_index(numLeaves); li++ {
        node := tree.getLeaf(li)
        if node == nil {
            continue
        }

        err := node.verify(&leafNodeVerifyOptions{
            cipher_suite:    cs,
            group_id:        ctx.group_id,
            leaf_index:      li,
            supported_creds: supported_creds,
            signature_keys:  signature_keys,
            encryption_keys: encryption_keys,
            now:            now,
        })
        if err != nil {
            return fmt.Errorf("leaf node at index %v: %v", li, err)
        }

        signature_keys[string(node.signature_key)] = struct{}{}
        encryption_keys[string(node.encryption_key)] = struct{}{}
    }

    for i, node := range tree {
        if node == nil || node.node_type != nodeTypeParent {
            continue
        }
        p := nodeIndex(i)
        for _, unmergedLeaf := range node.parent_node.unmerged_leaves {
            x := unmergedLeaf.nodeIndex()
            for {
                var ok bool
                if x, ok = numLeaves.parent(x); !ok {
                    return fmt.Errorf("mls: unmerged leaf %v is not a descendant of the parent node at index %v", unmergedLeaf, p)
                } else if x == p {
                    break
                }

                intermediateNode := tree.get(x)
                if intermediateNode != nil && !hasUnmergedLeaf(intermediateNode.parent_node, unmergedLeaf) {
                    return fmt.Errorf("mls: non-blank intermediate node at index %v is missing unmerged leaf %v", x, unmergedLeaf)
                }
            }
        }

        if _, dup := encryption_keys[string(node.parent_node.encryption_key)]; dup {
            return fmt.Errorf("mls: duplicate encryption key in ratchet tree")
        }
        encryption_keys[string(node.parent_node.encryption_key)] = struct{}{}
    }

    return nil
}

func hasUnmergedLeaf(node *parent_node, unmergedLeaf leaf_index) bool {
    for _, li := range node.unmerged_leaves {
        if li == unmergedLeaf {
            return true
        }
    }
    return false
}

func (tree ratchetTree) computeRootTreeHash(cs cipher_suite) ([]byte, error) {
    return tree.computeTreeHash(cs, tree.numLeaves().root(), nil)
}

func (tree ratchetTree) computeTreeHash(cs cipher_suite, x nodeIndex, exclude map[leaf_index]struct{}) ([]byte, error) {
    n := tree.get(x)

    var b cryptobyte.Builder
    if li, ok := x.leaf_index(); ok {
        _, excluded := exclude[li]

        var l *leaf_node
        if n != nil && !excluded {
            l = n.leaf_node
            if l == nil {
                panic("unreachable")
            }
        }

        marshalLeafNodeHashInput(&b, li, l)
    } else {
        left, right, ok := x.children()
        if !ok {
            panic("unreachable")
        }

        leftHash, err := tree.computeTreeHash(cs, left, exclude)
        if err != nil {
            return nil, err
        }
        rightHash, err := tree.computeTreeHash(cs, right, exclude)
        if err != nil {
            return nil, err
        }

        var p *parent_node
        if n != nil {
            p = n.parent_node
            if p == nil {
                panic("unreachable")
            }

            if len(p.unmerged_leaves) > 0 && len(exclude) > 0 {
                unmerged_leaves := make([]leaf_index, 0, len(p.unmerged_leaves))
                for _, li := range p.unmerged_leaves {
                    if _, excluded := exclude[li]; !excluded {
                        unmerged_leaves = append(unmerged_leaves, li)
                    }
                }

                filteredParent := *p
                filteredParent.unmerged_leaves = unmerged_leaves
                p = &filteredParent
            }
        }

        marshalParentNodeHashInput(&b, p, leftHash, rightHash)
    }
    in, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    h := cs.hash().New()
    h.Write(in)
    return h.Sum(nil), nil
}

func marshalLeafNodeHashInput(b *cryptobyte.Builder, i leaf_index, node *leaf_node) {
    b.AddUint8(uint8(nodeTypeLeaf))
    b.AddUint32(uint32(i))
    writeOptional(b, node != nil)
    if node != nil {
        node.marshal(b)
    }
}

func marshalParentNodeHashInput(b *cryptobyte.Builder, node *parent_node, leftHash, rightHash []byte) {
    b.AddUint8(uint8(nodeTypeParent))
    writeOptional(b, node != nil)
    if node != nil {
        node.marshal(b)
    }
    writeOpaqueVec(b, leftHash)
    writeOpaqueVec(b, rightHash)
}

func (tree ratchetTree) verifyParentHashes(cs cipher_suite) bool {
    for i, node := range tree {
        if node == nil {
            continue
        }

        x := nodeIndex(i)
        l, r, ok := x.children()
        if !ok {
            continue
        }

        parent_node := node.parent_node
        exclude := make(map[leaf_index]struct{}, len(parent_node.unmerged_leaves))
        for _, li := range parent_node.unmerged_leaves {
            exclude[li] = struct{}{}
        }

        leftTreeHash, err := tree.computeTreeHash(cs, l, exclude)
        if err != nil {
            return false
        }
        rightTreeHash, err := tree.computeTreeHash(cs, r, exclude)
        if err != nil {
            return false
        }

        leftParentHash, err := parent_node.compute_parent_hash(cs, rightTreeHash)
        if err != nil {
            return false
        }
        rightParentHash, err := parent_node.compute_parent_hash(cs, leftTreeHash)
        if err != nil {
            return false
        }

        isLeftDescendant := tree.findParentHash(tree.resolve(l), leftParentHash)
        isRightDescendant := tree.findParentHash(tree.resolve(r), rightParentHash)
        if isLeftDescendant == isRightDescendant {
            return false
        }
    }
    return true
}

func (tree ratchetTree) findParentHash(nodeIndices []nodeIndex, parent_hash []byte) bool {
    for _, x := range nodeIndices {
        node := tree.get(x)
        if node == nil {
            continue
        }
        var h []byte
        switch node.node_type {
        case nodeTypeLeaf:
            h = node.leaf_node.parent_hash
        case nodeTypeParent:
            h = node.parent_node.parent_hash
        }
        if bytes.Equal(h, parent_hash) {
            return true
        }
    }
    return false
}

func (tree ratchetTree) numLeaves() numLeaves {
    return numLeavesFromWidth(uint32(len(tree)))
}

func (tree ratchetTree) findLeaf(node *leaf_node) (leaf_index, bool) {
    for li := leaf_index(0); li < leaf_index(tree.numLeaves()); li++ {
        n := tree.getLeaf(li)
        if n == nil {
            continue
        }

        // Encryption keys are unique
        if !bytes.Equal(n.encryption_key, node.encryption_key) {
            continue
        }

        // Make sure both nodes are identical
        raw1, err1 := marshal(node)
        raw2, err2 := marshal(n)
        return li, err1 == nil && err2 == nil && bytes.Equal(raw1, raw2)
    }
    return 0, false
}

func (tree *ratchetTree) add(leaf_node *leaf_node) {
    li := leaf_index(0)
    var ni nodeIndex
    found := false
    for {
        ni = li.nodeIndex()
        if int(ni) >= len(*tree) {
            break
        }
        if tree.get(ni) == nil {
            found = true
            break
        }
        li++
    }
    if !found {
        ni = nodeIndex(len(*tree) + 1)
        newLen := ((len(*tree) + 1) * 2) - 1
        for len(*tree) < newLen {
            *tree = append(*tree, nil)
        }
    }

    numLeaves := tree.numLeaves()
    p := ni
    for {
        var ok bool
        p, ok = numLeaves.parent(p)
        if !ok {
            break
        }
        node := tree.get(p)
        if node != nil {
            node.parent_node.unmerged_leaves = append(node.parent_node.unmerged_leaves, li)
        }
    }

    tree.set(ni, &node{
        node_type: nodeTypeLeaf,
        leaf_node: leaf_node,
    })
}

func (tree ratchetTree) update(li leaf_index, leaf_node *leaf_node) {
    ni := li.nodeIndex()

    tree.set(ni, &node{
        node_type: nodeTypeLeaf,
        leaf_node: leaf_node,
    })

    numLeaves := tree.numLeaves()
    for {
        var ok bool
        ni, ok = numLeaves.parent(ni)
        if !ok {
            break
        }

        tree.set(ni, nil)
    }
}

func (tree *ratchetTree) remove(li leaf_index) {
    ni := li.nodeIndex()

    numLeaves := tree.numLeaves()
    for {
        tree.set(ni, nil)

        var ok bool
        ni, ok = numLeaves.parent(ni)
        if !ok {
            break
        }
    }

    li = leaf_index(numLeaves - 1)
    lastPowerOf2 := len(*tree)
    for {
        ni = li.nodeIndex()
        if tree.get(ni) != nil {
            break
        }

        if isPowerOf2(uint32(ni)) {
            lastPowerOf2 = int(ni)
        }

        if li == 0 {
            *tree = nil
            return
        }
        li--
    }

    if lastPowerOf2 < len(*tree) {
        *tree = (*tree)[:lastPowerOf2]
    }
}

func (tree ratchetTree) filteredDirectPath(x nodeIndex) []nodeIndex {
    numLeaves := tree.numLeaves()

    var path []nodeIndex
    for {
        p, ok := numLeaves.parent(x)
        if !ok {
            break
        }

        s, ok := numLeaves.sibling(x)
        if !ok {
            panic("unreachable")
        }

        if len(tree.resolve(s)) > 0 {
            path = append(path, p)
        }

        x = p
    }

    return path
}

func (tree ratchetTree) mergeUpdatePath(cs cipher_suite, senderLeafIndex leaf_index, path *updatePath) error {
    senderNodeIndex := senderLeafIndex.nodeIndex()
    numLeaves := tree.numLeaves()

    directPath := numLeaves.directPath(senderNodeIndex)
    for _, ni := range directPath {
        tree.set(ni, nil)
    }

    filteredDirectPath := tree.filteredDirectPath(senderNodeIndex)
    if len(filteredDirectPath) != len(path.nodes) {
        return fmt.Errorf("mls: UpdatePath has %v nodes, but filtered direct path has %v nodes", len(path.nodes), len(filteredDirectPath))
    }
    for i, ni := range filteredDirectPath {
        pathNode := path.nodes[i]
        tree.set(ni, &node{
            node_type: nodeTypeParent,
            parent_node: &parent_node{
                encryption_key: pathNode.encryption_key,
            },
        })
    }

    // Compute parent hashes, from root to leaf
    var prevParentHash []byte
    for i := len(filteredDirectPath) - 1; i >= 0; i-- {
        ni := filteredDirectPath[i]
        node := tree.get(ni).parent_node

        l, r, ok := ni.children()
        if !ok {
            panic("unreachable")
        }

        s := l
        found := false
        for _, ni := range directPath {
            if ni == s {
                found = true
                break
            }
        }
        if s == senderNodeIndex || found {
            s = r
        }

        treeHash, err := tree.computeTreeHash(cs, s, nil)
        if err != nil {
            return err
        }

        node.parent_hash = prevParentHash
        h, err := node.compute_parent_hash(cs, treeHash)
        if err != nil {
            return err
        }
        prevParentHash = h
    }

    if !bytes.Equal(path.leaf_node.parent_hash, prevParentHash) {
        return fmt.Errorf("mls: parent hash mismatch for update path's leaf node")
    }

    tree.set(senderNodeIndex, &node{
        node_type: nodeTypeLeaf,
        leaf_node: &path.leaf_node,
    })

    return nil
}

func (tree *ratchetTree) apply(proposals []proposal, senders []leaf_index) {
    // Apply all update proposals
    for i, prop := range proposals {
        if prop.proposalType == PROPOSAL_TYPE_UPDATE {
            tree.update(senders[i], &prop.update.leaf_node)
        }
    }

    // Apply all remove proposals
    for _, prop := range proposals {
        if prop.proposalType == PROPOSAL_TYPE_REMOVE {
            tree.remove(prop.remove.removed)
        }
    }

    // Apply all add proposals
    for _, prop := range proposals {
        if prop.proposalType == PROPOSAL_TYPE_ADD {
            tree.add(&prop.add.keyPackage.leaf_node)
        }
    }
}
*/
