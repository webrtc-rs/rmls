use crate::codec::*;
use crate::key_schedule::GroupContext;
use crate::tree::*;
use std::collections::HashMap;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub(crate) struct RatchetTree(pub(crate) Vec<Option<Node>>);

impl Reader for RatchetTree {
    fn read<B>(&mut self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: Buf,
    {
        read_vector(buf, |b: &mut Bytes| -> Result<()> {
            if read_optional(b)? {
                let mut node = Node::default();
                node.read(b)?;
                self.0.push(Some(node));
            } else {
                self.0.push(None);
            }
            Ok(())
        })?;

        // The raw tree doesn't include blank nodes at the end, fill it until next
        // power of 2
        while !is_power_of_two(self.0.len() as u32 + 1) {
            self.0.push(None);
        }

        Ok(())
    }
}

impl Writer for RatchetTree {
    fn write<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        let mut end = self.0.len();
        while end > 0 && self.0[end - 1].is_none() {
            end -= 1;
        }

        write_vector(end, buf, |i: usize, b: &mut BytesMut| -> Result<()> {
            write_optional(self.0[i].is_some(), b)?;
            if let Some(n) = &self.0[i] {
                n.write(b)?;
            }
            Ok(())
        })
    }
}

impl RatchetTree {
    // get returns the node at the provided index.
    //
    // nil is returned for blank nodes. get panics if the index is out of range.
    fn get(&self, i: NodeIndex) -> Option<&Node> {
        if (i.0 as usize) < self.0.len() {
            self.0[i.0 as usize].as_ref()
        } else {
            None
        }
    }

    fn get_mut(&mut self, i: NodeIndex) -> Option<&mut Node> {
        if (i.0 as usize) < self.0.len() {
            self.0[i.0 as usize].as_mut()
        } else {
            None
        }
    }

    fn set(&mut self, i: NodeIndex, node: Option<Node>) {
        if (i.0 as usize) < self.0.len() {
            self.0[i.0 as usize] = node;
        }
    }

    fn get_leaf(&self, li: LeafIndex) -> Option<&LeafNode> {
        if let Some(node) = self.get(li.node_index()) {
            if node.node_type != NodeType::Leaf {
                return None;
            }
            node.leaf_node.as_ref()
        } else {
            None
        }
    }

    // resolve computes the resolution of a node.
    fn resolve(&self, x: NodeIndex) -> Vec<NodeIndex> {
        if let Some(n) = self.get(x) {
            let mut res = vec![x];
            if n.node_type == NodeType::Parent {
                if let Some(parent_node) = &n.parent_node {
                    for leaf_index in &parent_node.unmerged_leaves {
                        res.push(leaf_index.node_index());
                    }
                }
            }
            res
        } else {
            let (l, r, ok) = x.children();
            if !ok {
                vec![] // leaf
            } else {
                let mut res = self.resolve(l);
                let mut right = self.resolve(r);
                res.append(&mut right);
                res
            }
        }
    }

    fn supported_creds(&self) -> HashSet<CredentialType> {
        let mut num_members = 0;
        let mut supported_creds_count = HashMap::<CredentialType, usize>::new();
        for li in 0..self.num_leaves().0 {
            if let Some(node) = self.get_leaf(LeafIndex(li)) {
                num_members += 1;
                for ct in &node.capabilities.credentials {
                    if let Some(count) = supported_creds_count.get_mut(ct) {
                        *count += 1;
                    } else {
                        supported_creds_count.insert(*ct, 1);
                    }
                }
            }
        }

        let mut supported_creds = HashSet::new();
        for (ct, n) in supported_creds_count {
            if n == num_members {
                supported_creds.insert(ct);
            }
        }

        supported_creds
    }

    fn keys(&self) -> (HashSet<Bytes>, HashSet<Bytes>) {
        let mut signature_keys = HashSet::new();
        let mut encryption_keys = HashSet::new();
        for li in 0..self.num_leaves().0 {
            if let Some(node) = self.get_leaf(LeafIndex(li)) {
                signature_keys.insert(node.signature_key.clone());
                encryption_keys.insert(node.encryption_key.clone());
            }
        }
        (signature_keys, encryption_keys)
    }

    // verify_integrity verifies the integrity of the ratchet tree, as described in
    // section 12.4.3.1.
    //
    // This function does not perform full leaf node validation. In particular:
    //
    //   - It doesn't check that credentials are valid.
    //   - It doesn't check the lifetime field.
    fn verify_integrity(&self, ctx: &GroupContext, now: impl Fn() -> SystemTime) -> Result<()> {
        let cs = ctx.cipher_suite;
        let num_leaves = self.num_leaves();

        let h = self.compute_root_tree_hash(cs)?;

        if h.as_ref() != ctx.tree_hash.as_ref() {
            return Err(Error::TreeHashVerificationFailed);
        }

        if !self.verify_parent_hashes(cs) {
            return Err(Error::ParentHashesVerificationFailed);
        }

        let supported_creds = self.supported_creds();
        let mut signature_keys = HashSet::new();
        let mut encryption_keys = HashSet::new();
        for li in 0..num_leaves.0 {
            if let Some(node) = self.get_leaf(LeafIndex(li)) {
                node.verify(LeafNodeVerifyOptions {
                    cipher_suite: cs,
                    group_id: &ctx.group_id,
                    leaf_index: LeafIndex(li),
                    supported_creds: &supported_creds,
                    signature_keys: &signature_keys,
                    encryption_keys: &encryption_keys,
                    now: &now,
                })?;

                signature_keys.insert(node.signature_key.clone());
                encryption_keys.insert(node.encryption_key.clone());
            }
        }

        for (i, node) in self.0.iter().enumerate() {
            if let Some(node) = node {
                if node.node_type != NodeType::Parent {
                    continue;
                }
                if let Some(parent_node) = &node.parent_node {
                    let p = NodeIndex(i as u32);
                    for unmerged_leaf in &parent_node.unmerged_leaves {
                        let mut x = unmerged_leaf.node_index();
                        loop {
                            let (y, ok) = num_leaves.parent(x);
                            if !ok {
                                return Err(Error::UnmergedLeafIsNotDescendantOfTheParentNode);
                            } else if y == p {
                                break;
                            }
                            x = y;

                            if let Some(intermediate_node) = self.get(x) {
                                if let Some(intermediate_node_parent_node) =
                                    &intermediate_node.parent_node
                                {
                                    if !RatchetTree::has_unmerged_leaf(
                                        intermediate_node_parent_node,
                                        unmerged_leaf,
                                    ) {
                                        return Err(
                                            Error::NonBlankIntermediateNodeMissingUnmergedLeaf,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    if encryption_keys.contains(&parent_node.encryption_key) {
                        return Err(Error::DuplicateEncryptionKeyInRatchetTree);
                    }
                    encryption_keys.insert(parent_node.encryption_key.clone());
                }
            }
        }

        Ok(())
    }

    fn has_unmerged_leaf(node: &ParentNode, unmerged_leaf: &LeafIndex) -> bool {
        for li in &node.unmerged_leaves {
            if li == unmerged_leaf {
                return true;
            }
        }
        false
    }

    fn compute_root_tree_hash(&self, cs: CipherSuite) -> Result<digest::Digest> {
        self.compute_tree_hash(cs, self.num_leaves().root(), &HashSet::new())
    }

    fn compute_tree_hash(
        &self,
        cs: CipherSuite,
        x: NodeIndex,
        exclude: &HashSet<LeafIndex>,
    ) -> Result<digest::Digest> {
        let n = self.get(x);

        let mut buf = BytesMut::new();
        let (li, ok) = x.leaf_index();
        if ok {
            let excluded = exclude.contains(&li);

            let mut l = None;
            if let Some(n) = n {
                if !excluded {
                    l = n.leaf_node.as_ref();
                    if l.is_none() {
                        return Err(Error::InvalidLeafNode);
                    }
                }
            }
            RatchetTree::marshal_leaf_node_hash_input(&mut buf, li, l)?;
        } else {
            let (left, right, ok) = x.children();
            if !ok {
                return Err(Error::InvalidChildren);
            }

            let left_hash = self.compute_tree_hash(cs, left, exclude)?;
            let right_hash = self.compute_tree_hash(cs, right, exclude)?;

            let mut filtered_parent;

            let p = if let Some(n) = n {
                if let Some(p) = n.parent_node.as_ref() {
                    if !p.unmerged_leaves.is_empty() && !exclude.is_empty() {
                        let mut unmerged_leaves = vec![]; // make([]leaf_index, 0, len(p.unmerged_leaves))
                        for li in &p.unmerged_leaves {
                            if !exclude.contains(li) {
                                unmerged_leaves.push(*li);
                            }
                        }

                        filtered_parent = p.clone();
                        filtered_parent.unmerged_leaves = unmerged_leaves;
                        Some(&filtered_parent)
                    } else {
                        Some(p)
                    }
                } else {
                    return Err(Error::InvalidParentNode);
                }
            } else {
                None
            };

            RatchetTree::marshal_parent_node_hash_input(
                &mut buf,
                p,
                left_hash.as_ref(),
                right_hash.as_ref(),
            )?;
        }

        let input = buf.freeze();
        let h = cs.hash();
        Ok(h.digest(&input))
    }

    fn marshal_leaf_node_hash_input<B: BufMut>(
        buf: &mut B,
        i: LeafIndex,
        node: Option<&LeafNode>,
    ) -> Result<()> {
        buf.put_u8(NodeType::Leaf as u8);
        buf.put_u32(i.0);
        write_optional(node.is_some(), buf)?;
        if let Some(node) = node {
            node.write(buf)?;
        }
        Ok(())
    }

    fn marshal_parent_node_hash_input<B: BufMut>(
        buf: &mut B,
        node: Option<&ParentNode>,
        left_hash: &[u8],
        right_hash: &[u8],
    ) -> Result<()> {
        buf.put_u8(NodeType::Parent as u8);
        write_optional(node.is_some(), buf)?;
        if let Some(node) = node {
            node.write(buf)?;
        }
        write_opaque_vec(left_hash, buf)?;
        write_opaque_vec(right_hash, buf)
    }

    fn verify_parent_hashes(&self, cs: CipherSuite) -> bool {
        for (i, node) in self.0.iter().enumerate() {
            if let Some(node) = node {
                let x = NodeIndex(i as u32);
                let (l, r, ok) = x.children();
                if !ok {
                    continue;
                }

                if let Some(parent_node) = node.parent_node.as_ref() {
                    let mut exclude = HashSet::new();
                    for li in &parent_node.unmerged_leaves {
                        exclude.insert(*li);
                    }

                    let left_tree_hash =
                        if let Ok(left_tree_hash) = self.compute_tree_hash(cs, l, &exclude) {
                            left_tree_hash
                        } else {
                            return false;
                        };
                    let right_tree_hash =
                        if let Ok(right_tree_hash) = self.compute_tree_hash(cs, r, &exclude) {
                            right_tree_hash
                        } else {
                            return false;
                        };

                    let left_parent_hash = if let Ok(left_parent_hash) =
                        parent_node.compute_parent_hash(cs, right_tree_hash.as_ref())
                    {
                        left_parent_hash
                    } else {
                        return false;
                    };
                    let right_parent_hash = if let Ok(right_parent_hash) =
                        parent_node.compute_parent_hash(cs, left_tree_hash.as_ref())
                    {
                        right_parent_hash
                    } else {
                        return false;
                    };

                    let is_left_descendant =
                        self.find_parent_hash(&self.resolve(l), left_parent_hash.as_ref());
                    let is_right_descendant =
                        self.find_parent_hash(&self.resolve(r), right_parent_hash.as_ref());
                    if is_left_descendant == is_right_descendant {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn find_parent_hash(&self, node_indices: &[NodeIndex], parent_hash: &[u8]) -> bool {
        for x in node_indices {
            if let Some(node) = self.get(*x) {
                let h = match node.node_type {
                    NodeType::Leaf => {
                        if let Some(leaf_node) = &node.leaf_node {
                            match &leaf_node.leaf_node_source {
                                LeafNodeSource::Commit(parent_hash) => parent_hash,
                                _ => continue,
                            }
                        } else {
                            continue;
                        }
                    }
                    NodeType::Parent => {
                        if let Some(parent_node) = &node.parent_node {
                            &parent_node.parent_hash
                        } else {
                            continue;
                        }
                    }
                };
                if h == parent_hash {
                    return true;
                }
            }
        }
        false
    }

    fn num_leaves(&self) -> NumLeaves {
        NumLeaves::new(self.0.len() as u32)
    }

    fn find_leaf(&self, node: &LeafNode) -> (LeafIndex, bool) {
        for li in 0..self.num_leaves().0 {
            if let Some(n) = self.get_leaf(LeafIndex(li)) {
                // Encryption keys are unique
                if n.encryption_key != node.encryption_key {
                    continue;
                }

                // Make sure both nodes are identical
                if let (Ok(raw1), Ok(raw2)) = (write(node), write(n)) {
                    return (LeafIndex(li), raw1 == raw2);
                } else {
                    return (LeafIndex(li), false);
                }
            }
        }
        (LeafIndex(0), false)
    }

    fn add(&mut self, leaf_node: Option<LeafNode>) {
        let mut li = LeafIndex(0);
        let mut ni: NodeIndex;
        let mut found = false;
        loop {
            ni = li.node_index();
            if (ni.0 as usize) >= self.0.len() {
                break;
            }
            if self.get(ni).is_none() {
                found = true;
                break;
            }
            li.0 += 1;
        }
        if !found {
            ni = NodeIndex(self.0.len() as u32 + 1);
            let new_len = ((self.0.len() + 1) * 2) - 1;
            while self.0.len() < new_len {
                self.0.push(None);
            }
        }

        let num_leaves = self.num_leaves();
        let mut p = ni;
        loop {
            let (q, ok) = num_leaves.parent(p);
            if !ok {
                break;
            }
            p = q;
            if let Some(node) = self.get_mut(p) {
                if let Some(parent_node) = &mut node.parent_node {
                    parent_node.unmerged_leaves.push(li);
                } else {
                    //TODO(yngrtc): what if none?
                }
            }
        }

        self.set(
            ni,
            Some(Node {
                node_type: NodeType::Leaf,
                leaf_node,
                parent_node: None,
            }),
        );
    }

    fn update(&mut self, li: LeafIndex, leaf_node: Option<LeafNode>) {
        let mut ni = li.node_index();

        self.set(
            ni,
            Some(Node {
                node_type: NodeType::Leaf,
                leaf_node,
                parent_node: None,
            }),
        );

        let num_leaves = self.num_leaves();
        loop {
            let (mi, ok) = num_leaves.parent(ni);
            if !ok {
                break;
            }
            ni = mi;
            self.set(ni, None);
        }
    }

    fn remove(&mut self, mut li: LeafIndex) {
        let mut ni = li.node_index();

        let num_leaves = self.num_leaves();
        loop {
            self.set(ni, None);

            let (mi, ok) = num_leaves.parent(ni);
            if !ok {
                break;
            }
            ni = mi;
        }

        li = LeafIndex(num_leaves.0 - 1);
        let mut last_power_of_two = self.0.len();
        loop {
            ni = li.node_index();
            if self.get(ni).is_some() {
                break;
            }

            if is_power_of_two(ni.0) {
                last_power_of_two = ni.0 as usize;
            }

            if li.0 == 0 {
                self.0.clear();
                return;
            }
            li.0 -= 1;
        }

        if last_power_of_two < self.0.len() {
            self.0.drain(last_power_of_two..);
        }
    }

    fn filtered_direct_path(&self, mut x: NodeIndex) -> Result<Vec<NodeIndex>> {
        let num_leaves = self.num_leaves();

        let mut path = vec![];
        loop {
            let (p, ok) = num_leaves.parent(x);
            if !ok {
                break;
            }

            let (s, ok) = num_leaves.sibling(x);
            if !ok {
                return Err(Error::InvalidSibling);
            }

            if !self.resolve(s).is_empty() {
                path.push(p);
            }

            x = p;
        }

        Ok(path)
    }

    fn merge_update_path(
        &mut self,
        cs: CipherSuite,
        sender_leaf_index: LeafIndex,
        path: UpdatePath,
    ) -> Result<()> {
        let sender_node_index = sender_leaf_index.node_index();
        let num_leaves = self.num_leaves();

        let direct_path = num_leaves.direct_path(sender_node_index);
        for ni in &direct_path {
            self.set(*ni, None);
        }

        let filtered_direct_path = self.filtered_direct_path(sender_node_index)?;
        if filtered_direct_path.len() != path.nodes.len() {
            return Err(Error::UpdatePathAndFilteredDirectPathHasDifferentNode);
        }
        for (i, ni) in filtered_direct_path.iter().enumerate() {
            let path_node = &path.nodes[i];
            self.set(
                *ni,
                Some(Node {
                    node_type: NodeType::Parent,
                    leaf_node: None,
                    parent_node: Some(ParentNode {
                        encryption_key: path_node.encryption_key.clone(),
                        ..Default::default()
                    }),
                }),
            );
        }

        let exclude = HashSet::new();
        // Compute parent hashes, from root to leaf
        let mut prev_parent_hash = None;
        for i in (0..filtered_direct_path.len()).rev() {
            let ni = filtered_direct_path[i];
            let node_parent_hash = if let Some(node) = self.get(ni) {
                if let Some(node) = &node.parent_node {
                    let (l, r, ok) = ni.children();
                    if !ok {
                        return Err(Error::InvalidChildren);
                    }

                    let mut s = l;
                    let mut found = false;
                    for ni in &direct_path {
                        if *ni == s {
                            found = true;
                            break;
                        }
                    }
                    if s == sender_node_index || found {
                        s = r;
                    }

                    let tree_hash = self.compute_tree_hash(cs, s, &exclude)?;

                    let node_parent_hash = prev_parent_hash.take();
                    prev_parent_hash = Some(node.compute_parent_hash(cs, tree_hash.as_ref())?);
                    node_parent_hash
                } else {
                    None
                }
            } else {
                None
            };

            //workaround to assign node.parent_hash
            if let Some(node_parent_hash) = node_parent_hash {
                if let Some(node) = self.get_mut(ni) {
                    if let Some(node) = &mut node.parent_node {
                        node.parent_hash = Bytes::from(node_parent_hash.as_ref().to_vec());
                    }
                }
            }
        }

        if let (LeafNodeSource::Commit(parent_hash), Some(prev_parent_hash)) =
            (&path.leaf_node.leaf_node_source, prev_parent_hash)
        {
            if parent_hash != prev_parent_hash.as_ref() {
                return Err(Error::ParentHashMismatchForUpdatePathLeafNode);
            }
        } else {
            return Err(Error::ParentHashMismatchForUpdatePathLeafNode);
        }

        self.set(
            sender_node_index,
            Some(Node {
                node_type: NodeType::Leaf,
                leaf_node: Some(path.leaf_node),
                parent_node: None,
            }),
        );

        Ok(())
    }

    /*TODO(yngrtc): fn apply(&mut self, proposals []proposal, senders []leaf_index) {
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
    }*/
}
