use super::*;
use crate::codec::codec_test::load_test_vector;
use crate::crypto::provider::{ring::RingCryptoProvider, rust::RustCryptoProvider, CryptoProvider};
use crate::error::*;
use crate::tree::ratchet_tree::RatchetTree;

use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeHash(#[serde(with = "hex")] Vec<u8>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeValidationTest {
    cipher_suite: u16,
    #[serde(with = "hex")]
    tree: Vec<u8>,
    #[serde(with = "hex")]
    group_id: Vec<u8>,

    resolutions: Vec<Vec<NodeIndex>>,
    tree_hashes: Vec<TreeHash>,
}

fn tree_validation_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TreeValidationTest,
) -> Result<()> {
    let mut tree = RatchetTree::default();
    let mut buf = tc.tree.as_ref();
    read(&mut tree, &mut buf)?;

    for (i, want) in tc.resolutions.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let res = tree.resolve(x);
        assert_eq!(&res, want, "resolve({:?}) = {:?}, want {:?}", x, res, want);
    }

    let exclude = HashSet::new();
    for (i, want) in tc.tree_hashes.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let h = tree.compute_tree_hash(crypto_provider, cipher_suite, x, &exclude)?;
        assert_eq!(
            &h, &want.0,
            "computeTreeHash({:?}) = {:?}, want {:?}",
            x, h, want
        );
    }

    assert!(
        tree.verify_parent_hashes(crypto_provider, cipher_suite),
        "verifyParentHashes() failed"
    );

    let group_id: GroupID = tc.group_id.clone().into();
    for (i, node) in tree.0.iter().enumerate() {
        if let Some(Node::Leaf(leaf_node)) = node {
            let (li, ok) = NodeIndex(i as u32).leaf_index();
            assert!(ok, "leafIndex({:?}) = false", i);
            assert!(
                leaf_node.verify_signature(crypto_provider, cipher_suite, &group_id, li),
                "verify({:?}) = false",
                li
            );
        }
    }

    Ok(())
}

fn test_tree_validation_with_crypto_provider(
    tests: &[TreeValidationTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!(
            "test_tree_validation {}:{}",
            cipher_suite, cipher_suite as u16
        );

        tree_validation_test(crypto_provider, cipher_suite, tc)?;
    }

    Ok(())
}

#[test]
fn test_tree_validation() -> Result<()> {
    let tests: Vec<TreeValidationTest> = load_test_vector("test-vectors/tree-validation.json")?;

    test_tree_validation_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    test_tree_validation_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PathSecretTest {
    node: u32,
    #[serde(with = "hex::serde")]
    path_secret: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct LeafPrivateTest {
    index: u32,
    #[serde(with = "hex::serde")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature_priv: Vec<u8>,
    path_secrets: Vec<PathSecretTest>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct PathTest {
    sender: u32,
    #[serde(with = "hex::serde")]
    update_path: Vec<u8>,
    path_secrets: Vec<Option<String>>,
    #[serde(with = "hex::serde")]
    commit_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    tree_hash_after: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeKEMTest {
    cipher_suite: u16,

    #[serde(with = "hex::serde")]
    group_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex::serde")]
    confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex::serde")]
    ratchet_tree: Vec<u8>,

    pub leaves_private: Vec<LeafPrivateTest>,
    pub update_paths: Vec<PathTest>,
}
/*
func testTreeKEM(t *testing.T, tc *treeKEMTest) {
    // TODO: test leaves_private

    for _, updatePathTest := range tc.UpdatePaths {
        var tree ratchetTree
        if err := unmarshal([]byte(tc.RatchetTree), &tree); err != nil {
            t.Fatalf("unmarshal(ratchetTree) = %v", err)
        }

        var up updatePath
        if err := unmarshal([]byte(updatePathTest.UpdatePath), &up); err != nil {
            t.Fatalf("unmarshal(updatePath) = %v", err)
        }

        // TODO: verify that UpdatePath is parent-hash valid relative to ratchet tree
        // TODO: process UpdatePath using private leaves

        if err := tree.mergeUpdatePath(tc.CipherSuite, updatePathTest.Sender, &up); err != nil {
            t.Fatalf("ratchetTree.mergeUpdatePath() = %v", err)
        }

        treeHash, err := tree.computeRootTreeHash(tc.CipherSuite)
        if err != nil {
            t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
        } else if !bytes.Equal(treeHash, []byte(updatePathTest.TreeHashAfter)) {
            t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, updatePathTest.TreeHashAfter)
        }

        // TODO: create and verify new update path
    }
}

func TestTreeKEM(t *testing.T) {
    var tests []treeKEMTest
    loadTestVector(t, "testdata/treekem.json", &tests)

    for i, tc := range tests {
        t.Run(fmt.Sprintf("[%v]", i), func(t *testing.T) {
            testTreeKEM(t, &tc)
        })
    }
}
*/

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeOperationsTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    tree_before: Vec<u8>,
    #[serde(with = "hex")]
    proposal: Vec<u8>,
    proposal_sender: u32,
    #[serde(with = "hex")]
    tree_after: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_after: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_before: Vec<u8>,
}
/*
func testTreeOperations(t *testing.T, tc *treeOperationsTest) {
    var tree ratchetTree
    if err := unmarshal([]byte(tc.TreeBefore), &tree); err != nil {
        t.Fatalf("unmarshal(tree) = %v", err)
    }

    treeHash, err := tree.computeRootTreeHash(tc.CipherSuite)
    if err != nil {
        t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
    } else if !bytes.Equal(treeHash, []byte(tc.TreeHashBefore)) {
        t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, tc.TreeHashBefore)
    }

    var prop proposal
    if err := unmarshal([]byte(tc.Proposal), &prop); err != nil {
        t.Fatalf("unmarshal(proposal) = %v", err)
    }

    switch prop.proposalType {
    case proposalTypeAdd:
        ctx := groupContext{
            version:     prop.add.keyPackage.version,
            cipherSuite: prop.add.keyPackage.cipherSuite,
        }
        if err := prop.add.keyPackage.verify(&ctx); err != nil {
            t.Errorf("keyPackage.verify() = %v", err)
        }
        tree.add(&prop.add.keyPackage.leafNode)
    case proposalTypeUpdate:
        signatureKeys, encryptionKeys := tree.keys()
        err := prop.update.leafNode.verify(&leafNodeVerifyOptions{
            cipherSuite:    tc.CipherSuite,
            groupID:        nil,
            leafIndex:      tc.ProposalSender,
            supportedCreds: tree.supportedCreds(),
            signatureKeys:  signatureKeys,
            encryptionKeys: encryptionKeys,
            now:            func() time.Time { return time.Time{} },
        })
        if err != nil {
            t.Errorf("leafNode.verify() = %v", err)
        }
        tree.update(tc.ProposalSender, &prop.update.leafNode)
    case proposalTypeRemove:
        if tree.getLeaf(prop.remove.removed) == nil {
            t.Errorf("leaf node %v is blank", prop.remove.removed)
        }
        tree.remove(prop.remove.removed)
    default:
        panic("unreachable")
    }

    rawTree, err := marshal(&tree)
    if err != nil {
        t.Fatalf("marshal(tree) = %v", err)
    } else if !bytes.Equal(rawTree, []byte(tc.TreeAfter)) {
        t.Errorf("marshal(tree) = %v, want %v", rawTree, tc.TreeAfter)
    }

    treeHash, err = tree.computeRootTreeHash(tc.CipherSuite)
    if err != nil {
        t.Errorf("ratchetTree.computeRootTreeHash() = %v", err)
    } else if !bytes.Equal(treeHash, []byte(tc.TreeHashAfter)) {
        t.Errorf("ratchetTree.computeRootTreeHash() = %v, want %v", treeHash, tc.TreeHashAfter)
    }
}

*/

fn test_tree_operations_with_crypto_provider(
    tests: &[TreeOperationsTest],
    _crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_tree_operations {}", cipher_suite);

        //TODO: testTreeOperations(t, &tc);
    }

    Ok(())
}

#[test]
fn test_tree_operations() -> Result<()> {
    let tests: Vec<TreeOperationsTest> = load_test_vector("test-vectors/tree-operations.json")?;

    test_tree_operations_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    test_tree_operations_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}
