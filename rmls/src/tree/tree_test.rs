use serde::{Deserialize, Serialize};

#[cfg(feature = "RingCryptoProvider")]
use crate::crypto::provider::RingCryptoProvider;
#[cfg(feature = "RustCryptoProvider")]
use crate::crypto::provider::RustCryptoProvider;
use crate::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::error::*;
use crate::key::schedule::GroupContext;
use crate::serde::serde_test::load_test_vector;
use crate::tree::{
    ratchet::RatchetTree,
    secret::{derive_secret_tree, RatchetLabel, SecretTree},
    *,
};

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
    let tree = RatchetTree::deserialize_exact(&tc.tree)?;

    for (i, want) in tc.resolutions.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let res = tree.resolve(x);
        assert_eq!(&res, want);
    }

    let exclude = HashSet::new();
    for (i, want) in tc.tree_hashes.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let h = tree.compute_tree_hash(crypto_provider, cipher_suite, x, &exclude)?;
        assert_eq!(&h, &want.0);
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

        if crypto_provider.supports(cipher_suite) {
            tree_validation_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_tree_validation() -> Result<()> {
    let tests: Vec<TreeValidationTest> = load_test_vector("test-vectors/tree-validation.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_tree_validation_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_tree_validation_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PathSecretTest {
    node: u32,
    #[serde(with = "hex")]
    path_secret: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct LeafPrivateTest {
    index: u32,
    #[serde(with = "hex")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex")]
    signature_priv: Vec<u8>,
    path_secrets: Vec<PathSecretTest>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct PathTest {
    sender: u32,
    #[serde(with = "hex")]
    update_path: Vec<u8>,
    path_secrets: Vec<Option<String>>,
    #[serde(with = "hex")]
    commit_secret: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_after: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeKEMTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    group_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex")]
    confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex")]
    ratchet_tree: Vec<u8>,

    pub leaves_private: Vec<LeafPrivateTest>,
    pub update_paths: Vec<PathTest>,
}

fn tree_kem_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TreeKEMTest,
) -> Result<()> {
    // TODO: test leaves_private

    for update_path_test in &tc.update_paths {
        let mut tree = RatchetTree::deserialize_exact(&tc.ratchet_tree)?;

        let up = UpdatePath::deserialize_exact(&update_path_test.update_path)?;

        // TODO: verify that UpdatePath is parent-hash valid relative to ratchet tree
        // TODO: process UpdatePath using private leaves

        tree.merge_update_path(
            crypto_provider,
            cipher_suite,
            LeafIndex(update_path_test.sender),
            &up,
        )?;

        let tree_hash = tree.compute_root_tree_hash(crypto_provider, cipher_suite)?;
        assert_eq!(&tree_hash, &update_path_test.tree_hash_after);

        // TODO: create and verify new update path
    }

    Ok(())
}

fn test_tree_kem_with_crypto_provider(
    tests: &[TreeKEMTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for (i, tc) in tests.iter().enumerate() {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_tree_kem {}:{}", i, cipher_suite);

        if crypto_provider.supports(cipher_suite) {
            tree_kem_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_tree_kem() -> Result<()> {
    let tests: Vec<TreeKEMTest> = load_test_vector("test-vectors/treekem.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_tree_kem_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_tree_kem_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

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

fn tree_operations_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TreeOperationsTest,
) -> Result<()> {
    let mut tree = RatchetTree::deserialize_exact(&tc.tree_before)?;

    let tree_hash = tree.compute_root_tree_hash(crypto_provider, cipher_suite)?;
    assert_eq!(&tree_hash, &tc.tree_hash_before);

    let prop = Proposal::deserialize_exact(&tc.proposal)?;

    match &prop {
        Proposal::Add(add) => {
            let ctx = GroupContext {
                version: add.key_package.version,
                cipher_suite: add.key_package.cipher_suite,
                ..Default::default()
            };
            add.key_package.verify(crypto_provider, &ctx)?;
            tree.add(add.key_package.leaf_node.clone());
        }
        Proposal::Update(update) => {
            let (signature_keys, encryption_keys) = tree.keys();
            update.leaf_node.verify(
                crypto_provider,
                LeafNodeVerifyOptions {
                    cipher_suite,
                    group_id: &Bytes::new(),
                    leaf_index: LeafIndex(tc.proposal_sender),
                    supported_creds: &tree.supported_creds(),
                    signature_keys: &signature_keys,
                    encryption_keys: &encryption_keys,
                    now: &|| -> SystemTime { UNIX_EPOCH },
                },
            )?;
            tree.update(LeafIndex(tc.proposal_sender), update.leaf_node.clone());
        }
        Proposal::Remove(remove) => {
            assert!(
                tree.get_leaf(remove.removed).is_some(),
                "leaf node {:?} is blank",
                remove.removed
            );
            tree.remove(remove.removed);
        }
        _ => assert!(false),
    }

    let raw_tree = tree.serialize_detached()?;
    assert_eq!(&raw_tree, &tc.tree_after);

    let tree_hash = tree.compute_root_tree_hash(crypto_provider, cipher_suite)?;
    assert_eq!(&tree_hash, &tc.tree_hash_after);

    Ok(())
}

fn test_tree_operations_with_crypto_provider(
    tests: &[TreeOperationsTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for (i, tc) in tests.iter().enumerate() {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_tree_operations {}:{}", i, cipher_suite);

        tree_operations_test(crypto_provider, cipher_suite, &tc)?;
    }

    Ok(())
}

#[test]
fn test_tree_operations() -> Result<()> {
    let tests: Vec<TreeOperationsTest> = load_test_vector("test-vectors/tree-operations.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_tree_operations_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_tree_operations_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SenderData {
    #[serde(with = "hex")]
    sender_data_secret: Vec<u8>,
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    key: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct Leaf {
    generation: u32,
    #[serde(with = "hex")]
    handshake_key: Vec<u8>,
    #[serde(with = "hex")]
    handshake_nonce: Vec<u8>,
    #[serde(with = "hex")]
    application_key: Vec<u8>,
    #[serde(with = "hex")]
    application_nonce: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SecretTreeTest {
    cipher_suite: u16,
    sender_data: SenderData,
    #[serde(with = "hex")]
    encryption_secret: Vec<u8>,
    leaves: Vec<Vec<Leaf>>,
}

fn secret_tree_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &SecretTreeTest,
) -> Result<()> {
    let key = expand_sender_data_key(
        crypto_provider,
        cipher_suite,
        &tc.sender_data.sender_data_secret,
        &tc.sender_data.ciphertext,
    )?;
    assert_eq!(&key, &tc.sender_data.key);

    let nonce = expand_sender_data_nonce(
        crypto_provider,
        cipher_suite,
        &tc.sender_data.sender_data_secret,
        &tc.sender_data.ciphertext,
    )?;
    assert_eq!(&nonce, &tc.sender_data.nonce);

    let tree = derive_secret_tree(
        crypto_provider,
        cipher_suite,
        NumLeaves(tc.leaves.len() as u32),
        &tc.encryption_secret,
    )?;

    for (i, gens) in tc.leaves.iter().enumerate() {
        let li = LeafIndex(i as u32);
        test_ratchet_secret(
            crypto_provider,
            cipher_suite,
            &tree,
            li,
            RatchetLabel::Handshake,
            gens,
        )?;

        test_ratchet_secret(
            crypto_provider,
            cipher_suite,
            &tree,
            li,
            RatchetLabel::Application,
            gens,
        )?;
    }

    Ok(())
}

fn test_ratchet_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tree: &SecretTree,
    li: LeafIndex,
    label: RatchetLabel,
    gens: &[Leaf],
) -> Result<()> {
    let mut secret =
        tree.derive_ratchet_root(crypto_provider, cipher_suite, li.node_index(), label)?;

    for gen in gens {
        assert!(!(gen.generation < secret.generation));

        while secret.generation != gen.generation {
            secret = secret.derive_next(crypto_provider, cipher_suite)?;
        }

        let (want_key, want_nonce) = match label {
            RatchetLabel::Handshake => (&gen.handshake_key, &gen.handshake_nonce),
            RatchetLabel::Application => (&gen.application_key, &gen.application_nonce),
        };

        let key = secret.derive_key(crypto_provider, cipher_suite)?;
        assert_eq!(&key, &want_key);

        let nonce = secret.derive_nonce(crypto_provider, cipher_suite)?;
        assert_eq!(&nonce, &want_nonce);
    }

    Ok(())
}

fn test_secret_tree_with_crypto_provider(
    tests: &[SecretTreeTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.try_into()?;
        println!("test_secret_tree {}", cipher_suite);

        secret_tree_test(crypto_provider, cipher_suite, tc)?;
    }

    Ok(())
}

#[test]
fn test_secret_tree() -> Result<()> {
    let tests: Vec<SecretTreeTest> = load_test_vector("test-vectors/secret-tree.json")?;

    #[cfg(feature = "RingCryptoProvider")]
    test_secret_tree_with_crypto_provider(&tests, &RingCryptoProvider {})?;
    #[cfg(feature = "RustCryptoProvider")]
    test_secret_tree_with_crypto_provider(&tests, &RustCryptoProvider {})?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeMathTest {
    n_leaves: NumLeaves,
    n_nodes: u32,
    root: NodeIndex,
    left: Vec<Option<NodeIndex>>,
    right: Vec<Option<NodeIndex>>,
    parent: Vec<Option<NodeIndex>>,
    sibling: Vec<Option<NodeIndex>>,
}

fn tree_math_test(tc: TreeMathTest) {
    let n = tc.n_leaves;
    let w = n.width();
    assert_eq!(w, tc.n_nodes);

    let r = n.root();
    assert_eq!(r, tc.root);

    for (i, want) in tc.left.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let l = new_optional_node_index(x.left());
        assert!(
            optional_node_index_equal(l, *want),
            "left({:?}) = {:?}, want {:?}",
            x,
            l,
            *want
        );
    }

    for (i, want) in tc.right.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let r = new_optional_node_index(x.right());
        assert!(
            optional_node_index_equal(r, *want),
            "right({:?}) = {:?}, want {:?}",
            x,
            r,
            *want
        );
    }

    for (i, want) in tc.parent.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let p = new_optional_node_index(n.parent(x));
        assert!(
            optional_node_index_equal(p, *want),
            "parent({:?}) = {:?}, want {:?}",
            x,
            p,
            *want
        );
    }

    for (i, want) in tc.sibling.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let s = new_optional_node_index(n.sibling(x));
        assert!(
            optional_node_index_equal(s, *want),
            "sibling({:?}) = {:?}, want {:?}",
            x,
            s,
            *want
        );
    }
}

fn new_optional_node_index(xok: (NodeIndex, bool)) -> Option<NodeIndex> {
    let (x, ok) = xok;
    if ok {
        Some(x)
    } else {
        None
    }
}

fn optional_node_index_equal(x: Option<NodeIndex>, y: Option<NodeIndex>) -> bool {
    if let (Some(x), Some(y)) = (x, y) {
        x == y
    } else {
        x.is_none() && y.is_none()
    }
}

#[test]
fn test_tree_math() -> Result<()> {
    let tests: Vec<TreeMathTest> = load_test_vector("test-vectors/tree-math.json")?;

    for test in tests {
        tree_math_test(test);
    }

    Ok(())
}
