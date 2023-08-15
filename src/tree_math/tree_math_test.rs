use super::*;
use crate::codec::codec_test::load_test_vector;

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

#[test]
fn test_tree_math() -> Result<()> {
    let tests: Vec<TreeMathTest> = load_test_vector("test-vectors/tree-math.json")?;

    for test in tests {
        println!("{:?}", test);
    }

    Ok(())
}
