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

fn tree_math_test(tc: TreeMathTest) {
    let n = tc.n_leaves;
    let w = n.width();
    assert_eq!(w, tc.n_nodes, "width({:?}) = {}, want {}", n, w, tc.n_nodes);

    let r = n.root();
    assert_eq!(r, tc.root, "root({:?}) = {:?}, want {:?}", n, r, tc.root);

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
