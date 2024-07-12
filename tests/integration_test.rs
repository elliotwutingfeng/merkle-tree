// Copyright (c) 2024 Wu Tingfeng <wutingfeng@outlook.com>
use std::borrow::BorrowMut;

use merkle_tree::MerkleTree;

#[test]
fn test_integration() {
    let data: Vec<String> = vec![
        "abc".to_string(),
        "bcd".to_string(),
        "cde".to_string(),
        "def".to_string(),
        "efg".to_string(),
    ];
    let root = MerkleTree::merkle_root(&data);
    assert_eq!(
        root.borrow().value,
        "b12bb480c5d29242ab22fe53c199c26a5a5bd1ac66ac2702099855ceaf006073"
    );
    let mut proof = MerkleTree::merkle_proof(&data, 1);
    assert_eq!(MerkleTree::verify_proof(root.to_owned(), &proof), true);
    proof.borrow_mut().leaf_content += "tainted";
    assert_eq!(MerkleTree::verify_proof(root.to_owned(), &proof), false);
}
