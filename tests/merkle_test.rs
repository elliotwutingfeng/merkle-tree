// Copyright (c) 2024 Wu Tingfeng <wutingfeng@outlook.com>
use merkle_tree::{Hash, MerkleTree};
use once_cell::sync::Lazy;
use std::borrow::BorrowMut;

static H0: Lazy<String> = Lazy::new(|| Hash::hash("0"));
static H1: Lazy<String> = Lazy::new(|| Hash::hash("1"));
static H2: Lazy<String> = Lazy::new(|| Hash::hash("2"));
static H3: Lazy<String> = Lazy::new(|| Hash::hash("3"));
static H4: Lazy<String> = Lazy::new(|| Hash::hash("4"));
static H5: Lazy<String> = Lazy::new(|| Hash::hash("5"));
static H6: Lazy<String> = Lazy::new(|| Hash::hash("6"));
static H7: Lazy<String> = Lazy::new(|| Hash::hash("7"));
static H8: Lazy<String> = Lazy::new(|| Hash::hash("8"));
static H_H0_H1: Lazy<String> = Lazy::new(|| Hash::hash(&format!("{}{}", *H0, *H1)));
static H_H2_H3: Lazy<String> = Lazy::new(|| Hash::hash(&format!("{}{}", *H2, *H3)));
static H_H4_H5: Lazy<String> = Lazy::new(|| Hash::hash(&format!("{}{}", *H4, *H5)));
static H_H6_H7: Lazy<String> = Lazy::new(|| Hash::hash(&format!("{}{}", *H6, *H7)));

#[test]
fn test_merkle_root() {
    let test_cases: Vec<(Vec<String>, String)> = vec![
        ((0..=0).map(|i| i.to_string()).collect(), format!("{}", *H0)),
        (
            (0..=1).map(|i| i.to_string()).collect(),
            format!("{}", *H_H0_H1),
        ),
        (
            (0..=2).map(|i| i.to_string()).collect(),
            Hash::hash(&format!("{}{}", *H_H0_H1, *H2)),
        ),
        (
            (0..=3).map(|i| i.to_string()).collect(),
            Hash::hash(&format!("{}{}", *H_H0_H1, *H_H2_H3)),
        ),
        (
            (0..=4).map(|i| i.to_string()).collect(),
            Hash::hash(&format!(
                "{}{}",
                Hash::hash(&format!("{}{}", *H_H0_H1, *H_H2_H3)),
                *H4
            )),
        ),
        (
            (0..=5).map(|i| i.to_string()).collect(),
            Hash::hash(&format!(
                "{}{}",
                Hash::hash(&format!("{}{}", *H_H0_H1, *H_H2_H3)),
                *H_H4_H5
            )),
        ),
        (
            (0..=6).map(|i| i.to_string()).collect(),
            Hash::hash(&format!(
                "{}{}",
                Hash::hash(&format!("{}{}", *H_H0_H1, *H_H2_H3)),
                Hash::hash(&format!("{}{}", *H_H4_H5, *H6))
            )),
        ),
        (
            (0..=7).map(|i| i.to_string()).collect(),
            Hash::hash(&format!(
                "{}{}",
                Hash::hash(&format!("{}{}", *H_H0_H1, *H_H2_H3)),
                Hash::hash(&format!("{}{}", *H_H4_H5, *H_H6_H7))
            )),
        ),
        (
            (0..=8).map(|i| i.to_string()).collect(),
            Hash::hash(&format!(
                "{}{}",
                Hash::hash(&format!(
                    "{}{}",
                    Hash::hash(&format!("{}{}", *H_H0_H1, *H_H2_H3)),
                    Hash::hash(&format!("{}{}", *H_H4_H5, *H_H6_H7))
                )),
                *H8,
            )),
        ),
    ];

    for (leaves, correct_root_value) in &test_cases {
        assert_eq!(
            MerkleTree::merkle_root(leaves).borrow().value,
            correct_root_value.to_owned()
        );
    }
}

#[test]
fn test_merkle_proof() {
    let test_cases: Vec<(Vec<String>, usize, Vec<String>)> = vec![
        ((0..=0).map(|i| i.to_string()).collect(), 0, Vec::new()),
        (
            (0..=1).map(|i| i.to_string()).collect(),
            0,
            vec![H1.to_string()],
        ),
        (
            (0..=2).map(|i| i.to_string()).collect(),
            1,
            vec![H0.to_string(), H2.to_string()],
        ),
        (
            (0..=2).map(|i| i.to_string()).collect(),
            2, // Same as above, but different leaf.
            vec![H_H0_H1.to_string()],
        ),
        (
            (0..=3).map(|i| i.to_string()).collect(),
            2,
            vec![H3.to_string(), H_H0_H1.to_string()],
        ),
        (
            (0..=4).map(|i| i.to_string()).collect(),
            1,
            vec![H0.to_string(), H_H2_H3.to_string(), H4.to_string()],
        ),
        (
            (0..=5).map(|i| i.to_string()).collect(),
            1,
            vec![H0.to_string(), H_H2_H3.to_string(), H_H4_H5.to_string()],
        ),
        (
            (0..=6).map(|i| i.to_string()).collect(),
            4,
            vec![
                H5.to_string(),
                H6.to_string(),
                Hash::hash(&format!("{}{}", H_H0_H1.to_string(), H_H2_H3.to_string())),
            ],
        ),
    ];
    for (leaves, leaf_index, expected_proof_nodes) in &test_cases {
        let proof = MerkleTree::merkle_proof(&leaves, leaf_index.to_owned());
        assert_eq!(proof.hashes.len(), expected_proof_nodes.len());
        let mut i = 0;
        for hash in &proof.hashes {
            assert_eq!(hash.borrow().value, expected_proof_nodes[i]);
            i += 1;
        }
    }
}

#[test]
fn test_verify_proof() {
    let leaves_sets: Vec<Vec<String>> = (0..=10)
        .map(|i| (0..i).map(|j| j.to_string()).collect())
        .collect();
    for leaves in leaves_sets {
        for leaf_index in 0..leaves.len() {
            let root = MerkleTree::merkle_root(&leaves);
            let mut proof = MerkleTree::merkle_proof(&leaves, leaf_index);
            assert_eq!(MerkleTree::verify_proof(root.to_owned(), &proof), true);
            proof.borrow_mut().leaf_content += "tainted";
            assert_eq!(MerkleTree::verify_proof(root, &proof), false);
        }
    }
}
