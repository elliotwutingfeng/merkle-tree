// Copyright (c) 2024 Wu Tingfeng <wutingfeng@outlook.com>
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::rc::Rc;

pub struct Hash {
    pub parent: Option<Rc<RefCell<Hash>>>,
    pub left: Option<Rc<RefCell<Hash>>>,
    pub right: Option<Rc<RefCell<Hash>>>,
    pub value: String,
    pub is_left: bool, // Needed for proof verification.
}

impl Hash {
    /// Initialize node of a merkle tree.
    ///
    /// # Arguments
    ///
    /// * `parent` - This node's parent.
    /// * `left` - This node's child.
    /// * `right` - This node's right child.
    /// * `value` - This node's hash value as hexdigest.
    /// * `is_left` - Whether this node is a left child.
    fn new(value: String) -> Self {
        Hash {
            parent: None,
            left: None,
            right: None,
            value,
            is_left: true,
        }
    }

    /// Hash a given string to its sha256 hexdigest.
    ///
    /// # Arguments
    ///
    /// * `value` - String to hash.
    pub fn hash(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }
}

/// Hold information needed to verify whether a particular leaf node belongs to a merkle tree.
pub struct MerkleProof {
    /// List of audit hashes needed to verify that a leaf node belongs to a merkle tree,
    /// arranged from the bottom-most hash up to the top-most hash (closest to root node).
    pub hashes: Vec<Rc<RefCell<Hash>>>,

    /// Number of leaves in the merkle tree.
    pub num_of_leaves: usize,

    /// 0-based index of leaf node to be verified.
    pub leaf_index: usize,

    /// Content of leaf node to be verified.
    pub leaf_content: String,
}

pub struct MerkleTree;

impl MerkleTree {
    /// Given a left child node and a right child node, return a parent node whose value
    /// is the hash of the left child's hash concatenated with the right child's hash.
    /// Links between the parent and children are added accordingly.
    ///
    /// # Arguments
    ///
    /// * `left` - Left child node.
    /// * `right` - Right child node.
    fn make_parent(left: Rc<RefCell<Hash>>, right: Rc<RefCell<Hash>>) -> Rc<RefCell<Hash>> {
        let parent = Rc::new(RefCell::new(Hash::new(Hash::hash(&format!(
            "{}{}",
            left.borrow().value,
            right.borrow().value
        )))));

        left.borrow_mut().is_left = true;
        right.borrow_mut().is_left = false;

        left.borrow_mut().parent = Some(Rc::to_owned(&parent));
        right.borrow_mut().parent = Some(Rc::to_owned(&parent));

        parent.borrow_mut().left = Some(left);
        parent.borrow_mut().right = Some(right);

        parent
    }

    /// Recursively build a merkle tree from the bottom level (leaves) up to the top level (root node).
    ///
    /// # Arguments
    ///
    /// * `nodes` - Nodes of current level.
    fn merkle_root_aux(nodes: Vec<Rc<RefCell<Hash>>>) -> Rc<RefCell<Hash>> {
        if nodes.len() == 1 {
            return nodes[0].to_owned();
        }

        let mut parents = Vec::new();
        let is_odd = nodes.len() % 2 != 0;

        // Iterate through sibling-pairs on the same level.
        for i in (0..(nodes.len() - if is_odd { 1 } else { 0 })).step_by(2) {
            parents.push(Self::make_parent(
                nodes[i].to_owned(),
                nodes[i + 1].to_owned(),
            ));
        }

        if is_odd {
            parents.push(nodes[nodes.len() - 1].to_owned()); // Last node has no sibling.
        }

        Self::merkle_root_aux(parents)
    }

    /// Generate a merkle tree and return the root node.
    ///
    /// # Arguments
    ///
    /// * `leaves` - Leaves of merkle tree.
    pub fn merkle_root(leaves: &Vec<String>) -> Rc<RefCell<Hash>> {
        let nodes: Vec<Rc<RefCell<Hash>>> = leaves
            .into_iter()
            .map(|leaf| Rc::new(RefCell::new(Hash::new(Hash::hash(&leaf)))))
            .collect();
        Self::merkle_root_aux(nodes)
    }

    /// Recursively build a merkle tree from the bottom level (leaves) up to the top level (root node).
    /// This is similar to `__merkle_root_aux` except that an accumulating of `audit_nodes` is maintained along with
    /// a `target_index`. At each recursive call, the sibling of the node at `target_index` is added to `audit_nodes`,
    /// then `target_index` is updated to the 0-based index of its parent at the immediate upper level. `audit_nodes`
    /// is returned when the root node level is reached.
    ///
    /// # Arguments
    ///
    /// * `nodes` - Nodes of current level.
    /// * `audit_nodes` - Accumulating list of nodes that are needed for the merkle proof.
    /// * `target_index` - 0-based index of target node of the current level. The target node's sibling is
    /// the audit node for the current level.
    fn merkle_proof_aux(
        nodes: Vec<Rc<RefCell<Hash>>>,
        mut audit_nodes: Vec<Rc<RefCell<Hash>>>,
        target_index: usize,
    ) -> Vec<Rc<RefCell<Hash>>> {
        if nodes.len() == 1 {
            return audit_nodes;
        }

        let mut parents = Vec::new();
        let sibling_index = if target_index % 2 == 0 {
            target_index + 1
        } else {
            target_index - 1
        };

        if sibling_index < nodes.len() {
            audit_nodes.push(nodes[sibling_index].to_owned());
        } // Handle edge case for siblingless rightmost node on the level.

        let new_target_index = target_index / 2;

        let is_odd = nodes.len() % 2 != 0;

        // Iterate through sibling-pairs on the same level.
        for i in (0..(nodes.len() - if is_odd { 1 } else { 0 })).step_by(2) {
            parents.push(Self::make_parent(
                nodes[i].to_owned(),
                nodes[i + 1].to_owned(),
            ));
        }

        if is_odd {
            parents.push(nodes[nodes.len() - 1].to_owned()); // Last node has no sibling.
        }

        Self::merkle_proof_aux(parents, audit_nodes, new_target_index)
    }

    /// Generate a merkle proof.
    ///
    /// # Arguments
    ///
    /// * `leaves` - Leaves of merkle tree.
    /// * `leaf_index` - 0-based index of leaf node that needs to be verified.
    pub fn merkle_proof(leaves: &Vec<String>, leaf_index: usize) -> MerkleProof {
        let nodes: Vec<Rc<RefCell<Hash>>> = leaves
            .iter()
            .map(|leaf| Rc::new(RefCell::new(Hash::new(Hash::hash(leaf)))))
            .collect();

        let audit_nodes = Self::merkle_proof_aux(nodes.to_owned(), Vec::new(), leaf_index);

        MerkleProof {
            hashes: audit_nodes,
            num_of_leaves: nodes.len(),
            leaf_index,
            leaf_content: leaves[leaf_index].to_owned(),
        }
    }

    /// Given a merkle root node, verify a proof by checking whether it is able
    /// to reconstruct the same root node.
    ///
    /// # Arguments
    ///
    /// * `root` - Root node of the merkle tree.
    /// * `proof` - Proof to be verified.
    pub fn verify_proof(root: Rc<RefCell<Hash>>, proof: &MerkleProof) -> bool {
        let mut result = Hash::hash(&proof.leaf_content);

        for audit_hash in &proof.hashes {
            let audit_value = &audit_hash.borrow().value;
            result = if audit_hash.borrow().is_left {
                Hash::hash(&format!("{}{}", audit_value, result))
            } else {
                Hash::hash(&format!("{}{}", result, audit_value))
            };
        }

        result == root.borrow().value
    }
}
