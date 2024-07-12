# Copyright (c) 2024 Wu Tingfeng <wutingfeng@outlook.com>
from __future__ import annotations

import hashlib
from typing import Any, Iterator


class Hash:
    def __init__(
        self,
        parent: Hash | None = None,
        left: Hash | None = None,
        right: Hash | None = None,
        value: str = "",
        is_left: bool = True,
    ) -> None:
        """Initialize node of a merkle tree.

        Args:
            parent (Hash | None, optional): This node's parent. Defaults to None.
            left (Hash | None, optional): This node's child. Defaults to None.
            right (Hash | None, optional): This node's right child. Defaults to None.
            value (str, optional): This node's hash value as hexdigest. Defaults to "".
            is_left (bool, optional): Whether this node is a left child. Defaults to True.
        """
        self.parent: Hash = parent
        self.left: Hash = left
        self.right: Hash = right
        self.value = value
        self.is_left = is_left  # Needed for proof verification.

    @classmethod
    def hash(cls, value: str) -> str:
        """Hash a given string to its sha256 hexdigest.

        Args:
            value (str): String to hash.

        Returns:
            str: sha256 hexdigest.
        """
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


class MerkleProof:
    def __init__(
        self, hashes: list[Hash], num_of_leaves: int, leaf_index: int, leaf_content: Any
    ) -> None:
        """Hold information needed to verify whether a particular leaf node belongs to a merkle tree.

        Args:
            hashes (list[Hash]): List of audit hashes needed to verify that a leaf node belongs to a merkle tree,
            arranged from the bottom-most hash up to the top-most hash (closest to root node).
            num_of_leaves (int): Number of leaves in the merkle tree.
            leaf_index (int): 0-based index of leaf node to be verified.
            leaf_content (Any): Content of leaf node to be verified.
        """
        self.hashes = hashes
        self.num_of_leaves = num_of_leaves
        self.leaf_index = leaf_index
        self.leaf_content = leaf_content


class MerkleTree:
    @classmethod
    def __make_parent(cls, left: Hash, right: Hash) -> Hash:
        """Given a left child node and a right child node, return a parent node whose value
        is the hash of the left child's hash concatenated with the right child's hash.
        Links between the parent and children are added accordingly.

        Args:
            left (Hash): Left child node.
            right (Hash): Right child node.

        Returns:
            Hash: Parent node.
        """
        parent = Hash(
            left=left,
            right=right,
            value=Hash.hash(left.value + right.value),
        )
        left.is_left = True
        right.is_left = False

        left.parent = parent
        right.parent = parent
        return parent

    @classmethod
    def __merkle_root_aux(cls, nodes: list[Hash]) -> Hash:
        """Recursively build a merkle tree from the bottom level (leaves) up to the top level (root node).

        Args:
            nodes (list[Hash]): Nodes of current level.

        Returns:
            Hash: Root node of the merkle tree.
        """
        if len(nodes) == 1:
            return nodes[0]
        parents = []
        is_odd = len(nodes) % 2 != 0

        # Iterate through sibling-pairs on the same level.
        for i in range(0, len(nodes) - (1 if is_odd else 0), 2):
            parents.append(cls.__make_parent(nodes[i], nodes[i + 1]))

        if is_odd:
            parents.append(nodes[-1])  # Last node has no sibling.
        return cls.__merkle_root_aux(parents)

    @classmethod
    def merkle_root(cls, leaves: Iterator) -> Hash:
        """Generate a merkle tree and return the root node.

        Args:
            leaves (Iterator): Leaves of merkle tree.

        Returns:
            Hash: Root node of merkle tree.
        """
        nodes: list[Hash] = [
            Hash(left=None, right=None, value=Hash.hash(leaf)) for leaf in leaves
        ]
        root: Hash = cls.__merkle_root_aux(nodes)
        return root

    @classmethod
    def __merkle_proof_aux(
        cls, nodes: list[Hash], audit_nodes: list[Hash], target_index: int
    ) -> list[Hash]:
        """Recursively build a merkle tree from the bottom level (leaves) up to the top level (root node).
        This is similar to `__merkle_root_aux` except that an accumulating of `audit_nodes` is maintained along with
        a `target_index`. At each recursive call, the sibling of the node at `target_index` is added to `audit_nodes`,
        then `target_index` is updated to the 0-based index of its parent at the immediate upper level. `audit_nodes`
        is returned when the root node level is reached.


        Args:
            nodes (list[Hash]): Nodes of current level.
            audit_nodes (list[Hash]): Accumulating list of nodes that are needed for the merkle proof.
            target_index (int): 0-based index of target node of the current level. The target node's sibling is
            the audit node for the current level.

        Returns:
            list[Hash]: List of nodes that are needed for the merkle proof.
        """
        if len(nodes) == 1:
            return audit_nodes
        parents = []
        sibling_index = (
            (target_index + 1) if target_index % 2 == 0 else (target_index - 1)
        )
        if sibling_index < len(nodes):
            audit_nodes.append(
                nodes[sibling_index]
            )  # Handle edge case for siblingless rightmost node on the level.
        new_target_index = target_index // 2

        is_odd = len(nodes) % 2 != 0

        # Iterate through sibling-pairs on the same level.
        for i in range(0, len(nodes) - (1 if is_odd else 0), 2):
            parents.append(cls.__make_parent(nodes[i], nodes[i + 1]))

        if is_odd:
            parents.append(nodes[-1])  # Last node has no sibling.
        return cls.__merkle_proof_aux(parents, audit_nodes, new_target_index)

    @classmethod
    def merkle_proof(cls, leaves: Iterator, leaf_index: int) -> MerkleProof:
        """Generate a merkle proof.

        Args:
            leaves (Iterator): Leaves of merkle tree.
            leaf_index (int): 0-based index of leaf node that needs to be verified.

        Returns:
            MerkleProof: Holds information needed to verify whether a particular leaf node belongs to a merkle tree.
        """
        nodes: list[Hash] = [
            Hash(left=None, right=None, value=Hash.hash(leaf)) for leaf in leaves
        ]
        audit_nodes = cls.__merkle_proof_aux(nodes, [], leaf_index)
        return MerkleProof(audit_nodes, len(leaves), leaf_index, leaves[leaf_index])

    @classmethod
    def verify_proof(cls, root: Hash, proof: MerkleProof) -> bool:
        """Given a merkle root node, verify a proof by checking whether it is able
        to reconstruct the same root node.

        Args:
            root (Hash): Root node of the merkle tree.
            proof (MerkleProof): Proof to be verified.

        Returns:
            bool: True if verification is successful, otherwise False.
        """
        result = Hash.hash(proof.leaf_content)

        for audit_hash in proof.hashes:
            if audit_hash.is_left:
                result = Hash.hash(audit_hash.value + result)
            else:
                result = Hash.hash(result + audit_hash.value)
        return result == root.value


if __name__ == "__main__":
    data = ["abc", "bcd", "cde", "def", "efg"]
    root = MerkleTree.merkle_root(data)
    if root.value != "b12bb480c5d29242ab22fe53c199c26a5a5bd1ac66ac2702099855ceaf006073":
        raise ValueError("Incorrect root value")
    proof = MerkleTree.merkle_proof(data, 1)
    if not MerkleTree.verify_proof(root, proof):
        raise ValueError("Expected proof to be accepted, but it was rejected.")
    proof.leaf_content += "tainted"
    if MerkleTree.verify_proof(root, proof):
        raise ValueError("Expected proof to be rejected, but it was accepted.")
