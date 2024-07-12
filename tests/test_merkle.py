# Copyright (c) 2024 Wu Tingfeng <wutingfeng@outlook.com>
import unittest

from src.lib import Hash, MerkleProof, MerkleTree


class TestMerkleTree(unittest.TestCase):
    h0 = Hash.hash("0")
    h1 = Hash.hash("1")
    h2 = Hash.hash("2")
    h3 = Hash.hash("3")
    h4 = Hash.hash("4")
    h5 = Hash.hash("5")
    h6 = Hash.hash("6")
    h7 = Hash.hash("7")
    h8 = Hash.hash("8")
    h_h0_h1 = Hash.hash(h0 + h1)
    h_h2_h3 = Hash.hash(h2 + h3)
    h_h4_h5 = Hash.hash(h4 + h5)
    h_h6_h7 = Hash.hash(h6 + h7)

    def test_merkle_root(self):
        for leaves, correct_root_value in [
            (list("0"), self.h0),
            (list("01"), self.h_h0_h1),
            (list("012"), Hash.hash(self.h_h0_h1 + self.h2)),
            (list("0123"), Hash.hash(self.h_h0_h1 + self.h_h2_h3)),
            (
                list("01234"),
                Hash.hash(Hash.hash(self.h_h0_h1 + self.h_h2_h3) + self.h4),
            ),
            (
                list("012345"),
                Hash.hash(Hash.hash(self.h_h0_h1 + self.h_h2_h3) + self.h_h4_h5),
            ),
            (
                list("0123456"),
                Hash.hash(
                    Hash.hash(self.h_h0_h1 + self.h_h2_h3)
                    + Hash.hash(self.h_h4_h5 + self.h6)
                ),
            ),
            (
                list("01234567"),
                Hash.hash(
                    Hash.hash(self.h_h0_h1 + self.h_h2_h3)
                    + Hash.hash(self.h_h4_h5 + self.h_h6_h7)
                ),
            ),
            (
                list("012345678"),
                Hash.hash(
                    Hash.hash(
                        Hash.hash(self.h_h0_h1 + self.h_h2_h3)
                        + Hash.hash(self.h_h4_h5 + self.h_h6_h7)
                    )
                    + self.h8,
                ),
            ),
        ]:
            assert MerkleTree.merkle_root(leaves).value == correct_root_value

    def test_merkle_proof(self):
        for leaves, leaf_index, expected_proof_nodes in [
            (list("0"), 0, []),
            (list("01"), 0, [self.h1]),
            (list("012"), 1, [self.h0, self.h2]),
            (list("012"), 2, [self.h_h0_h1]),  # Same as above, but different leaf.
            (list("0123"), 2, [self.h3, self.h_h0_h1]),
            (list("01234"), 1, [self.h0, self.h_h2_h3, self.h4]),
            (list("012345"), 1, [self.h0, self.h_h2_h3, self.h_h4_h5]),
            (
                list("0123456"),
                4,
                [self.h5, self.h6, Hash.hash(self.h_h0_h1 + self.h_h2_h3)],
            ),
        ]:
            proof: MerkleProof = MerkleTree.merkle_proof(leaves, leaf_index)
            proof_hash_values = [h.value for h in proof.hashes]
            assert proof_hash_values == expected_proof_nodes

    def test_verify_proof(self):
        for leaves in [list(map(str, range(i))) for i in range(1, 11)]:
            root = MerkleTree.merkle_root(leaves)
            for leaf_index in range(len(leaves)):
                proof = MerkleTree.merkle_proof(leaves, leaf_index)
                assert MerkleTree.verify_proof(root, proof) is True
                proof.leaf_content += "tainted"
                assert MerkleTree.verify_proof(root, proof) is False
