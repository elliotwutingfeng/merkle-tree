# Toy Merkle Tree

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

Toy Merkle Tree implemented in Rust and in Python using the SHA256 hash function.

## Details

- Supports arbitrary number of leaves. They are initially hashed using the same hash
function as the inner nodes. Inner nodes are created by concatenating child hashes
and hashing again.
- This implementation does not perform any sorting of the input data (leaves).
- If the number of leaves is not even, the last leaf is promoted to the upper layer.

## Requirements

- Rust >= 1.79.0
- Python >= 3.12

## Usage

### Rust Example

```rust
use merkle_tree::MerkleTree;
use std::borrow::BorrowMut;

pub fn main() {
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
```

### Python Example

```python
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
```

## Testing

### Testing In Rust

```bash
cargo test
```

### Testing In Python

```bash
python -m unittest discover tests
```

## References

- <https://en.wikipedia.org/wiki/Merkle_tree>
- <https://ethereum.org/en/developers/tutorials/merkle-proofs-for-offline-data-integrity>
- Merkle Trees: What They Are and the Problems They Solve <https://www.codementor.io/blog/merkle-trees-5h9arzd3n8>
