/// Merkle tree for committing to polynomial evaluations.
///
/// A Merkle tree lets us commit to a list of values with a single hash (the root),
/// and later prove that any individual value was part of the committed list.
///
/// In our STARK:
/// - The prover commits to trace and quotient polynomial evaluations via Merkle trees
/// - The verifier asks to see specific evaluations (queries)
/// - The prover provides the values along with Merkle proofs
/// - The verifier checks the proofs against the committed root
use sha2::{Digest, Sha256};

/// Hash a field element (or arbitrary bytes) to 32 bytes.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash two 32-byte values together (for internal Merkle nodes).
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// A Merkle tree over a list of leaf hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes, stored as a flat array. nodes[1] is the root.
    /// nodes[n..2n] are the leaves (for n leaves).
    nodes: Vec<[u8; 32]>,
    num_leaves: usize,
}

/// A proof that a specific leaf is part of the tree.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    /// Each leaf is hashed individually, then pairs are hashed up the tree.
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        let n = leaves.len();
        assert!(n.is_power_of_two(), "number of leaves must be a power of 2");

        // Allocate 2n nodes. Index 0 is unused; index 1 is root; n..2n are leaves.
        let mut nodes = vec![[0u8; 32]; 2 * n];

        // Hash leaves
        for i in 0..n {
            nodes[n + i] = hash_bytes(&leaves[i]);
        }

        // Build internal nodes bottom-up
        for i in (1..n).rev() {
            nodes[i] = hash_pair(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        MerkleTree { nodes, num_leaves: n }
    }

    /// The root hash (commitment to all leaves).
    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    /// generatorerate a proof for the leaf at the given index.
    pub fn prove(&self, index: usize) -> MerkleProof {
        assert!(index < self.num_leaves);
        let mut siblings = Vec::new();
        let mut pos = self.num_leaves + index;

        while pos > 1 {
            // Sibling is the other child of the same parent
            let sibling = pos ^ 1;
            siblings.push(self.nodes[sibling]);
            pos >>= 1; // move to parent
        }

        MerkleProof { siblings }
    }

    /// Verify a Merkle proof.
    pub fn verify(
        root: &[u8; 32],
        index: usize,
        leaf_data: &[u8],
        proof: &MerkleProof,
        num_leaves: usize,
    ) -> bool {
        let mut current = hash_bytes(leaf_data);
        let mut pos = num_leaves + index;

        for sibling in &proof.siblings {
            if pos & 1 == 0 {
                // current is left child
                current = hash_pair(&current, sibling);
            } else {
                // current is right child
                current = hash_pair(sibling, &current);
            }
            pos >>= 1;
        }

        current == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_prove_verify() {
        let leaves: Vec<Vec<u8>> = (0..8u64)
            .map(|i| i.to_le_bytes().to_vec())
            .collect();
        let tree = MerkleTree::new(&leaves);

        // Every leaf should verify
        for i in 0..8 {
            let proof = tree.prove(i);
            assert!(
                MerkleTree::verify(&tree.root(), i, &leaves[i], &proof, 8),
                "proof failed for leaf {}",
                i,
            );
        }
    }

    #[test]
    fn test_merkle_tampered_data_fails() {
        let leaves: Vec<Vec<u8>> = (0..4u64)
            .map(|i| i.to_le_bytes().to_vec())
            .collect();
        let tree = MerkleTree::new(&leaves);
        let proof = tree.prove(0);

        // Tampered data should fail verification
        let bad_data = 99u64.to_le_bytes().to_vec();
        assert!(!MerkleTree::verify(&tree.root(), 0, &bad_data, &proof, 4));
    }
}