/// Fiat-Shamir transcript — turning an interactive proof into a non-interactive one.
///
/// In an interactive proof, the verifier sends random challenges to the prover.
/// The Fiat-Shamir heuristic replaces this: the prover hashes their commitments
/// to derive the challenges deterministically. The verifier re-derives the same
/// challenges from the same commitments, ensuring consistency.
///
/// Think of it as: the verifier seals their challenges in an envelope (the hash)
/// before the prover commits. The prover can't cheat because the challenges depend
/// on what they already committed.
use sha2::{Digest, Sha256};
use crate::field::{Fp, P};

/// A Fiat-Shamir channel that absorbs commitments and squeezes challenges.
pub struct Channel {
    state: Sha256,
}

impl Channel {
    pub fn new() -> Self {
        Channel { state: Sha256::new() }
    }

    /// Feed data into the transcript (e.g., a Merkle root or a field element).
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Absorb a field element.
    pub fn absorb_field(&mut self, val: Fp) {
        self.absorb(&val.value().to_le_bytes());
    }

    /// Derive a field element challenge from the current transcript state.
    /// This finalizes the current hash, uses the output as the challenge,
    /// then resets the state with the hash output as the new seed.
    pub fn squeeze_field(&mut self) -> Fp {
        let hash = self.state.finalize_reset();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);

        // Seed the next state with this hash
        self.state.update(&bytes);

        // Reduce the first 8 bytes to a field element
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&bytes[0..8]);
        let raw = u64::from_le_bytes(val_bytes);
        Fp::new(raw % P)
    }

    /// Derive multiple distinct indices in [0, max) from the transcript.
    /// Used for query index generatoreration.
    pub fn squeeze_indices(&mut self, count: usize, max: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(count);
        while indices.len() < count {
            let val = self.squeeze_field().value() as usize;
            let idx = val % max;
            if !indices.contains(&idx) {
                indices.push(idx);
            }
        }
        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        // Same inputs should produce same outputs
        let mut c1 = Channel::new();
        let mut c2 = Channel::new();
        c1.absorb(b"hello");
        c2.absorb(b"hello");
        assert_eq!(c1.squeeze_field(), c2.squeeze_field());
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let mut c1 = Channel::new();
        let mut c2 = Channel::new();
        c1.absorb(b"hello");
        c2.absorb(b"world");
        assert_ne!(c1.squeeze_field(), c2.squeeze_field());
    }

    #[test]
    fn test_squeeze_indices() {
        let mut c = Channel::new();
        c.absorb(b"test");
        let indices = c.squeeze_indices(5, 100);
        assert_eq!(indices.len(), 5);
        // All should be distinct and in range
        for &idx in &indices {
            assert!(idx < 100);
        }
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        assert_eq!(unique.len(), 5);
    }
}