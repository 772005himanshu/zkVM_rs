/// FRI (Fast Reed-Solomon Interactive Oracle Proof) — low-degree testing.
///
/// FRI is the mechanism that convinces the verifier that a committed polynomial
/// is actually low-degree (not arbitrary data). Without this, the prover could
/// commit to random data and fake the constraint check at individual query points.
///
/// **Core idea:** If f(x) is a polynomial of degree < d, we can "fold" it into
/// a polynomial of degree < d/2 by splitting into even and odd parts:
///   f(x) = f_even(x^2) + x * f_odd(x^2)
///   f_folded(y) = f_even(y) + beta * f_odd(y)
///
/// After log2(d) folding rounds, we should be left with a constant.
/// If the original function was NOT a low-degree polynomial, the folded values
/// will be inconsistent, and the verifier will catch it.
use crate::field::Fp;
use crate::merkle::{MerkleTree, MerkleProof};
use crate::channel::Channel;

/// Number of FRI queries (each provides ~3 bits of security with blowup 8).
pub const NUM_FRI_QUERIES: usize = 30;

/// A single FRI layer's commitment and metadata.
#[derive(Debug, Clone)]
pub struct FriLayer {
    /// Merkle root of this layer's evaluations.
    pub root: [u8; 32],
    /// The evaluations themselves (prover keeps these, verifier doesn't see them).
    pub evaluations: Vec<Fp>,
    /// The Merkle tree (prover keeps for generating proofs).
    pub tree: MerkleTree,
}

/// The complete FRI proof.
#[derive(Debug, Clone)]
pub struct FriProof {
    /// Merkle root of each folding layer.
    pub layer_roots: Vec<[u8; 32]>,
    /// The final constant value after all folding rounds.
    pub final_value: Fp,
    /// Query proofs: for each query, the opened values and Merkle proofs at each layer.
    pub query_proofs: Vec<FriQueryProof>,
}

/// Proof data for a single FRI query across all layers.
#[derive(Debug, Clone)]
pub struct FriQueryProof {
    /// For each layer: (value_at_index, value_at_sibling, merkle_proof_index, merkle_proof_sibling)
    pub layers: Vec<FriQueryLayer>,
}

/// Query data for one layer.
#[derive(Debug, Clone)]
pub struct FriQueryLayer {
    pub value: Fp,
    pub sibling_value: Fp,
    pub proof: MerkleProof,
    pub sibling_proof: MerkleProof,
}

/// FRI commit phase: fold the polynomial evaluations down to a constant.
///
/// Takes evaluations of a polynomial on a coset domain and produces:
/// - Merkle commitments at each layer
/// - The final constant value
/// - All data needed for query proofs
///
/// `evaluations`: polynomial evaluations on the LDE domain
/// `domain_generator`: generator of the LDE domain (before coset shift)
/// `domain_offset`: coset offset of the LDE domain
pub fn fri_commit(
    evaluations: &[Fp],
    domain_generator: Fp,
    domain_offset: Fp,
    channel: &mut Channel,
) -> (Vec<FriLayer>, Fp) {
    let mut layers: Vec<FriLayer> = Vec::new();
    let mut current_evals = evaluations.to_vec();
    let mut current_generator = domain_generator;
    let mut current_offset = domain_offset;

    // Keep folding until we have a single value or a very small layer
    while current_evals.len() > 1 {
        // Commit to current layer
        let leaf_data: Vec<Vec<u8>> = current_evals
            .iter()
            .map(|v| v.value().to_le_bytes().to_vec())
            .collect();
        let tree = MerkleTree::new(&leaf_data);
        let root = tree.root();

        channel.absorb(&root);

        layers.push(FriLayer {
            root,
            evaluations: current_evals.clone(),
            tree,
        });

        // If only 2 elements, one more fold gives us a constant
        if current_evals.len() <= 2 {
            break;
        }

        // Derive folding challenge
        let beta = channel.squeeze_field();

        // Fold: split evaluations into pairs (index, index + half)
        // For evaluation at domain point d_i = offset * generator^i:
        //   f(d_i) and f(d_{i+half}) where d_{i+half} = -d_i (on a coset)
        //
        // f_even = (f(d_i) + f(-d_i)) / 2
        // f_odd  = (f(d_i) - f(-d_i)) / (2 * d_i)
        // f_folded = f_even + beta * f_odd
        let half = current_evals.len() / 2;
        let mut folded = Vec::with_capacity(half);

        let two_inv = Fp::new(2).inv();

        for i in 0..half {
            let f_pos = current_evals[i];
            let f_neg = current_evals[i + half];

            // d_i = offset * generator^i
            let d_i = current_offset * current_generator.pow(i as u64);

            let f_even = (f_pos + f_neg) * two_inv;
            let f_odd = (f_pos - f_neg) * (Fp::new(2) * d_i).inv();

            folded.push(f_even + beta * f_odd);
        }

        // New domain: generator squared, offset squared, half the size
        current_generator = current_generator * current_generator;
        current_offset = current_offset * current_offset;
        current_evals = folded;
    }

    // The final value is the (only remaining) evaluation
    let final_value = if current_evals.len() == 1 {
        current_evals[0]
    } else {
        // Fold the last pair
        let beta = channel.squeeze_field();
        let d_0 = current_offset;
        let two_inv = Fp::new(2).inv();
        let f_even = (current_evals[0] + current_evals[1]) * two_inv;
        let f_odd = (current_evals[0] - current_evals[1]) * (Fp::new(2) * d_0).inv();
        f_even + beta * f_odd
    };

    (layers, final_value)
}

/// FRI query phase: open values at queried indices across all layers.
pub fn fri_query(
    layers: &[FriLayer],
    query_indices: &[usize],
) -> Vec<FriQueryProof> {
    query_indices
        .iter()
        .map(|&initial_idx| {
            let mut layer_proofs = Vec::new();
            let mut idx = initial_idx;

            for layer in layers {
                let half = layer.evaluations.len() / 2;
                // Normalize index to be in the first half
                let lo = idx % half;
                let hi = lo + half;

                layer_proofs.push(FriQueryLayer {
                    value: layer.evaluations[lo],
                    sibling_value: layer.evaluations[hi],
                    proof: layer.tree.prove(lo),
                    sibling_proof: layer.tree.prove(hi),
                });

                // Index for next layer is lo (halved domain)
                idx = lo;
            }

            FriQueryProof { layers: layer_proofs }
        })
        .collect()
}

/// FRI commit-phase replay: absorb layer roots and derive folding challenges.
///
/// This must be called before deriving query indices, because in the prover's
/// transcript, FRI layer roots are absorbed before query indices are squeezed.
/// Returns the folding challenges (betas).
pub fn fri_derive_betas(
    proof: &FriProof,
    channel: &mut Channel,
) -> Vec<Fp> {
    let num_layers = proof.layer_roots.len();
    let mut betas = Vec::new();
    for root in &proof.layer_roots {
        channel.absorb(root);
        if betas.len() < num_layers {
            betas.push(channel.squeeze_field());
        }
    }
    betas
}

/// FRI query-phase verification: check that the folding is consistent at queried indices.
///
/// Called after `fri_derive_betas` and after the verifier derives its own query indices.
pub fn fri_verify_queries(
    proof: &FriProof,
    betas: &[Fp],
    initial_domain_generator: Fp,
    initial_domain_offset: Fp,
    initial_domain_size: usize,
    query_indices: &[usize],
) -> Result<(), String> {
    if query_indices.is_empty() {
        return Err("no query indices — proof has no security".to_string());
    }
    if proof.query_proofs.len() != query_indices.len() {
        return Err(format!(
            "expected {} FRI query proofs, got {}",
            query_indices.len(), proof.query_proofs.len()
        ));
    }

    let current_generator = initial_domain_generator;
    let current_offset = initial_domain_offset;
    let current_size = initial_domain_size;

    for (q_idx, query_proof) in proof.query_proofs.iter().enumerate() {
        let mut idx = query_indices[q_idx];
        let mut generator = current_generator;
        let mut offset = current_offset;
        let mut size = current_size;

        for (layer_idx, ql) in query_proof.layers.iter().enumerate() {
            let half = size / 2;
            let lo = idx % half;
            let hi = lo + half;

            // Verify Merkle proofs
            let lo_data = ql.value.value().to_le_bytes().to_vec();
            let hi_data = ql.sibling_value.value().to_le_bytes().to_vec();

            if !MerkleTree::verify(
                &proof.layer_roots[layer_idx],
                lo,
                &lo_data,
                &ql.proof,
                size,
            ) {
                return Err(format!(
                    "FRI Merkle proof failed: query {}, layer {}, index {}",
                    q_idx, layer_idx, lo
                ));
            }
            if !MerkleTree::verify(
                &proof.layer_roots[layer_idx],
                hi,
                &hi_data,
                &ql.sibling_proof,
                size,
            ) {
                return Err(format!(
                    "FRI Merkle proof failed: query {}, layer {}, sibling index {}",
                    q_idx, layer_idx, hi
                ));
            }

            // Verify folding consistency (if not the last layer)
            if layer_idx + 1 < query_proof.layers.len() {
                let d_i = offset * generator.pow(lo as u64);
                let two_inv = Fp::new(2).inv();
                let beta = betas[layer_idx];

                let f_even = (ql.value + ql.sibling_value) * two_inv;
                let f_odd = (ql.value - ql.sibling_value) * (Fp::new(2) * d_i).inv();
                let expected = f_even + beta * f_odd;

                // The next layer's value at `lo` should match
                // (but we need the correct index in the next layer)
                let next_lo = lo % (half / 2);
                let actual = if lo == next_lo {
                    query_proof.layers[layer_idx + 1].value
                } else {
                    query_proof.layers[layer_idx + 1].sibling_value
                };

                if expected != actual {
                    return Err(format!(
                        "FRI folding mismatch: query {}, layer {}, expected {:?}, got {:?}",
                        q_idx, layer_idx, expected, actual
                    ));
                }
            } else {
                // Last layer: folded value should equal the claimed final constant
                let d_i = offset * generator.pow(lo as u64);
                let two_inv = Fp::new(2).inv();
                let beta = betas[layer_idx];
                let f_even = (ql.value + ql.sibling_value) * two_inv;
                let f_odd = (ql.value - ql.sibling_value) * (Fp::new(2) * d_i).inv();
                let expected = f_even + beta * f_odd;

                if expected != proof.final_value {
                    return Err(format!(
                        "FRI final value mismatch: query {}, expected {:?}, got {:?}",
                        q_idx, expected, proof.final_value
                    ));
                }
            }

            // Move to next layer's domain
            generator = generator * generator;
            offset = offset * offset;
            size = half;
            idx = lo;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomial::Polynomial;
    use crate::domain::Domain;

    #[test]
    fn test_fri_honest_polynomial() {
        // Create a low-degree polynomial and prove it via FRI
        let trace_size = 8;
        let blowup = 8;
        let lde_domain = Domain::lde_domain(trace_size, blowup);

        // A random degree-7 polynomial
        let poly = Polynomial {
            coeffs: vec![
                Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4),
                Fp::new(5), Fp::new(6), Fp::new(7), Fp::new(8),
            ],
        };

        // Evaluate on LDE domain
        let lde_elems = lde_domain.elements();
        let evals: Vec<Fp> = lde_elems.iter().map(|x| poly.evaluate(*x)).collect();

        // Commit
        let mut prover_channel = Channel::new();
        prover_channel.absorb(b"test_fri");
        let (layers, final_value) = fri_commit(
            &evals,
            lde_domain.generator,
            lde_domain.offset,
            &mut prover_channel,
        );

        // Derive query indices (must replay the same transcript as the prover)
        let max_queries = (lde_domain.size / 4).min(NUM_FRI_QUERIES);
        let query_indices = prover_channel.squeeze_indices(max_queries, lde_domain.size / 2);
        let query_proofs = fri_query(&layers, &query_indices);

        let fri_proof = FriProof {
            layer_roots: layers.iter().map(|l| l.root).collect(),
            final_value,
            query_proofs,
        };

        // Verify: replay transcript to derive betas, then derive query indices, then check queries
        let mut verifier_channel = Channel::new();
        verifier_channel.absorb(b"test_fri");
        let betas = fri_derive_betas(&fri_proof, &mut verifier_channel);
        let verifier_indices = verifier_channel.squeeze_indices(max_queries, lde_domain.size / 2);
        assert_eq!(query_indices, verifier_indices, "query indices must match");

        let result = fri_verify_queries(
            &fri_proof,
            &betas,
            lde_domain.generator,
            lde_domain.offset,
            lde_domain.size,
            &verifier_indices,
        );

        assert!(result.is_ok(), "FRI verification failed: {:?}", result.err());
    }
}