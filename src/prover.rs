/// The STARK prover: generatorerates a proof that the execution trace is valid.
///
/// The prover's job:
/// 1. Interpolate trace columns into polynomials
/// 2. Evaluate them on a larger domain (LDE — Low Degree Extension)
/// 3. Commit to the evaluations via Merkle tree
/// 4. Build the composition polynomial from all constraints
/// 5. Compute the quotient: Q(x) = C(x) / Z_H(x)
/// 6. Run FRI on Q(x) to prove it's low-degree
/// 7. Open trace and quotient at random query points
use crate::field::Fp;
use crate::instruction::Instruction;
use crate::trace::{ExecutionTrace, NUM_COLUMNS};
use crate::air;
use crate::polynomial::Polynomial;
use crate::domain::Domain;
use crate::merkle::MerkleTree;
use crate::channel::Channel;
use crate::fri::{self, FriProof, NUM_FRI_QUERIES};

/// Blowup factor for the LDE domain. Higher = more security per query.
pub const BLOWUP_FACTOR: usize = 8;

/// The complete STARK proof.
#[derive(Debug, Clone)]
pub struct StarkProof {
    /// Merkle root committing to trace evaluations on the LDE domain.
    pub trace_root: [u8; 32],
    /// Merkle root committing to quotient evaluations on the LDE domain.
    pub quotient_root: [u8; 32],
    /// FRI proof that the quotient polynomial is low-degree.
    pub fri_proof: FriProof,
    /// Query responses: opened trace and quotient values at queried positions.
    pub query_responses: Vec<QueryResponse>,
    /// Query indices (derived from Fiat-Shamir, included for convenience).
    pub query_indices: Vec<usize>,
    /// The program (public).
    pub program: Vec<Instruction>,
    /// Claimed register outputs at the HALT row.
    pub outputs: [Fp; 4],
    /// Trace length (padded, power of 2).
    pub trace_length: usize,
    /// Number of real (non-padding) rows.
    pub real_trace_length: usize,
}

/// Data opened at a single query point.
#[derive(Debug, Clone)]
pub struct QueryResponse {
    /// Index in the LDE domain.
    pub index: usize,
    /// Trace column values at this LDE point (all NUM_COLUMNS columns).
    pub trace_values: [Fp; NUM_COLUMNS],
    /// Trace column values at the "next" LDE point (index + blowup_factor).
    pub trace_next_values: [Fp; NUM_COLUMNS],
    /// Merkle proof for trace_values.
    pub trace_proof: crate::merkle::MerkleProof,
    /// Merkle proof for trace_next_values.
    pub trace_next_proof: crate::merkle::MerkleProof,
    /// Quotient polynomial value at this LDE point.
    pub quotient_value: Fp,
    /// Merkle proof for quotient_value.
    pub quotient_proof: crate::merkle::MerkleProof,
}

/// generatorerate a STARK proof for the given execution trace.
pub fn prove(trace: &ExecutionTrace, program: &[Instruction]) -> StarkProof {
    let n = trace.len();
    assert!(n.is_power_of_two());

    let trace_domain = Domain::trace_domain(n);
    let lde_domain = Domain::lde_domain(n, BLOWUP_FACTOR);
    let lde_size = lde_domain.size;
    let lde_elements = lde_domain.elements();

    println!("  Trace length: {} (padded), LDE domain: {} points", n, lde_size);

    // --- Step 1: Interpolate each trace column into a polynomial ---
    let trace_omega = trace_domain.generator;
    let trace_polys: Vec<Polynomial> = (0..NUM_COLUMNS)
        .map(|col| {
            let values = trace.get_column(col);
            Polynomial::interpolate_subgroup(trace_omega, &values)
        })
        .collect();

    println!("  Interpolated {} trace columns", NUM_COLUMNS);

    // --- Step 2: Evaluate trace polynomials on LDE domain ---
    let trace_lde: Vec<Vec<Fp>> = trace_polys
        .iter()
        .map(|poly| poly.evaluate_domain(&lde_elements))
        .collect();

    // --- Step 3: Commit to trace LDE via Merkle tree ---
    // Each leaf is the concatenation of all column values at one LDE point.
    let trace_leaves: Vec<Vec<u8>> = (0..lde_size)
        .map(|i| {
            let mut data = Vec::with_capacity(NUM_COLUMNS * 8);
            for col in 0..NUM_COLUMNS {
                data.extend_from_slice(&trace_lde[col][i].value().to_le_bytes());
            }
            data
        })
        .collect();
    let trace_tree = MerkleTree::new(&trace_leaves);
    let trace_root = trace_tree.root();

    println!("  Committed to trace (Merkle root: {:02x}{:02x}...)", trace_root[0], trace_root[1]);

    // --- Step 4: Fiat-Shamir — derive composition challenge alpha ---
    let mut channel = Channel::new();
    // Absorb the program (public input) so challenges are bound to it.
    // Without this, a valid proof for program A could be resubmitted as a proof for program B.
    for instr in program {
        channel.absorb(&[instr.opcode as u8, instr.rd, instr.rs1, instr.rs2]);
        channel.absorb(&instr.imm.to_le_bytes());
    }
    channel.absorb(&trace_root);
    let alpha = channel.squeeze_field();

    println!("  Composition challenge alpha: {}", alpha);

    // --- Step 5: Build composition polynomial C(x) = SUM_i alpha^i * C_i(x) ---
    // Evaluate the composition on the LDE domain pointwise.
    // For each LDE point, we need the trace values at that point AND the next point
    // (since transition constraints relate adjacent rows).
    //
    // The "next" point for LDE index i is at index (i + blowup_factor) % lde_size,
    // because on the trace domain, the next row omega^{k+1} maps to
    // LDE point omega_lde^{(k+1)*blowup} = omega_lde^{k*blowup + blowup}.
    let mut composition_evals = vec![Fp::ZERO; lde_size];

    for i in 0..lde_size {
        let next_i = (i + BLOWUP_FACTOR) % lde_size;

        let mut current = [Fp::ZERO; NUM_COLUMNS];
        let mut next = [Fp::ZERO; NUM_COLUMNS];
        for col in 0..NUM_COLUMNS {
            current[col] = trace_lde[col][i];
            next[col] = trace_lde[col][next_i];
        }

        composition_evals[i] = air::evaluate_composition(&current, &next, alpha);
    }

    // --- Step 6: Compute quotient Q(x) = C(x) / Z_H(x) ---
    // Z_H(x) = x^n - 1, which vanishes on the trace domain.
    // We compute Q pointwise on the LDE domain: Q(d) = C(d) / Z_H(d).
    let mut quotient_evals = vec![Fp::ZERO; lde_size];
    for i in 0..lde_size {
        let x = lde_elements[i];
        // Z_H(x) = x^n - 1
        let z_h = x.pow(n as u64) - Fp::ONE;
        // z_h should never be zero on the LDE domain (since it's a coset, not the trace domain)
        assert!(z_h != Fp::ZERO, "vanishing polynomial is zero on LDE domain at index {}", i);
        quotient_evals[i] = composition_evals[i] * z_h.inv();
    }

    println!("  Computed quotient polynomial");

    // --- Step 7: Commit to quotient LDE ---
    let quotient_leaves: Vec<Vec<u8>> = quotient_evals
        .iter()
        .map(|v| v.value().to_le_bytes().to_vec())
        .collect();
    let quotient_tree = MerkleTree::new(&quotient_leaves);
    let quotient_root = quotient_tree.root();

    channel.absorb(&quotient_root);

    println!("  Committed to quotient (Merkle root: {:02x}{:02x}...)", quotient_root[0], quotient_root[1]);

    // --- Step 8: FRI on the quotient polynomial ---
    let (fri_layers, fri_final_value) = fri::fri_commit(
        &quotient_evals,
        lde_domain.generator,
        lde_domain.offset,
        &mut channel,
    );

    println!("  FRI: {} layers, final value: {}", fri_layers.len(), fri_final_value);

    // --- Step 9: Derive query indices ---
    // Cap queries to half the available positions to avoid infinite loops on small traces
    let max_queries = (lde_size / 4).min(NUM_FRI_QUERIES);
    let query_indices = channel.squeeze_indices(max_queries, lde_size / 2);

    // generatorerate FRI query proofs
    let fri_query_proofs = fri::fri_query(&fri_layers, &query_indices);

    let fri_proof = FriProof {
        layer_roots: fri_layers.iter().map(|l| l.root).collect(),
        final_value: fri_final_value,
        query_proofs: fri_query_proofs,
    };

    // --- Step 10: Open trace and quotient at query points ---
    let query_responses: Vec<QueryResponse> = query_indices
        .iter()
        .map(|&idx| {
            let next_idx = (idx + BLOWUP_FACTOR) % lde_size;

            let mut trace_values = [Fp::ZERO; NUM_COLUMNS];
            let mut trace_next_values = [Fp::ZERO; NUM_COLUMNS];
            for col in 0..NUM_COLUMNS {
                trace_values[col] = trace_lde[col][idx];
                trace_next_values[col] = trace_lde[col][next_idx];
            }

            QueryResponse {
                index: idx,
                trace_values,
                trace_next_values,
                trace_proof: trace_tree.prove(idx),
                trace_next_proof: trace_tree.prove(next_idx),
                quotient_value: quotient_evals[idx],
                quotient_proof: quotient_tree.prove(idx),
            }
        })
        .collect();

    // Collect outputs (register values at the last real row)
    let last_real = &trace.rows[trace.real_len - 1];
    let outputs = [last_real.r0, last_real.r1, last_real.r2, last_real.r3];

    println!("  generatorerated {} query responses", query_responses.len());

    StarkProof {
        trace_root,
        quotient_root,
        fri_proof,
        query_responses,
        query_indices,
        program: program.to_vec(),
        outputs,
        trace_length: n,
        real_trace_length: trace.real_len,
    }
}