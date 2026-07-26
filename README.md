# zkVM-rs

A STARK-based zkVM in Rust. A minimal register-based virtual machine with a complete proving pipeline: execution, trace generation, algebraic constraints (AIR), STARK proof generation, and verification.


## The VM

- 4 registers (`r0`–`r3`)
- 6 instructions: `NOP`, `IMM`, `ADD`, `MUL`, `SUB`, `HALT`
- No memory, no branches, no jumps
- All arithmetic in the Goldilocks field (`p = 2^64 - 2^32 + 1`)

## The Pipeline

```
Program → VM Execution → Execution Trace → Polynomial Interpolation →
Constraint Evaluation → Quotient Division → FRI Low-Degree Test → Verification
```

The prover interpolates the trace into polynomials, evaluates them on an LDE domain (8x blowup), commits via Merkle trees, computes a quotient polynomial, and runs FRI. The verifier re-derives Fiat-Shamir challenges, checks FRI, verifies Merkle proofs, and confirms `C(z) = Q(z) * Z_H(z)` at random query points. 30 queries give ~90 bits of soundness.

## Quick Start

```bash
cargo run    # Execute a program, generate and verify a STARK proof
cargo test   # Run all 37 tests
```

The demo computes `(3 + 4)^2 - (3 + 4) = 42` in six instructions and proves the execution.

## Source Files

| File | Description |
|---|---|
| `field.rs` | Goldilocks field arithmetic (`Fp`) |
| `polynomial.rs` | Polynomial operations, Lagrange interpolation |
| `domain.rs` | Trace and LDE evaluation domains |
| `instruction.rs` | ISA definition (6 opcodes, uniform encoding) |
| `vm.rs` | Fetch-decode-execute loop, produces execution trace |
| `trace.rs` | 13-column trace table, power-of-two padding |
| `air.rs` | 8 transition constraints, selector polynomials, composition |
| `prover.rs` | Full STARK prover |
| `verifier.rs` | STARK verifier |
| `fri.rs` | FRI protocol (commit, query, verify) |
| `merkle.rs` | Binary Merkle tree (SHA-256) |
| `channel.rs` | Fiat-Shamir transcript |

## Dependencies

The only external dependency is [`sha2`](https://crates.io/crates/sha2) for Merkle tree hashing.