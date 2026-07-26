/// This program demonstrates the complete STARK pipeline:
/// 1. Define a program in our toy instruction set
/// 2. Execute it to produce an execution trace
/// 3. Verify the trace satisfies all algebraic constraints
/// 4. generatorerate a STARK proof (with FRI)
/// 5. Verify the proof WITHOUT re-executing
use zkVM_rs::instruction::Instruction;
use zkVM_rs::vm;
use zkVM_rs::air;
use zkVM_rs::prover;
use zkVM_rs::verifier;

fn main() {
    println!("=== Educational ZKVM (v0.2) ===");
    println!("Field: Goldilocks (p = 2^64 - 2^32 + 1)");
    println!("ISA: 6 instructions (NOP, IMM, ADD, MUL, SUB, HALT)");
    println!("Proof system: STARK with FRI\n");

    // --- Step 1: Define a program ---
    // Computes: (3 + 4) * (3 + 4) - 7 = 42
    let program = vec![
        Instruction::imm(0, 3),       // r0 = 3
        Instruction::imm(1, 4),       // r1 = 4
        Instruction::add(2, 0, 1),    // r2 = r0 + r1 = 7
        Instruction::mul(3, 2, 2),    // r3 = r2 * r2 = 49
        Instruction::sub(0, 3, 2),    // r0 = r3 - r2 = 42
        Instruction::halt(),          // stop
    ];

    println!("Program ({} instructions):", program.len());
    println!("  0: IMM r0, 3");
    println!("  1: IMM r1, 4");
    println!("  2: ADD r2, r0, r1    // r2 = 7");
    println!("  3: MUL r3, r2, r2    // r3 = 49");
    println!("  4: SUB r0, r3, r2    // r0 = 42");
    println!("  5: HALT");
    println!();

    // --- Step 2: Execute and produce trace ---
    println!("[1] Executing program...");
    let mut trace = vm::execute(&program);
    println!("  Execution complete. {} steps before HALT.\n", trace.real_len);

    println!("[2] Execution trace:");
    trace.print();
    println!();

    // Pad trace to power of 2
    trace.pad_to_power_of_two();
    println!("  Padded trace to {} rows (next power of 2)\n", trace.len());

    // --- Step 3: Verify constraints directly ---
    println!("[3] Verifying AIR constraints on trace...");
    match air::verify_trace_constraints(&trace.rows) {
        Ok(()) => println!("  All transition constraints satisfied!\n"),
        Err((row, constraint)) => {
            println!("  CONSTRAINT VIOLATION at row {}, constraint {}", row, constraint);
            return;
        }
    }

    // --- Step 4: generatorerate STARK proof ---
    println!("[4] generatorerating STARK proof...");
    let proof = prover::prove(&trace, &program);
    println!("  Proof generatorerated successfully.\n");

    // --- Step 5: Verify the proof ---
    println!("[5] Verifying STARK proof (without re-executing the program)...");
    match verifier::verify(&proof) {
        Ok(()) => {
            println!("\n  *** PROOF VERIFIED ***");
            println!("  The verifier is convinced that:");
            println!("    - A committed trace satisfies all {} transition constraints", air::NUM_CONSTRAINTS);
            println!("    - The quotient polynomial is low-degree (FRI verified)");
            println!("  Note: the declared program is absorbed into Fiat-Shamir, but the trace");
            println!("  is not constrained to match it. Outputs are unverified claims (see section 14).");
            println!("  Claimed (unverified) outputs: r0={}, r1={}, r2={}, r3={}",
                proof.outputs[0], proof.outputs[1], proof.outputs[2], proof.outputs[3]);
        }
        Err(e) => {
            println!("  PROOF REJECTED: {}", e);
        }
    }
}