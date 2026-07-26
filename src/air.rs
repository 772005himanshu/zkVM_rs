/// Algebraic Intermediate Representation (AIR) — the constraint system.
///
/// This module defines the algebraic rules that a valid execution trace must satisfy.
/// The key idea: instead of using `if opcode == ADD { ... }` (runtime branching),
/// we use *selector polynomials* — Lagrange basis polynomials that evaluate to 1
/// for exactly one opcode and 0 for all others. This makes every constraint a
/// pure algebraic expression, which is what allows us to prove them with polynomials.
///
/// Constraint types:
/// - Transition constraints: relate adjacent rows (current → next)
/// - Boundary constraints: pin specific rows to known values (initial state, final output)
use crate::field::Fp;
use crate::trace::NUM_COLUMNS;

/// Number of opcodes in our ISA.
const NUM_OPCODES: u64 = 6; // NOP=0, IMM=1, ADD=2, MUL=3, SUB=4, HALT=5

/// Number of registers.
const NUM_REGS: u64 = 4;

/// Number of transition constraints.
pub const NUM_CONSTRAINTS: usize = 8;

// --- Selectors ---

/// Opcode selector: evaluates to 1 when `opcode == target`, 0 for other valid opcodes.
///
/// This is a Lagrange basis polynomial over {0, 1, 2, 3, 4, 5}:
///   s_t(x) = PROD_{v in {0..5}, v != t} (x - v) / (t - v)
///
/// Degree: 5 (product of 5 linear terms).
pub fn opcode_selector(opcode: Fp, target: u64) -> Fp {
    let mut num = Fp::ONE; // numerator
    let mut den = Fp::ONE; // denominator (constant, could be precomputed)
    let t = Fp::new(target);
    for v in 0..NUM_OPCODES {
        if v == target {
            continue;
        }
        let fv = Fp::new(v);
        num = num * (opcode - fv);
        den = den * (t - fv);
    }
    num * den.inv()
}

/// Register selector: evaluates to 1 when `idx == target`, 0 for other valid indices.
///
/// Lagrange basis over {0, 1, 2, 3}. Degree: 3.
pub fn register_selector(idx: Fp, target: u64) -> Fp {
    let mut num = Fp::ONE;
    let mut den = Fp::ONE;
    let t = Fp::new(target);
    for v in 0..NUM_REGS {
        if v == target {
            continue;
        }
        let fv = Fp::new(v);
        num = num * (idx - fv);
        den = den * (t - fv);
    }
    num * den.inv()
}

/// Evaluate all 8 transition constraints between two adjacent rows.
/// Returns an array of constraint evaluations — all should be zero for a valid trace.
///
/// Columns (by index):
///   0=clk, 1=pc, 2=opcode, 3=rd, 4=rs1, 5=rs2, 6=imm,
///   7=r0, 8=r1, 9=r2, 10=r3, 11=rs1_val, 12=rs2_val
pub fn evaluate_transition_constraints(
    current: &[Fp; NUM_COLUMNS],
    next: &[Fp; NUM_COLUMNS],
) -> [Fp; NUM_CONSTRAINTS] {
    let op = current[2];
    let rd = current[3];
    let imm = current[6];
    let rs1_val = current[11];
    let rs2_val = current[12];

    // Opcode selectors
    let s_nop = opcode_selector(op, 0);
    let s_imm = opcode_selector(op, 1);
    let s_add = opcode_selector(op, 2);
    let s_mul = opcode_selector(op, 3);
    let s_sub = opcode_selector(op, 4);
    let s_halt = opcode_selector(op, 5);

    // Is this a writing instruction? (IMM, ADD, MUL, SUB)
    let is_write = s_imm + s_add + s_mul + s_sub;

    // What value gets written to the destination register?
    let write_val = s_imm * imm
        + s_add * (rs1_val + rs2_val)
        + s_mul * (rs1_val * rs2_val)
        + s_sub * (rs1_val - rs2_val);

    // --- C0: Clock increments by 1 ---
    let c0 = next[0] - current[0] - Fp::ONE;

    // --- C1: PC update ---
    // NOP and HALT: PC stays the same
    // IMM, ADD, MUL, SUB: PC increments by 1
    let c1 = (s_nop + s_halt) * (next[1] - current[1])
        + (s_imm + s_add + s_mul + s_sub) * (next[1] - current[1] - Fp::ONE);

    // --- C2–C5: Register updates ---
    // For each register i:
    //   next.r_i = cur.r_i + sel_i(rd) * is_write * (write_val - cur.r_i)
    //
    // If this instruction writes to register i (sel_i=1, is_write=1):
    //   next.r_i = cur.r_i + (write_val - cur.r_i) = write_val
    // Otherwise (sel_i=0 or is_write=0):
    //   next.r_i = cur.r_i (register preserved)
    let mut reg_constraints = [Fp::ZERO; 4];
    for i in 0..4 {
        let sel_i = register_selector(rd, i as u64);
        let cur_ri = current[7 + i];
        let next_ri = next[7 + i];
        reg_constraints[i] = next_ri - cur_ri - sel_i * is_write * (write_val - cur_ri);
    }

    // --- C6: rs1_val consistency ---
    // rs1_val must equal the register at index rs1
    let rs1_idx = current[4];
    let mut rs1_expected = Fp::ZERO;
    for i in 0..4 {
        rs1_expected = rs1_expected + register_selector(rs1_idx, i as u64) * current[7 + i];
    }
    let c6 = current[11] - rs1_expected;

    // --- C7: rs2_val consistency ---
    let rs2_idx = current[5];
    let mut rs2_expected = Fp::ZERO;
    for i in 0..4 {
        rs2_expected = rs2_expected + register_selector(rs2_idx, i as u64) * current[7 + i];
    }
    let c7 = current[12] - rs2_expected;

    [
        c0,
        c1,
        reg_constraints[0],
        reg_constraints[1],
        reg_constraints[2],
        reg_constraints[3],
        c6,
        c7,
    ]
}

/// Combine all transition constraints into a single value using random linear combination.
/// composition = SUM_i alpha^i * C_i
pub fn evaluate_composition(
    current: &[Fp; NUM_COLUMNS],
    next: &[Fp; NUM_COLUMNS],
    alpha: Fp,
) -> Fp {
    let constraints = evaluate_transition_constraints(current, next);
    let mut result = Fp::ZERO;
    let mut alpha_power = Fp::ONE;
    for c in &constraints {
        result = result + alpha_power * *c;
        alpha_power = alpha_power * alpha;
    }
    result
}

/// Verify that all transition constraints hold for the given trace (direct check).
/// Returns Ok(()) if valid, Err with the failing row index if not.
pub fn verify_trace_constraints(
    rows: &[crate::trace::TraceRow],
) -> Result<(), (usize, usize)> {
    for i in 0..rows.len() - 1 {
        let current = rows[i].to_array();
        let next = rows[i + 1].to_array();
        let constraints = evaluate_transition_constraints(&current, &next);
        for (j, c) in constraints.iter().enumerate() {
            if *c != Fp::ZERO {
                return Err((i, j)); // row i, constraint j failed
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::Instruction;
    use crate::vm;

    #[test]
    fn test_opcode_selector() {
        // Selector for target=2 (ADD) should be 1 when opcode=2, 0 otherwise
        for op in 0..6u64 {
            let sel = opcode_selector(Fp::new(op), 2);
            if op == 2 {
                assert_eq!(sel, Fp::ONE, "selector(2) should be 1 for opcode 2");
            } else {
                assert_eq!(sel, Fp::ZERO, "selector(2) should be 0 for opcode {}", op);
            }
        }
    }

    #[test]
    fn test_register_selector() {
        for target in 0..4u64 {
            for idx in 0..4u64 {
                let sel = register_selector(Fp::new(idx), target);
                if idx == target {
                    assert_eq!(sel, Fp::ONE);
                } else {
                    assert_eq!(sel, Fp::ZERO);
                }
            }
        }
    }

    #[test]
    fn test_constraints_hold_for_valid_trace() {
        let program = vec![
            Instruction::imm(0, 3),
            Instruction::imm(1, 4),
            Instruction::add(2, 0, 1),
            Instruction::mul(3, 2, 2),
            Instruction::sub(0, 3, 2),
            Instruction::halt(),
        ];
        let mut trace = vm::execute(&program);
        trace.pad_to_power_of_two();
        assert!(verify_trace_constraints(&trace.rows).is_ok());
    }

    #[test]
    fn test_constraints_catch_tampered_trace() {
        let program = vec![
            Instruction::imm(0, 3),
            Instruction::imm(1, 4),
            Instruction::add(2, 0, 1),
            Instruction::halt(),
        ];
        let mut trace = vm::execute(&program);
        trace.pad_to_power_of_two();

        // Tamper: change r2 in row 3 (should be 7, set it to 999)
        trace.rows[3].r2 = Fp::new(999);
        assert!(verify_trace_constraints(&trace.rows).is_err());
    }
}