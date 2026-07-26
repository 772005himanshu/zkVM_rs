/// The virtual machine: executes a program and produces an execution trace.
///
/// This is a simple register machine with 4 registers and 6 instructions.
/// All arithmetic happens in the Goldilocks field — there are no integer
/// overflows, just modular arithmetic.
use crate::field::Fp;
use crate::instruction::{Instruction, Opcode};
use crate::trace::{ExecutionTrace, TraceRow};

/// Look up a register value by index (0–3).
fn read_reg(regs: &[Fp; 4], idx: u8) -> Fp {
    regs[idx as usize]
}

/// Execute a program and return the execution trace.
///
/// The VM starts with all registers at zero and PC at 0.
/// It runs until a HALT instruction is reached.
pub fn execute(program: &[Instruction]) -> ExecutionTrace {
    let mut regs: [Fp; 4] = [Fp::ZERO; 4];
    let mut pc: usize = 0;
    let mut rows: Vec<TraceRow> = Vec::new();

    loop {
        assert!(pc < program.len(), "PC out of bounds: {}", pc);
        let inst = &program[pc];
        let clk = rows.len() as u64;

        // Look up source register values
        let rs1_val = read_reg(&regs, inst.rs1);
        let rs2_val = read_reg(&regs, inst.rs2);

        // Record the state BEFORE executing this instruction
        rows.push(TraceRow {
            clk: Fp::new(clk),
            pc: Fp::new(pc as u64),
            opcode: Fp::new(inst.opcode as u64),
            rd: Fp::new(inst.rd as u64),
            rs1: Fp::new(inst.rs1 as u64),
            rs2: Fp::new(inst.rs2 as u64),
            imm: Fp::new(inst.imm),
            r0: regs[0],
            r1: regs[1],
            r2: regs[2],
            r3: regs[3],
            rs1_val,
            rs2_val,
        });

        // Execute the instruction
        match inst.opcode {
            Opcode::Nop => {}
            Opcode::Imm => {
                regs[inst.rd as usize] = Fp::new(inst.imm);
            }
            Opcode::Add => {
                regs[inst.rd as usize] = rs1_val + rs2_val;
            }
            Opcode::Mul => {
                regs[inst.rd as usize] = rs1_val * rs2_val;
            }
            Opcode::Sub => {
                regs[inst.rd as usize] = rs1_val - rs2_val;
            }
            Opcode::Halt => {
                break;
            }
        }

        pc += 1;
    }

    ExecutionTrace::new(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_program() {
        // (3 + 4) * (3 + 4) - 7 = 42
        let program = vec![
            Instruction::imm(0, 3),       // r0 = 3
            Instruction::imm(1, 4),       // r1 = 4
            Instruction::add(2, 0, 1),    // r2 = r0 + r1 = 7
            Instruction::mul(3, 2, 2),    // r3 = r2 * r2 = 49
            Instruction::sub(0, 3, 2),    // r0 = r3 - r2 = 42
            Instruction::halt(),
        ];
        let trace = execute(&program);
        assert_eq!(trace.real_len, 6);
        let last = &trace.rows[trace.real_len - 1];
        // After executing SUB, registers should be: r0=42, r1=4, r2=7, r3=49
        // But the trace records state BEFORE the HALT, which is AFTER the SUB.
        assert_eq!(last.r0.value(), 42);
        assert_eq!(last.r1.value(), 4);
        assert_eq!(last.r2.value(), 7);
        assert_eq!(last.r3.value(), 49);
    }

    #[test]
    fn test_padding() {
        let program = vec![
            Instruction::imm(0, 10),
            Instruction::halt(),
        ];
        let mut trace = execute(&program);
        assert_eq!(trace.real_len, 2);
        trace.pad_to_power_of_two();
        assert_eq!(trace.len(), 2); // already power of 2
    }

    #[test]
    fn test_padding_to_next_power() {
        let program = vec![
            Instruction::imm(0, 1),
            Instruction::imm(1, 2),
            Instruction::add(2, 0, 1),
            Instruction::halt(),
        ];
        let mut trace = execute(&program);
        assert_eq!(trace.real_len, 4);
        trace.pad_to_power_of_two();
        assert_eq!(trace.len(), 4); // 4 is already a power of 2
    }

    #[test]
    fn test_trace_columns() {
        let program = vec![
            Instruction::imm(0, 5),
            Instruction::halt(),
        ];
        let mut trace = execute(&program);
        trace.pad_to_power_of_two();

        // Column 0 is clk
        let clk_col = trace.get_column(0);
        assert_eq!(clk_col[0].value(), 0);
        assert_eq!(clk_col[1].value(), 1);
    }
}