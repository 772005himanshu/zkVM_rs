/// The execution trace: a table recording every step of VM execution.
///
/// Each row captures the full VM state at one clock cycle.
/// The trace has 13 columns:
///   clk, pc, opcode, rd, rs1, rs2, imm, r0, r1, r2, r3, rs1_val, rs2_val
///
/// After execution, the trace is padded to a power-of-2 length with NOP rows
/// (state frozen, opcode=0). This is required for polynomial interpolation on
/// a multiplicative subgroup.
use crate::field::Fp;
use crate::instruction::Opcode;

pub const NUM_COLUMNS: usize = 13;

/// One row of the execution trace.
#[derive(Debug, Clone, Copy)]
pub struct TraceRow {
    pub clk: Fp,
    pub pc: Fp,
    pub opcode: Fp,
    pub rd: Fp,
    pub rs1: Fp,
    pub rs2: Fp,
    pub imm: Fp,
    pub r0: Fp,
    pub r1: Fp,
    pub r2: Fp,
    pub r3: Fp,
    pub rs1_val: Fp,
    pub rs2_val: Fp,
}

impl TraceRow {
    /// Convert this row into an array of field elements (column-ordered).
    pub fn to_array(&self) -> [Fp; NUM_COLUMNS] {
        [
            self.clk, self.pc, self.opcode, self.rd, self.rs1, self.rs2,
            self.imm, self.r0, self.r1, self.r2, self.r3,
            self.rs1_val, self.rs2_val,
        ]
    }

    /// Create a NOP padding row that copies the state from the previous row.
    pub fn padding(clk: u64, prev: &TraceRow) -> Self {
        TraceRow {
            clk: Fp::new(clk),
            pc: prev.pc,
            opcode: Fp::new(Opcode::Nop as u64),
            rd: Fp::ZERO,
            rs1: Fp::ZERO,
            rs2: Fp::ZERO,
            imm: Fp::ZERO,
            r0: prev.r0,
            r1: prev.r1,
            r2: prev.r2,
            r3: prev.r3,
            // rs1=0 and rs2=0 both point to r0, so rs1_val = rs2_val = r0
            rs1_val: prev.r0,
            rs2_val: prev.r0,
        }
    }
}

/// The complete execution trace (list of rows).
#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    pub rows: Vec<TraceRow>,
    /// How many rows are "real" execution (before padding).
    pub real_len: usize,
}

impl ExecutionTrace {
    pub fn new(rows: Vec<TraceRow>) -> Self {
        let real_len = rows.len();
        ExecutionTrace { rows, real_len }
    }

    /// Pad the trace to the next power of 2.
    /// Padding rows are NOP with register state frozen.
    pub fn pad_to_power_of_two(&mut self) {
        let target = self.rows.len().next_power_of_two();
        if target < 2 {
            // Minimum trace length of 2 for polynomial interpolation
            let target = 2;
            while self.rows.len() < target {
                let clk = self.rows.len() as u64;
                let prev = *self.rows.last().unwrap();
                self.rows.push(TraceRow::padding(clk, &prev));
            }
            return;
        }
        while self.rows.len() < target {
            let clk = self.rows.len() as u64;
            let prev = *self.rows.last().unwrap();
            self.rows.push(TraceRow::padding(clk, &prev));
        }
    }

    /// Extract a single column as a vector of field elements.
    pub fn get_column(&self, col: usize) -> Vec<Fp> {
        self.rows.iter().map(|row| row.to_array()[col]).collect()
    }

    /// Total number of rows (including padding).
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Print the trace as a table (for debugging / educational output).
    pub fn print(&self) {
        println!(
            "{:>4} | {:>4} | {:>4} | {:>3} | {:>3} | {:>3} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6}",
            "clk", "pc", "op", "rd", "rs1", "rs2", "imm", "r0", "r1", "r2", "r3", "rs1v", "rs2v"
        );
        println!("{}", "-".repeat(90));
        for (i, row) in self.rows.iter().enumerate() {
            let marker = if i >= self.real_len { " (pad)" } else { "" };
            println!(
                "{:>4} | {:>4} | {:>4} | {:>3} | {:>3} | {:>3} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6} | {:>6}{}",
                row.clk.value(), row.pc.value(), row.opcode.value(),
                row.rd.value(), row.rs1.value(), row.rs2.value(), row.imm.value(),
                row.r0.value(), row.r1.value(), row.r2.value(), row.r3.value(),
                row.rs1_val.value(), row.rs2_val.value(),
                marker,
            );
        }
    }
}