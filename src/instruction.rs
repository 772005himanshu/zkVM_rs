/// The 6-instruction ISA for our ZKVM.
///
/// Every instruction is encoded with:
/// - opcode: which operation (0–5)
/// - rd: destination register index (0–3)
/// - rs1, rs2: source register indices (0–3)
/// - imm: an immediate value (field element)
///
/// Only 4 registers exist (r0–r3). All arithmetic is in the Goldilocks field.

/// The six opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Nop = 0,  // No operation (used for trace padding)
    Imm = 1,  // rd = imm
    Add = 2,  // rd = rs1 + rs2
    Mul = 3,  // rd = rs1 * rs2
    Sub = 4,  // rd = rs1 - rs2
    Halt = 5, // Stop execution
}

impl Opcode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Opcode::Nop,
            1 => Opcode::Imm,
            2 => Opcode::Add,
            3 => Opcode::Mul,
            4 => Opcode::Sub,
            5 => Opcode::Halt,
            _ => panic!("invalid opcode: {}", v),
        }
    }
}

/// A single instruction.
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub opcode: Opcode,
    pub rd: u8,
    pub rs1: u8,
    pub rs2: u8,
    pub imm: u64,
}

// Convenient builders so programs read nicely.
impl Instruction {
    pub fn nop() -> Self {
        Instruction { opcode: Opcode::Nop, rd: 0, rs1: 0, rs2: 0, imm: 0 }
    }

    pub fn imm(rd: u8, value: u64) -> Self {
        assert!(rd < 4, "register index must be 0–3");
        Instruction { opcode: Opcode::Imm, rd, rs1: 0, rs2: 0, imm: value }
    }

    pub fn add(rd: u8, rs1: u8, rs2: u8) -> Self {
        assert!(rd < 4 && rs1 < 4 && rs2 < 4);
        Instruction { opcode: Opcode::Add, rd, rs1, rs2, imm: 0 }
    }

    pub fn mul(rd: u8, rs1: u8, rs2: u8) -> Self {
        assert!(rd < 4 && rs1 < 4 && rs2 < 4);
        Instruction { opcode: Opcode::Mul, rd, rs1, rs2, imm: 0 }
    }

    pub fn sub(rd: u8, rs1: u8, rs2: u8) -> Self {
        assert!(rd < 4 && rs1 < 4 && rs2 < 4);
        Instruction { opcode: Opcode::Sub, rd, rs1, rs2, imm: 0 }
    }

    pub fn halt() -> Self {
        Instruction { opcode: Opcode::Halt, rd: 0, rs1: 0, rs2: 0, imm: 0 }
    }
}