use core::panic;
use std::{collections::{HashMap, HashSet}, error::{self, Error}, fmt::{self, Display, format}, hash::Hash};

use crate::{class_parser::{AttributeCode, AttributeInfo, ClassFile, CpInfo, CpNameAndType}, register_allocation};

const JVM_OPCODE_AALOAD: u8 = 50;
const JVM_OPCODE_AASTORE: u8 = 83;
const JVM_OPCODE_ACONST_NULL: u8 = 1;
const JVM_OPCODE_ALOAD: u8 = 25;
const JVM_OPCODE_ALOAD_0: u8 = 42;
const JVM_OPCODE_ALOAD_1: u8 = 43;
const JVM_OPCODE_ALOAD_2: u8 = 44;
const JVM_OPCODE_ALOAD_3: u8 = 45;
const JVM_OPCODE_ANEWARRAY: u8 = 189;
const JVM_OPCODE_ARETURN: u8 = 176;
const JVM_OPCODE_ARRAYLENGTH: u8 = 190;
const JVM_OPCODE_ASTORE: u8 = 58;
const JVM_OPCODE_ASTORE_0: u8 = 75;
const JVM_OPCODE_ASTORE_1: u8 = 76;
const JVM_OPCODE_ASTORE_2: u8 = 77;
const JVM_OPCODE_ASTORE_3: u8 = 78;
const JVM_OPCODE_ATHROW: u8 = 191;
const JVM_OPCODE_BALOAD: u8 = 51;
const JVM_OPCODE_BASTORE: u8 = 84;
const JVM_OPCODE_BIPUSH: u8 = 16;
const JVM_OPCODE_CALOAD: u8 = 52;
const JVM_OPCODE_CASTORE: u8 = 85;
const JVM_OPCODE_CHECKCAST: u8 = 192;
const JVM_OPCODE_D2F: u8 = 144;
const JVM_OPCODE_D2I: u8 = 142;
const JVM_OPCODE_D2L: u8 = 143;
const JVM_OPCODE_DADD: u8 = 99;
const JVM_OPCODE_DALOAD: u8 = 49;
const JVM_OPCODE_DASTORE: u8 = 82;
const JVM_OPCODE_DCMPG: u8 = 152;
const JVM_OPCODE_DCMPL: u8 = 151;
const JVM_OPCODE_DCONST_0: u8 = 14;
const JVM_OPCODE_DCONST_1: u8 = 15;
const JVM_OPCODE_DDIV: u8 = 111;
const JVM_OPCODE_DLOAD: u8 = 24;
const JVM_OPCODE_DLOAD_0: u8 = 38;
const JVM_OPCODE_DLOAD_1: u8 = 39;
const JVM_OPCODE_DLOAD_2: u8 = 40;
const JVM_OPCODE_DLOAD_3: u8 = 41;
const JVM_OPCODE_DMUL: u8 = 107;
const JVM_OPCODE_DNEG: u8 = 119;
const JVM_OPCODE_DREM: u8 = 115;
const JVM_OPCODE_DRETURN: u8 = 175;
const JVM_OPCODE_DSTORE: u8 = 57;
const JVM_OPCODE_DSTORE_0: u8 = 71;
const JVM_OPCODE_DSTORE_1: u8 = 72;
const JVM_OPCODE_DSTORE_2: u8 = 73;
const JVM_OPCODE_DSTORE_3: u8 = 74;
const JVM_OPCODE_DSUB: u8 = 103;
const JVM_OPCODE_DUP: u8 = 89;
const JVM_OPCODE_DUP_X1: u8 = 90;
const JVM_OPCODE_DUP_X2: u8 = 91;
const JVM_OPCODE_DUP2: u8 = 92;
const JVM_OPCODE_DUP2_X1: u8 = 93;
const JVM_OPCODE_DUP2_X2: u8 = 94;
const JVM_OPCODE_F2D: u8 = 141;
const JVM_OPCODE_F2I: u8 = 139;
const JVM_OPCODE_F2L: u8 = 140;
const JVM_OPCODE_FADD: u8 = 98;
const JVM_OPCODE_FALOAD: u8 = 48;
const JVM_OPCODE_FASTORE: u8 = 81;
const JVM_OPCODE_FCMPG: u8 = 150;
const JVM_OPCODE_FCMPL: u8 = 149;
const JVM_OPCODE_FCONST_0: u8 = 11;
const JVM_OPCODE_FCONST_1: u8 = 12;
const JVM_OPCODE_FCONST_2: u8 = 13;
const JVM_OPCODE_FDIV: u8 = 110;
const JVM_OPCODE_FLOAD: u8 = 23;
const JVM_OPCODE_FLOAD_0: u8 = 34;
const JVM_OPCODE_FLOAD_1: u8 = 35;
const JVM_OPCODE_FLOAD_2: u8 = 36;
const JVM_OPCODE_FLOAD_3: u8 = 37;
const JVM_OPCODE_FMUL: u8 = 106;
const JVM_OPCODE_FNEG: u8 = 118;
const JVM_OPCODE_FREM: u8 = 114;
const JVM_OPCODE_FRETURN: u8 = 174;
const JVM_OPCODE_FSTORE: u8 = 56;
const JVM_OPCODE_FSTORE_0: u8 = 67;
const JVM_OPCODE_FSTORE_1: u8 = 68;
const JVM_OPCODE_FSTORE_2: u8 = 69;
const JVM_OPCODE_FSTORE_3: u8 = 70;
const JVM_OPCODE_FSUB: u8 = 102;
const JVM_OPCODE_GETFIELD: u8 = 180;
const JVM_OPCODE_GETSTATIC: u8 = 178;
const JVM_OPCODE_GOTO: u8 = 167;
const JVM_OPCODE_GOTO_W: u8 = 200;
const JVM_OPCODE_I2B: u8 = 145;
const JVM_OPCODE_I2C: u8 = 146;
const JVM_OPCODE_I2D: u8 = 135;
const JVM_OPCODE_I2F: u8 = 134;
const JVM_OPCODE_I2L: u8 = 133;
const JVM_OPCODE_I2S: u8 = 147;
const JVM_OPCODE_IADD: u8 = 96;
const JVM_OPCODE_IALOAD: u8 = 46;
const JVM_OPCODE_IAND: u8 = 126;
const JVM_OPCODE_IASTORE: u8 = 79;
const JVM_OPCODE_ICONST_M1: u8 = 2;
const JVM_OPCODE_ICONST_0: u8 = 3;
const JVM_OPCODE_ICONST_1: u8 = 4;
const JVM_OPCODE_ICONST_2: u8 = 5;
const JVM_OPCODE_ICONST_3: u8 = 6;
const JVM_OPCODE_ICONST_4: u8 = 7;
const JVM_OPCODE_ICONST_5: u8 = 8;
const JVM_OPCODE_IDIV: u8 = 108;
const JVM_OPCODE_IF_ACMPEQ: u8 = 165;
const JVM_OPCODE_IF_ACMPNE: u8 = 166;
const JVM_OPCODE_IF_ICMPEQ: u8 = 159;
const JVM_OPCODE_IF_ICMPNE: u8 = 160;
const JVM_OPCODE_IF_ICMPLT: u8 = 161;
const JVM_OPCODE_IF_ICMPGE: u8 = 162;
const JVM_OPCODE_IF_ICMPGT: u8 = 163;
const JVM_OPCODE_IF_ICMPLE: u8 = 164;
const JVM_OPCODE_IFEQ: u8 = 153;
const JVM_OPCODE_IFNE: u8 = 154;
const JVM_OPCODE_IFLT: u8 = 155;
const JVM_OPCODE_IFGE: u8 = 156;
const JVM_OPCODE_IFGT: u8 = 157;
const JVM_OPCODE_IFLE: u8 = 158;
const JVM_OPCODE_IFNONNNULL: u8 = 199;
const JVM_OPCODE_IFNULL: u8 = 198;
const JVM_OPCODE_IINC: u8 = 132;
const JVM_OPCODE_ILOAD: u8 = 21;
const JVM_OPCODE_ILOAD_0: u8 = 26;
const JVM_OPCODE_ILOAD_1: u8 = 27;
const JVM_OPCODE_ILOAD_2: u8 = 28;
const JVM_OPCODE_ILOAD_3: u8 = 29;
const JVM_OPCODE_IMUL: u8 = 104;
const JVM_OPCODE_INEG: u8 = 116;
const JVM_OPCODE_INSTANCEOF: u8 = 193;
const JVM_OPCODE_INVOKEDYNAMIC: u8 = 186;
const JVM_OPCODE_INVOKEINTERFACE: u8 = 185;
const JVM_OPCODE_INVOKESPECIAL: u8 = 183;
const JVM_OPCODE_INVOKESTATIC: u8 = 184;
const JVM_OPCODE_INVOKEVIRTUAL: u8 = 182;
const JVM_OPCODE_IOR: u8 = 128;
const JVM_OPCODE_IREM: u8 = 112;
const JVM_OPCODE_IRETURN: u8 = 172;
const JVM_OPCODE_ISHL: u8 = 120;
const JVM_OPCODE_ISHR: u8 = 122;
const JVM_OPCODE_ISTORE: u8 = 54;
const JVM_OPCODE_ISTORE_0: u8 = 59;
const JVM_OPCODE_ISTORE_1: u8 = 60;
const JVM_OPCODE_ISTORE_2: u8 = 61;
const JVM_OPCODE_ISTORE_3: u8 = 62;
const JVM_OPCODE_ISUB: u8 = 100;
const JVM_OPCODE_IUSHR: u8 = 124;
const JVM_OPCODE_IXOR: u8 = 130;
const JVM_OPCODE_JSR: u8 = 168;
const JVM_OPCODE_JSR_W: u8 = 201;
const JVM_OPCODE_L2D: u8 = 138;
const JVM_OPCODE_L2F: u8 = 137;
const JVM_OPCODE_L2I: u8 = 136;
const JVM_OPCODE_LADD: u8 = 97;
const JVM_OPCODE_LALOAD: u8 = 47;
const JVM_OPCODE_LAND: u8 = 127;
const JVM_OPCODE_LASTORE: u8 = 80;
const JVM_OPCODE_LCMP: u8 = 148;
const JVM_OPCODE_LCONST_0: u8 = 9;
const JVM_OPCODE_LCONST_1: u8 = 10;
const JVM_OPCODE_LDC: u8 = 18;
const JVM_OPCODE_LDC_W: u8 = 19;
const JVM_OPCODE_LDC2_W: u8 = 20;
const JVM_OPCODE_LDIV: u8 = 109;
const JVM_OPCODE_LLOAD: u8 = 22;
const JVM_OPCODE_LLOAD_0: u8 = 30;
const JVM_OPCODE_LLOAD_1: u8 = 31;
const JVM_OPCODE_LLOAD_2: u8 = 32;
const JVM_OPCODE_LLOAD_3: u8 = 33;
const JVM_OPCODE_LMUL: u8 = 105;
const JVM_OPCODE_LNEG: u8 = 117;
const JVM_OPCODE_LOOKUPSWITCH: u8 = 171;
const JVM_OPCODE_LOR: u8 = 129;
const JVM_OPCODE_LREM: u8 = 113;
const JVM_OPCODE_LRETURN: u8 = 173;
const JVM_OPCODE_LSHL: u8 = 121;
const JVM_OPCODE_LSHR: u8 = 123;
const JVM_OPCODE_LSTORE: u8 = 55;
const JVM_OPCODE_LSTORE_0: u8 = 63;
const JVM_OPCODE_LSTORE_1: u8 = 64;
const JVM_OPCODE_LSTORE_2: u8 = 65;
const JVM_OPCODE_LSTORE_3: u8 = 66;
const JVM_OPCODE_LSUB: u8 = 101;
const JVM_OPCODE_LUSHR: u8 = 125;
const JVM_OPCODE_LXOR: u8 = 131;
const JVM_OPCODE_MONITORENTER: u8 = 194;
const JVM_OPCODE_MONITOREXIT: u8 = 195;
const JVM_OPCODE_MULTIANEWARRAY: u8 = 197;
const JVM_OPCODE_NEW: u8 = 187;
const JVM_OPCODE_NEWARRAY: u8 = 188;
const JVM_OPCODE_NOP: u8 = 0;
const JVM_OPCODE_POP: u8 = 87;
const JVM_OPCODE_POP2: u8 = 88;
const JVM_OPCODE_PUTFIELD: u8 = 181;
const JVM_OPCODE_PUTSTATIC: u8 = 179;
const JVM_OPCODE_RET: u8 = 169;
const JVM_OPCODE_RETURN: u8 = 177;
const JVM_OPCODE_SALOAD: u8 = 53;
const JVM_OPCODE_SASTORE: u8 = 86;
const JVM_OPCODE_SIPUSH: u8 = 17;
const JVM_OPCODE_SWAP: u8 = 95;
const JVM_OPCODE_TABLESWITCH: u8 = 170;
const JVM_OPCODE_WIDE: u8 = 196;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RiscvMnemonic {
    ADDI,
    SLTI,
    SLTIU,
    ANDI,
    ORI,
    XORI,
    SLLI,
    SRLI,
    SRAI,
    LUI,
    AUIPC,

    ADD,
    SLT,
    SLTU,
    AND,
    OR,
    XOR,
    SLL,
    SRL,
    SUB,
    SRA,

    JAL,
    JALR,

    BEQ,
    BNE,
    BLT,
    BLTU,
    BGE,
    BGEU,

    LW,
    LH,
    LHU,
    LB,
    LBU,
    SW,
    SH,
    SB,

    FENCE,

    ECALL,
    EBREAK,

    /* M extension */

    MUL,
    MULH,
    MULHU,
    MULHSU,
    DIV,
    DIVU,
    REM,
    REMU,

    /* F extension */

    // load/store
    FLW,
    FSW,

    // arithmetic
    FADDS,
    FSUBS,
    FMULS,
    FDIVS,
    FSQRTS,
    FMINS,
    FMAXS,

    //FMADD,
    //FNMADD,
    //FMSUB,
    //FNMSUB,

    // int/float conversion
    FCVTWS,
    FCVTWUS,
    FCVTSW,
    FCVTSWU,

    // sign injection (uporabljeno tudi za move med float registri)
    FSGNJS,
    FSGNJNS,
    FSGNJXS,

    // move med float in int registri (brez conversiona)
    FMVXW,
    FMVWX,

    // compare
    FEQS,
    FLTS,
    FLES,

    // klasifikacija (shranjena v int registre)
    FCLASSS,
}

impl RiscvMnemonic {
    fn to_string(self) -> String {
        return match self {
            //RiscvMnemonic::FLW => todo!(),
            //RiscvMnemonic::FSW => todo!(),
            RiscvMnemonic::FADDS => "FADD.S".to_string(),
            RiscvMnemonic::FSUBS => "FSUB.S".to_string(),
            RiscvMnemonic::FMULS => "FMUL.S".to_string(),
            RiscvMnemonic::FDIVS => "FDIV.S".to_string(),
            RiscvMnemonic::FSQRTS => "FSQRT.S".to_string(),
            RiscvMnemonic::FMINS => "FMIN.S".to_string(),
            RiscvMnemonic::FMAXS => "FMAX.S".to_string(),
            RiscvMnemonic::FCVTWS => "FCVT.W.S".to_string(),
            RiscvMnemonic::FCVTWUS => "FCVT.WU.S".to_string(),
            RiscvMnemonic::FCVTSW => "FCVT.S.W".to_string(),
            RiscvMnemonic::FCVTSWU => "FCVT.S.WU".to_string(),
            RiscvMnemonic::FSGNJS => "FSGNJ.S".to_string(),
            RiscvMnemonic::FSGNJNS => "FSGNJN.S".to_string(),
            RiscvMnemonic::FSGNJXS => "FSGNJX.S".to_string(),
            RiscvMnemonic::FMVXW => "FMV.X.W".to_string(),
            RiscvMnemonic::FMVWX => "FMV.W.X".to_string(),
            RiscvMnemonic::FEQS => "FEQ.S".to_string(),
            RiscvMnemonic::FLTS => "FLT.S".to_string(),
            RiscvMnemonic::FLES => "FLE.S".to_string(),
            RiscvMnemonic::FCLASSS => "FCLASS.S".to_string(),
            _ => format!("{}", self)
        }
    }
}

impl fmt::Display for RiscvMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RiscvInstrFormat {
    R,
    I,
    S,
    U,
    B,
    J,

    RCVT, // za float/in conversion ukaze, ki so v formatu R, ampak uporabljajo samo rd in rs1 (ne pa rs2)
}

impl fmt::Display for RiscvInstrFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RiscvTempReg {
    INT(u32),
    FLOAT(u32)
}

impl RiscvTempReg {
    fn to_string(&self, vreg_to_reg_int: &Option<&HashMap<u32, u32>>, vreg_to_reg_float: &Option<&HashMap<u32, u32>>) -> String {
        return match self {
            RiscvTempReg::INT(value) => match vreg_to_reg_int {
                Some(mapping) => format!("t{}", mapping.get(value).unwrap().to_string()),
                None => format!("VREG_x{}", value.to_string()),
            },
            RiscvTempReg::FLOAT(value) => match vreg_to_reg_float {
                Some(mapping) => format!("f{}", mapping.get(value).unwrap().to_string()),
                None => format!("VREG_f{}", value.to_string()),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RiscvReg {
    TEMP(RiscvTempReg),
    ZERO, // zero/x0, hardwired na vrednost 0
    RA, // ra/x1, return address
    SP, // sp/x2, stack pointer
    FP, // fp/s0/x8, frame pointer

    A0, // a0/x10, return register 1
    A1, // a1/x11, return register 2
    FA0, // fa0/f10 return register za floate

    CP, // s1, eden od saved registrov, uporabljen za pointer do constant poola
    HP, // s2, eden od saved registrov, uporabljen za pointer do heap

}

impl RiscvReg {
    pub fn to_string(&self, vreg_to_reg_int: &Option<&HashMap<u32, u32>>, vreg_to_reg_float: &Option<&HashMap<u32, u32>>) -> String {
        return match self {
            RiscvReg::TEMP(riscv_temp_reg) => riscv_temp_reg.to_string(vreg_to_reg_int, vreg_to_reg_float),
            RiscvReg::ZERO => "zero".to_string(),
            RiscvReg::RA => "ra".to_string(),
            RiscvReg::SP => "sp".to_string(),
            RiscvReg::HP => "s2".to_string(),
            RiscvReg::CP => "s1".to_string(),
            RiscvReg::FP => "fp".to_string(),
            RiscvReg::A0 => "a0".to_string(),
            RiscvReg::A1 => "a1".to_string(),
            RiscvReg::FA0 => "fa0".to_string()
        }
    }
}

/** Vrne naslednji anonimni label (za jumpe). */
fn next_anon_label(anon_label_counter: &mut u32) -> String {
    let label = format!("L{}", *anon_label_counter);
    *anon_label_counter += 1;
    return label;
}

#[derive(Debug, Clone)]
pub struct RiscvInstr {
    pub rd: Option<RiscvReg>,
    pub rs1: Option<RiscvReg>,
    pub rs2: Option<RiscvReg>,
    pub imm: Option<i32>,

    pub mnemonic: RiscvMnemonic,
    pub format: RiscvInstrFormat,

    pub label: Option<String>,

    pub jumps: Vec<String>,

    pub uses_int: HashSet<u32>,
    pub defs_int: HashSet<u32>,

    pub uses_float: HashSet<u32>,
    pub defs_float: HashSet<u32>,

    pub live_in_int: HashSet<u32>,
    pub live_out_int: HashSet<u32>,

    pub live_in_float: HashSet<u32>,
    pub live_out_float: HashSet<u32>,
}

#[derive(Debug)]
struct InvalidRiscvInstrError {
    rd: Option<RiscvReg>,
    rs1: Option<RiscvReg>,
    rs2: Option<RiscvReg>,
    imm: Option<i32>,
    format: RiscvInstrFormat
}

impl Display for InvalidRiscvInstrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Neveljaven Risc-V ukaz: rd = {:#?}, rs1 = {:#?}, rs2 = {:#?}, imm = {:#?}, format = {}.", self.rd, self.rs1, self.rs2, self.imm, self.format)
    }
}

impl Error for InvalidRiscvInstrError {}

// 10 bits
const RUSTV_INSTR_FORMAT_I_IMM_MIN: i32 = -2048;
const RUSTV_INSTR_FORMAT_I_IMM_MAX: i32 = 2047;

// 7 bits
const RUSTV_INSTR_FORMAT_S_IMM_MIN: i32 = -128;
const RUSTV_INSTR_FORMAT_S_IMM_MAX: i32 = 127;

// 20 bits
const RUSTV_INSTR_FORMAT_U_IMM_MIN: i32 = -1_048_576;
const RUSTV_INSTR_FORMAT_U_IMM_MAX: i32 = 1_048_575;

impl RiscvInstr {
    pub fn new(rd: Option<RiscvReg>, rs1: Option<RiscvReg>, rs2: Option<RiscvReg>, imm: Option<i32>, mnemonic: RiscvMnemonic, label: Option<String>, jumps: Option<Vec<String>>) -> Result<RiscvInstr, Box<dyn error::Error>> {
        let format = match mnemonic {
            RiscvMnemonic::ADDI
            | RiscvMnemonic::SLTI
            | RiscvMnemonic::SLTIU
            | RiscvMnemonic::ANDI
            | RiscvMnemonic::ORI
            | RiscvMnemonic::XORI
            | RiscvMnemonic::SLLI
            | RiscvMnemonic::SRLI
            | RiscvMnemonic::SRAI
            | RiscvMnemonic::JALR
            | RiscvMnemonic::LW
            | RiscvMnemonic::LH
            | RiscvMnemonic::LHU
            | RiscvMnemonic::LB
            | RiscvMnemonic::LBU
            | RiscvMnemonic::FENCE
            | RiscvMnemonic::EBREAK
            | RiscvMnemonic::ECALL
            | RiscvMnemonic::FLW => {
                RiscvInstrFormat::I
            },
            RiscvMnemonic::LUI
            | RiscvMnemonic::AUIPC => {
                RiscvInstrFormat::U
            },
            RiscvMnemonic::ADD
            | RiscvMnemonic::SLT
            | RiscvMnemonic::SLTU
            | RiscvMnemonic::AND
            | RiscvMnemonic::OR
            | RiscvMnemonic::XOR
            | RiscvMnemonic::SLL
            | RiscvMnemonic::SRL
            | RiscvMnemonic::SUB
            | RiscvMnemonic::SRA
            | RiscvMnemonic::MUL
            | RiscvMnemonic::MULH
            | RiscvMnemonic::MULHU
            | RiscvMnemonic::MULHSU
            | RiscvMnemonic::DIV
            | RiscvMnemonic::DIVU
            | RiscvMnemonic::REM
            | RiscvMnemonic::REMU
            | RiscvMnemonic::FADDS
            | RiscvMnemonic::FSUBS
            | RiscvMnemonic::FMULS
            | RiscvMnemonic::FDIVS
            | RiscvMnemonic::FSQRTS
            | RiscvMnemonic::FMINS
            | RiscvMnemonic::FMAXS
            | RiscvMnemonic::FSGNJS
            | RiscvMnemonic::FSGNJNS
            | RiscvMnemonic::FSGNJXS
            | RiscvMnemonic::FMVXW
            | RiscvMnemonic::FMVWX
            | RiscvMnemonic::FEQS
            | RiscvMnemonic::FLTS
            | RiscvMnemonic::FLES
            | RiscvMnemonic::FCLASSS
            => {
                RiscvInstrFormat::R
            },
            RiscvMnemonic::SW
            | RiscvMnemonic::SH
            | RiscvMnemonic::SB
            | RiscvMnemonic::FSW => {
                RiscvInstrFormat::S
            },
            RiscvMnemonic::JAL => {
                RiscvInstrFormat::J
            },
            RiscvMnemonic::BEQ
            | RiscvMnemonic::BNE
            | RiscvMnemonic::BLT
            | RiscvMnemonic::BLTU
            | RiscvMnemonic::BGE
            | RiscvMnemonic::BGEU => {
                RiscvInstrFormat::B
            },
            RiscvMnemonic::FCVTWS
            | RiscvMnemonic::FCVTWUS
            | RiscvMnemonic::FCVTSW
            | RiscvMnemonic::FCVTSWU => {
                RiscvInstrFormat::RCVT
            }
        };

        let some_regs = match format {
            RiscvInstrFormat::R | RiscvInstrFormat::S | RiscvInstrFormat::B => {
                match (rs1, rs2) {
                    (Some(rs1), Some(rs2)) => Ok(Vec::from([rs1, rs2])),
                    _ => Err(InvalidRiscvInstrError { rd, rs1, rs2, imm, format }),
                }
            },
            RiscvInstrFormat::I | RiscvInstrFormat::RCVT => {
                match rs1 {
                    Some(rs1) => Ok(Vec::from([rs1])),
                    None => Err(InvalidRiscvInstrError { rd, rs1, rs2, imm, format }),
                }
            },
            RiscvInstrFormat::U | RiscvInstrFormat::J => Ok(Vec::new()),
        }?;

        let mut uses_int = HashSet::new();
        let mut uses_float = HashSet::new();

        for reg in some_regs {
            if let RiscvReg::TEMP(reg) = reg {
                if let RiscvTempReg::INT(reg) = reg {
                    uses_int.insert(reg);
                }
                else if let RiscvTempReg::FLOAT(reg) = reg {
                    uses_float.insert(reg);
                }
            }
        }

        let some_regs = match format {
            RiscvInstrFormat::R | RiscvInstrFormat::I | RiscvInstrFormat::U | RiscvInstrFormat::J | RiscvInstrFormat::RCVT => {
                match rd {
                    Some(rd) => Ok(Vec::from([rd])),
                    _ => Err(InvalidRiscvInstrError { rd, rs1, rs2, imm, format }),
                }
            },
            RiscvInstrFormat::S | RiscvInstrFormat::B => {
                Ok(Vec::new())
            }
        }?;

        let mut defs_int = HashSet::new();
        let mut defs_float = HashSet::new();

        for reg in some_regs {
            if let RiscvReg::TEMP(reg) = reg {
                if let RiscvTempReg::INT(reg) = reg {
                    defs_int.insert(reg);
                }
                else if let RiscvTempReg::FLOAT(reg) = reg {
                    defs_float.insert(reg);
                }
            }
        }

        if let Some(imm) = imm {
            match format {
                RiscvInstrFormat::R | RiscvInstrFormat::RCVT => {
                    return Err(InvalidRiscvInstrError { rd, rs1, rs2, imm: Some(imm), format }.into())
                },
                RiscvInstrFormat::I => {
                    if imm > RUSTV_INSTR_FORMAT_I_IMM_MAX || imm < RUSTV_INSTR_FORMAT_I_IMM_MIN {
                        return Err(InvalidRiscvInstrError { rd, rs1, rs2, imm: Some(imm), format }.into())
                    }
                },
                RiscvInstrFormat::S | RiscvInstrFormat::B => {
                    if imm > RUSTV_INSTR_FORMAT_S_IMM_MAX || imm < RUSTV_INSTR_FORMAT_S_IMM_MIN {
                        return Err(InvalidRiscvInstrError { rd, rs1, rs2, imm: Some(imm), format }.into())
                    }
                },
                RiscvInstrFormat::U | RiscvInstrFormat::J => {
                    if imm > RUSTV_INSTR_FORMAT_U_IMM_MAX || imm < RUSTV_INSTR_FORMAT_U_IMM_MIN {
                        return Err(InvalidRiscvInstrError { rd, rs1, rs2, imm: Some(imm), format }.into())
                    }
                },
            }
        }

        return Ok(RiscvInstr {
            rd,
            rs1,
            rs2,
            imm,
            mnemonic,
            format,
            uses_int,
            uses_float,
            defs_int,
            defs_float,
            label,
            jumps: jumps.unwrap_or(Vec::new()),
            live_in_int: HashSet::new(),
            live_in_float: HashSet::new(),
            live_out_int: HashSet::new(),
            live_out_float: HashSet::new(),
        })
    }

    pub fn to_string(&self, vreg_to_reg_int: &Option<&HashMap<u32, u32>>, vreg_to_reg_float: &Option<&HashMap<u32, u32>>) -> String {
        let fixed_rd;
        let fixed_rs1;
        let fixed_rs2;

        match self.rd {
            Some(some_rd) => {
                fixed_rd = Some(some_rd.to_string(vreg_to_reg_int, vreg_to_reg_float));
            },
            None => {
                fixed_rd = None;
            },
        }

        match self.rs1 {
            Some(some_rs1) => {
                fixed_rs1 = Some(some_rs1.to_string(vreg_to_reg_int, vreg_to_reg_float));
            },
            None => {
                fixed_rs1 = None;
            },
        }

        match self.rs2 {
            Some(some_rs2) => {
                fixed_rs2 = Some(some_rs2.to_string(vreg_to_reg_int, vreg_to_reg_float));
            },
            None => {
                fixed_rs2 = None;
            },
        }

        let label_or_empty = match &self.label {
            Some(l) => format!("{}: ", l.clone()),
            None => "".to_string(),
        };

        return match self.format {
            RiscvInstrFormat::R => format!("{}{} {}, {}, {}", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), fixed_rs1.unwrap(), fixed_rs2.unwrap()),
            RiscvInstrFormat::I => {
                if self.mnemonic == RiscvMnemonic::JALR {
                    format!("{}{} {}, {}({})", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), self.imm.unwrap(), fixed_rs1.unwrap())
                }
                else {
                    match self.mnemonic {
                        RiscvMnemonic::LW | RiscvMnemonic::FLW => {
                            format!("{}{} {}, {}({})", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), self.imm.unwrap(), fixed_rs1.unwrap())
                        }
                        _ => {
                            format!("{}{} {}, {}, {}", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), fixed_rs1.unwrap(), self.imm.unwrap())
                        }
                    }
                }
            },
            RiscvInstrFormat::S => format!("{}{} {}, {}({})", label_or_empty, self.mnemonic.to_string(), fixed_rs2.unwrap(), self.imm.unwrap(), fixed_rs1.unwrap()),
            RiscvInstrFormat::U => format!("{}{} {}, {}", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), self.imm.unwrap()),
            RiscvInstrFormat::B => {
                let branch_target;
                if self.jumps.len() == 1 {
                    branch_target = self.jumps[0].clone();
                }
                else {
                    branch_target = self.imm.unwrap().to_string();
                }

                format!("{}{} {}, {}, {}", label_or_empty, self.mnemonic.to_string(), fixed_rs1.unwrap(), fixed_rs2.unwrap(), branch_target)
            },
            RiscvInstrFormat::J => {
                let jump_target;
                if self.jumps.len() == 1 {
                    jump_target = self.jumps[0].clone();
                }
                else {
                    jump_target = self.imm.unwrap().to_string();
                }

                format!("{}{} {}, {}", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), jump_target)
            },
            RiscvInstrFormat::RCVT => format!("{}{} {}, {}", label_or_empty, self.mnemonic.to_string(), fixed_rd.unwrap(), fixed_rs1.unwrap()),
        };
    }
}

pub fn get_class_name_utf8(class_file: &ClassFile) -> String {
    let this_class_cpinfo = &class_file.constant_pool[class_file.this_class as usize];
    let this_class_name_index;
    if let CpInfo::Class(cpinfo_class) = this_class_cpinfo {
        this_class_name_index = cpinfo_class.name_index;
    }
    else {
        panic!("class_file.this_clas leads to {:#?}", this_class_cpinfo);
    }

    let this_class_name_cpinfo = &class_file.constant_pool[this_class_name_index as usize];
    let this_class_name_utf8;
    if let CpInfo::Utf8(cpinfo_utf8) = this_class_name_cpinfo {
        this_class_name_utf8 = cpinfo_utf8.converted.clone();
    }
    else {
        panic!("this_class_name_index leads to {:#?}", this_class_name_cpinfo);
    }

    return this_class_name_utf8;
}

pub fn to_riscv_vregs(class_file: &ClassFile) -> Result<HashMap<usize, Vec<RiscvInstr>>, Box<dyn error::Error>> {
    let class_name = get_class_name_utf8(class_file);

    let mut anon_label_counter = 0;

    let mut method_i_to_riscv_code_vregs = HashMap::new();
    for (i, method) in class_file.methods.iter().enumerate() {

        // skip <init> and <clinit>
        let method_name_cpinfo = &class_file.constant_pool[method.name_index as usize];
        let method_name_utf8;
        if let CpInfo::Utf8(cpinfo_utf8) = method_name_cpinfo {
            method_name_utf8 = cpinfo_utf8.converted.clone();
        }
        else {
            panic!("method.name_index leads to {:#?}", method_name_cpinfo);
        }

        if method_name_utf8 == "<init>" || method_name_utf8 == "<clinit>" {
            continue;
        }

        let method_descriptor_utf8 = match &class_file.constant_pool[method.descriptor_index as usize] {
            CpInfo::Utf8(cp_utf8) => cp_utf8.converted.clone(),
            other => panic!("asm_write, getting utf8 method descriptor, instead got {:#?}", other)
        };

        for attribute in &method.attributes {
            if let AttributeInfo::Code(attribute_code) = attribute {
                let riscv_code_vregs = code_to_riscv_vregs(&attribute_code, &class_file.constant_pool, class_name.clone(), method_name_utf8.clone(), method_descriptor_utf8.clone(), &mut anon_label_counter)?;

                method_i_to_riscv_code_vregs.insert(i, riscv_code_vregs);
            }
        }
    }

    return Ok(method_i_to_riscv_code_vregs);
}

#[derive(Debug)]
struct UnknownJVMOpcodeError {
    opcode: u8
}

impl Display for UnknownJVMOpcodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Neznan JVM opcode: {}.", self.opcode)
    }
}

impl Error for UnknownJVMOpcodeError {}

#[derive(Debug)]
struct UnimplementedJVMInstrError {
    opcode: u8,
    instr: String,
}

impl Display for UnimplementedJVMInstrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prevod JVM ukaza {} z opcode {} ni implementiran.", self.instr, self.opcode)
    }
}

impl Error for UnimplementedJVMInstrError {}

pub const WORD_SIZE: u8 = 4;

/** Za JVM ukaze, ki premaknejo vrednost iz local variable array v stack (oblika: {x}load npr. iload ali {x}load_{n} npr. iload_0), v RISC-V je to samo move med registri. */
fn riscv_vregs_append_xload(riscv_code_vregs: &mut Vec<RiscvInstr>, local_index: u32, vreg_base: u32, jvm_type: JvmType) -> Result<(), Box<dyn error::Error>> {
    match jvm_type {
        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 1)));
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::FLOAT => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(local_index + 1)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(local_index + 1)));
            let imm = None;
            let mnemonic = RiscvMnemonic::FSGNJS;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::LONG => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 2)));
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 1)));
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        }
    }

    return Ok(());
}

/** Za JVM ukaze, ki premaknejo vrednost iz operand stacka v local variable array (oblika: {x}store npr. istore ali {x}store_{n} npr. istore_0). V RISC-V je to samo move med registri. */
fn riscv_vregs_append_xstore(riscv_code_vregs: &mut Vec<RiscvInstr>, local_index: u32, vreg_base: u32, jvm_type: JvmType) -> Result<(), Box<dyn error::Error>> {
    match jvm_type {
        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::FLOAT => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(local_index + 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
            let imm = None;
            let mnemonic = RiscvMnemonic::FSGNJS;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::LONG => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 2)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        }
    }
    
    return Ok(());
}

/** Za JVM ukaze, ki dajo konstanto n na operand stack (oblika {x}const_{n} npr. fconst_0). V RISC-V je to samo move med registri.

Deluje tudi za floate (n se pretvori v float).
*/
fn riscv_vregs_append_xconst_n(riscv_code_vregs: &mut Vec<RiscvInstr>, n: i32, vreg_base: u32, jvm_type: JvmType) -> Result<(), Box<dyn error::Error>> {
    match jvm_type {
        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
            let rs1 = Some(RiscvReg::ZERO);
            let rs2 = None;
            let imm = Some(n);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::FLOAT => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
            let rs1 = Some(RiscvReg::ZERO);
            let rs2 = None;
            let imm = Some(n);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

            let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
            let rs2 = None;
            let imm = None;
            let mnemonic = RiscvMnemonic::FCVTSW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::LONG => {
            // konstante so majhne, za long so lahko samo 1 ali 0
            // => v MSB zapišemo 0, v LSB pa n
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
            let rs1 = Some(RiscvReg::ZERO);
            let rs2 = None;
            let imm = Some(0);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
            let rs1 = Some(RiscvReg::ZERO);
            let rs2 = None;
            let imm = Some(n);
            let mnemonic = RiscvMnemonic::ADDI;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        }
    }

    return Ok(());
}

fn get_jvm_type_element_size(jvm_type: JvmType) -> i32 {
    return match jvm_type {
        JvmType::BYTE => 1,
        JvmType::SHORT | JvmType::CHAR => (WORD_SIZE / 2).into(),
        JvmType::INT => WORD_SIZE.into(),
        JvmType::LONG => (WORD_SIZE * 2).into(),
        JvmType::FLOAT => 4,
        JvmType::REFERENCE => WORD_SIZE.into(),
    };
}

/** Za JVM ukaze, ki loadajo podatke iz array (oblika {x}a_load npr. ia_load). */
fn riscv_vregs_append_xa_load(riscv_code_vregs: &mut Vec<RiscvInstr>, vreg_base: u32, jvm_type: JvmType) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(get_jvm_type_element_size(jvm_type));
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
    
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
    let imm = None;
    let mnemonic = RiscvMnemonic::MUL;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
    let imm = None;
    let mnemonic = RiscvMnemonic::ADD;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
    
    match jvm_type {
        JvmType::BYTE => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::LB;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::CHAR | JvmType::SHORT => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::LH;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::INT | JvmType::REFERENCE => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::LW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::LONG => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(i32::from(WORD_SIZE * 2));
            let mnemonic = RiscvMnemonic::LW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::LW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::FLOAT => {
            let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let rs2 = None;
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::FLW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
    }
    
    return Ok(());
}

/** Za JVM ukaze, ki storajo podatke v array (oblika {x}a_load npr. ia_load). */
fn riscv_vregs_append_xa_store(riscv_code_vregs: &mut Vec<RiscvInstr>, vreg_base: u32, jvm_type: JvmType) -> Result<(), Box<dyn error::Error>> {
    let negative_vreg_offset = match jvm_type {
        JvmType::LONG => 2,
        _ => 1
    };

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(get_jvm_type_element_size(jvm_type));
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
    
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - negative_vreg_offset)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - negative_vreg_offset)));
    let imm = None;
    let mnemonic = RiscvMnemonic::MUL;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - negative_vreg_offset - 1)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - negative_vreg_offset - 1)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - negative_vreg_offset)));
    let imm = None;
    let mnemonic = RiscvMnemonic::ADD;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
    
    match jvm_type {
        JvmType::BYTE => {
            let rd = None;
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::SB;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::SHORT | JvmType::CHAR => {
            let rd = None;
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::SH;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::INT | JvmType::REFERENCE => {
            let rd = None;
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::SW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::LONG => {
            let rd = None;
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
            let imm = Some(i32::from(WORD_SIZE * 2));
            let mnemonic = RiscvMnemonic::SW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

            let rd = None;
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::SW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
        JvmType::FLOAT => {
            let rd = None;
            let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
            let imm = Some(i32::from(WORD_SIZE));
            let mnemonic = RiscvMnemonic::FSW;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
        },
    }
    
    return Ok(());
}

fn riscv_vregs_append_int_move(riscv_code_vregs: &mut Vec<RiscvInstr>, from: u32, to: u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(to)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(from)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

fn riscv_vregs_append_float_move(riscv_code_vregs: &mut Vec<RiscvInstr>, from: u32, to: u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(to)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(from)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(from)));
    let imm = None;
    let mnemonic = RiscvMnemonic::FSGNJS;
    
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

/**
 * from/to registra hranita MSB
*/
fn riscv_vregs_append_long_move(riscv_code_vregs: &mut Vec<RiscvInstr>, from: u32, to: u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(to)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(from)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(to - 1)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(from - 1)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

/** Doda move za int/float/long.
 * za longe: from/to registra hranita MSB
*/
fn riscv_vregs_append_move_by_type(riscv_code_vregs: &mut Vec<RiscvInstr>, from: u32, to: u32, jvm_type: JvmType) -> Result<(), Box<dyn error::Error>> {
    return match jvm_type {
        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
            riscv_vregs_append_int_move(riscv_code_vregs, from, to)
        },
        JvmType::FLOAT => {
            riscv_vregs_append_float_move(riscv_code_vregs, from, to)
        },
        JvmType::LONG => {
            riscv_vregs_append_long_move(riscv_code_vregs, from, to)
        }
    }
}

/* Doda deljenje med longi. V vreg_base - 3 in vreg_base - 2 shrani kvocient ali ostanek (če je save_remainder_instead_of_quotient = true) */
fn riscv_append_long_div(riscv_code_vregs: &mut Vec<RiscvInstr>, vreg_base: u32, anon_label_counter: &mut u32, save_remainder_instead_of_quotient: bool) -> Result<(), Box<dyn error::Error>> {
    let dividendlow_vreg = vreg_base - 3;
    let dividendhigh_vreg = vreg_base - 2;
    let divisorlow_vreg = vreg_base - 1;
    let divisorhigh_vreg = vreg_base;

    let quotientlow_vreg = vreg_base + 1;
    let quotienthigh_vreg = vreg_base + 2;

    let remainderlow_vreg = vreg_base + 3;
    let remainderhigh_vreg = vreg_base + 4;

    let dividend_bit_position_vreg = vreg_base + 5;

    let dividend_bit_i_vreg = vreg_base + 6;
    let divident_adjusted_bit_position_vreg = vreg_base + 7;
    let const_32_vreg = vreg_base + 8;

    let carry_check_vreg = vreg_base + 9;

    let dividend_is_negative_vreg = vreg_base + 10;
    // let divisor_is_negative_vreg = vreg_base + 11;

    let quotient_bit_select_mask_vreg = vreg_base + 12;


    /* init */

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotienthigh_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotientlow_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(63);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(32);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    /* save signs, to absolute */

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_is_negative_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividendhigh_vreg)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::SLTI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    riscv_vregs_append_absolute_long(riscv_code_vregs, dividendhigh_vreg, dividendlow_vreg, dividend_bit_i_vreg, carry_check_vreg)?; // using dividend_bit_i_vreg for abs_mask_vreg

    // let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisor_is_negative_vreg)));
    // let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisorhigh_vreg)));
    // let rs2 = None;
    // let imm = Some(0);
    // let mnemonic = RiscvMnemonic::SLTI;
    // riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    riscv_vregs_append_absolute_long(riscv_code_vregs, divisorhigh_vreg, divisorlow_vreg, dividend_bit_i_vreg, carry_check_vreg)?; // using dividend_bit_i_vreg for abs_mask_vreg

    /* loop start */

    let loop_label = next_anon_label(anon_label_counter);

    /* remainder = remainder << 1 */

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::SLLI;
    let label = Some(loop_label.clone());
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let left_shift_overflow_label = next_anon_label(anon_label_counter);
    let left_shift_end_of_overflow_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs2 = Some(RiscvReg::ZERO);
    let imm = None;
    let mnemonic = RiscvMnemonic::BLT;
    let jumps = Some(Vec::from([left_shift_overflow_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let rd = Some(RiscvReg::ZERO);
    let rs1 = None;
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([left_shift_end_of_overflow_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::ADDI;
    let label = Some(left_shift_overflow_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::SLLI;
    let label = Some(left_shift_end_of_overflow_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    /* remainder[0] = dividend[i] */

    let dividend_bit_select_use_low_label = next_anon_label(anon_label_counter);
    let dividend_bit_select_end_of_use_low_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BLT;
    let jumps = Some(Vec::from([dividend_bit_select_use_low_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    // 63 > i > 32
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(divident_adjusted_bit_position_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs2 = None;
    let imm = Some(-32);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_i_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividendhigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divident_adjusted_bit_position_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SRL;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::ZERO);
    let rs1 = None;
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([dividend_bit_select_end_of_use_low_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);
    //

    // i < 32
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_i_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividendlow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SRL;
    let label = Some(dividend_bit_select_use_low_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);
    //

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_i_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_i_vreg)));
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::ANDI;
    let label = Some(dividend_bit_select_end_of_use_low_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_i_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::ADD;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    /* if remainder >= divisor */

    let remainder_geq_divisor_label = next_anon_label(anon_label_counter);
    let remainder_not_geq_divisor_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisorhigh_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BGE;
    let jumps = Some(Vec::from([remainder_geq_divisor_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let both_negative_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderhigh_vreg)));
    let rs2 = Some(RiscvReg::ZERO);
    let imm = None;
    let mnemonic = RiscvMnemonic::BLT;
    let jumps = Some(Vec::from([both_negative_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    // Oba operanda sta pozitivna ali enaka 0, unsigned compare spodnjih 32 bitov

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisorlow_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BGEU;
    let jumps = Some(Vec::from([remainder_geq_divisor_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let rd = Some(RiscvReg::ZERO);
    let rs1 = None;
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([remainder_not_geq_divisor_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    // Oba operanda sta negativna, obrnjen unsigned compare spodnjih 32 bitov

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisorlow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(remainderlow_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BGEU;
    let label = Some(both_negative_label);
    let jumps = Some(Vec::from([remainder_geq_divisor_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, jumps)?);

    let rd = Some(RiscvReg::ZERO);
    let rs1 = None;
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([remainder_not_geq_divisor_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    /* remainder -= divisor */

    riscv_vregs_append_long_sub(riscv_code_vregs, remainderhigh_vreg, remainderlow_vreg, divisorhigh_vreg, divisorlow_vreg, carry_check_vreg)?;

    /* quotient[i] = 1 */

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotient_bit_select_mask_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::BLT;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotient_bit_select_mask_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotient_bit_select_mask_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divident_adjusted_bit_position_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SLL;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
    
    let quotient_bit_set_use_low_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BLT;
    let jumps = Some(Vec::from([quotient_bit_set_use_low_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);
    
    // 64 > i > 32
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotienthigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotienthigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotient_bit_select_mask_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::OR;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::ZERO);
    let rs1 = None;
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([remainder_not_geq_divisor_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);
    //

    // i < 32
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotientlow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotientlow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(quotient_bit_select_mask_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::OR;
    let label = Some(quotient_bit_set_use_low_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);
    //

    /* update dividend_bit_position, loop */

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs2 = None;
    let imm = Some(-1);
    let mnemonic = RiscvMnemonic::ADDI;
    let label = Some(remainder_not_geq_divisor_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_bit_position_vreg)));
    let rs2 = Some(RiscvReg::ZERO);
    let imm = None;
    let mnemonic = RiscvMnemonic::BLT;
    let jumps = Some(Vec::from([loop_label]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    /* end, fix sign of result if needed and save */

    let end_label = next_anon_label(anon_label_counter);

    // let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisor_is_negative_vreg)));
    // let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_is_negative_vreg)));
    // let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisor_is_negative_vreg)));
    // let imm = None;
    // let mnemonic = RiscvMnemonic::SUB;
    // riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    // let rd = None;
    // let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(divisor_is_negative_vreg)));
    // let rs2 = Some(RiscvReg::ZERO);
    // let imm = None;
    // let mnemonic = RiscvMnemonic::BNE;
    // let jumps = Some(Vec::from([end_label.clone()]));
    // riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividend_is_negative_vreg)));
    let rs2 = Some(RiscvReg::ZERO);
    let imm = None;
    let mnemonic = RiscvMnemonic::BEQ;
    let jumps = Some(Vec::from([end_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let resulthigh_vreg;
    let resultlow_vreg;

    if !save_remainder_instead_of_quotient {
        resulthigh_vreg = quotienthigh_vreg;
        resultlow_vreg = quotientlow_vreg;
    }
    else {
        resulthigh_vreg = remainderhigh_vreg;
        resultlow_vreg = remainderlow_vreg;
    }

    riscv_append_long_sign_flip(riscv_code_vregs, resulthigh_vreg, resultlow_vreg, carry_check_vreg, anon_label_counter)?;

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividendhigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(resulthigh_vreg)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    let label = Some(end_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(dividendlow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(resultlow_vreg)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

/** Doda shift right longa.
 * arithmetic - ali je arithmetic shift right
 */
fn riscv_append_long_shift_right(riscv_code_vregs: &mut Vec<RiscvInstr>, vreg_base: u32, anon_label_counter: &mut u32, arithmetic: bool) -> Result<(), Box<dyn error::Error>> {
    let valuehigh_vreg = vreg_base - 2;
    let valuelow_vreg = vreg_base - 1;
    let shift_amount_vreg = vreg_base;

    let const_32_vreg = vreg_base + 1;

    let temp_valuehigh_adjusted_shift_vreg = vreg_base + 2;
    let valuehigh_temp_vreg = vreg_base + 3;

    let final_valuelow_shift = vreg_base + 4; 

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(32);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let shift_geq_32_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BGE;
    let jumps = Some(Vec::from([shift_geq_32_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    // shift < 32

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_valuehigh_adjusted_shift_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SUB;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_temp_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_valuehigh_adjusted_shift_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SLL;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
    let imm = None;
    let mnemonic = match arithmetic {
        true => RiscvMnemonic::SRA,
        false => RiscvMnemonic::SRL,
    };
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SRL;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(final_valuelow_shift)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let end_of_shift_geq_32_label = next_anon_label(anon_label_counter);

    let rd = Some(RiscvReg::ZERO);
    let rs1 = None;
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([end_of_shift_geq_32_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    // shift >= 32

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_temp_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    let label = Some(shift_geq_32_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = None;
    let imm = Some(32);
    let mnemonic = match arithmetic {
        true => RiscvMnemonic::SRAI,
        false => RiscvMnemonic::SRLI,
    };
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(final_valuelow_shift)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SUB;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    // or valuehigh_temp_vreg to valuelow_vreg and shift if needed

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_temp_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::OR;
    let label = Some(end_of_shift_geq_32_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(final_valuelow_shift)));
    let imm = None;
    let mnemonic = match arithmetic {
        true => RiscvMnemonic::SRA,
        false => RiscvMnemonic::SRL,
    };
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

fn riscv_vregs_append_save_ret_val_and_j_to_epilogue(riscv_code_vregs: &mut Vec<RiscvInstr>, vreg_base: u32, return_type: Option<JvmType>, epilogue_label: String) -> Result<(), Box<dyn error::Error>> {
    if let Some(return_type) = return_type {
        match return_type {
            JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
                let rd = Some(RiscvReg::A0);
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JvmType::LONG => {
                let rd = Some(RiscvReg::A0);
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::A1);
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JvmType::FLOAT => {
                let rd = Some(RiscvReg::FA0);
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FSGNJNS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
        }   
    }

    let rd = Some(RiscvReg::ZERO);
    let rs1 = Some(RiscvReg::ZERO);
    let rs2 = None;
    let imm = None;
    let mnemonic = RiscvMnemonic::JAL;
    let jumps = Some(Vec::from([epilogue_label]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    return Ok(());
}

#[derive(Debug, Clone, Copy)]
pub enum JvmType {
    BYTE,
    SHORT,
    INT,
    LONG,
    CHAR,
    FLOAT,
    // DOUBLE,
    REFERENCE,
}

const JVM_TYPE_COMPUTATIONAL_CATEGORY_1: u8 = 1;
const JVM_TYPE_COMPUTATIONAL_CATEGORY_2: u8 = 2;

fn get_jvm_type_computational_category(jvm_type: JvmType) -> u8 {
    return match jvm_type {
        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::FLOAT | JvmType::REFERENCE => {
            JVM_TYPE_COMPUTATIONAL_CATEGORY_1
        }
        JvmType::LONG => {
            JVM_TYPE_COMPUTATIONAL_CATEGORY_2
        }
    }
}

pub fn get_name_and_type_from_field_or_method_or_interface_method_info(constant_pool: &Vec<CpInfo>, cp_index: u16) -> &CpNameAndType {
    let cp_info;
    if let Some(some_cp_info) = constant_pool.get(usize::from(cp_index)) {
        cp_info = some_cp_info;
    }
    else {
        panic!("Got cp index {} for cp of length {}.", cp_index, constant_pool.len());
    }

    let name_and_type_index;
    match cp_info {
        CpInfo::FieldRef(some_cp_field_ref) => name_and_type_index = some_cp_field_ref.name_and_type_index,
        CpInfo::MethodRef(some_method_ref) => name_and_type_index = some_method_ref.name_and_type_index,
        CpInfo::InterfaceMethodRef(some_interface_ref) => name_and_type_index = some_interface_ref.name_and_type_index,
        _ => panic!("cp_info at {} is not field_ref or method_ref or interface_method_ref.", cp_index)
    }

    let cp_info;
    if let Some(some_cp_info) = constant_pool.get(usize::from(name_and_type_index)) {
        cp_info = some_cp_info;
    }
    else {
        panic!("Trying to get name_and_type, have index {} for cp of length {}.", name_and_type_index, constant_pool.len());
    }

    let name_and_type;
    if let CpInfo::NameAndType(some_name_and_type) = cp_info {
        name_and_type = some_name_and_type
    }
    else {
        panic!("cp_info at {} is not name_and_type.", name_and_type_index);
    }

    return name_and_type;
}

pub fn get_utf8_descriptor_from_field_or_method_or_interface_method_info(constant_pool: &Vec<CpInfo>, cp_index: u16) -> String {
    let name_and_type = get_name_and_type_from_field_or_method_or_interface_method_info(constant_pool, cp_index);

    let cp_info;
    if let Some(some_cp_info) = constant_pool.get(usize::from(name_and_type.descriptor_index)) {
        cp_info = some_cp_info;
    }
    else {
        panic!("Trying to get descriptor, have index {} for cp of length {}.", name_and_type.descriptor_index, constant_pool.len());
    }

    let utf8;
    if let CpInfo::Utf8(some_utf8) = cp_info {
        utf8 = some_utf8;
    }
    else {
        panic!("cp_info at {} is not utf8.", name_and_type.descriptor_index);
    }

    return utf8.converted.clone();
}

pub fn get_utf8_name_from_field_or_method_or_interface_method_info(constant_pool: &Vec<CpInfo>, cp_index: u16) -> String {
    let name_and_type = get_name_and_type_from_field_or_method_or_interface_method_info(constant_pool, cp_index);

    let cp_info;
    if let Some(some_cp_info) = constant_pool.get(usize::from(name_and_type.name_index)) {
        cp_info = some_cp_info;
    }
    else {
        panic!("Trying to get descriptor, have index {} for cp of length {}.", name_and_type.name_index, constant_pool.len());
    }

    let utf8;
    if let CpInfo::Utf8(some_utf8) = cp_info {
        utf8 = some_utf8;
    }
    else {
        panic!("cp_info at {} is not utf8.", name_and_type.name_index);
    }

    return utf8.converted.clone();
}

pub fn get_jvm_type_from_descriptor(descriptor_type_char: char) -> Result<JvmType, Box<dyn error::Error>> {
    return match descriptor_type_char {
        'B' => Ok(JvmType::BYTE),
        'C' => Ok(JvmType::CHAR),
        'D' => panic!("got 'D' (double) in descriptor, not implemented."),
        'F' => Ok(JvmType::FLOAT),
        'I' => Ok(JvmType::INT),
        'J' => Ok(JvmType::LONG),
        'L' => panic!("got 'L' (class instance) in descriptor, not implemented."),
        'S' => Ok(JvmType::SHORT),
        'Z' => Ok(JvmType::INT), // boolean
        '[' => Ok(JvmType::REFERENCE), // array
        _ => panic!("Invalid descriptor char: '{}'", descriptor_type_char)
    };
}

pub fn get_function_label(method_name: String, _class_name: String) -> String {
    return format!("{}", method_name);
}

pub fn get_function_epilogue_label(method_name: String, _class_name: String) -> String {
    return format!("{}_epilogue", method_name);
}

pub fn get_method_arg_and_return_types(method_descriptor: String) -> Result<(Vec<JvmType>, Option<JvmType>), Box<dyn error::Error>> {
    let mut args_types = Vec::new();
    let mut return_type = None;

    let mut getting_return_type = false;

    let descriptor_chars: Vec<char> = method_descriptor.chars().collect();
    let mut char_i = 0;
    while char_i < descriptor_chars.len() {
        let c = descriptor_chars[char_i];

        if getting_return_type {
            match c {
                'V' => return_type = None,
                c => {
                    return_type = Some(get_jvm_type_from_descriptor(c)?);
                }
            }

            break;
        }
        else {
            // getting args
            match c {
                '(' | ',' => {
                    char_i += 1;
                    continue;
                },
                ')' => getting_return_type = true,
                c => {
                    args_types.push(get_jvm_type_from_descriptor(c)?);
                },
            }
        }

        // preskoči chare, ki označujejo array
        while descriptor_chars[char_i] == '[' {
            char_i += 1;
        }

        char_i += 1;
    }

    return Ok((args_types, return_type));
}

fn get_cp_offset_from_index(constant_pool: &Vec<CpInfo>, index: u16) -> u32 {
    let mut offset: u32 = 0;

    for i in 0..index {
        offset += match &constant_pool[i as usize] {
            CpInfo::Utf8(cp_utf8) => cp_utf8.converted.bytes().len() as u32 + 1, // še null terminator
            CpInfo::Integer(_) => 4,
            CpInfo::Float(_) => 4,
            CpInfo::Long(_) => 8,
            CpInfo::Double(cp_double) => panic!("cp_double in constant pool, not implemented: {:#?}", cp_double),
            CpInfo::Class(cp_class) => {
                let cp_utf8 = match &constant_pool[cp_class.name_index as usize] {
                    CpInfo::Utf8(cp_utf8) => cp_utf8,
                    other => panic!("trying to get name of class in cp, instead got: {:#?}", other)
                };

                cp_utf8.converted.bytes().len() as u32 + 1
            },
            CpInfo::String(cp_string) => {
                let cp_utf8 = match &constant_pool[cp_string.string_index as usize] {
                    CpInfo::Utf8(cp_utf8) => cp_utf8,
                    other => panic!("trying to get utf8 of string in cp, instead got: {:#?}", other)
                };

                cp_utf8.converted.bytes().len() as u32 + 1
            },
            CpInfo::FieldRef(_) => {
                let descriptor = get_utf8_descriptor_from_field_or_method_or_interface_method_info(constant_pool, i as u16);
                let type_char = descriptor.chars().nth(0).unwrap();
                let jvm_type = get_jvm_type_from_descriptor(type_char).unwrap();
                match jvm_type {
                    JvmType::LONG => 8,
                    _ => 4,
                }
            },
            CpInfo::MethodRef(_) | CpInfo::InterfaceMethodRef(_) | CpInfo::NameAndType(_) | CpInfo::MethodHandle(_) | CpInfo::MethodType(_) | CpInfo::Dynamic(_) | CpInfo::InvokeDynamic(_) | CpInfo::Module(_) | CpInfo::Package(_) => 4,
        }
    }

    return offset;
}

fn _riscv_vregs_append_absolute_int(riscv_code_vregs: &mut Vec<RiscvInstr>, value_vreg: u32, abs_mask_vreg: u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(abs_mask_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value_vreg)));
    let rs2 = None;
    let imm = Some((WORD_SIZE * 8 - 1).into());
    let mnemonic = RiscvMnemonic::SRAI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(abs_mask_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::XOR;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(abs_mask_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SUB;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

/* Rezultat se shrani v minuendhigh_vreg in minuendlow_vreg */
fn riscv_vregs_append_long_sub(riscv_code_vregs: &mut Vec<RiscvInstr>, minuendhigh_vreg: u32, minuendlow_vreg: u32, subtrahendhigh_vreg: u32, subtrahendlow_vreg: u32, carry_check_vreg: u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendlow_vreg)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendlow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendlow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(subtrahendlow_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SUB;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendlow_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SLTU;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendhigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendhigh_vreg)));
    let rs2;
    let imm = None;
    let mnemonic = RiscvMnemonic::SUB;
    if subtrahendhigh_vreg == 0 {
        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(subtrahendhigh_vreg)));
    }
    else {
        rs2 = Some(RiscvReg::ZERO);
    }
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
    
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendhigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(minuendhigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::SUB;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

fn riscv_vregs_append_absolute_long(riscv_code_vregs: &mut Vec<RiscvInstr>, valuehigh_vreg: u32, valuelow_vreg: u32, abs_mask_vreg: u32, carry_check_vreg: u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(abs_mask_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = None;
    let imm = Some((WORD_SIZE * 8 - 1).into());
    let mnemonic = RiscvMnemonic::SRAI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(abs_mask_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::XOR;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(abs_mask_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::XOR;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    riscv_vregs_append_long_sub(riscv_code_vregs, valuehigh_vreg, valuelow_vreg, 0, abs_mask_vreg, carry_check_vreg)?;

    return Ok(());
}

fn riscv_append_long_sign_flip(riscv_code_vregs: &mut Vec<RiscvInstr>, valuehigh_vreg: u32, valuelow_vreg: u32, carry_check_vreg: u32, anon_label_counter: &mut u32) -> Result<(), Box<dyn error::Error>> {
    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = None;
    let imm = Some(-1);
    let mnemonic = RiscvMnemonic::XORI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = None;
    let imm = Some(-1);
    let mnemonic = RiscvMnemonic::XORI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let no_overflow_label = next_anon_label(anon_label_counter);

    let rd = None;
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let imm = None;
    let mnemonic = RiscvMnemonic::BLT;
    let jumps = Some(Vec::from([no_overflow_label.clone()]));
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
    let rs2 = None;
    let imm = Some(1);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(carry_check_vreg)));
    let rs2 = None;
    let imm = Some(0);
    let mnemonic = RiscvMnemonic::ADDI;
    let label = Some(no_overflow_label);
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

    return Ok(());
}

fn riscv_append_set_vreg_to_cp_offset(riscv_code_vregs: &mut Vec<RiscvInstr>, constant_pool: &Vec<CpInfo>, cp_index: u16, cp_offset_vreg: u32) -> Result<(), Box<dyn error::Error>> {
    let cp_offset = get_cp_offset_from_index(&constant_pool, cp_index);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
    let rs1 = None;
    let rs2 = None;
    let imm = Some(cp_offset as i32);
    let mnemonic = RiscvMnemonic::LUI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
    let rs2 = None;
    let imm = Some((cp_offset & 0xFFF) as i32);
    let mnemonic = RiscvMnemonic::ADDI;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
    let rs2 = Some(RiscvReg::CP);
    let imm = None;
    let mnemonic = RiscvMnemonic::ADD;
    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

    return Ok(());
}

fn code_to_riscv_vregs(attribute_code: &AttributeCode, constant_pool: &Vec<CpInfo>, this_class_name: String, this_method_name: String, this_method_descriptor: String, anon_label_counter: &mut u32) -> Result<Vec<RiscvInstr>, Box<dyn error::Error>> {
    let mut riscv_code_vregs: Vec<RiscvInstr> = Vec::new();

    // vreg_base = max_locals + trenutni operand stack size
    let mut vreg_base = u32::from(attribute_code.max_locals);

    // Tipi na operand stacku
    let mut operand_stack_types = Vec::new();

    let mut jsr_return_indexes = Vec::new();

    // map med indeksom opcode v attribute_code.code in indeksom riscv ukaza v riscv_code_vregs, ki predstavlja prvi riscv ukaz v nizu 1 ali več ukazov, v katere se prevede java bytecode ukaz
    // uporabljeno za labeling/jumpe
    let mut first_riscv_instr_index_by_code_index = HashMap::new();
    let mut riscv_instr_index_jumps_to_code_index = HashMap::new();

    let this_method_epilogue_label = get_function_epilogue_label(this_method_name.clone(), this_class_name.clone());

    // Če ni main, pričakujemo argumente na stacku
    if this_method_name != "main" {
        let (args_types, _) = get_method_arg_and_return_types(this_method_descriptor).unwrap();

        let mut sp_offset = -(args_types.len() as i32 - 1) * i32::from(WORD_SIZE);
        let mut local_index = 0;
        for arg_type in args_types {
            match arg_type {
                JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 1)));
                    let rs1 = Some(RiscvReg::FP);
                    let rs2 = None;
                    let imm = Some(sp_offset);
                    let mnemonic = RiscvMnemonic::LW;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                    sp_offset += i32::from(WORD_SIZE);
                    local_index += 1;
                },
                JvmType::LONG => {
                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 2)));
                    let rs1 = Some(RiscvReg::FP);
                    let rs2 = None;
                    let imm = Some(sp_offset);
                    let mnemonic = RiscvMnemonic::LW;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                    sp_offset += i32::from(WORD_SIZE);

                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(local_index + 1)));
                    let rs1 = Some(RiscvReg::FP);
                    let rs2 = None;
                    let imm = Some(sp_offset);
                    let mnemonic = RiscvMnemonic::LW;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                    sp_offset += i32::from(WORD_SIZE);
                    local_index += 2;
                },
                JvmType::FLOAT => {
                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(local_index + 1)));
                    let rs1 = Some(RiscvReg::FP);
                    let rs2 = None;
                    let imm = Some(sp_offset);
                    let mnemonic = RiscvMnemonic::FLW;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                    sp_offset += i32::from(WORD_SIZE);
                    local_index += 1;
                },
            }
        }
    }

    let mut i = 0;
    while i < attribute_code.code.len() {
        let curr_opcode_i = i;
        let starting_riscv_vregs_len = riscv_code_vregs.len();

        let opcode = attribute_code.code[i];
        match opcode {
            JVM_OPCODE_AALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base -= 1;
            },
            JVM_OPCODE_AASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 3;
            },
            JVM_OPCODE_ACONST_NULL => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 0, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
            },
            JVM_OPCODE_ALOAD => {
                i += 1;
                let local_index = attribute_code.code[i];

                riscv_vregs_append_xload(&mut riscv_code_vregs, u32::from(local_index), vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
            },
            JVM_OPCODE_ALOAD_0 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 0, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
            },
            JVM_OPCODE_ALOAD_1 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 1, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
            },
            JVM_OPCODE_ALOAD_2 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 2, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
            },
            JVM_OPCODE_ALOAD_3 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 3, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
            },
            JVM_OPCODE_ANEWARRAY => {
                i += 2;

                let rd = None;
                let rs1 = Some(RiscvReg::HP);
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = Some(i32::from(WORD_SIZE));
                let mnemonic = RiscvMnemonic::SW;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(1);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(i32::from(WORD_SIZE));
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::HP);
                let rs2 = None;
                let imm = Some(i32::from(WORD_SIZE));
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::HP);
                let rs1 = Some(RiscvReg::HP);
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::REFERENCE);
            },
            JVM_OPCODE_ARETURN => {
                riscv_vregs_append_save_ret_val_and_j_to_epilogue(&mut riscv_code_vregs, vreg_base, Some(JvmType::REFERENCE), this_method_epilogue_label.clone())?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ARRAYLENGTH => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::LW;
                
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
            },
            JVM_OPCODE_ASTORE => {
                i += 1;
                let local_index = attribute_code.code[i];

                riscv_vregs_append_xstore(&mut riscv_code_vregs, u32::from(local_index), vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ASTORE_0 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 0, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ASTORE_1 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 1, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ASTORE_2 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 2, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ASTORE_3 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 3, vreg_base, JvmType::REFERENCE)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ATHROW => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "athrow".to_string() }.into());
            },
            JVM_OPCODE_BALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::BYTE)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
                vreg_base -= 1;
            },
            JVM_OPCODE_BASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::BYTE)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 3;
            },
            JVM_OPCODE_BIPUSH => {
                i += 1;
                let imm_byte = attribute_code.code[i];

                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, imm_byte as i8 as i32, vreg_base, JvmType::BYTE)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_CALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::CHAR)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
                vreg_base -= 1;
            },
            JVM_OPCODE_CASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::CHAR)?;
                
                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 3;
            },
            JVM_OPCODE_CHECKCAST => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "checkcast".to_string() }.into());
            },
            JVM_OPCODE_D2F => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "d2f".to_string() }.into());
            },
            JVM_OPCODE_D2I => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "d2i".to_string() }.into());
            },
            JVM_OPCODE_D2L => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "d2l".to_string() }.into());
            },
            JVM_OPCODE_DADD => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dadd".to_string() }.into());
            },
            JVM_OPCODE_DALOAD => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "daload".to_string() }.into());
            },
            JVM_OPCODE_DASTORE => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dastore".to_string() }.into());
            },
            JVM_OPCODE_DCMPG => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dcmpg".to_string() }.into());
            },
            JVM_OPCODE_DCMPL => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dcmpl".to_string() }.into());
            },
            JVM_OPCODE_DCONST_0 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dconst_0".to_string() }.into());
            },
            JVM_OPCODE_DCONST_1 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dconst_1".to_string() }.into());
            },
            JVM_OPCODE_DDIV => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "ddiv".to_string() }.into());
            },
            JVM_OPCODE_DLOAD => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dload".to_string() }.into());
            },
            JVM_OPCODE_DLOAD_0 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dload_0".to_string() }.into());
            },
            JVM_OPCODE_DLOAD_1 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dload_1".to_string() }.into());
            },
            JVM_OPCODE_DLOAD_2 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dload_2".to_string() }.into());
            },
            JVM_OPCODE_DLOAD_3 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dload_3".to_string() }.into());
            },
            JVM_OPCODE_DMUL => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dmul".to_string() }.into());
            },
            JVM_OPCODE_DNEG => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dneg".to_string() }.into());
            },
            JVM_OPCODE_DREM => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "drem".to_string() }.into());
            },
            JVM_OPCODE_DRETURN => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dreturn".to_string() }.into());
            },
            JVM_OPCODE_DSTORE => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dstore".to_string() }.into());
            },
            JVM_OPCODE_DSTORE_0 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dstore_0".to_string() }.into());
            },
            JVM_OPCODE_DSTORE_1 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dstore_1".to_string() }.into());
            },
            JVM_OPCODE_DSTORE_2 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dstore_2".to_string() }.into());
            },
            JVM_OPCODE_DSTORE_3 => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dstore_3".to_string() }.into());
            },
            JVM_OPCODE_DSUB => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "dsub".to_string() }.into());
            },
            JVM_OPCODE_DUP => {
                let value_type = match operand_stack_types.last() {
                    Some(value) => value.clone(),
                    None => panic!("at JVM_OPCODE_DUP, operand_stack_types is empty")
                };

                riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 1, value_type)?;

                operand_stack_types.push(value_type.clone());
                vreg_base += 1;
            },
            JVM_OPCODE_DUP_X1 => {
                let value_type_1 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP_X1, operand_stack_types is empty at value_type_1")
                };

                let value_type_2 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP_X1, operand_stack_types is empty at value_type_2")
                };

                riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 1, value_type_1)?;
                riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base, value_type_2)?;
                riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 1, vreg_base - 1, value_type_1)?;

                operand_stack_types.push(value_type_1.clone());
                operand_stack_types.push(value_type_2.clone());
                operand_stack_types.push(value_type_1.clone());
                vreg_base += 1;
            },
            JVM_OPCODE_DUP_X2 => {
                let value_type_1 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP_X2, operand_stack_types is empty at value_type_1")
                };

                let value_type_2 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP_X2, operand_stack_types is empty at value_type_2")
                };

                let value_type_1_cat = get_jvm_type_computational_category(value_type_1);
                let value_type_2_cat = get_jvm_type_computational_category(value_type_2);

                if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 && value_type_2_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 {
                    let value_type_3 = match operand_stack_types.pop() {
                        Some(value) => value,
                        None => panic!("at JVM_OPCODE_DUP_X2, operand_stack_types is empty at value_type_3")
                    };

                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 1, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base, value_type_2)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base - 1, value_type_3)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 1, vreg_base - 2, value_type_1)?;

                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_3.clone());
                    operand_stack_types.push(value_type_1.clone());
                }
                else if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 && value_type_2_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 {
                    /*
                    val2LSB, val2MSB, val1
                    val2LSB, val2MSB, val1,    val1
                    val2LSB, val2LSB, val2MSB, val1
                    val1,    val2LSB, val2MSB, val1
                    */

                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 1, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base, value_type_2)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 1, vreg_base - 2, value_type_1)?;

                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());
                }
                else {
                    panic!("at JVM_OPCODE_DUP_X2, invalid categories: value_type_1_cat = {}, value_type_2_cat = {}", value_type_1_cat, value_type_2_cat);
                }

                vreg_base += 1;
            },
            JVM_OPCODE_DUP2 => {
                let value_type_1 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP2, operand_stack_types is empty at value_type_1")
                };

                let value_type_1_cat = get_jvm_type_computational_category(value_type_1);

                if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 {
                    let value_type_2 = match operand_stack_types.pop() {
                        Some(value) => value,
                        None => panic!("at JVM_OPCODE_DUP2, operand_stack_types is empty at value_type_2")
                    };

                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base + 1, value_type_2)?;

                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());
                    vreg_base += 2;
                }
                else if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 {
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 1, value_type_1)?;

                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_1.clone());
                    vreg_base += 1;
                }
                else {
                    panic!("at JVM_OPCODE_DUP2, invalid category: value_type_1_cat = {}", value_type_1_cat);
                }
            },
            JVM_OPCODE_DUP2_X1 => {
                let value_type_1 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP2_X1, operand_stack_types is empty at value_type_1")
                };
                let value_type_1_cat = get_jvm_type_computational_category(value_type_1);

                let value_type_2 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP2_X1, operand_stack_types is empty at value_type_2")
                };
                let value_type_2_cat = get_jvm_type_computational_category(value_type_2);

                if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 && value_type_2_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 {
                    /*
                    val2,    val1LSB, val1MSB
                    val2,    val1LSB, val1MSB, val1LSB, val1MSB
                    val2,    val1LSB, val2,    val1LSB, val1MSB
                    val1LSB, val1MSB, val2,    val1LSB, val1MSB
                    */
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base, value_type_2)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 2, vreg_base - 1, value_type_1)?;

                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());

                    vreg_base += 2;
                }
                else {
                    let value_type_3 = match operand_stack_types.pop() {
                        Some(value) => value,
                        None => panic!("at JVM_OPCODE_DUP2_X1, operand_stack_types is empty at value_type_3")
                    };

                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base + 1, value_type_2)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base, value_type_3)?;

                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 2, vreg_base - 1, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 1, vreg_base - 2, value_type_2)?;

                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_3.clone());
                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());
                    vreg_base += 2;
                }
            },
            JVM_OPCODE_DUP2_X2 => {
                let value_type_1 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP2_X2, operand_stack_types is empty at value_type_1")
                };
                let value_type_1_cat = get_jvm_type_computational_category(value_type_1);

                let value_type_2 = match operand_stack_types.pop() {
                    Some(value) => value,
                    None => panic!("at JVM_OPCODE_DUP2_X2, operand_stack_types is empty at value_type_2")
                };
                let value_type_2_cat = get_jvm_type_computational_category(value_type_2);

                if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 && value_type_2_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 {
                    // form 4

                    /*
                    val2LSB, val2MSB, val1LSB, val1MSB
                    val2LSB, val2MSB, val1LSB, val1MSB, {val1LSB, val1MSB}
                    val2LSB, val2MSB, {val2LSB, val2MSB}, val1LSB, val1MSB
                    {val1LSB, val1MSB}, val2LSB, val2MSB, val1LSB, val1MSB
                    */

                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base, value_type_2)?;
                    riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 2, vreg_base - 2, value_type_1)?;

                    operand_stack_types.push(value_type_1.clone());
                    operand_stack_types.push(value_type_2.clone());
                    operand_stack_types.push(value_type_1.clone());

                    vreg_base += 2;
                }
                else {
                    let value_type_3 = match operand_stack_types.pop() {
                        Some(value) => value,
                        None => panic!("at JVM_OPCODE_DUP2_X2, operand_stack_types is empty at value_type_3")
                    };
                    let value_type_3_cat = get_jvm_type_computational_category(value_type_3);

                    if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 && value_type_2_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 && value_type_3_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 {
                        // form 3

                        /*
                        value3LSB, value3MSB, value2,     value1
                        value3LSB, value3MSB, value2,     value1,             , {value1}
                        value3LSB, value3MSB, value2,     value1,     {value2}, value1
                        value3LSB, value3MSB, {value3LSB, value3MSB}, value2,   value1
                        value3LSB, {value1},  value3LSB,  value3MSB,  value2,   value1
                        {value2},  value1,    value3LSB,  value3MSB,  value2,   value1
                        */

                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base + 1, value_type_2)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base, value_type_3)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 2, vreg_base - 2, value_type_1)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 1, vreg_base - 3, value_type_2)?;

                        operand_stack_types.push(value_type_2.clone());
                        operand_stack_types.push(value_type_1.clone());
                        operand_stack_types.push(value_type_3.clone());
                        operand_stack_types.push(value_type_2.clone());
                        operand_stack_types.push(value_type_1.clone());

                        vreg_base += 2;
                    }
                    else if value_type_1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_2 && value_type_2_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 && value_type_3_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 {
                        // form 2

                        /*
                        value3,     value2,     value1LSB, value1MSB
                        value3,     value2,     value1LSB, value1MSB, {value1LSB, value1MSB}
                        value3,     value2,     value1LSB, {value2},  value1LSB,  value1MSB
                        value3,     value2,     {value3},  value2,    value1LSB,  value1MSB
                        {value1LSB, value1MSB}, value3,    value2,    value1LSB,  value1MSB
                        */

                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base, value_type_2)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 3, vreg_base - 1, value_type_3)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 2, vreg_base - 2, value_type_1)?;

                        operand_stack_types.push(value_type_1.clone());
                        operand_stack_types.push(value_type_3.clone());
                        operand_stack_types.push(value_type_2.clone());
                        operand_stack_types.push(value_type_1.clone());

                        vreg_base += 2;
                    }
                    else {
                        let value_type_4 = match operand_stack_types.pop() {
                            Some(value) => value,
                            None => panic!("at JVM_OPCODE_DUP2_X2, operand_stack_types is empty at value_type_4")
                        };

                        // form 1

                        /*
                        value4,   value3,   value2,   value1
                        value4,   value3,   value2,   value1,           , {value1}
                        value4,   value3,   value2,   value1,   {value2}, value1
                        value4,   value3,   value2,   {value3}, value2,   value1
                        value4,   value3,   {value4}, value3,   value2,   value1
                        value4,   {value1}, value4,   value3,   value2,   value1
                        {value2}, value1,   value4,   value3,   value2,   value1
                        */

                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base, vreg_base + 2, value_type_1)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 1, vreg_base + 1, value_type_2)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 2, vreg_base, value_type_3)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base - 3, vreg_base - 1, value_type_4)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 2, vreg_base - 2, value_type_1)?;
                        riscv_vregs_append_move_by_type(&mut riscv_code_vregs, vreg_base + 1, vreg_base - 3, value_type_2)?;

                        operand_stack_types.push(value_type_2.clone());
                        operand_stack_types.push(value_type_1.clone());
                        operand_stack_types.push(value_type_4.clone());
                        operand_stack_types.push(value_type_3.clone());
                        operand_stack_types.push(value_type_2.clone());
                        operand_stack_types.push(value_type_1.clone());

                        vreg_base += 2;
                    }
                }
            },
            JVM_OPCODE_F2D => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "f2d".to_string() }.into());
            },
            JVM_OPCODE_F2I => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::FCVTWS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
            },
            JVM_OPCODE_F2L => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "f2l".to_string() }.into());
            },
            JVM_OPCODE_FADD => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FADDS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::FLOAT);
                vreg_base -= 1;
            },
            JVM_OPCODE_FASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 3;
            },
            /* fcmpg in fcmpl
            FLTS rd, regvalue1, regvalue2
            BNEQ rd, zero, lessthan

            FEQS rd, regvalue1, regvalue2
            BNEQ rd, zero, equal

            FLTS rd, regvalue2, regvalue1
            BNEQ rd, zero, morethan

            // eden od njih je NaN
            // če fcmpg, se zapiše rezultat 1, torej isto kot če value1 > value2
            // če fcmpl, se zapiše rezultat -1, torej isto kot če value1 < value2

            lessthan:
            ADDI regresult, zero, -1
            J end

            morethan:
            ADDI regresult, zero, 1

            equal:
            ADDI regresult, zero, 0
            J end

            end:
            NOP
            */
            JVM_OPCODE_FCMPG | JVM_OPCODE_FCMPL => {
                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::BNE;
                let end_label = next_anon_label(anon_label_counter);
                let jumps = Some(Vec::from([end_label.clone()]));
                let jump_to_end_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?;

                let write_result_lt_label = next_anon_label(anon_label_counter);
                let write_result_eq_label = next_anon_label(anon_label_counter);
                let write_result_gt_label = next_anon_label(anon_label_counter);


                
                /* compare, branch if value1 < value2 */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FLTS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = Some(RiscvReg::ZERO);
                let imm = None;
                let mnemonic = RiscvMnemonic::BNE;
                let jumps = Some(Vec::from([write_result_lt_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);


                /* compare, branch if value1 == value2 */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FEQS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            
                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = Some(RiscvReg::ZERO);
                let imm = None;
                let mnemonic = RiscvMnemonic::BNE;
                let jumps = Some(Vec::from([write_result_eq_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);


                /* compare, branch if value1 > value2 */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FLTS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                
                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = Some(RiscvReg::ZERO);
                let imm = None;
                let mnemonic = RiscvMnemonic::BNE;
                let jumps = Some(Vec::from([write_result_gt_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);


                /* setup za zapis rezultata */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(-1);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(write_result_lt_label);
                let write_result_lt_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?;

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(1);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(write_result_gt_label);
                let write_result_gt_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?;

                match opcode {
                    JVM_OPCODE_FCMPG => {
                        // najprej zapis rezultata v primeru value1 > value2, ker se to zgodi tudi če je eden od njiju NaN
                        riscv_code_vregs.push(write_result_gt_instr);
                        riscv_code_vregs.push(jump_to_end_instr.clone());
                        // in še za value1 < value2
                        riscv_code_vregs.push(write_result_lt_instr);
                        riscv_code_vregs.push(jump_to_end_instr.clone());
                    },
                    JVM_OPCODE_FCMPL => {
                        // najprej zapis rezultata v primeru value1 < value2, ker se to zgodi tudi če je eden od njiju NaN
                        riscv_code_vregs.push(write_result_lt_instr);
                        riscv_code_vregs.push(jump_to_end_instr.clone());
                        // in še za value1 > value2
                        riscv_code_vregs.push(write_result_gt_instr);
                        riscv_code_vregs.push(jump_to_end_instr.clone());
                    },
                    _ => panic!("At fcmpg or fcmpl, opcode is not one of fcmpg, fcmpl at second match.")
                }

                // še zapis rezultata v primeru value1 = value2
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(write_result_eq_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                // end (NOP)
                let rd = Some(RiscvReg::ZERO);
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(end_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
                vreg_base -= 1;
            },
            JVM_OPCODE_FCONST_0 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 0, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FCONST_1 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 1, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FCONST_2 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 2, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FDIV => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FDIVS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FLOAD => {
                i += 1;
                let local_index = attribute_code.code[i];

                riscv_vregs_append_xload(&mut riscv_code_vregs, local_index.into(), vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FLOAD_0 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 0, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FLOAD_1 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 1, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FLOAD_2 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 2, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FLOAD_3 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 3, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.push(JvmType::FLOAT);
                vreg_base += 1;
            },
            JVM_OPCODE_FMUL => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FMULS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FNEG => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FSGNJNS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_FREM => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FDIVS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::FCVTWS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::FCVTSW;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FMULS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FSUBS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);


                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FRETURN => {
                riscv_vregs_append_save_ret_val_and_j_to_epilogue(&mut riscv_code_vregs, vreg_base, Some(JvmType::FLOAT), this_method_epilogue_label.clone())?;

                vreg_base = 0;
                i = attribute_code.code.len();
                operand_stack_types.clear();
            },
            JVM_OPCODE_FSTORE => {
                i += 1;
                let local_index = attribute_code.code[i];

                riscv_vregs_append_xstore(&mut riscv_code_vregs, local_index.into(), vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FSTORE_0 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 0, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FSTORE_1 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 1, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FSTORE_2 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 2, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FSTORE_3 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 3, vreg_base, JvmType::FLOAT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_FSUB => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::FSUBS;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_GETFIELD => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "getfield".to_string() }.into());
            },
            JVM_OPCODE_GETSTATIC => {
                let index_byte_1 = attribute_code.code[i + 1];
                let index_byte_2 = attribute_code.code[i + 2];
                i += 2;

                let cp_offset_vreg = vreg_base + 3;

                let cp_index = (u16::from(index_byte_1) << 8) | u16::from(index_byte_2);

                let field_decriptor_utf8 = get_utf8_descriptor_from_field_or_method_or_interface_method_info(&constant_pool, cp_index);
                let type_char = field_decriptor_utf8.chars().nth(0).unwrap();

                let jvm_type = get_jvm_type_from_descriptor(type_char)?;

                riscv_append_set_vreg_to_cp_offset(&mut riscv_code_vregs, constant_pool, cp_index, cp_offset_vreg)?;

                match jvm_type {
                    JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::LW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                    JvmType::LONG => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = None;
                        let imm = Some(i32::from(WORD_SIZE));
                        let mnemonic = RiscvMnemonic::LW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::LW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        vreg_base += 1;
                    },
                    JvmType::FLOAT => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::FLW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                }

                operand_stack_types.push(jvm_type);
                vreg_base += 1;
            },
            JVM_OPCODE_GOTO => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];

                let branch_offset = i32::from(((u16::from(branch_byte_1) << 8) | u16::from(branch_byte_2)) as i16);
                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), (i as i32 + branch_offset) as usize);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                i += 2;
            },
            JVM_OPCODE_GOTO_W => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];
                let branch_byte_3 = attribute_code.code[i + 3];
                let branch_byte_4 = attribute_code.code[i + 4];

                let branch_offset = ((u32::from(branch_byte_1) << 24) | (u32::from(branch_byte_2) << 16) | (u32::from(branch_byte_3) << 8) | u32::from(branch_byte_4)) as i32;
                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), (i as i32 + branch_offset) as usize);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                i += 4;
            },
            JVM_OPCODE_I2B => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(24);
                let mnemonic = RiscvMnemonic::SLLI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(24);
                let mnemonic = RiscvMnemonic::SRAI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_I2C => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(24);
                let mnemonic = RiscvMnemonic::SLLI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(24);
                let mnemonic = RiscvMnemonic::SRLI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_I2D => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "i2d".to_string() }.into());
            },
            JVM_OPCODE_I2F => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::FCVTSW;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::FLOAT);
            },
            JVM_OPCODE_I2L => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = None;
                let imm = Some((WORD_SIZE - 1).into());
                let mnemonic = RiscvMnemonic::SRAI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::LONG);
                vreg_base += 1;
            },
            JVM_OPCODE_I2S => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(16);
                let mnemonic = RiscvMnemonic::SLLI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = None;
                let imm = Some(16);
                let mnemonic = RiscvMnemonic::SRAI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::SHORT);
            },
            JVM_OPCODE_IADD => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::INT)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
                vreg_base -= 1;
            },
            JVM_OPCODE_IAND => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::AND;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::INT)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 3;
            },
            JVM_OPCODE_ICONST_M1 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, -1, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ICONST_0 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 0, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ICONST_1 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 1, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ICONST_2 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 2, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ICONST_3 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 3, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ICONST_4 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 4, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ICONST_5 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 5, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_IDIV => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::DIV;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IF_ACMPEQ | JVM_OPCODE_IF_ACMPNE => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];

                let branch_offset = i32::from(((u16::from(branch_byte_1) << 8) | u16::from(branch_byte_2)) as i16);
                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), (i as i32 + branch_offset) as usize);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = match opcode {
                    JVM_OPCODE_IF_ACMPEQ => RiscvMnemonic::BEQ,
                    JVM_OPCODE_IF_ACMPNE => RiscvMnemonic::BNE,
                    _ => panic!("At acmpeq or acmpne, opcode is not one of acmpeq, acmpne at 2. match.")
                };
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 2;
                i += 2;
            },
            JVM_OPCODE_IF_ICMPEQ | JVM_OPCODE_IF_ICMPGE | JVM_OPCODE_IF_ICMPGT | JVM_OPCODE_IF_ICMPLE | JVM_OPCODE_IF_ICMPLT | JVM_OPCODE_IF_ICMPNE => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];

                let branch_offset = i32::from(((u16::from(branch_byte_1) << 8) | u16::from(branch_byte_2)) as i16);
                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), (i as i32 + branch_offset) as usize);

                let rs1;
                let rs2;
                let mnemonic;
                match opcode {
                    JVM_OPCODE_IF_ICMPEQ => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        mnemonic = RiscvMnemonic::BEQ;
                    },
                    JVM_OPCODE_IF_ICMPGE => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        mnemonic = RiscvMnemonic::BGE;
                    }
                    JVM_OPCODE_IF_ICMPGT => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        mnemonic = RiscvMnemonic::BLT;
                    },
                    JVM_OPCODE_IF_ICMPLE => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        mnemonic = RiscvMnemonic::BGE;
                    },
                    JVM_OPCODE_IF_ICMPLT => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        mnemonic = RiscvMnemonic::BLT;
                    },
                    JVM_OPCODE_IF_ICMPNE => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        mnemonic = RiscvMnemonic::BNE;
                    },
                    _ => panic!("At icmpeq or icmpge or icmpgt or icmple or icmplt or icmpne, opcode is not one of icmpeq, icmpge, icmpgt, icmple, icmplt, icmpne at 2. match.")
                };
                let rd = None;
                let imm = None;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 2;
                i += 2;
            },
            JVM_OPCODE_IFEQ | JVM_OPCODE_IFNE | JVM_OPCODE_IFLT | JVM_OPCODE_IFGE | JVM_OPCODE_IFGT | JVM_OPCODE_IFLE => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];

                let branch_offset = i32::from(((u16::from(branch_byte_1) << 8) | u16::from(branch_byte_2)) as i16);
                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), (i as i32 + branch_offset) as usize);

                let rs1;
                let rs2;
                let mnemonic;
                match opcode {
                    JVM_OPCODE_IFEQ => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        rs2 = Some(RiscvReg::ZERO);
                        mnemonic = RiscvMnemonic::BEQ;
                    },
                    JVM_OPCODE_IFNE => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        rs2 = Some(RiscvReg::ZERO);
                        mnemonic = RiscvMnemonic::BNE;
                    },
                    JVM_OPCODE_IFLT => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        rs2 = Some(RiscvReg::ZERO);
                        mnemonic = RiscvMnemonic::BLT;
                    },
                    JVM_OPCODE_IFGE => {
                        rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        rs2 = Some(RiscvReg::ZERO);
                        mnemonic = RiscvMnemonic::BGE;
                    }
                    JVM_OPCODE_IFGT => {
                        rs1 = Some(RiscvReg::ZERO);
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        mnemonic = RiscvMnemonic::BLT;
                    },
                    JVM_OPCODE_IFLE => {
                        rs1 = Some(RiscvReg::ZERO);
                        rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        mnemonic = RiscvMnemonic::BGE;
                    },
                    _ => panic!("At ifeq or ifne or iflt or ifge or ifgt or ifle, opcode is not one of ifeq, ifne, iflt, ifge, ifgt, ifle at 2. match.")
                };
                let rd = None;
                let imm = None;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
                i += 2;
            },
            JVM_OPCODE_IFNONNNULL | JVM_OPCODE_IFNULL => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];

                let branch_offset = i32::from(((u16::from(branch_byte_1) << 8) | u16::from(branch_byte_2)) as i16);
                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), (i as i32 + branch_offset) as usize);

                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = Some(RiscvReg::ZERO);
                let rd = None;
                let imm = None;
                let mnemonic;
                match opcode {
                    JVM_OPCODE_IFNONNNULL => {
                        mnemonic = RiscvMnemonic::BNE;
                    },
                    JVM_OPCODE_IFNULL => {
                        mnemonic = RiscvMnemonic::BEQ;
                    }
                    _ => panic!("At ifnonnull or ifnull, opcode is not one of ifnonnull, ifnull at 2. match.")
                }
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
                i += 2;
            },
            JVM_OPCODE_IINC => {
                let local_index = attribute_code.code[i + 1];
                let const_value = attribute_code.code[i + 2] as i32;

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT((local_index + 1).into())));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT((local_index + 1).into())));
                let rs2 = None;
                let imm = Some(const_value);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                i += 2;
            },
            JVM_OPCODE_ILOAD => {
                let local_index = attribute_code.code[i + 1];
                riscv_vregs_append_xload(&mut riscv_code_vregs, local_index.into(), vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
                i += 1;
            },
            JVM_OPCODE_ILOAD_0 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 0, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ILOAD_1 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 1, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ILOAD_2 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 2, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_ILOAD_3 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 3, vreg_base, JvmType::INT)?;

                operand_stack_types.push(JvmType::INT);
                vreg_base += 1;
            },
            JVM_OPCODE_IMUL => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_INEG => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SUB;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_INSTANCEOF => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "instanceof".to_string() }.into());
            },
            JVM_OPCODE_INVOKEDYNAMIC => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "invokedynamic".to_string() }.into());
            },
            JVM_OPCODE_INVOKEINTERFACE => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "invokeinterface".to_string() }.into());
            },
            JVM_OPCODE_INVOKESPECIAL => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "invokespecial".to_string() }.into());
            },
            JVM_OPCODE_INVOKESTATIC => {
                let index_byte_1 = attribute_code.code[i + 1];
                let index_byte_2 = attribute_code.code[i + 2];
                i += 2;

                let cp_index = (u16::from(index_byte_1) << 8) | u16::from(index_byte_2);

                let method_descriptor_utf8 = get_utf8_descriptor_from_field_or_method_or_interface_method_info(&constant_pool, cp_index);
                let method_name_utf8 = get_utf8_name_from_field_or_method_or_interface_method_info(&constant_pool, cp_index);

                // push args on stack
                let (args_types, return_type) = get_method_arg_and_return_types(method_descriptor_utf8.clone())?;
                let mut sp_offset = 0;
                for arg_type in args_types.iter() {
                    match arg_type {
                        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
                            sp_offset -= i32::from(WORD_SIZE);

                            let rd = None;
                            let rs1 = Some(RiscvReg::SP);
                            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                            let imm = Some(sp_offset);
                            let mnemonic = RiscvMnemonic::SW;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            vreg_base -= 1;
                        },
                        JvmType::LONG => {
                            sp_offset -= i32::from(WORD_SIZE);

                            let rd = None;
                            let rs1 = Some(RiscvReg::SP);
                            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                            let imm = Some(sp_offset);
                            let mnemonic = RiscvMnemonic::SW;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            sp_offset -= i32::from(WORD_SIZE);

                            let rd = None;
                            let rs1 = Some(RiscvReg::SP);
                            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                            let imm = Some(sp_offset);
                            let mnemonic = RiscvMnemonic::SW;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            vreg_base -= 2;
                        },
                        JvmType::FLOAT => {
                            sp_offset -= i32::from(WORD_SIZE);

                            let rd = None;
                            let rs1 = Some(RiscvReg::SP);
                            let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                            let imm = Some(sp_offset);
                            let mnemonic = RiscvMnemonic::FSW;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            vreg_base -= 1;
                        },
                    }
                }

                let rd = Some(RiscvReg::SP);
                let rs1 = Some(RiscvReg::SP);
                let rs2 = None;
                let imm = Some(sp_offset);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let function_label = get_function_label(method_name_utf8, this_class_name.clone());

                let rd = Some(RiscvReg::RA);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([function_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // Po returnu iz funkcije bodo return vrednosti v rezerviranih registrih
                if let Some(return_type) = return_type {
                    match return_type {
                        JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
                            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                            let rs1 = Some(RiscvReg::A0);
                            let rs2 = None;
                            let imm = Some(0);
                            let mnemonic = RiscvMnemonic::ADDI;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            vreg_base += 1;
                        },
                        JvmType::LONG => {
                            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                            let rs1 = Some(RiscvReg::A1);
                            let rs2 = None;
                            let imm = Some(0);
                            let mnemonic = RiscvMnemonic::ADDI;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                            let rs1 = Some(RiscvReg::A0);
                            let rs2 = None;
                            let imm = Some(0);
                            let mnemonic = RiscvMnemonic::ADDI;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            vreg_base += 2;
                        },
                        JvmType::FLOAT => {
                            let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                            let rs1 = Some(RiscvReg::FA0);
                            let rs2 = Some(RiscvReg::FA0);
                            let imm = None;
                            let mnemonic = RiscvMnemonic::FSGNJS;
                            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                            vreg_base += 1;
                        },
                    }
                }

                // sprosti prostor od argumentov
                let rd = Some(RiscvReg::SP);
                let rs1 = Some(RiscvReg::SP);
                let rs2 = None;
                let imm = Some(-sp_offset);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_INVOKEVIRTUAL => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "invokevirtual".to_string() }.into());
            },
            JVM_OPCODE_IOR => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::OR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IREM => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::REM;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IRETURN => {
                riscv_vregs_append_save_ret_val_and_j_to_epilogue(&mut riscv_code_vregs, vreg_base, Some(JvmType::INT), this_method_epilogue_label.clone())?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISHL => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SLL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISHR => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SRA;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISTORE => {
                let local_index = attribute_code.code[i + 1];

                riscv_vregs_append_xstore(&mut riscv_code_vregs, local_index.into(), vreg_base, JvmType::INT)?;

                i += 1;
                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISTORE_0 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 0, vreg_base, JvmType::INT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISTORE_1 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 1, vreg_base, JvmType::INT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISTORE_2 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 2, vreg_base, JvmType::INT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISTORE_3 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 3, vreg_base, JvmType::INT)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_ISUB => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SUB;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IUSHR => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SRL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_IXOR => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::XOR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_JSR => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];
                let return_opcode_index = i + 3;
                jsr_return_indexes.push(return_opcode_index);

                let branch_offset = i32::from(((u16::from(branch_byte_1) << 8) | u16::from(branch_byte_2)) as i16);
                let branch_target = (i as i32 + branch_offset) as usize;

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = None;
                let rs2 = None;
                let imm = Some(return_opcode_index as i32);
                let mnemonic = RiscvMnemonic::LUI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = None;
                let imm = Some((return_opcode_index & 0xFFF) as i32);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), branch_target);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
                i += 2;
            },
            JVM_OPCODE_JSR_W => {
                let branch_byte_1 = attribute_code.code[i + 1];
                let branch_byte_2 = attribute_code.code[i + 2];
                let branch_byte_3 = attribute_code.code[i + 3];
                let branch_byte_4 = attribute_code.code[i + 4];
                let return_opcode_index = i + 5;
                jsr_return_indexes.push(return_opcode_index);

                let branch_offset = ((u32::from(branch_byte_1) << 24) | (u32::from(branch_byte_2) << 16) | (u32::from(branch_byte_3) << 8) | u32::from(branch_byte_4)) as i32;
                let branch_target = (i as i32 + branch_offset) as usize;

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = None;
                let rs2 = None;
                let imm = Some(return_opcode_index as i32);
                let mnemonic = RiscvMnemonic::LUI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = None;
                let imm = Some((return_opcode_index & 0xFFF) as i32);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), branch_target);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.push(JvmType::REFERENCE);
                vreg_base += 1;
                i += 4;
            },
            JVM_OPCODE_L2D => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "l2d".to_string() }.into());
            },
            JVM_OPCODE_L2F => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "l2f".to_string() }.into());
            },
            JVM_OPCODE_L2I => {
                // Ker je long v 2 registrih in so MSB na višjem, LSB pa na nižjem, je tukaj treba samo posodobiti vreg_base, da se začne ignorirati MSB.

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
                vreg_base -= 1;
            },
            JVM_OPCODE_LADD => {
                /* lower 32 bits */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let skip_overflow_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let jumps = Some(Vec::from([skip_overflow_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);
                
                /* overflow */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs2 = None;
                let imm = Some(1);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* upper 32 bits */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                let label = Some(skip_overflow_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                /* move result of lower 32 bits */
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::LONG);
            },
            JVM_OPCODE_LAND => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::AND;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::AND;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
                vreg_base -= 4;
            },
            JVM_OPCODE_LCMP => {
                let result_less_than_label = next_anon_label(anon_label_counter);
                let result_greater_than_label = next_anon_label(anon_label_counter);
                let result_equal_label = next_anon_label(anon_label_counter);
                
                let end_label = next_anon_label(anon_label_counter);

                /* Compare top 32 bitov */

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLT;
                let jumps = Some(Vec::from([result_less_than_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLT;
                let jumps = Some(Vec::from([result_greater_than_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                /* top 32 bitov je istih, preveri še spodnjih 32 */

                // Na tej točki sta ali oba operanda pozitivna ali oba enaka 0 ali oba negativna
                // (če bi bil en pozitiven, drug pa negativen, bi to zaznala primerjava prvih 32 bitov)
                let both_negative_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs2 = Some(RiscvReg::ZERO);
                let imm = None;
                let mnemonic = RiscvMnemonic::BLT;
                let jumps = Some(Vec::from([both_negative_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // Oba operanda sta pozitivna ali enaka 0, unsigned compare spodnjih 32 bitov

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let jumps = Some(Vec::from([result_less_than_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let jumps = Some(Vec::from([result_greater_than_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([result_equal_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // Oba operanda sta negativna, obrnjen unsigned compare spodnjih 32 bitov

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let label = Some(both_negative_label.clone());
                let jumps = Some(Vec::from([result_less_than_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, jumps)?);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let jumps = Some(Vec::from([result_greater_than_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([result_equal_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                /* Zapisi rezultatov */

                // value1 < value2
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2: Option<RiscvReg> = None;
                let imm = Some(-1);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(result_less_than_label.clone());
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([end_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // value1 > value2
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2: Option<RiscvReg> = None;
                let imm = Some(1);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(result_greater_than_label.clone());
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([end_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // value1 == value2
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2: Option<RiscvReg> = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(result_equal_label.clone());
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                /* End */

                let rd = Some(RiscvReg::ZERO);
                let rs1 = Some(RiscvReg::ZERO);
                let rs2: Option<RiscvReg> = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(end_label.clone());
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);


                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::INT);
                vreg_base -= 3;
            },
            JVM_OPCODE_LCONST_0 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 0, vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LCONST_1 => {
                riscv_vregs_append_xconst_n(&mut riscv_code_vregs, 1, vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LDC | JVM_OPCODE_LDC_W => {
                let cp_index = match opcode {
                    JVM_OPCODE_LDC => {
                        let index = attribute_code.code[i + 1];
                        i += 1;

                        u16::from(index)
                    }
                    JVM_OPCODE_LDC_W => {
                        let index_byte_1 = attribute_code.code[i + 1];
                        let index_byte_2 = attribute_code.code[i + 2];
                        i += 2;

                        (u16::from(index_byte_1) << 8) | u16::from(index_byte_2)
                    }
                    _ => panic!()
                };

                match &constant_pool[cp_index as usize] {
                    CpInfo::Integer(cp_integer) => {
                        let value = ((u32::from(cp_integer.bytes[0]) << 24) | (u32::from(cp_integer.bytes[1]) << 16) | (u32::from(cp_integer.bytes[2]) << 8) | u32::from(cp_integer.bytes[3])) as i32;
                        
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = None;
                        let rs2 = None;
                        let imm = Some(value);
                        let mnemonic = RiscvMnemonic::LUI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs2 = None;
                        let imm = Some(value & 0xFFF);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        operand_stack_types.push(JvmType::INT);
                    }
                    CpInfo::Float(cp_float) => {
                        let value = ((u32::from(cp_float.bytes[0]) << 24) | (u32::from(cp_float.bytes[1]) << 16) | (u32::from(cp_float.bytes[2]) << 8) | u32::from(cp_float.bytes[3])) as i32;
                        
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = None;
                        let rs2 = None;
                        let imm = Some(value);
                        let mnemonic = RiscvMnemonic::LUI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs2 = None;
                        let imm = Some(value & 0xFFF);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs2 = None;
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FMVWX;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        operand_stack_types.push(JvmType::FLOAT);
                    },
                    CpInfo::Class(_) | CpInfo::String(_) => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::CP);
                        let rs2 = None;
                        let imm = Some(i32::from(cp_index) * i32::from(WORD_SIZE));
                        let mnemonic = RiscvMnemonic::LW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        operand_stack_types.push(JvmType::REFERENCE);
                    }
                    CpInfo::MethodHandle(_) => return Err(UnimplementedJVMInstrError { opcode, instr: "ldc or ldc_w (with CpInfo MethodHandle)".to_string() }.into()),
                    CpInfo::MethodType(_) => return Err(UnimplementedJVMInstrError { opcode, instr: "ldc or ldc_w (with CpInfo MethodType)".to_string() }.into()),
                    CpInfo::Dynamic(_) => return Err(UnimplementedJVMInstrError { opcode, instr: "ldc or ldc_w (with CpInfo MethodHandle)".to_string() }.into()),
                    other => panic!("at ldc or ldc_w, got cp_index = {}, invalid cp_info: {:#?}", cp_index, other)
                }

                vreg_base += 1;
            },
            JVM_OPCODE_LDC2_W => {
                let index_byte_1 = attribute_code.code[i + 1];
                let index_byte_2 = attribute_code.code[i + 2];
                i += 2;

                let cp_index = (u16::from(index_byte_1) << 8) | u16::from(index_byte_2);
                match &constant_pool[cp_index as usize] {
                    CpInfo::Long(cp_long) => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = None;
                        let rs2 = None;
                        let imm: Option<i32> = Some(cp_long.low_bytes as i32);
                        let mnemonic = RiscvMnemonic::LUI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                        let rs2 = None;
                        let imm = Some(cp_long.low_bytes as i32 & 0xFFF);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                        let rs1 = None;
                        let rs2 = None;
                        let imm: Option<i32> = Some(cp_long.high_bytes as i32);
                        let mnemonic = RiscvMnemonic::LUI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 2)));
                        let rs2 = None;
                        let imm = Some(cp_long.high_bytes as i32 & 0xFFF);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        operand_stack_types.push(JvmType::LONG);
                    },
                    CpInfo::Double(_) => return Err(UnimplementedJVMInstrError { opcode, instr: "ldc2_w (with CpInfo Double)".to_string() }.into()),
                    other => panic!("at ldc2_w, got cp_index = {}, invalid cp_info: {:#?}", cp_index, other)
                }

                vreg_base += 2;
            },
            JVM_OPCODE_LDIV => {
                riscv_append_long_div(&mut riscv_code_vregs, vreg_base, anon_label_counter, false)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LLOAD => {
                let local_index = attribute_code.code[i + 1];
                i += 1;

                riscv_vregs_append_xload(&mut riscv_code_vregs, local_index.into(), vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LLOAD_0 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 0, vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LLOAD_1 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 1, vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LLOAD_2 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 2, vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LLOAD_3 => {
                riscv_vregs_append_xload(&mut riscv_code_vregs, 3, vreg_base, JvmType::LONG)?;

                operand_stack_types.push(JvmType::LONG);
                vreg_base += 2;
            },
            JVM_OPCODE_LMUL => {
                let value1low_vreg = vreg_base - 3;
                let value1high_vreg = vreg_base - 2;
                let value2low_vreg = vreg_base - 1;
                let value2high_vreg = vreg_base;

                let value1_is_negative_vreg = vreg_base + 1;
                let value2_is_negative_vreg = vreg_base + 2;

                let value1low_value2low_low_vreg = vreg_base + 3;
                let value1low_value2low_high_vreg = vreg_base + 4;

                let value1low_value2high_low_vreg = vreg_base + 5;

                let value1high_value2low_low_vreg = vreg_base + 6;

                let abs_mask_vreg = vreg_base + 7;
                let carry_check_vreg = vreg_base + 8;

                /* to absolute */

                // value1
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_is_negative_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::SLTI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                riscv_vregs_append_absolute_long(&mut riscv_code_vregs, value1high_vreg, value1low_vreg, abs_mask_vreg, carry_check_vreg)?;

                // value2
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_is_negative_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2high_vreg)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::SLTI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                riscv_vregs_append_absolute_long(&mut riscv_code_vregs, value2high_vreg, value2low_vreg, abs_mask_vreg, carry_check_vreg)?;

                /* value1low * value2low (need low and high bits of result) */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2low_low_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2low_high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2high_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MULHU;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* value1low * value2high (need only low bits) */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2high_low_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2high_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* value1high * value2low (need only low bits) */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_value2low_low_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* add partial results for final result */

                // result low
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2low_low_vreg)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                // result high
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2low_high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_value2low_low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let partial_result_no_overflow_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2low_high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let jumps = Some(Vec::from([partial_result_no_overflow_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = None;
                let imm = Some(1);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2high_low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                let label = Some(partial_result_no_overflow_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                let final_result_no_overflow_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_value2high_low_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLTU;
                let jumps = Some(Vec::from([final_result_no_overflow_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = None;
                let imm = Some(1);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* fix sign of result if needed */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_is_negative_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_is_negative_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_is_negative_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::XOR;
                let label = Some(final_result_no_overflow_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                let end_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_is_negative_vreg)));
                let rs2 = Some(RiscvReg::ZERO);
                let imm = None;
                let mnemonic = RiscvMnemonic::BEQ;
                let jumps = Some(Vec::from([end_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                riscv_append_long_sign_flip(&mut riscv_code_vregs, value1high_vreg, value1low_vreg, carry_check_vreg, anon_label_counter)?;

                let rd = Some(RiscvReg::ZERO);
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(end_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LNEG => {
                riscv_append_long_sign_flip(&mut riscv_code_vregs, vreg_base, vreg_base - 1, vreg_base + 1, anon_label_counter)?;
            },
            JVM_OPCODE_LOOKUPSWITCH => {
                if i % 4 != 0 {
                    i += 4 - i % 4;
                }

                let defaultbyte_1 = attribute_code.code[i + 1];
                let defaultbyte_2 = attribute_code.code[i + 2];
                let defaultbyte_3 = attribute_code.code[i + 3];
                let defaultbyte_4 = attribute_code.code[i + 4];
                i += 4;

                let default = ((u32::from(defaultbyte_1) << 24) | (u32::from(defaultbyte_2) << 16) | (u32::from(defaultbyte_3) << 8) | u32::from(defaultbyte_4)) as i32;
                let default_branch_target = (curr_opcode_i as i32 + default) as usize;

                let npairs_1 = attribute_code.code[i + 1];
                let npairs_2 = attribute_code.code[i + 2];
                let npairs_3 = attribute_code.code[i + 3];
                let npairs_4 = attribute_code.code[i + 4];
                i += 4;

                let npairs = ((u32::from(npairs_1) << 24) | (u32::from(npairs_2) << 16) | (u32::from(npairs_3) << 8) | u32::from(npairs_4)) as i32;

                let match_value_vreg = vreg_base + 1;

                for j in 0..npairs as usize {
                    let match_1 = attribute_code.code[i + j * 4 + 1];
                    let match_2 = attribute_code.code[i + j * 4 + 2];
                    let match_3 = attribute_code.code[i + j * 4 + 3];
                    let match_4 = attribute_code.code[i + j * 4 + 4];
                    let match_value = ((u32::from(match_1) << 24) | (u32::from(match_2) << 16) | (u32::from(match_3) << 8) | u32::from(match_4)) as i32;

                    let offset_1 = attribute_code.code[i + j * 4 + 5];
                    let offset_2 = attribute_code.code[i + j * 4 + 6];
                    let offset_3 = attribute_code.code[i + j * 4 + 7];
                    let offset_4 = attribute_code.code[i + j * 4 + 8];
                    let offset = ((u32::from(offset_1) << 24) | (u32::from(offset_2) << 16) | (u32::from(offset_3) << 8) | u32::from(offset_4)) as i32;

                    let branch_target = (curr_opcode_i as i32 + offset) as usize;

                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(match_value_vreg)));
                    let rs1 = None;
                    let rs2 = None;
                    let imm = Some(match_value);
                    let mnemonic = RiscvMnemonic::LUI;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(match_value_vreg)));
                    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(match_value_vreg)));
                    let rs2 = None;
                    let imm = Some(match_value & 0xFFF);
                    let mnemonic = RiscvMnemonic::ADDI;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                    riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), branch_target);

                    let rd = None;
                    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(match_value_vreg)));
                    let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                    let imm = None;
                    let mnemonic = RiscvMnemonic::BEQ;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                }

                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), default_branch_target);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
                i += (npairs * 8) as usize;
            },
            JVM_OPCODE_LOR => {
                let value1low_vreg = vreg_base - 3;
                let value1high_vreg = vreg_base - 2;
                let value2low_vreg = vreg_base - 1;
                let value2high_vreg = vreg_base;

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1low_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::OR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2high_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::OR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LREM => {
                riscv_append_long_div(&mut riscv_code_vregs, vreg_base, anon_label_counter, true)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LRETURN => {
                riscv_vregs_append_save_ret_val_and_j_to_epilogue(&mut riscv_code_vregs, vreg_base, Some(JvmType::LONG), this_method_epilogue_label.clone())?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LSHL => {
                let valuehigh_vreg = vreg_base - 2;
                let valuelow_vreg = vreg_base - 1;
                let shift_amount_vreg = vreg_base;

                let const_32_vreg = vreg_base + 1;

                let temp_valuelow_adjusted_shift_vreg = vreg_base + 2;
                let valuelow_temp_vreg = vreg_base + 3;

                let final_valuehigh_shift = vreg_base + 4; 

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(32);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let shift_geq_32_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BGE;
                let jumps = Some(Vec::from([shift_geq_32_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // shift < 32

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_valuelow_adjusted_shift_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SUB;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_temp_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_valuelow_adjusted_shift_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SRL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SLL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SLL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(final_valuehigh_shift)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let end_of_shift_geq_32_label = next_anon_label(anon_label_counter);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([end_of_shift_geq_32_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                // shift >= 32

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_temp_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(shift_geq_32_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_vreg)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(final_valuehigh_shift)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(shift_amount_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_32_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SUB;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                // add valuelow_temp_vreg to valuehigh_vreg and shift if needed

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuelow_temp_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                let label = Some(end_of_shift_geq_32_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(valuehigh_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(final_valuehigh_shift)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SLL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_LSHR => {
                riscv_append_long_shift_right(&mut riscv_code_vregs, vreg_base, anon_label_counter, true)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_LSTORE => {
                let local_index = attribute_code.code[i + 1];
                i += 1;

                riscv_vregs_append_xstore(&mut riscv_code_vregs, u32::from(local_index), vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LSTORE_0 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 0, vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LSTORE_1 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 1, vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LSTORE_2 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 2, vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LSTORE_3 => {
                riscv_vregs_append_xstore(&mut riscv_code_vregs, 3, vreg_base, JvmType::LONG)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LSUB => {
                riscv_vregs_append_long_sub(&mut riscv_code_vregs, vreg_base - 3, vreg_base - 2, vreg_base - 1, vreg_base, vreg_base + 1)?;

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_LUSHR => {
                riscv_append_long_shift_right(&mut riscv_code_vregs, vreg_base, anon_label_counter, false)?;

                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_LXOR => {
                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 3)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                let imm = None;
                let mnemonic = RiscvMnemonic::XOR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 2)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let imm = None;
                let mnemonic = RiscvMnemonic::XOR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                vreg_base -= 2;
            },
            JVM_OPCODE_MONITORENTER => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "monitorenter".to_string() }.into());
            },
            JVM_OPCODE_MONITOREXIT => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "monitorexit".to_string() }.into());
            },
            JVM_OPCODE_MULTIANEWARRAY => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "multianewarray".to_string() }.into());

                // let dimensions = attribute_code.code[i + 3];
                // i += 3;

                // let array_pointer_vreg = vreg_base + 1;
                // let const_word_size_vreg = vreg_base + 2;

                // let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_pointer_vreg)));
                // let rs1 = Some(RiscvReg::GP);
                // let rs2 = None;
                // let imm = Some(i32::from(WORD_SIZE));
                // let mnemonic = RiscvMnemonic::ADDI;
                // riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                // let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_word_size_vreg)));
                // let rs1 = Some(RiscvReg::ZERO);
                // let rs2 = None;
                // let imm = Some(i32::from(WORD_SIZE));
                // let mnemonic = RiscvMnemonic::ADDI;
                // riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                // fn multinewarray(dimension_i: u8, total_dimensions: u8, offset_to_parent_array: i32, riscv_code_vregs: &mut Vec<RiscvInstr>, vreg_base: u32) -> Result<(), Box<dyn error::Error>> {
                //     let count_vreg = vreg_base - u32::from(total_dimensions) + u32::from(dimension_i) + 1;
                //     let const_word_size_vreg = vreg_base + 2;
                //     let array_size_vreg = vreg_base + 3;

                //     let rd = None;
                //     let rs1 = Some(RiscvReg::GP);
                //     let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(count_vreg)));
                //     let imm = Some(i32::from(WORD_SIZE));
                //     let mnemonic = RiscvMnemonic::SW;
                //     riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                //     let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                //     let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(count_vreg)));
                //     let rs2 = None;
                //     let imm = Some(1);
                //     let mnemonic = RiscvMnemonic::ADDI;
                //     riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                //     let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                //     let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                //     let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_word_size_vreg)));
                //     let imm = None;
                //     let mnemonic = RiscvMnemonic::MUL;
                //     riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                //     if offset_to_parent_array >= 0 {
                //         let rd = Some(RiscvReg::GP);
                //         let rs1 = Some(RiscvReg::GP);
                //         let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                //         let imm = None;
                //         let mnemonic = RiscvMnemonic::ADD;
                //         riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                //     }
                //     else {

                //     }

                    

                //     let next_dimension_i = dimension_i + 1;
                //     if next_dimension_i < total_dimensions {
                        
                //     }

                //     return Ok(());
                // }

                // let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - u32::from(dimensions) + 1)));
                // let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_pointer_vreg)));
                // let rs2 = None;
                // let imm = Some(0);
                // let mnemonic = RiscvMnemonic::ADDI;
                // riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                // for _ in 0..dimensions {
                //     operand_stack_types.pop();
                // }
                // operand_stack_types.push(JvmType::REFERENCE);
                // vreg_base -= u32::from(dimensions - 1);
            },
            JVM_OPCODE_NEW => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "new".to_string() }.into());
            },
            JVM_OPCODE_NEWARRAY => {
                let atype = attribute_code.code[i + 1];
                i += 1;

                let count_vreg = vreg_base;
                let array_size_vreg = vreg_base + 1;
                let element_size_vreg = vreg_base + 2;
                let array_pointer_vreg = vreg_base + 3;

                let init_offset = vreg_base + 4;

                let element_size;
                let init_instr;

                let array_init_label = next_anon_label(anon_label_counter);
                match atype {
                    4 | 8 => {
                        element_size = 1;

                        let rd = None;
                        let rs1 = Some(RiscvReg::HP);
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                        let imm = Some(WORD_SIZE.into());
                        let mnemonic = RiscvMnemonic::SB;
                        let label = Some(array_init_label.clone());
                        init_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?;
                    },
                    5 | 9 => {
                        element_size = 2;

                        let rd = None;
                        let rs1 = Some(RiscvReg::HP);
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                        let imm = Some(WORD_SIZE.into());
                        let mnemonic = RiscvMnemonic::SH;
                        let label = Some(array_init_label.clone());
                        init_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?;
                    },
                    6 | 10 => {
                        element_size = 4;

                        let rd = None;
                        let rs1 = Some(RiscvReg::HP);
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                        let imm = Some(WORD_SIZE.into());
                        let mnemonic = RiscvMnemonic::SW;
                        let label = Some(array_init_label.clone());
                        init_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?;
                    },
                    7 => {
                        return Err(UnimplementedJVMInstrError { opcode, instr: "newarray (double)".to_string() }.into());
                    },
                    11 => {
                        element_size = WORD_SIZE * 2;

                        let rd = None;
                        let rs1 = Some(RiscvReg::HP);
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                        let imm = Some(WORD_SIZE.into());
                        let mnemonic = RiscvMnemonic::SH;
                        let label = Some(array_init_label.clone());
                        init_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?;
                    },
                    other => panic!("at newarray, got atype = {}", other)
                }

                /* init */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(element_size.into());
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(element_size_vreg)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(i32::from(element_size));
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                //

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_pointer_vreg)));
                let rs1 = Some(RiscvReg::HP);
                let rs2 = None;
                let imm = Some(i32::from(WORD_SIZE));
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = None;
                let rs1 = Some(RiscvReg::HP);
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(count_vreg)));
                let imm = Some(i32::from(WORD_SIZE));
                let mnemonic = RiscvMnemonic::SW;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(count_vreg)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(element_size_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* initializing array */

                riscv_code_vregs.push(init_instr.clone());

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(element_size_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(init_offset)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLT;
                let jumps = Some(Vec::from([array_init_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                //

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let rs2 = None;
                let imm = Some(WORD_SIZE.into());
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::HP);
                let rs1 = Some(RiscvReg::HP);
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_size_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(array_pointer_vreg)));
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                operand_stack_types.pop();
                operand_stack_types.push(JvmType::REFERENCE);
            },
            JVM_OPCODE_NOP => {
                let rd = Some(RiscvReg::ZERO);
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_POP => {
                operand_stack_types.pop();
                vreg_base -= 1;
            },
            JVM_OPCODE_POP2 => {
                let value1_type = operand_stack_types.pop().unwrap();
                let value1_cat = get_jvm_type_computational_category(value1_type);

                if value1_cat == JVM_TYPE_COMPUTATIONAL_CATEGORY_1 {
                    operand_stack_types.pop();
                }

                vreg_base -= 2;
            },
            JVM_OPCODE_PUTFIELD => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "putfield".to_string() }.into());
            },
            JVM_OPCODE_PUTSTATIC => {
                let index_byte_1 = attribute_code.code[i + 1];
                let index_byte_2 = attribute_code.code[i + 2];
                i += 2;

                let cp_offset_vreg = vreg_base + 1;

                let cp_index = (u16::from(index_byte_1) << 8) | u16::from(index_byte_2);

                let field_decriptor_utf8 = get_utf8_descriptor_from_field_or_method_or_interface_method_info(&constant_pool, cp_index);
                let type_char = field_decriptor_utf8.chars().nth(0).unwrap();

                let jvm_type = get_jvm_type_from_descriptor(type_char)?;

                match jvm_type {
                    JvmType::BYTE => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        let rs2 = None;
                        let imm = Some(0xFF);
                        let mnemonic = RiscvMnemonic::ANDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                    JvmType::SHORT | JvmType::CHAR => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        let rs2 = None;
                        let imm = Some(0xFFFF);
                        let mnemonic = RiscvMnemonic::ANDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                    _ => ()
                }

                // boolean
                if type_char == 'Z' {
                    let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                    let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                    let rs2 = None;
                    let imm = Some(0x1);
                    let mnemonic = RiscvMnemonic::ANDI;
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                }

                riscv_append_set_vreg_to_cp_offset(&mut riscv_code_vregs, constant_pool, cp_index, cp_offset_vreg)?;

                match jvm_type {
                    JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE => {
                        let rd = None;
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::SW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        vreg_base -= 1;
                    },
                    JvmType::LONG => {
                        let rd = None;
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base)));
                        let imm = Some(i32::from(WORD_SIZE));
                        let mnemonic = RiscvMnemonic::LW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = None;
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base - 1)));
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::LW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        vreg_base -= 2;
                    },
                    JvmType::FLOAT => {
                        let rd = None;
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(cp_offset_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(vreg_base)));
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FLW;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        vreg_base -= 1;
                    },
                }

                operand_stack_types.pop();
            },
            JVM_OPCODE_RET => {
                i += 1;

                let return_index = jsr_return_indexes.pop().unwrap();

                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), return_index);
                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            },
            JVM_OPCODE_RETURN => {
                riscv_vregs_append_save_ret_val_and_j_to_epilogue(&mut riscv_code_vregs, vreg_base, None, this_method_epilogue_label.clone())?;
            },
            JVM_OPCODE_SALOAD => {
                riscv_vregs_append_xa_load(&mut riscv_code_vregs, vreg_base, JvmType::SHORT)?;

                vreg_base -= 1;
                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.push(JvmType::SHORT);
            },
            JVM_OPCODE_SASTORE => {
                riscv_vregs_append_xa_store(&mut riscv_code_vregs, vreg_base, JvmType::SHORT)?;

                vreg_base -= 3;
                operand_stack_types.pop();
                operand_stack_types.pop();
                operand_stack_types.pop();
            },
            JVM_OPCODE_SIPUSH => {
                let byte_1 = attribute_code.code[i + 1];
                let byte_2 = attribute_code.code[i + 2];
                i += 2;

                let value = ((u16::from(byte_1) << 8) | u16::from(byte_2)) as i32;

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = None;
                let rs2 = None;
                let imm = Some(value);
                let mnemonic = RiscvMnemonic::LUI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(vreg_base + 1)));
                let rs2 = None;
                let imm = Some(value & 0xFFF);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                vreg_base += 1;
                operand_stack_types.push(JvmType::SHORT);
            },
            JVM_OPCODE_SWAP => {
                let value2_vreg = vreg_base - 1;
                let value1_vreg = vreg_base;
                let temp_vreg = vreg_base + 1;

                let jvm_type_1 = operand_stack_types.pop().unwrap();
                let jvm_type_2 = operand_stack_types.pop().unwrap();

                match (jvm_type_1, jvm_type_2) {
                    (JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE, JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE) => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                    (JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE, JvmType::FLOAT) => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value1_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value2_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value2_vreg)));
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FSGNJS;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                    (JvmType::FLOAT, JvmType::BYTE | JvmType::SHORT | JvmType::INT | JvmType::CHAR | JvmType::REFERENCE) => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value2_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value1_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value1_vreg)));
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FSGNJS;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                        
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let rs2 = None;
                        let imm = Some(0);
                        let mnemonic = RiscvMnemonic::ADDI;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    },
                    (JvmType::FLOAT, JvmType::FLOAT) => {
                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(temp_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value1_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(value1_vreg)));
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FSGNJS;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value1_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FSGNJS;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                        let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(value2_vreg)));
                        let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_vreg)));
                        let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(temp_vreg)));
                        let imm = None;
                        let mnemonic = RiscvMnemonic::FSGNJS;
                        riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                    }
                    (other1, other2) => panic!("at swap, got jvm_type_1 = {:#?}, jvm_type_2 = {:#?}", other1, other2)
                }

                operand_stack_types.push(jvm_type_1);
                operand_stack_types.push(jvm_type_2);
            },
            JVM_OPCODE_TABLESWITCH => {
                if i % 4 != 0 {
                    i += 4 - i % 4;
                }

                let default_1 = attribute_code.code[i + 1];
                let default_2 = attribute_code.code[i + 2];
                let default_3 = attribute_code.code[i + 3];
                let default_4 = attribute_code.code[i + 4];
                let default = ((u32::from(default_1) << 24) | (u32::from(default_2) << 16) | (u32::from(default_3) << 8) | u32::from(default_4)) as i32;
                let default_target = (curr_opcode_i as i32 + default) as usize;

                i += 4;

                let low_1 = attribute_code.code[i + 1];
                let low_2 = attribute_code.code[i + 2];
                let low_3 = attribute_code.code[i + 3];
                let low_4 = attribute_code.code[i + 4];
                let low = ((u32::from(low_1) << 24) | (u32::from(low_2) << 16) | (u32::from(low_3) << 8) | u32::from(low_4)) as i32;

                i += 4;

                let high_1 = attribute_code.code[i + 1];
                let high_2 = attribute_code.code[i + 2];
                let high_3 = attribute_code.code[i + 3];
                let high_4 = attribute_code.code[i + 4];
                let high = ((u32::from(high_1) << 24) | (u32::from(high_2) << 16) | (u32::from(high_3) << 8) | u32::from(high_4)) as i32;

                i += 4;

                if high - low + 1 < 0 {
                    panic!("at tableswitch, high - low + 1 < 0.");
                }

                let index_vreg = vreg_base;
                let low_vreg = vreg_base + 1;
                let high_vreg = vreg_base + 2;
                let pc_rel_index_vreg = vreg_base + 3;
                let const_word_size_reg = vreg_base + 4;

                /* init */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(low_vreg)));
                let rs1 = None;
                let rs2 = None;
                let imm = Some(low);
                let mnemonic = RiscvMnemonic::LUI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(low_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(low_vreg)));
                let rs2 = None;
                let imm = Some(low & 0xFFF);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(high_vreg)));
                let rs1 = None;
                let rs2 = None;
                let imm = Some(high);
                let mnemonic = RiscvMnemonic::LUI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(high_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(high_vreg)));
                let rs2 = None;
                let imm = Some(high & 0xFFF);
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_word_size_reg)));
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(WORD_SIZE.into());
                let mnemonic = RiscvMnemonic::ADDI;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                /* check if default jump */

                let jump_to_default_label = next_anon_label(anon_label_counter);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLT;
                let jumps = Some(Vec::from([jump_to_default_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                let rd = None;
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(high_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::BLT;
                let jumps = Some(Vec::from([jump_to_default_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                /* jump to jump based on index */

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(low_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::SUB;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(const_word_size_reg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::MUL;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(pc_rel_index_vreg)));
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::AUIPC;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(pc_rel_index_vreg)));
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(pc_rel_index_vreg)));
                let rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(index_vreg)));
                let imm = None;
                let mnemonic = RiscvMnemonic::ADD;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
                
                let rd = Some(RiscvReg::ZERO);
                let rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(pc_rel_index_vreg)));
                let rs2 = None;
                let imm = Some(i32::from(WORD_SIZE) * 3);
                let mnemonic = RiscvMnemonic::JALR;
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);

                let jump_instr_i = riscv_code_vregs.len() - 1;
                let mut jumps = Vec::new();

                for j in 0..(high - low + 1) as usize {
                    let offset_1 = attribute_code.code[i + j * 4 + 1];
                    let offset_2 = attribute_code.code[i + j * 4 + 2];
                    let offset_3 = attribute_code.code[i + j * 4 + 3];
                    let offset_4 = attribute_code.code[i + j * 4 + 4];
                    let offset = ((u32::from(offset_1) << 24) | (u32::from(offset_2) << 16) | (u32::from(offset_3) << 8) | u32::from(offset_4)) as i32;
                    let offset_target = (curr_opcode_i as i32 + offset) as usize;

                    riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), offset_target);
                    
                    let rd = Some(RiscvReg::ZERO);
                    let rs1 = None;
                    let rs2 = None;
                    let imm = None;
                    let mnemonic = RiscvMnemonic::JAL;
                    let label = next_anon_label(anon_label_counter);
                    riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, Some(label.clone()), None)?);

                    jumps.push(label);
                }

                riscv_code_vregs[jump_instr_i].jumps = jumps;

                let end_of_jump_to_default_label = next_anon_label(anon_label_counter);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let jumps = Some(Vec::from([end_of_jump_to_default_label.clone()]));
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, jumps)?);

                /* default jump */

                riscv_instr_index_jumps_to_code_index.insert(riscv_code_vregs.len(), default_target);

                let rd = Some(RiscvReg::ZERO);
                let rs1 = None;
                let rs2 = None;
                let imm = None;
                let mnemonic = RiscvMnemonic::JAL;
                let label = Some(jump_to_default_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                /* end */

                let rd = Some(RiscvReg::ZERO);
                let rs1 = Some(RiscvReg::ZERO);
                let rs2 = None;
                let imm = Some(0);
                let mnemonic = RiscvMnemonic::ADDI;
                let label = Some(end_of_jump_to_default_label);
                riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, label, None)?);

                vreg_base -= 1;
                operand_stack_types.pop();
                i += (4 * (high - low + 1)) as usize;
            },
            JVM_OPCODE_WIDE => {
                return Err(UnimplementedJVMInstrError { opcode, instr: "wide".to_string() }.into());
            },
            /*
            let rd = ;
            let rs1 = ;
            let rs2 = ;
            let imm = ;
            let mnemonic = ;
            riscv_code_vregs.push(RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?);
            */
            opcode => {
                return Err(UnknownJVMOpcodeError { opcode }.into())
            }
        }
        first_riscv_instr_index_by_code_index.insert(curr_opcode_i, starting_riscv_vregs_len);

        i += 1;
    }

    for (riscv_instr_index, target_index) in riscv_instr_index_jumps_to_code_index {
        let jump_target_instr_index = first_riscv_instr_index_by_code_index[&target_index];
        let mut instr = &mut riscv_code_vregs[jump_target_instr_index];

        let label = match &instr.label {
            Some(some_label) => some_label.clone(),
            None => next_anon_label(anon_label_counter)
        };

        instr.label = Some(label.clone());

        instr = &mut riscv_code_vregs[riscv_instr_index];
        instr.jumps.push(label.clone());        
    }

    return Ok(riscv_code_vregs);
}
