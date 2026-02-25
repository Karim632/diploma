use std::{collections::HashMap, fs::File, io::Write};

use crate::{class_parser::{ClassFile, CpInfo}, register_allocation::{CodeInfo, NUM_TEMP_REGS_FLOAT, NUM_TEMP_REGS_INT}, translator::{JvmType, RiscvInstr, RiscvReg, WORD_SIZE, get_class_name_utf8, get_function_epilogue_label, get_function_label, get_jvm_type_from_descriptor, get_method_arg_and_return_types, get_utf8_descriptor_from_field_or_method_or_interface_method_info, get_utf8_name_from_field_or_method_or_interface_method_info}};

pub const HEAP_SIZE: u32 = 2_u32.pow(16);

pub fn asm_write(out_file_path: String, class_file: &ClassFile, method_i_to_riscv_code: &HashMap<usize, Vec<RiscvInstr>>, method_i_to_code_info: Option<&HashMap<usize, CodeInfo>>) {
    let class_name = get_class_name_utf8(class_file);
    let mut out_file = File::create(out_file_path.clone()).unwrap();

    let hp_reg = RiscvReg::HP.to_string(&None, &None);
    let cp_reg = RiscvReg::CP.to_string(&None, &None);

    writeln!(&out_file, ".data").unwrap();
    writeln!(&out_file, "heap: .space {}", HEAP_SIZE).unwrap();
    writeln!(&out_file, "").unwrap();
    writeln!(&out_file, ".text").unwrap();
    writeln!(&out_file, "").unwrap();
    writeln!(&out_file, ".globl main").unwrap();
    writeln!(&out_file, ".type main, @function").unwrap();
    writeln!(&out_file, "main:").unwrap();
    writeln!(&out_file, "\t\tLA {}, heap", hp_reg).unwrap();
    writeln!(&out_file, "\t\tMV {}, {}", cp_reg, hp_reg).unwrap(); // na začetku heapa je constant_pool
    // initialize constant pool
    for (i, cp_info) in class_file.constant_pool.iter().enumerate() {
        match cp_info {
            CpInfo::Utf8(cp_utf8) => {
                write_string_to_cp(&mut out_file, &cp_utf8.converted, &hp_reg);
            },
            CpInfo::Integer(cp_integer) => {
                let word = (u32::from(cp_integer.bytes[0]) << 24) | (u32::from(cp_integer.bytes[1]) << 16) |(u32::from(cp_integer.bytes[2]) << 8) | u32::from(cp_integer.bytes[3]);
                write_word_to_cp(&mut out_file, word, &hp_reg);
            },
            CpInfo::Float(cp_float) => {
                let word = (u32::from(cp_float.bytes[0]) << 24) | (u32::from(cp_float.bytes[1]) << 16) |(u32::from(cp_float.bytes[2]) << 8) | u32::from(cp_float.bytes[3]);
                write_word_to_cp(&mut out_file, word, &hp_reg);
            },
            CpInfo::Long(cp_long) => {
                write_word_to_cp(&mut out_file, cp_long.low_bytes, &hp_reg);
                write_word_to_cp(&mut out_file, cp_long.high_bytes, &hp_reg);
            },
            CpInfo::Double(cp_double) => panic!("cp_double in constant pool, not implemented: {:#?}", cp_double),
            CpInfo::Class(cp_class) => {
                let cp_utf8 = match &class_file.constant_pool[cp_class.name_index as usize] {
                    CpInfo::Utf8(cp_utf8) => cp_utf8,
                    other => panic!("trying to get name of class in cp, instead got: {:#?}", other)
                };

                write_string_to_cp(&mut out_file, &cp_utf8.converted, &hp_reg);
            },
            CpInfo::String(cp_string) => {
                let cp_utf8 = match &class_file.constant_pool[cp_string.string_index as usize] {
                    CpInfo::Utf8(cp_utf8) => cp_utf8,
                    other => panic!("trying to get utf8 of string in cp, instead got: {:#?}", other)
                };

                write_string_to_cp(&mut out_file, &cp_utf8.converted, &hp_reg);
            },
            CpInfo::FieldRef(_) => {
                let descriptor = get_utf8_descriptor_from_field_or_method_or_interface_method_info(&class_file.constant_pool, i as u16);
                let type_char = descriptor.chars().nth(0).unwrap();
                let jvm_type = get_jvm_type_from_descriptor(type_char).unwrap();
                match jvm_type {
                    JvmType::LONG => {
                        write_word_to_cp(&mut out_file, 0, &hp_reg);
                        write_word_to_cp(&mut out_file, 0, &hp_reg);
                    },
                    _ => {
                        write_word_to_cp(&mut out_file, 0, &hp_reg);
                    },
                }
            },
            CpInfo::MethodRef(_) | CpInfo::InterfaceMethodRef(_) | CpInfo::NameAndType(_) | CpInfo::MethodHandle(_) | CpInfo::MethodType(_) | CpInfo::Dynamic(_) | CpInfo::InvokeDynamic(_) | CpInfo::Module(_) | CpInfo::Package(_) => {
                write_word_to_cp(&mut out_file, 0, &hp_reg); // at runtime se ne uporablja
            },
        }
    }

    // klic <clinit> za inicializacijo razrednih spremenljivk
    writeln!(&out_file, "\t\tCALL clinit").unwrap();
    
    // klic main in exit
    writeln!(&out_file, "\t\tCALL _main").unwrap();
    writeln!(&out_file, "\t\tLI a0, 0").unwrap();
    writeln!(&out_file, "\t\tCALL exit").unwrap();
    writeln!(&out_file, "\n").unwrap();

    let mut sorted_method_is: Vec<&usize> = method_i_to_riscv_code.keys().collect();
    sorted_method_is.sort();

    // for (method_i, riscv_code) in method_i_to_riscv_code {
    for method_i in sorted_method_is {
        let riscv_code = &method_i_to_riscv_code[method_i];
        let mut vreg_to_reg_int = None;
        let mut vreg_to_reg_float = None;
        let mut code_info = None;

        if let Some(method_i_to_code_info) = method_i_to_code_info {
            code_info = Some(method_i_to_code_info.get(method_i).unwrap());
            vreg_to_reg_int = Some(&code_info.unwrap().vreg_to_reg_int);
            vreg_to_reg_float = Some(&code_info.unwrap().vreg_to_reg_float);
        }

        let mut saved_temps_size = 0;
        if let Some(code_info) = code_info {
            saved_temps_size = code_info.saved_temps_size;
        }
        

        let method_info = &class_file.methods[*method_i as usize];

        let method_name_utf8 = match &class_file.constant_pool[method_info.name_index as usize] {
            CpInfo::Utf8(cp_utf8) => cp_utf8.converted.clone(),
            other => panic!("asm_write, getting utf8 method name, instead got {:#?}", other)
        };

        let mut function_label = get_function_label(method_name_utf8.clone(), class_name.clone());
        let epilogue_label = get_function_epilogue_label(method_name_utf8.clone(), class_name.clone());

        if method_name_utf8 == "main" {
            function_label = "_main".to_string();
        }

        writeln!(&out_file, ".globl {}", function_label).unwrap();
        writeln!(&out_file, ".type {}, @function", function_label).unwrap();
        writeln!(&out_file, "{}:", function_label).unwrap();
        write_prologue(&mut out_file, saved_temps_size);
        for instr in riscv_code {
            writeln!(&out_file, "\t\t{}", instr.to_string(&vreg_to_reg_int, &vreg_to_reg_float)).unwrap();
        }
        write_epilogue(&mut out_file, epilogue_label);
        // else {
        //     writeln!(&out_file, "{}:", epilogue_label).unwrap();
        //     writeln!(&out_file, "\t\tRET").unwrap();
        // }
        writeln!(&out_file, "\n").unwrap();
    }
}

fn write_string_to_cp(out_file: &mut File, value: &String, hp_reg: &String) {
    if !hp_reg.is_ascii() {
        panic!("found non-ascii string in constant pool: \"{}\"", hp_reg);
    }
    
    write_bytes_to_cp(out_file, &value.bytes().collect(), hp_reg, true);
}

fn write_word_to_cp(out_file: &mut File, word: u32, hp_reg: &String) {
    writeln!(out_file, "\t\tLI t0, {}", word).unwrap();
    writeln!(out_file, "\t\tSW t0, {}({})", WORD_SIZE, hp_reg).unwrap();
    writeln!(out_file, "\t\tADDI {}, {}, {}", hp_reg, hp_reg, WORD_SIZE).unwrap();
}

fn write_bytes_to_cp(out_file: &mut File, bytes: &Vec<u8>, hp_reg: &String, null_terminator: bool) {
    for byte in bytes {
        writeln!(out_file, "\t\tADDI t0, zero, {}", byte).unwrap();
        writeln!(out_file, "\t\tSW t0, {}({})", WORD_SIZE, hp_reg).unwrap();
        writeln!(out_file, "\t\tADDI {}, {}, {}", hp_reg, hp_reg, WORD_SIZE).unwrap();
    }

    if null_terminator {
        writeln!(out_file, "\t\tSW zero, {}({})", WORD_SIZE, hp_reg).unwrap();
        writeln!(out_file, "\t\tADDI {}, {}, {}", hp_reg, hp_reg, WORD_SIZE).unwrap();
    }
}

fn write_prologue(out_file: &mut File, saved_temps_size: u32) {
    // store ra, fp
    writeln!(out_file, "\t\tSW ra, {}(sp)", -i32::from(WORD_SIZE)).unwrap();
    writeln!(out_file, "\t\tSW fp, {}(sp)", -(i32::from(WORD_SIZE) * 2)).unwrap();

    // store temp args
    for i in 0..NUM_TEMP_REGS_INT {
        writeln!(out_file, "\t\tSW t{}, {}(sp)", i, -(i32::from(WORD_SIZE) * (3 + i))).unwrap();
    }
    for i in 0..NUM_TEMP_REGS_FLOAT {
        writeln!(out_file, "\t\tFSW f{}, {}(sp)", i, -(4 * (3 + i + NUM_TEMP_REGS_INT))).unwrap();
    }

    // fp = sp
    writeln!(out_file, "\t\tMV fp, sp").unwrap();

    // add to sp
    writeln!(out_file, "\t\tADDI sp, sp, {}", -(i32::from(WORD_SIZE) * (2 + NUM_TEMP_REGS_INT + NUM_TEMP_REGS_FLOAT)) - saved_temps_size as i32).unwrap();
}

fn write_epilogue(out_file: &mut File, epilogue_label: String) {
    writeln!(out_file, "{}:", epilogue_label).unwrap();

    // sp = fp
    writeln!(out_file, "\t\tMV sp, fp").unwrap();

    // load ra, fp
    writeln!(out_file, "\t\tLW ra, {}(sp)", -i32::from(WORD_SIZE)).unwrap();
    writeln!(out_file, "\t\tLW fp, {}(sp)", -i32::from(WORD_SIZE) * 2).unwrap();

    // load temp args
    for i in 0..NUM_TEMP_REGS_INT {
        writeln!(out_file, "\t\tLW t{}, {}(sp)", i, -(i32::from(WORD_SIZE) * (3 + i))).unwrap();
    }
    for i in 0..NUM_TEMP_REGS_FLOAT {
        writeln!(out_file, "\t\tFLW f{}, {}(sp)", i, -(4 * (3 + i + NUM_TEMP_REGS_INT))).unwrap();
    }

    writeln!(out_file, "\t\tRET").unwrap();
}