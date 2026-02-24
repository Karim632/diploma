use std::{collections::HashMap, fs::write, path::{Path, PathBuf}};

use crate::{class_parser::{AttributeInfo, CpInfo}, register_allocation::CodeInfo, translator::{get_class_name_utf8, get_function_epilogue_label}};

pub mod class_parser;
pub mod util;
pub mod translator;
pub mod liveness_analysis;
pub mod register_allocation;
pub mod asm_writer;

fn main() {
    let class_file = match class_parser::parse_class_file("Test1.class") {
        Ok(result) => result,
        Err(err) => panic!("{}", err),
    };

    let class_name = get_class_name_utf8(&class_file);

    let mut method_i_to_riscv_code_vregs = match translator::to_riscv_vregs(&class_file) {
        Ok(result) => result,
        Err(err) => panic!("{}", err),
    };

    let mut method_i_to_epilogue_label = HashMap::new();
    let mut method_i_to_max_locals = HashMap::new();
    let mut method_i_to_max_stack = HashMap::new();

    for (i, mut riscv_code_vregs) in method_i_to_riscv_code_vregs.iter_mut() {
        let method_info = &class_file.methods[*i as usize];
        
        let method_name_utf8 = match &class_file.constant_pool[method_info.name_index as usize] {
            CpInfo::Utf8(cp_utf8) => cp_utf8.converted.clone(),
            other => panic!("in main, getting utf8 method name, instead got {:#?}", other)
        };

        let epilogue_label = get_function_epilogue_label(method_name_utf8, class_name.clone());

        for attribute in method_info.attributes.iter() {
            if let AttributeInfo::Code(code_info) = attribute {
                method_i_to_epilogue_label.insert(*i, epilogue_label.clone());
                method_i_to_max_locals.insert(*i, code_info.max_locals);
                method_i_to_max_stack.insert(*i, code_info.max_stack);

                break;
            }
        }

        liveness_analysis::analyse(&mut riscv_code_vregs, epilogue_label);
    }

    let mut method_i_to_code_info = HashMap::new();

    asm_writer::asm_write("outvregs.s".to_string(), &class_file, &method_i_to_riscv_code_vregs, None);

    for (i, mut riscv_code_vregs) in method_i_to_riscv_code_vregs.iter_mut() {
        let max_locals = *method_i_to_max_locals.get(i).unwrap();
        let max_stack = *method_i_to_max_stack.get(i).unwrap();
        let epilogue_label = method_i_to_epilogue_label.get(i).unwrap();

        match register_allocation::allocate(&mut riscv_code_vregs, max_locals.into(), max_stack.into(), epilogue_label.clone()) {
            Ok(code_info) => {
                method_i_to_code_info.insert(*i, code_info);
            },
            Err(err) => panic!("{}", err),
        };
    }
    
    asm_writer::asm_write("out.s".to_string(), &class_file, &method_i_to_riscv_code_vregs, Some(&method_i_to_code_info));
}
