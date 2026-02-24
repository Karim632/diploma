use std::collections::{HashMap, HashSet};

use crate::translator::{RiscvInstr, RiscvMnemonic, RiscvReg};

fn is_function_call(instr: &RiscvInstr) -> bool {
    return instr.mnemonic == RiscvMnemonic::JAL && instr.rd == Some(RiscvReg::RA);
}

pub fn analyse(code: &mut Vec<RiscvInstr>, epilogue_label: String) {
    let mut prev_sizes_in_int = vec![0; code.len()];
    let mut prev_sizes_in_float = vec![0; code.len()];
    let mut prev_sizes_out_int = vec![0; code.len()];
    let mut prev_sizes_out_float = vec![0; code.len()];

    let mut label_to_instr = HashMap::new();

    for instr in code.iter_mut() {

        // če se med register allocationom zgodi spill, se liveness analysis ponovi
        // zato je pred začetkov treba sprazniti in in out
        instr.live_in_int.clear();
        instr.live_in_float.clear();
        instr.live_out_int.clear();
        instr.live_out_float.clear();
        

        instr.live_in_int.extend(&instr.uses_int);
        instr.live_in_float.extend(&instr.uses_float);

        prev_sizes_in_int.push(instr.live_in_int.len());
        prev_sizes_in_float.push(instr.live_in_int.len());

        if let Some(label) = &instr.label {
            label_to_instr.insert(label.clone(), instr.clone());
        }
    }

    let code_len = code.len();
    let mut converged = false;
    while !converged {
        converged = true;

        let mut prev_instr: Option<&mut RiscvInstr> = None;
        for (i, instr) in code.iter_mut().enumerate() {
            let out_minus_def_int = instr.live_out_int.difference(&instr.defs_int);
            instr.live_in_int.extend(out_minus_def_int);

            let out_minus_def_float = instr.live_out_float.difference(&instr.defs_float);
            instr.live_in_float.extend(out_minus_def_float);

            if i < code_len {
                if let Some(some_prev_instr) = prev_instr {
                    some_prev_instr.live_out_int.extend(&instr.live_in_int);
                    some_prev_instr.live_out_float.extend(&instr.live_in_float);
                }

                if !is_function_call(instr) {
                    for jump_label in &instr.jumps {
                        match label_to_instr.get(jump_label) {
                            Some(jump_target_instr) => {
                                instr.live_out_int.extend(&jump_target_instr.live_in_int);
                                instr.live_out_float.extend(&jump_target_instr.live_in_float);
                            },
                            None => {
                                if *jump_label != epilogue_label {
                                    panic!("at liveness analasys, jump label '{}' not found in label_to_instr and it isnt the epilogue label '{}'", jump_label, epilogue_label)
                                }
                            },
                        }
                    }
                }
            }

            converged = converged && instr.live_in_int.len() == prev_sizes_in_int[i] && instr.live_out_int.len() == prev_sizes_out_int[i] && instr.live_in_float.len() == prev_sizes_in_float[i] && instr.live_out_float.len() == prev_sizes_out_float[i];

            prev_instr = Some(instr);
        }

        for i in 0..code.len() {
            prev_sizes_in_int[i] = code[i].live_in_int.len();
            prev_sizes_out_int[i] = code[i].live_out_int.len();

            prev_sizes_in_float[i] = code[i].live_in_float.len();
            prev_sizes_out_float[i] = code[i].live_out_float.len();
        }
    }
}