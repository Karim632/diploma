use std::{cell::RefCell, collections::{HashMap, HashSet}, error, hash::Hash, mem::replace, rc::Rc};

use crate::{liveness_analysis::analyse, translator::{RiscvInstr, RiscvMnemonic, RiscvReg, RiscvTempReg, WORD_SIZE}};

pub const NUM_TEMP_REGS_INT: i32 = 7;
pub const NUM_TEMP_REGS_FLOAT: i32 = 7;

#[derive(Clone, Copy)]
enum TempRegType {
    INT,
    FLOAT
}

pub struct CodeInfo {
    pub vreg_to_reg_int: HashMap<u32, u32>,
    pub vreg_to_reg_float: HashMap<u32, u32>,

    pub saved_temps_size: u32,
}

pub fn allocate(riscv_code_vregs: &mut Vec<RiscvInstr>, max_locals: u32, max_stack: u32, epilogue_label: String) -> Result<CodeInfo, Box<dyn error::Error>> {
    let mut vreg_to_reg_int = HashMap::new();
    let mut vreg_to_reg_float = HashMap::new();
    let mut saved_temps_size = 0;
    let mut max_vreg = max_locals + max_stack;

    allocate_int_or_float(riscv_code_vregs, TempRegType::INT, &mut saved_temps_size, &mut vreg_to_reg_int, &mut max_vreg, epilogue_label.clone())?;
    allocate_int_or_float(riscv_code_vregs, TempRegType::FLOAT, &mut saved_temps_size, &mut vreg_to_reg_float, &mut max_vreg, epilogue_label)?;

    return Ok(CodeInfo {
        vreg_to_reg_int,
        vreg_to_reg_float,
        saved_temps_size,
    });
}

fn allocate_int_or_float(riscv_code_vregs: &mut Vec<RiscvInstr>, temp_reg_type: TempRegType, saved_temps_size: &mut u32, vreg_to_reg: &mut HashMap<u32, u32>, max_vreg: &mut u32, epilogue_label: String) -> Result<(), Box<dyn error::Error>> {
    let mut start_over = true;
    while start_over {
        let mut graph = ClashGraph::new(riscv_code_vregs, temp_reg_type.clone());

        let mut node_stack = Vec::new();

        while !graph.nodes.is_empty() {
            // simplify
            let mut to_remove = Vec::new();
            for (i, node) in graph.nodes.iter().enumerate() {
                if node.borrow().neighbours.len() < NUM_TEMP_REGS_INT as usize {
                    to_remove.push(i);
                    node_stack.push(node.clone());
                }
            }
            for i in to_remove.into_iter().rev() {
                graph.nodes.swap_remove(i);
            }

            // Spill
            if !graph.nodes.is_empty() {
                let node_to_mark = &graph.nodes.pop().unwrap();
                node_to_mark.borrow_mut().potential_spill = true;
                node_stack.push(node_to_mark.clone());
            }
        }

        // Select
        let mut spilled_vregs = HashSet::new();
        for node in node_stack.iter() {
            let mut neighbour_colors = HashSet::new();
            for neighbour in node.borrow().neighbours.iter() {
                let color = neighbour.borrow().color;
                if color > -1 {
                    neighbour_colors.insert(color);
                }
            }

            let mut new_color = 0;
            while neighbour_colors.contains(&new_color) {
                new_color += 1;
            }

            let num_regs = match temp_reg_type {
                TempRegType::INT => NUM_TEMP_REGS_INT,
                TempRegType::FLOAT => NUM_TEMP_REGS_FLOAT,
            };

            if new_color >= num_regs {
                // Zmanjkalo barv, potrdi spill
                if node.borrow().potential_spill {
                    spilled_vregs.insert(node.borrow().vreg);
                }
                else {
                    panic!("ran out of colors but node wasn't marked as potential_spill");
                }
            }
            else {
                node.borrow_mut().color = new_color;
            }
        }

        if !spilled_vregs.is_empty() {
            for spilled_vreg in spilled_vregs {
                *saved_temps_size += u32::from(WORD_SIZE);

                // old FP, RA, shranjeni temps od prejšnje funkcije, do zdaj shranjeni temps trenutne funkcije  
                let fp_offset = -(i32::from(WORD_SIZE) * 2) - (NUM_TEMP_REGS_INT + NUM_TEMP_REGS_FLOAT) * i32::from(WORD_SIZE) - *saved_temps_size as i32;

                let mut i = 0;
                while i < riscv_code_vregs.len() {
                    let instr = &mut riscv_code_vregs[i];

                    let (uses, defs) = match temp_reg_type {
                        TempRegType::INT => (&mut instr.uses_int, &mut instr.defs_int),
                        TempRegType::FLOAT => (&mut instr.uses_float, &mut instr.defs_float),
                    };

                    let in_uses = uses.contains(&spilled_vreg);
                    let in_defs = defs.contains(&spilled_vreg);

                    if in_uses || in_defs {
                        // replace spilled vreg
                        *max_vreg += 1;
                        let new_vreg = *max_vreg;

                        let mut replacement_rd  = instr.rd;
                        let mut replacement_rs1 = instr.rs1;
                        let mut replacement_rs2 = instr.rs2;
                        let replacement_imm = instr.imm;
                        let replacement_mnemonic = instr.mnemonic;
                        let replacement_label = instr.label.clone();
                        let replacement_jumps = Some(instr.jumps.clone());
                        match temp_reg_type {
                            TempRegType::INT => {
                                match instr.rd {
                                    Some(RiscvReg::TEMP(RiscvTempReg::INT(some_rd))) => {
                                        if some_rd == spilled_vreg {
                                            replacement_rd = Some(RiscvReg::TEMP(RiscvTempReg::INT(new_vreg)));
                                        }
                                    },
                                    _ => (),
                                }

                                match instr.rs1 {
                                    Some(RiscvReg::TEMP(RiscvTempReg::INT(some_rs1))) => {
                                        if some_rs1 == spilled_vreg {
                                            replacement_rs1 = Some(RiscvReg::TEMP(RiscvTempReg::INT(new_vreg)));
                                        }
                                    },
                                    _ => (),
                                }

                                match instr.rs2 {
                                    Some(RiscvReg::TEMP(RiscvTempReg::INT(some_rs2))) => {
                                        if some_rs2 == spilled_vreg {
                                            replacement_rs2 = Some(RiscvReg::TEMP(RiscvTempReg::INT(new_vreg)));
                                        }
                                    },
                                    _ => (),
                                }
                            },
                            TempRegType::FLOAT => {
                                match instr.rd {
                                    Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(some_rd))) => {
                                        if some_rd == spilled_vreg {
                                            replacement_rd = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(new_vreg)));
                                        }
                                    },
                                    _ => (),
                                }

                                match instr.rs1 {
                                    Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(some_rs1))) => {
                                        if some_rs1 == spilled_vreg {
                                            replacement_rs1 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(new_vreg)));
                                        }
                                    },
                                    _ => (),
                                }

                                match instr.rs2 {
                                    Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(some_rs2))) => {
                                        if some_rs2 == spilled_vreg {
                                            replacement_rs2 = Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(new_vreg)));
                                        }
                                    },
                                    _ => (),
                                }
                            },
                        }

                        let replacement_instr = RiscvInstr::new(replacement_rd, replacement_rs1, replacement_rs2, replacement_imm, replacement_mnemonic, replacement_label, replacement_jumps)?;
                        
                        let _ = replace(&mut riscv_code_vregs[i], replacement_instr);

                        // add load or store
                        let new_instr;
                        let new_instr_i;
                        if in_uses {
                            // load in before use
                            let rs1 = Some(RiscvReg::FP);
                            let rs2 = None;
                            let imm = Some(fp_offset);
                            let (rd, mnemonic) = match temp_reg_type {
                                TempRegType::INT => (Some(RiscvReg::TEMP(RiscvTempReg::INT(new_vreg))), RiscvMnemonic::LW),
                                TempRegType::FLOAT => (Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(new_vreg))), RiscvMnemonic::FLW),
                            };

                            new_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?;
                            new_instr_i = i;
                        }
                        else {
                            // store after def
                            let rd = None;
                            let rs2 = Some(RiscvReg::FP);
                            let imm = Some(fp_offset);
                            let (rs1, mnemonic) = match temp_reg_type {
                                TempRegType::INT => (Some(RiscvReg::TEMP(RiscvTempReg::INT(new_vreg))), RiscvMnemonic::SW),
                                TempRegType::FLOAT => (Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(new_vreg))), RiscvMnemonic::FSW),
                            };

                            new_instr = RiscvInstr::new(rd, rs1, rs2, imm, mnemonic, None, None)?;
                            new_instr_i = i + 1;
                        }

                        riscv_code_vregs.insert(new_instr_i, new_instr);

                        i += 1;
                    }

                    i += 1;
                }
            }

            // redo liveness analysis
            analyse(riscv_code_vregs, epilogue_label.clone());
        }
        else {
            // done
            start_over = false;
            for node in graph.original_nodes {
                vreg_to_reg.insert(node.borrow().vreg, node.borrow().color as u32);
            }
        }
    }

    return Ok(());
}

#[derive(PartialEq, Eq)]
pub struct ClashNode {
    pub neighbours: Vec<Rc<RefCell<ClashNode>>>,
    pub vreg: u32,
    pub color: i32,
    pub potential_spill: bool
}

impl ClashNode {
    fn new(vreg: u32) -> Rc<RefCell<ClashNode>> {
        return Rc::new(RefCell::new(ClashNode {
            neighbours: Vec::new(),
            vreg,
            color: -1,
            potential_spill: false,
        }));
    }
}

pub struct ClashGraph {
    pub nodes: Vec<Rc<RefCell<ClashNode>>>,
    pub original_nodes: Vec<Rc<RefCell<ClashNode>>>,
    pub vreg_to_node: HashMap<u32, Rc<RefCell<ClashNode>>>
}

impl ClashGraph {
    fn new(riscv_code_vregs: &Vec<RiscvInstr>, temp_reg_type: TempRegType) -> ClashGraph {
        let mut nodes = Vec::new();
        let mut original_nodes = Vec::new();
        let mut vreg_to_node = HashMap::new();

        for instr in riscv_code_vregs {
            let (live_in, live_out) = match temp_reg_type {
                TempRegType::INT => {
                    (&instr.live_in_int, &instr.live_out_int)
                },
                TempRegType::FLOAT => {
                    (&instr.live_in_float, &instr.live_out_float)
                },
            };

            for vreg in [instr.rd, instr.rs1, instr.rs2] {
                match temp_reg_type {
                    TempRegType::INT => {
                        if let Some(RiscvReg::TEMP(RiscvTempReg::INT(some_vreg))) = vreg {
                            get_or_add_node(some_vreg, &mut nodes, &mut original_nodes, &mut vreg_to_node);
                        }
                    },
                    TempRegType::FLOAT => {
                        if let Some(RiscvReg::TEMP(RiscvTempReg::FLOAT(some_vreg))) = vreg {
                            get_or_add_node(some_vreg, &mut nodes, &mut original_nodes, &mut vreg_to_node);
                        }
                    },
                }
            }

            let mut in_and_out_vregs: HashSet<u32> = HashSet::new();

            in_and_out_vregs.extend(live_in.iter());
            in_and_out_vregs.extend(live_out.iter());

            let in_and_out_vregs: Vec<u32> = in_and_out_vregs.into_iter().collect();
            // let mut mut_borrowed_neighbours = Vec::new();
            // for vreg in &in_and_out_vregs {
            //     let node = get_or_add_node(*vreg, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //     let neighbours = &mut node.borrow_mut().neighbours;
            //     // mut_borrowed_neighbours.push(neighbours);
            // }

            for i in 0..in_and_out_vregs.len() {
                let vreg1 = in_and_out_vregs[i];
                let node1 = get_or_add_node(vreg1, &mut nodes, &mut original_nodes, &mut vreg_to_node);
                let neighbours1 = &mut node1.borrow_mut().neighbours;
                
                for j in 0..in_and_out_vregs.len() {
                    let vreg2 = in_and_out_vregs[j];
                    if vreg1 == vreg2 {
                        continue;
                    }
                    
                    let node2 = get_or_add_node(vreg2, &mut nodes, &mut original_nodes, &mut vreg_to_node);
                    let mut contains = false;
                    for neighbour in neighbours1.iter() {
                        if neighbour.borrow().vreg == node2.borrow().vreg {
                            contains = true;
                            break;
                        }
                    }
                    if !contains {
                        neighbours1.push(node2.clone());
                    }
                }
            }

            // for vreg1 in live_in.iter() {
            //     get_or_add_node(*vreg1, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //     for vreg2 in live_in.iter() {
            //         if *vreg1 != *vreg2 {
            //             add_neighbour_vregs(*vreg1, *vreg2, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //         }
            //     }
            // }

            // for vreg1 in live_out.iter() {
            //     get_or_add_node(*vreg1, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //     for vreg2 in live_out.iter() {
            //         if *vreg1 != *vreg2 {
            //             add_neighbour_vregs(*vreg1, *vreg2, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //         }
            //     }
            // }

            // for vreg1 in live_in.iter() {
            //     get_or_add_node(*vreg1, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //     for vreg2 in live_out.iter() {
            //         if *vreg1 != *vreg2 {
            //             add_neighbour_vregs(*vreg1, *vreg2, &mut nodes, &mut original_nodes, &mut vreg_to_node);
            //         }
            //     }
            // }
        }

        return ClashGraph {
            nodes,
            original_nodes,
            vreg_to_node,
        }
    }
}

fn get_or_add_node(vreg: u32, nodes: &mut Vec<Rc<RefCell<ClashNode>>>, original_nodes: &mut Vec<Rc<RefCell<ClashNode>>>, vreg_to_node: &mut HashMap<u32, Rc<RefCell<ClashNode>>>) -> Rc<RefCell<ClashNode>> {
    let node = vreg_to_node.get(&vreg);
    match node {
        Some(some_node) => return some_node.clone(),
        None => {
            let new_node = ClashNode::new(vreg);
            vreg_to_node.insert(vreg, new_node.clone());
            original_nodes.push(new_node.clone());
            nodes.push(new_node.clone());

            return new_node;
        }
    }
}

// fn add_neighbour_vregs(node1: Rc<RefCell<ClashNode>>, node2: Rc<RefCell<ClashNode>>, nodes: &mut Vec<Rc<RefCell<ClashNode>>>, original_nodes: &mut Vec<Rc<RefCell<ClashNode>>>, vreg_to_node: &mut HashMap<u32, Rc<RefCell<ClashNode>>>) {
//     // let node1 = get_or_add_node(vreg1, nodes, original_nodes, vreg_to_node);
//     // let node2 = get_or_add_node(vreg2, nodes, original_nodes, vreg_to_node);

//     // let node1_neighbours = match vreg_to_neighburs.get(&node1.borrow().vreg) {
//     //     Some(neighbours) => neighbours,
//     //     None => {
//     //         let neighbours = node1.borrow_mut().neighbours.as_mut_ptr();
//     //         vreg_to_neighburs.insert(node1.borrow().vreg, neighbours);
            
//     //         &neighbours
//     //     },
//     // };

//     // let node2_neighbours = match vreg_to_neighburs.get(&node2.borrow().vreg) {
//     //     Some(neighbours) => neighbours,
//     //     None => {
//     //         let neighbours = &node2.borrow_mut().neighbours;
//     //         vreg_to_neighburs.insert(node2.borrow().vreg, &mut neighbours);

//     //         neighbours
//     //     },
//     // };

//     let node1_neighbours = &mut node1.borrow_mut().neighbours;
//     let node2_neighbours = &mut node2.borrow_mut().neighbours;

//     if !node1_neighbours.contains(&node2) {
//         node1_neighbours.push(node2.clone());
//     }

//     if !node2_neighbours.contains(&node1) {
//         node2_neighbours.push(node1.clone());
//     }
// }