use serde::{Deserialize, Serialize};
use crate::analysis;
use crate::error::AppError;
use crate::r2::R2Driver;

/// Payload for `agent flow` command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentFlowData {
    pub function_name: String,
    pub function_addr: u64,
    pub function_addr_hex: String,
    pub total_blocks: usize,
    pub decision_nodes: Vec<BranchGateNode>,
    pub exit_nodes: Vec<u64>,
    pub loop_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BranchGateNode {
    pub addr: u64,
    pub addr_hex: String,
    pub condition_instruction: String,
    pub branch_instruction: String,
    pub jump_target: u64,
    pub jump_target_hex: String,
    pub fail_target: u64,
    pub fail_target_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_type: Option<String>,
}

pub fn run_flow(driver: &R2Driver, function: &str) -> Result<AgentFlowData, AppError> {
    let target_addr = match driver.resolve_address(function) {
        Ok(addr) => addr,
        Err(AppError::InvalidArgument(e)) => return Err(AppError::InvalidArgument(e)),
        Err(AppError::Timeout(e)) => return Err(AppError::Timeout(e)),
        Err(_) => return Err(AppError::SymbolNotFound(function.to_string())),
    };

    // Analyze basic blocks
    let blocks_resp = match analysis::analyze_blocks(driver, function, true) {
        Ok(b) => b,
        Err(_) => analysis::analyze_blocks(driver, &format!("0x{:x}", target_addr), true)?,
    };

    let function_name = if blocks_resp.function_name.is_empty() {
        function.to_string()
    } else {
        blocks_resp.function_name
    };
    let function_addr = blocks_resp.function_addr;
    let total_blocks = blocks_resp.blocks.len();

    let mut decision_nodes = Vec::new();
    let mut exit_nodes = Vec::new();
    let mut loop_count = 0;

    for b in &blocks_resp.blocks {
        match (b.jump, b.fail) {
            (Some(jump_target), Some(fail_target)) => {
                // Conditional branch decision gate
                let mut condition_inst = String::new();
                let mut branch_inst = String::new();
                let mut branch_addr = b.addr;

                if !b.instructions.is_empty() {
                    let last_idx = b.instructions.len() - 1;
                    let last_inst = &b.instructions[last_idx];
                    branch_inst = last_inst.opcode.clone();
                    branch_addr = last_inst.addr;

                    if b.instructions.len() >= 2 {
                        let cond_inst = &b.instructions[last_idx - 1];
                        condition_inst = cond_inst.opcode.clone();
                    } else {
                        condition_inst = "implicit".to_string();
                    }
                }

                if branch_inst.is_empty() {
                    branch_inst = format!("branch 0x{:x}", jump_target);
                }
                if condition_inst.is_empty() {
                    condition_inst = "flags_eval".to_string();
                }

                // Check for loops (back-edges)
                if jump_target <= b.addr || fail_target <= b.addr {
                    loop_count += 1;
                }

                let gate_type = if branch_inst.starts_with("je") || branch_inst.starts_with("jz") {
                    Some("equality_zero_check".to_string())
                } else if branch_inst.starts_with("jne") || branch_inst.starts_with("jnz") {
                    Some("inequality_nonzero_check".to_string())
                } else if branch_inst.starts_with("jg") || branch_inst.starts_with("ja") {
                    Some("greater_check".to_string())
                } else if branch_inst.starts_with("jl") || branch_inst.starts_with("jb") {
                    Some("less_check".to_string())
                } else {
                    Some("conditional_branch".to_string())
                };

                decision_nodes.push(BranchGateNode {
                    addr: branch_addr,
                    addr_hex: format!("0x{:x}", branch_addr),
                    condition_instruction: condition_inst,
                    branch_instruction: branch_inst,
                    jump_target,
                    jump_target_hex: format!("0x{:x}", jump_target),
                    fail_target,
                    fail_target_hex: format!("0x{:x}", fail_target),
                    gate_type,
                });
            }
            (None, None) => {
                exit_nodes.push(b.addr);
            }
            (Some(jump_target), None) => {
                if jump_target <= b.addr {
                    loop_count += 1;
                }
            }
            (None, Some(_)) => {}
        }
    }

    Ok(AgentFlowData {
        function_name,
        function_addr,
        function_addr_hex: format!("0x{:x}", function_addr),
        total_blocks,
        decision_nodes,
        exit_nodes,
        loop_count,
    })
}
