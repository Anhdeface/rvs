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

                let gate_type = classify_gate_type(&branch_inst);

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

/// Classifies branch instruction into standard decision gate types.
/// Supports both x86/x86_64 mnemonics and AArch64 conditional branches:
/// b.eq, b.ne, b.cs, b.cc, b.mi, b.pl, b.vs, b.vc, b.hi, b.ls, b.ge, b.lt, b.gt, b.le, cbz, cbnz, tbz, tbnz.
pub fn classify_gate_type(branch_inst: &str) -> Option<String> {
    let lower = branch_inst.to_lowercase();
    let mnemonic = lower.split_whitespace().next().unwrap_or("");

    if mnemonic.starts_with("je")
        || mnemonic.starts_with("jz")
        || mnemonic == "b.eq"
        || mnemonic == "cbz"
        || mnemonic == "tbz"
    {
        Some("equality_zero_check".to_string())
    } else if mnemonic.starts_with("jne")
        || mnemonic.starts_with("jnz")
        || mnemonic == "b.ne"
        || mnemonic == "cbnz"
        || mnemonic == "tbnz"
    {
        Some("inequality_nonzero_check".to_string())
    } else if mnemonic.starts_with("jg")
        || mnemonic.starts_with("ja")
        || mnemonic == "b.gt"
        || mnemonic == "b.hi"
        || mnemonic == "b.ge"
        || mnemonic == "b.pl"
    {
        Some("greater_check".to_string())
    } else if mnemonic.starts_with("jl")
        || mnemonic.starts_with("jb")
        || mnemonic == "b.lt"
        || mnemonic == "b.lo"
        || mnemonic == "b.le"
        || mnemonic == "b.ls"
        || mnemonic == "b.cc"
        || mnemonic == "b.mi"
    {
        Some("less_check".to_string())
    } else {
        Some("conditional_branch".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_gate_type_aarch64_branches() {
        assert_eq!(classify_gate_type("b.eq 0x1000").as_deref(), Some("equality_zero_check"));
        assert_eq!(classify_gate_type("cbz w0, 0x1000").as_deref(), Some("equality_zero_check"));
        assert_eq!(classify_gate_type("tbz w0, #0, 0x1000").as_deref(), Some("equality_zero_check"));

        assert_eq!(classify_gate_type("b.ne 0x1000").as_deref(), Some("inequality_nonzero_check"));
        assert_eq!(classify_gate_type("cbnz w0, 0x1000").as_deref(), Some("inequality_nonzero_check"));
        assert_eq!(classify_gate_type("tbnz w0, #1, 0x1000").as_deref(), Some("inequality_nonzero_check"));

        assert_eq!(classify_gate_type("b.gt 0x1000").as_deref(), Some("greater_check"));
        assert_eq!(classify_gate_type("b.ge 0x1000").as_deref(), Some("greater_check"));
        assert_eq!(classify_gate_type("b.hi 0x1000").as_deref(), Some("greater_check"));
        assert_eq!(classify_gate_type("b.pl 0x1000").as_deref(), Some("greater_check"));

        assert_eq!(classify_gate_type("b.lt 0x1000").as_deref(), Some("less_check"));
        assert_eq!(classify_gate_type("b.le 0x1000").as_deref(), Some("less_check"));
        assert_eq!(classify_gate_type("b.lo 0x1000").as_deref(), Some("less_check"));
        assert_eq!(classify_gate_type("b.ls 0x1000").as_deref(), Some("less_check"));
        assert_eq!(classify_gate_type("b.cc 0x1000").as_deref(), Some("less_check"));
        assert_eq!(classify_gate_type("b.mi 0x1000").as_deref(), Some("less_check"));

        assert_eq!(classify_gate_type("b.cs 0x1000").as_deref(), Some("conditional_branch"));
        assert_eq!(classify_gate_type("b.vs 0x1000").as_deref(), Some("conditional_branch"));
        assert_eq!(classify_gate_type("b.vc 0x1000").as_deref(), Some("conditional_branch"));
    }

    #[test]
    fn test_classify_gate_type_x86_branches_preserved() {
        assert_eq!(classify_gate_type("je 0x1000").as_deref(), Some("equality_zero_check"));
        assert_eq!(classify_gate_type("jz 0x1000").as_deref(), Some("equality_zero_check"));
        assert_eq!(classify_gate_type("jne 0x1000").as_deref(), Some("inequality_nonzero_check"));
        assert_eq!(classify_gate_type("jnz 0x1000").as_deref(), Some("inequality_nonzero_check"));
        assert_eq!(classify_gate_type("jg 0x1000").as_deref(), Some("greater_check"));
        assert_eq!(classify_gate_type("ja 0x1000").as_deref(), Some("greater_check"));
        assert_eq!(classify_gate_type("jl 0x1000").as_deref(), Some("less_check"));
        assert_eq!(classify_gate_type("jb 0x1000").as_deref(), Some("less_check"));
    }

    #[test]
    fn test_aarch64_flow_fixture_gates() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_aarch64_lib.so");
        if fixture.exists() {
            let driver = R2Driver::new(&fixture, None, None, true).expect("Failed to create driver");
            
            // 1. auth_gate_check contains b.ne
            let flow_auth = run_flow(&driver, "auth_gate_check").expect("flow auth_gate_check failed");
            assert!(!flow_auth.decision_nodes.is_empty());
            let node0 = &flow_auth.decision_nodes[0];
            assert_eq!(node0.gate_type.as_deref(), Some("inequality_nonzero_check"));

            // 2. check_zero_and_call contains cbz & cbnz
            let flow_zero = run_flow(&driver, "check_zero_and_call").expect("flow check_zero_and_call failed");
            assert!(flow_zero.decision_nodes.len() >= 2);
            assert!(flow_zero.decision_nodes.iter().any(|n| n.gate_type.as_deref() == Some("equality_zero_check")));
            assert!(flow_zero.decision_nodes.iter().any(|n| n.gate_type.as_deref() == Some("inequality_nonzero_check")));

            // 3. check_bit_flags contains tbz & tbnz
            let flow_bit = run_flow(&driver, "check_bit_flags").expect("flow check_bit_flags failed");
            assert!(flow_bit.decision_nodes.len() >= 2);
            assert!(flow_bit.decision_nodes.iter().any(|n| n.gate_type.as_deref() == Some("equality_zero_check")));
            assert!(flow_bit.decision_nodes.iter().any(|n| n.gate_type.as_deref() == Some("inequality_nonzero_check")));
        }
    }
}
