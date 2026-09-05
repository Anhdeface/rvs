use serde::{Deserialize, Serialize};
use crate::agent::flow::{run_flow, AgentFlowData};
use crate::analysis::dynamic::{analyze_emulate, EmulateOptions, RegisterDiff, ReturnValueInfo};
use crate::error::AppError;
use crate::r2::R2Driver;

/// AI-agent composite representation of dynamic emulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentEmulateData {
    pub function_name: String,
    pub start_addr_hex: String,
    pub final_addr_hex: String,
    pub steps_executed: usize,
    pub stop_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<ReturnValueInfo>,
    pub key_registers_changed: Vec<RegisterDiff>,
    pub branches_encountered: Vec<AgentBranchOutcome>,
    pub agent_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentBranchOutcome {
    pub gate_addr_hex: String,
    pub condition_instruction: String,
    pub branch_instruction: String,
    pub taken: bool,
    pub target_addr_hex: String,
}

/// Executes AI-optimized dynamic function emulation and decision gate analysis.
pub fn run_agent_emulate(
    driver: &R2Driver,
    target: &str,
    steps: usize,
    until: Option<String>,
    reg_set: Vec<String>,
    read_mem: Option<String>,
    mem_len: usize,
) -> Result<AgentEmulateData, AppError> {
    let opts = EmulateOptions {
        target: target.to_string(),
        steps: if steps == 0 { 100 } else { steps },
        until: until.clone(),
        reg_set,
        read_mem,
        mem_len,
        include_initial_regs: false,
    };

    let emu_resp = analyze_emulate(driver, &opts)?;

    // Attempt to enrich with flow decision gates if target is a known function
    let flow_info: Option<AgentFlowData> = run_flow(driver, target).ok();

    let mut branches = Vec::new();
    if let Some(flow) = flow_info {
        for gate in flow.decision_nodes {
            // Check if final or intermediate execution reached this branch gate
            let _gate_addr = gate.addr;
            let final_addr = emu_resp.final_addr;

            // If final address matches jump target or fail target
            if final_addr == gate.jump_target {
                branches.push(AgentBranchOutcome {
                    gate_addr_hex: gate.addr_hex,
                    condition_instruction: gate.condition_instruction,
                    branch_instruction: gate.branch_instruction,
                    taken: true,
                    target_addr_hex: gate.jump_target_hex,
                });
            } else if final_addr == gate.fail_target {
                branches.push(AgentBranchOutcome {
                    gate_addr_hex: gate.addr_hex,
                    condition_instruction: gate.condition_instruction,
                    branch_instruction: gate.branch_instruction,
                    taken: false,
                    target_addr_hex: gate.fail_target_hex,
                });
            }
        }
    }

    // Compose concise natural language agent summary
    let mut summary = format!(
        "Emulated target '{}' from {} to {} in {} steps ({})",
        emu_resp.target, emu_resp.start_addr_hex, emu_resp.final_addr_hex, emu_resp.steps_executed, emu_resp.stop_reason
    );

    if let Some(ref ret) = emu_resp.return_value {
        summary.push_str(&format!(". Return register {} = {}", ret.reg.to_uppercase(), ret.value_hex));
    }

    if !branches.is_empty() {
        summary.push_str(&format!(". Resolved {} conditional branch decision(s)", branches.len()));
    }

    Ok(AgentEmulateData {
        function_name: target.to_string(),
        start_addr_hex: emu_resp.start_addr_hex,
        final_addr_hex: emu_resp.final_addr_hex,
        steps_executed: emu_resp.steps_executed,
        stop_reason: emu_resp.stop_reason,
        return_value: emu_resp.return_value,
        key_registers_changed: emu_resp.register_diff,
        branches_encountered: branches,
        agent_summary: summary,
    })
}
