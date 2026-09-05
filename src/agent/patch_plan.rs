use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::error::AppError;
use crate::patch::{self, verify::create_backup};
use crate::r2::R2Driver;

/// Schema for `agent patch-plan` inputs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchPlan {
    pub name: String,
    #[serde(default)]
    pub dry_run: bool,
    pub steps: Vec<PatchPlanStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchPlanStep {
    #[serde(rename = "type")]
    pub step_type: String, // "instruction", "string", "bytes", "nop"
    pub addr: String,
    #[serde(default)]
    pub assembly: Option<String>,
    #[serde(default)]
    pub new_string: Option<String>,
    #[serde(default)]
    pub hex: Option<String>,
    #[serde(default)]
    pub count: Option<usize>,
}

/// Payload for `agent patch-plan` command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentPatchPlanResult {
    pub plan_name: String,
    pub applied: bool,
    pub dry_run: bool,
    pub total_steps: usize,
    pub steps_executed: usize,
    pub step_results: Vec<PatchStepResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchStepResult {
    pub step_index: usize,
    pub step_type: String,
    pub addr: u64,
    pub addr_hex: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patched_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub fn run_patch_plan(driver: &R2Driver, plan_str: &str) -> Result<AgentPatchPlanResult, AppError> {
    // 1. Read JSON from file or string literal
    let raw_json = if Path::new(plan_str).exists() {
        std::fs::read_to_string(plan_str)?
    } else {
        plan_str.to_string()
    };

    let plan: PatchPlan = serde_json::from_str(&raw_json)
        .map_err(|e| AppError::PatchPlanError(format!("Malformed patch plan JSON: {e}")))?;

    // 2. Validate step constraints
    for (idx, step) in plan.steps.iter().enumerate() {
        if step.addr.trim().is_empty() {
            return Err(AppError::PatchPlanError(format!(
                "Step {idx} missing required field 'addr'"
            )));
        }

        match step.step_type.to_lowercase().as_str() {
            "instruction" => {
                let asm = step.assembly.as_ref().ok_or_else(|| {
                    AppError::PatchPlanError(format!(
                        "Step {idx} of type 'instruction' missing required field 'assembly'"
                    ))
                })?;
                crate::patch::validate_assembly(asm)?;
            }
            "bytes" => {
                if step.hex.is_none() {
                    return Err(AppError::PatchPlanError(format!(
                        "Step {idx} of type 'bytes' missing required field 'hex'"
                    )));
                }
            }
            "string" => {
                if step.new_string.is_none() {
                    return Err(AppError::PatchPlanError(format!(
                        "Step {idx} of type 'string' missing required field 'new_string'"
                    )));
                }
            }
            "nop" => {}
            other => {
                return Err(AppError::PatchPlanError(format!(
                    "Unknown step type '{other}' in step {idx}"
                )));
            }
        }
    }

    let total_steps = plan.steps.len();

    // 3. Execution / Simulation
    if plan.dry_run {
        let mut step_results = Vec::with_capacity(total_steps);

        for (idx, step) in plan.steps.iter().enumerate() {
            let addr_num = driver.resolve_address(&step.addr)?;
            let addr_hex = format!("0x{:x}", addr_num);

            match step.step_type.to_lowercase().as_str() {
                "instruction" => {
                    let asm = step.assembly.as_ref().ok_or_else(|| {
                        AppError::PatchPlanError(format!(
                            "Step {idx} of type 'instruction' missing required field 'assembly'"
                        ))
                    })?;
                    let asm_hex = driver
                        .cmd(&format!("s {addr_num}; pa {asm}"))?
                        .trim()
                        .to_string();
                    if asm_hex.is_empty() {
                        return Err(AppError::AssemblyFailed {
                            instruction: asm.clone(),
                            details: "Assembler returned empty machine code".to_string(),
                        });
                    }
                    let byte_count = asm_hex.len() / 2;
                    let orig_bytes = driver.read_bytes_hex(&addr_hex, byte_count).unwrap_or_default();

                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(orig_bytes),
                        patched_bytes: Some(asm_hex),
                        message: Some("Dry run simulation successful".to_string()),
                    });
                }
                "bytes" => {
                    let h = step.hex.as_ref().ok_or_else(|| {
                        AppError::PatchPlanError(format!(
                            "Step {idx} of type 'bytes' missing required field 'hex'"
                        ))
                    })?;
                    let clean_hex = h.trim().trim_start_matches("0x").replace(' ', "");
                    if clean_hex.len() % 2 != 0 || !clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(AppError::InvalidHexString {
                            hex: h.clone(),
                            reason: "Hex string must have even length and valid hex characters".to_string(),
                        });
                    }
                    let byte_count = clean_hex.len() / 2;
                    let orig_bytes = driver.read_bytes_hex(&addr_hex, byte_count).unwrap_or_default();

                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(orig_bytes),
                        patched_bytes: Some(clean_hex),
                        message: Some("Dry run simulation successful".to_string()),
                    });
                }
                "nop" => {
                    let count = step.count.unwrap_or(1);
                    let nop_hex = "90".repeat(count);
                    let orig_bytes = driver.read_bytes_hex(&addr_hex, count).unwrap_or_default();

                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(orig_bytes),
                        patched_bytes: Some(nop_hex),
                        message: Some("Dry run simulation successful".to_string()),
                    });
                }
                "string" => {
                    let new_str = step.new_string.as_ref().ok_or_else(|| {
                        AppError::PatchPlanError(format!(
                            "Step {idx} of type 'string' missing required field 'new_string'"
                        ))
                    })?;
                    let str_hex: String = new_str.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
                    let orig_bytes = driver.read_bytes_hex(&addr_hex, new_str.len()).unwrap_or_default();

                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(orig_bytes),
                        patched_bytes: Some(str_hex),
                        message: Some("Dry run simulation successful".to_string()),
                    });
                }
                _ => {
                    return Err(AppError::PatchPlanError(format!(
                        "Unsupported step type '{}'",
                        step.step_type
                    )));
                }
            }
        }

        Ok(AgentPatchPlanResult {
            plan_name: plan.name,
            applied: false,
            dry_run: true,
            total_steps,
            steps_executed: total_steps,
            step_results,
            backup_path: None,
        })
    } else {
        // Live execution with backup
        let backup_path = create_backup(&driver.binary_path)?;
        let mut step_results = Vec::with_capacity(total_steps);

        for (idx, step) in plan.steps.iter().enumerate() {
            let addr_num = driver.resolve_address(&step.addr)?;
            let addr_hex = format!("0x{:x}", addr_num);

            match step.step_type.to_lowercase().as_str() {
                "instruction" => {
                    let asm = step.assembly.as_ref().ok_or_else(|| {
                        AppError::PatchPlanError(format!(
                            "Step {idx} of type 'instruction' missing required field 'assembly'"
                        ))
                    })?;
                    let p_res = patch::patch_instruction(
                        driver,
                        &step.addr,
                        Some(asm),
                        None,
                        false,
                    )?;
                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(p_res.original_bytes),
                        patched_bytes: Some(p_res.patched_bytes),
                        message: Some(format!("Assembled instruction '{asm}'")),
                    });
                }
                "bytes" => {
                    let h = step.hex.as_ref().ok_or_else(|| {
                        AppError::PatchPlanError(format!(
                            "Step {idx} of type 'bytes' missing required field 'hex'"
                        ))
                    })?;
                    let p_res = patch::patch_bytes(driver, &step.addr, h, false)?;
                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(p_res.original_bytes),
                        patched_bytes: Some(p_res.patched_bytes),
                        message: Some(format!("Patched {} bytes", p_res.bytes_modified)),
                    });
                }
                "nop" => {
                    let count = step.count.unwrap_or(1);
                    let p_res = patch::patch_instruction(
                        driver,
                        &step.addr,
                        None,
                        Some(count),
                        false,
                    )?;
                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(p_res.original_bytes),
                        patched_bytes: Some(p_res.patched_bytes),
                        message: Some(format!("Inserted {count} NOP instructions")),
                    });
                }
                "string" => {
                    let new_str = step.new_string.as_ref().ok_or_else(|| {
                        AppError::PatchPlanError(format!(
                            "Step {idx} of type 'string' missing required field 'new_string'"
                        ))
                    })?;
                    let p_res = patch::patch_string(
                        driver,
                        Some(&step.addr),
                        None,
                        new_str,
                        true,
                        false,
                        false,
                    )?;
                    step_results.push(PatchStepResult {
                        step_index: idx,
                        step_type: step.step_type.clone(),
                        addr: addr_num,
                        addr_hex,
                        success: true,
                        original_bytes: Some(p_res.original_bytes),
                        patched_bytes: Some(p_res.patched_bytes),
                        message: Some(format!("Wrote string '{new_str}'")),
                    });
                }
                _ => {
                    return Err(AppError::PatchPlanError(format!(
                        "Unsupported step type '{}'",
                        step.step_type
                    )));
                }
            }
        }

        Ok(AgentPatchPlanResult {
            plan_name: plan.name,
            applied: true,
            dry_run: false,
            total_steps,
            steps_executed: total_steps,
            step_results,
            backup_path: Some(backup_path.display().to_string()),
        })
    }
}
