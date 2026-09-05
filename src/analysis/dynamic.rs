use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

pub const EMU_DELIMITER: &str = "===RVS_EMU_BOUNDARY_DELIM===";
pub const TRACE_DELIMITER: &str = "===RVS_TRACE_BOUNDARY_DELIM===";

/// Represents the change in a CPU register during emulation or stepping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegisterDiff {
    pub reg: String,
    pub before: u64,
    pub before_hex: String,
    pub after: u64,
    pub after_hex: String,
}

/// Function return value extracted from architecture ABI register (RAX/EAX/R0/X0).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReturnValueInfo {
    pub reg: String,
    pub value: u64,
    pub value_hex: String,
}

/// Full response emitted by dynamic emulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DynamicEmulateResponse {
    pub target: String,
    pub start_addr: u64,
    pub start_addr_hex: String,
    pub final_addr: u64,
    pub final_addr_hex: String,
    pub steps_requested: usize,
    pub steps_executed: usize,
    pub stop_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<ReturnValueInfo>,
    pub register_diff: Vec<RegisterDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_registers: Option<BTreeMap<String, u64>>,
    pub final_registers: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_after: Option<String>,
}

/// A single step in an instruction trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceStepInfo {
    pub step: usize,
    pub addr: u64,
    pub addr_hex: String,
    pub disasm: String,
    pub opcode: String,
    pub reg_changes: Vec<RegisterDiff>,
}

/// Full response emitted by dynamic execution trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DynamicTraceResponse {
    pub target: String,
    pub start_addr: u64,
    pub start_addr_hex: String,
    pub total_steps: usize,
    pub trace: Vec<TraceStepInfo>,
}

/// Response for a single step or small stepping sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DynamicStepResponse {
    pub current_addr: u64,
    pub current_addr_hex: String,
    pub next_addr: u64,
    pub next_addr_hex: String,
    pub instruction: String,
    pub steps: usize,
    pub reg_changes: Vec<RegisterDiff>,
    pub final_registers: BTreeMap<String, u64>,
}

/// Validates and formats register override assignments (`reg=val`).
pub fn format_reg_set(reg_set: &[String]) -> Result<String, AppError> {
    let mut out = String::new();
    for entry in reg_set {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((reg, val)) = trimmed.split_once('=') {
            let reg = reg.trim();
            let val = val.trim();
            if reg.is_empty() || !reg.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Err(AppError::InvalidArgument(format!("Invalid register name: '{}'", reg)));
            }
            if val.is_empty() || !val.chars().all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X' || c == '-' || c == '+') {
                return Err(AppError::InvalidArgument(format!("Invalid register value for '{}': '{}'", reg, val)));
            }
            out.push_str(&format!("aer {}={}; ", reg, val));
        } else {
            return Err(AppError::InvalidArgument(format!(
                "Invalid register assignment format (expected 'reg=val'): '{}'",
                trimmed
            )));
        }
    }
    Ok(out)
}

/// Parse registers JSON map into a BTreeMap<String, u64>.
pub fn parse_registers_json(raw: &str) -> Result<BTreeMap<String, u64>, AppError> {
    let value: serde_json::Value = R2Driver::parse_json(raw)?;
    let mut map = BTreeMap::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if let Some(n) = v.as_u64() {
                map.insert(k.clone(), n);
            } else if let Some(n) = v.as_i64() {
                map.insert(k.clone(), n as u64);
            } else if let Some(s) = v.as_str() {
                let trimmed = s.trim();
                let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    trimmed.parse::<u64>().unwrap_or(0)
                };
                map.insert(k.clone(), parsed);
            }
        }
    }
    Ok(map)
}

/// Calculates diffs between two register states.
pub fn calculate_register_diff(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> Vec<RegisterDiff> {
    let mut diffs = Vec::new();
    for (reg, after_val) in after {
        let before_val = before.get(reg).copied().unwrap_or(0);
        if before_val != *after_val {
            diffs.push(RegisterDiff {
                reg: reg.clone(),
                before: before_val,
                before_hex: format!("{:#x}", before_val),
                after: *after_val,
                after_hex: format!("{:#x}", after_val),
            });
        }
    }
    // Sort for determinism
    diffs.sort_by(|a, b| a.reg.cmp(&b.reg));
    diffs
}

/// Attempts to identify instruction pointer from registers map.
pub fn get_instruction_pointer(regs: &BTreeMap<String, u64>) -> Option<u64> {
    regs.get("rip")
        .or_else(|| regs.get("eip"))
        .or_else(|| regs.get("pc"))
        .copied()
}

/// Identifies return value register (RAX, EAX, R0, X0) from registers map.
pub fn get_return_value(regs: &BTreeMap<String, u64>) -> Option<ReturnValueInfo> {
    for reg_name in &["rax", "eax", "r0", "x0"] {
        if let Some(&val) = regs.get(*reg_name) {
            return Some(ReturnValueInfo {
                reg: reg_name.to_string(),
                value: val,
                value_hex: format!("{:#x}", val),
            });
        }
    }
    None
}

/// Options for dynamic emulation.
#[derive(Debug, Clone)]
pub struct EmulateOptions {
    pub target: String,
    pub steps: usize,
    pub until: Option<String>,
    pub reg_set: Vec<String>,
    pub read_mem: Option<String>,
    pub mem_len: usize,
    pub include_initial_regs: bool,
}

impl Default for EmulateOptions {
    fn default() -> Self {
        Self {
            target: String::new(),
            steps: 100,
            until: None,
            reg_set: Vec::new(),
            read_mem: None,
            mem_len: 32,
            include_initial_regs: false,
        }
    }
}

/// Executes dynamic ESIL emulation on the target binary.
pub fn analyze_emulate(
    driver: &R2Driver,
    opts: &EmulateOptions,
) -> Result<DynamicEmulateResponse, AppError> {
    let start_addr = driver.resolve_address(&opts.target)?;
    let start_addr_hex = format!("{:#x}", start_addr);

    let until_addr = if let Some(ref u) = opts.until {
        Some(driver.resolve_address(u)?)
    } else {
        None
    };

    let mem_addr = if let Some(ref m) = opts.read_mem {
        Some(driver.resolve_address(m)?)
    } else {
        None
    };

    let reg_set_cmds = format_reg_set(&opts.reg_set)?;

    // Build the batched radare2 commands
    let mut cmd = String::new();
    cmd.push_str("aa; ");
    cmd.push_str(&format!("s {}; ", start_addr_hex));
    cmd.push_str("aei; aeim; aeip; ");
    if !reg_set_cmds.is_empty() {
        cmd.push_str(&reg_set_cmds);
    }

    // Optional memory read before
    if let Some(m_addr) = mem_addr {
        cmd.push_str(&format!("p8 {} @ {:#x}; ", opts.mem_len, m_addr));
        cmd.push_str(&format!("?e {}; ", EMU_DELIMITER));
    }

    // Initial registers
    cmd.push_str("aerj; ");
    cmd.push_str(&format!("?e {}; ", EMU_DELIMITER));

    // Emulation step execution
    if let Some(u_addr) = until_addr {
        let max_steps = if opts.steps > 0 { opts.steps } else { 1000 };
        cmd.push_str(&format!("e esil.maxsteps={}; ", max_steps));
        cmd.push_str(&format!("aesu {:#x}; ", u_addr));
    } else {
        cmd.push_str(&format!("aes {}; ", opts.steps));
    }

    cmd.push_str(&format!("?e {}; ", EMU_DELIMITER));

    // Final registers
    cmd.push_str("aerj; ");

    // Optional memory read after
    if let Some(m_addr) = mem_addr {
        cmd.push_str(&format!("?e {}; ", EMU_DELIMITER));
        cmd.push_str(&format!("p8 {} @ {:#x}; ", opts.mem_len, m_addr));
    }

    let output = driver.cmd(&cmd)?;
    let parts: Vec<&str> = output.split(EMU_DELIMITER).collect();

    let mut part_idx = 0;
    let mem_before = if mem_addr.is_some() && part_idx < parts.len() {
        let s = parts[part_idx].trim().to_string();
        part_idx += 1;
        Some(s)
    } else {
        None
    };

    let initial_regs_raw = if part_idx < parts.len() {
        parts[part_idx].trim()
    } else {
        "{}"
    };
    part_idx += 1;

    // skip execution output
    part_idx += 1;

    let final_regs_raw = if part_idx < parts.len() {
        parts[part_idx].trim()
    } else {
        "{}"
    };
    part_idx += 1;

    let mem_after = if mem_addr.is_some() && part_idx < parts.len() {
        Some(parts[part_idx].trim().to_string())
    } else {
        None
    };

    let initial_regs = parse_registers_json(initial_regs_raw).unwrap_or_default();
    let final_regs = parse_registers_json(final_regs_raw).unwrap_or_default();

    let register_diff = calculate_register_diff(&initial_regs, &final_regs);
    let final_addr = get_instruction_pointer(&final_regs).unwrap_or(start_addr);
    let final_addr_hex = format!("{:#x}", final_addr);

    let stop_reason = if let Some(u_addr) = until_addr {
        if final_addr == u_addr {
            "until_reached".to_string()
        } else {
            "step_limit_or_trap".to_string()
        }
    } else {
        "step_limit_completed".to_string()
    };

    let return_val = get_return_value(&final_regs);

    Ok(DynamicEmulateResponse {
        target: opts.target.clone(),
        start_addr,
        start_addr_hex,
        final_addr,
        final_addr_hex,
        steps_requested: opts.steps,
        steps_executed: opts.steps,
        stop_reason,
        return_value: return_val,
        register_diff,
        initial_registers: if opts.include_initial_regs {
            Some(initial_regs)
        } else {
            None
        },
        final_registers: final_regs,
        memory_before: mem_before,
        memory_after: mem_after,
    })
}

/// Options for execution tracing.
#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub target: String,
    pub steps: usize,
    pub reg_set: Vec<String>,
}

/// Executes instruction-level dynamic execution trace with register deltas.
pub fn analyze_trace(
    driver: &R2Driver,
    opts: &TraceOptions,
) -> Result<DynamicTraceResponse, AppError> {
    let start_addr = driver.resolve_address(&opts.target)?;
    let start_addr_hex = format!("{:#x}", start_addr);

    let steps = if opts.steps == 0 {
        20
    } else if opts.steps > 200 {
        200
    } else {
        opts.steps
    };

    let reg_set_cmds = format_reg_set(&opts.reg_set)?;

    let mut cmd = String::new();
    cmd.push_str("aa; ");
    cmd.push_str(&format!("s {}; ", start_addr_hex));
    cmd.push_str("aei; aeim; aeip; ");
    if !reg_set_cmds.is_empty() {
        cmd.push_str(&reg_set_cmds);
    }

    for i in 0..steps {
        if i > 0 {
            cmd.push_str("aes 1; ");
        }
        cmd.push_str("pi 1 @ `aer rip`; aerj; ");
        cmd.push_str(&format!("?e {}; ", TRACE_DELIMITER));
    }

    let raw = driver.cmd(&cmd)?;
    let chunks: Vec<&str> = raw.split(TRACE_DELIMITER).collect();

    let mut trace_steps = Vec::new();
    let mut prev_regs: Option<BTreeMap<String, u64>> = None;

    for (step_idx, chunk) in chunks.iter().enumerate() {
        let chunk_trimmed = chunk.trim();
        if chunk_trimmed.is_empty() || step_idx >= steps {
            continue;
        }

        let mut lines: Vec<&str> = chunk_trimmed.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
        let mut reg_json_str = "{}";
        let mut disasm_line = String::new();

        if let Some(json_idx) = lines.iter().position(|l| l.starts_with('{')) {
            reg_json_str = lines[json_idx];
            let asm_lines = &lines[..json_idx];
            disasm_line = asm_lines.join(" ");
        } else if let Some(last) = lines.pop() {
            if last.starts_with('{') {
                reg_json_str = last;
                disasm_line = lines.join(" ");
            } else {
                disasm_line = format!("{} {}", lines.join(" "), last);
            }
        }

        let curr_regs = parse_registers_json(reg_json_str).unwrap_or_default();
        let step_addr = get_instruction_pointer(&curr_regs).unwrap_or(start_addr);

        let reg_changes = if let Some(ref p) = prev_regs {
            calculate_register_diff(p, &curr_regs)
        } else {
            Vec::new()
        };

        let opcode = disasm_line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();

        trace_steps.push(TraceStepInfo {
            step: step_idx,
            addr: step_addr,
            addr_hex: format!("{:#x}", step_addr),
            disasm: disasm_line.trim().to_string(),
            opcode,
            reg_changes,
        });

        prev_regs = Some(curr_regs);
    }

    Ok(DynamicTraceResponse {
        target: opts.target.clone(),
        start_addr,
        start_addr_hex,
        total_steps: trace_steps.len(),
        trace: trace_steps,
    })
}

/// Executes a single step or N steps from the given target address.
pub fn analyze_step(
    driver: &R2Driver,
    target: &str,
    count: usize,
    reg_set: &[String],
) -> Result<DynamicStepResponse, AppError> {
    let start_addr = driver.resolve_address(target)?;
    let start_addr_hex = format!("{:#x}", start_addr);
    let step_count = if count == 0 { 1 } else { count };

    let reg_set_cmds = format_reg_set(reg_set)?;

    let mut cmd = String::new();
    cmd.push_str("aa; ");
    cmd.push_str(&format!("s {}; ", start_addr_hex));
    cmd.push_str("aei; aeim; aeip; ");
    if !reg_set_cmds.is_empty() {
        cmd.push_str(&reg_set_cmds);
    }

    // Capture initial
    cmd.push_str("pi 1 @ `aer rip`; aerj; ");
    cmd.push_str(&format!("?e {}; ", EMU_DELIMITER));

    // Execute step
    cmd.push_str(&format!("aes {}; ", step_count));
    cmd.push_str("aerj; ");

    let raw = driver.cmd(&cmd)?;
    let parts: Vec<&str> = raw.split(EMU_DELIMITER).collect();

    let before_chunk = parts.first().copied().unwrap_or("").trim();
    let after_chunk = parts.get(1).copied().unwrap_or("").trim();

    let mut disasm_str = String::new();
    let mut initial_json = "{}";
    for line in before_chunk.lines() {
        let l = line.trim();
        if l.starts_with('{') {
            initial_json = l;
        } else if !l.is_empty() {
            if !disasm_str.is_empty() {
                disasm_str.push(' ');
            }
            disasm_str.push_str(l);
        }
    }

    let initial_regs = parse_registers_json(initial_json).unwrap_or_default();
    let final_regs = parse_registers_json(after_chunk).unwrap_or_default();

    let reg_changes = calculate_register_diff(&initial_regs, &final_regs);
    let next_addr = get_instruction_pointer(&final_regs).unwrap_or(start_addr);

    Ok(DynamicStepResponse {
        current_addr: start_addr,
        current_addr_hex: start_addr_hex,
        next_addr,
        next_addr_hex: format!("{:#x}", next_addr),
        instruction: disasm_str,
        steps: step_count,
        reg_changes,
        final_registers: final_regs,
    })
}
