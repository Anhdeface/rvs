use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrologueEpilogueResponse {
    pub count: usize,
    pub functions: Vec<FunctionFrameInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionFrameInfo {
    pub name: String,
    pub addr: u64,
    pub addr_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prologue: Option<FrameBoundary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epilogue: Option<FrameBoundary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub epilogues: Vec<FrameBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrameBoundary {
    #[serde(default = "default_true")]
    pub detected: bool,
    pub start_addr: u64,
    pub start_addr_hex: String,
    pub end_addr: u64,
    pub end_addr_hex: String,
    pub size: u64,
    pub pattern: String,
    pub instructions: Vec<FrameInstruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrameInstruction {
    pub addr: u64,
    pub addr_hex: String,
    pub opcode: String,
    pub bytes: String,
}

pub fn analyze_prologue_epilogue(
    driver: &R2Driver,
    target: Option<&str>,
) -> Result<PrologueEpilogueResponse, AppError> {
    if let Some(t) = target {
        let addr = driver.resolve_address(t)?;
        // Single function scoped analysis
        let cmd = format!("s {:#x}; af; pdfj", addr);
        let pdf_val: serde_json::Value = driver.cmdj(&cmd).unwrap_or(serde_json::Value::Null);

        let ops = pdf_val.get("ops").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let fname = pdf_val.get("name").and_then(|v| v.as_str()).unwrap_or(t).to_string();
        let prologue = detect_prologue(&ops);
        let epilogues = detect_epilogues(&ops);
        let epilogue = epilogues.last().cloned();

        return Ok(PrologueEpilogueResponse {
            count: 1,
            functions: vec![FunctionFrameInfo {
                name: fname,
                addr,
                addr_hex: format!("{:#x}", addr),
                prologue,
                epilogue,
                epilogues,
            }],
        });
    }

    // Multi-function analysis: 1 pass for AFL, then batch pdfj in chunks
    let all_funcs: Vec<serde_json::Value> = driver.cmdj("aa; aflj")?;
    let mut func_targets = Vec::new();
    for f in all_funcs {
        let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let addr = f.get("offset").or_else(|| f.get("addr")).and_then(|v| v.as_u64()).unwrap_or(0);
        if !name.is_empty() && !name.starts_with("sym.imp.") && !name.starts_with("reloc.") {
            func_targets.push((name, addr));
        }
    }

    let mut results = Vec::with_capacity(func_targets.len());

    // Process in chunks of 50 to respect CLI buffer limits
    for chunk in func_targets.chunks(50) {
        let cmds: Vec<String> = chunk.iter().map(|(_, addr)| format!("s {:#x}; pdfj", addr)).collect();
        let cmd_refs: Vec<&str> = cmds.iter().map(|s| s.as_str()).collect();
        let outputs = driver.cmd_batch(&cmd_refs).unwrap_or_default();

        for (i, (name, addr)) in chunk.iter().enumerate() {
            let pdf_raw = outputs.get(i).map(|s| s.as_str()).unwrap_or("");
            let pdf_val: serde_json::Value = R2Driver::parse_json(pdf_raw).unwrap_or(serde_json::Value::Null);

            let ops = pdf_val.get("ops").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let fname = pdf_val.get("name").and_then(|v| v.as_str()).unwrap_or(name).to_string();

            let prologue = detect_prologue(&ops);
            let epilogues = detect_epilogues(&ops);
            let epilogue = epilogues.last().cloned();

            results.push(FunctionFrameInfo {
                name: fname,
                addr: *addr,
                addr_hex: format!("{:#x}", addr),
                prologue,
                epilogue,
                epilogues,
            });
        }
    }

    Ok(PrologueEpilogueResponse {
        count: results.len(),
        functions: results,
    })
}

fn detect_prologue(ops: &[serde_json::Value]) -> Option<FrameBoundary> {
    if ops.is_empty() {
        return None;
    }

    let mut prologue_ops = Vec::new();
    let mut has_frame_ptr = false;
    let mut has_stack_alloc = false;
    let mut is_arm = false;

    for op in ops {
        let opcode = op.get("opcode").or_else(|| op.get("disasm")).and_then(|v| v.as_str()).unwrap_or("");
        let op_type = op.get("type").and_then(|v| v.as_str()).unwrap_or("");

        let is_x86_prologue = opcode.starts_with("endbr")
            || opcode.starts_with("push rbp")
            || opcode.starts_with("push ebp")
            || opcode.starts_with("mov rbp, rsp")
            || opcode.starts_with("mov ebp, esp")
            || (opcode.starts_with("sub rsp") || opcode.starts_with("sub esp"))
            || (op_type == "rpush" && (opcode.starts_with("push r") || opcode.starts_with("push e")));

        let is_arm64_prologue = opcode.starts_with("stp x29, x30") || opcode.starts_with("mov x29, sp");
        let is_arm32_prologue = opcode.starts_with("push {") && (opcode.contains("lr") || opcode.contains("r11"));

        if is_x86_prologue || is_arm64_prologue || is_arm32_prologue {
            if opcode.contains("rbp, rsp") || opcode.contains("ebp, esp") || is_arm64_prologue || is_arm32_prologue {
                has_frame_ptr = true;
            }
            if is_arm64_prologue || is_arm32_prologue {
                is_arm = true;
            }
            if opcode.starts_with("sub rsp") || opcode.starts_with("sub esp") || opcode.starts_with("sub sp") {
                has_stack_alloc = true;
            }
            prologue_ops.push(op);
        } else {
            // Reached non-prologue instruction
            break;
        }
    }

    if prologue_ops.is_empty() {
        return None;
    }

    let pattern = if is_arm && has_frame_ptr {
        "arm_standard_frame"
    } else if has_frame_ptr {
        "x86_64_standard_frame"
    } else if has_stack_alloc {
        "stack_allocation_only"
    } else {
        "custom_prologue"
    };

    let start_addr = prologue_ops.first()
        .and_then(|o| o.get("addr").or_else(|| o.get("offset")).and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let last_op = prologue_ops.last()?;
    let last_offset = last_op.get("addr").or_else(|| last_op.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
    let last_size = last_op.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let end_addr = last_offset + last_size;
    let size = end_addr.saturating_sub(start_addr);

    let instructions = prologue_ops.into_iter().map(|op| {
        let op_offset = op.get("addr").or_else(|| op.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
        let opcode = op.get("opcode").or_else(|| op.get("disasm")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bytes = op.get("bytes").and_then(|v| v.as_str()).unwrap_or("").to_string();
        FrameInstruction {
            addr: op_offset,
            addr_hex: format!("{:#x}", op_offset),
            opcode,
            bytes,
        }
    }).collect();

    Some(FrameBoundary {
        detected: true,
        start_addr,
        start_addr_hex: format!("{:#x}", start_addr),
        end_addr,
        end_addr_hex: format!("{:#x}", end_addr),
        size,
        pattern: pattern.to_string(),
        instructions,
    })
}

fn extract_epilogue_at(ops: &[serde_json::Value], target_idx: usize) -> Option<FrameBoundary> {
    let mut epilogue_ops = Vec::new();
    let mut idx = target_idx as isize;

    while idx >= 0 {
        let op = match ops.get(idx as usize) {
            Some(o) => o,
            None => break,
        };
        let opcode = op.get("opcode").or_else(|| op.get("disasm")).and_then(|v| v.as_str()).unwrap_or("");
        let is_epilogue_inst = opcode.starts_with("ret")
            || opcode.starts_with("leave")
            || opcode.starts_with("pop rbp")
            || opcode.starts_with("pop ebp")
            || opcode.starts_with("pop r")
            || opcode.starts_with("pop e")
            || opcode.starts_with("add rsp")
            || opcode.starts_with("add esp")
            || opcode.starts_with("ldp x29, x30")
            || opcode.starts_with("bx lr")
            || (opcode.starts_with("pop {") && (opcode.contains("pc") || opcode.contains("lr")));

        if is_epilogue_inst {
            epilogue_ops.push(op);
            if opcode.starts_with("leave")
                || (opcode.starts_with("pop rbp") && epilogue_ops.len() >= 2)
                || opcode.starts_with("ldp x29, x30")
            {
                break;
            }
            idx -= 1;
        } else {
            break;
        }
    }

    if epilogue_ops.is_empty() {
        return None;
    }

    epilogue_ops.reverse();

    let pattern = if epilogue_ops.iter().any(|o| o.get("opcode").and_then(|v| v.as_str()).unwrap_or("").starts_with("leave")) {
        "leave_ret"
    } else if epilogue_ops.iter().any(|o| o.get("opcode").and_then(|v| v.as_str()).unwrap_or("").contains("ldp x29, x30")) {
        "arm64_ldp_ret"
    } else if epilogue_ops.iter().any(|o| o.get("opcode").and_then(|v| v.as_str()).unwrap_or("").contains("pop rbp")) {
        "x86_64_pop_ret"
    } else if epilogue_ops.iter().any(|o| o.get("opcode").and_then(|v| v.as_str()).unwrap_or("").starts_with("add rsp")) {
        "stack_restore_ret"
    } else {
        "bare_ret"
    };

    let start_addr = epilogue_ops.first()
        .and_then(|o| o.get("addr").or_else(|| o.get("offset")).and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let last_op = epilogue_ops.last()?;
    let last_offset = last_op.get("addr").or_else(|| last_op.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
    let last_size = last_op.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let end_addr = last_offset + last_size;
    let size = end_addr.saturating_sub(start_addr);

    let instructions = epilogue_ops.into_iter().map(|op| {
        let op_offset = op.get("addr").or_else(|| op.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
        let opcode = op.get("opcode").or_else(|| op.get("disasm")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bytes = op.get("bytes").and_then(|v| v.as_str()).unwrap_or("").to_string();
        FrameInstruction {
            addr: op_offset,
            addr_hex: format!("{:#x}", op_offset),
            opcode,
            bytes,
        }
    }).collect();

    Some(FrameBoundary {
        detected: true,
        start_addr,
        start_addr_hex: format!("{:#x}", start_addr),
        end_addr,
        end_addr_hex: format!("{:#x}", end_addr),
        size,
        pattern: pattern.to_string(),
        instructions,
    })
}

fn detect_epilogues(ops: &[serde_json::Value]) -> Vec<FrameBoundary> {
    if ops.is_empty() {
        return Vec::new();
    }

    let mut ret_indices = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let op_type = op.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let opcode = op.get("opcode").or_else(|| op.get("disasm")).and_then(|v| v.as_str()).unwrap_or("");
        if op_type == "ret"
            || opcode.starts_with("ret")
            || opcode.starts_with("bx lr")
            || (opcode.starts_with("pop {") && opcode.contains("pc"))
        {
            ret_indices.push(i);
        }
    }

    let mut boundaries = Vec::new();
    let mut seen_addrs = std::collections::HashSet::new();

    for ret_idx in ret_indices {
        if let Some(boundary) = extract_epilogue_at(ops, ret_idx) {
            if seen_addrs.insert(boundary.start_addr) {
                boundaries.push(boundary);
            }
        }
    }

    boundaries
}
