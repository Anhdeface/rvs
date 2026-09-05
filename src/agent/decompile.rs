use serde::{Deserialize, Serialize};
use crate::analysis::{self, xrefs::XrefDirection};
use crate::error::AppError;
use crate::r2::R2Driver;

/// Payload for `agent decompile` command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentDecompileData {
    pub function_name: String,
    pub function_addr: u64,
    pub function_addr_hex: String,
    pub size: u64,
    pub pseudo_c: String,
    pub blocks_count: usize,
    pub instructions_count: usize,
    pub calls: Vec<String>,
    pub strings_referenced: Vec<String>,
}

pub fn run_decompile(driver: &R2Driver, function: &str) -> Result<AgentDecompileData, AppError> {
    let target_addr = match driver.resolve_address(function) {
        Ok(addr) => addr,
        Err(AppError::InvalidArgument(e)) => return Err(AppError::InvalidArgument(e)),
        Err(AppError::Timeout(e)) => return Err(AppError::Timeout(e)),
        Err(_) => return Err(AppError::SymbolNotFound(function.to_string())),
    };

    // Find function info
    let funcs_resp = analysis::analyze_functions(driver, None, false)?;
    let func_info = funcs_resp.functions.iter().find(|f| {
        f.offset == target_addr || f.name == function || f.name.ends_with(&format!(".{function}"))
    });

    let (function_name, function_addr, size) = if let Some(info) = func_info {
        (info.name.clone(), info.offset, info.size)
    } else {
        (function.to_string(), target_addr, 0)
    };

    let target_hex = format!("0x{:x}", function_addr);

    // Get basic blocks
    let blocks_resp = match analysis::analyze_blocks(driver, function, true) {
        Ok(b) => b,
        Err(_) => analysis::analyze_blocks(driver, &target_hex, true)?,
    };

    let blocks_count = blocks_resp.blocks.len();
    let mut instructions_count = 0;
    let mut calls = Vec::new();
    let mut strings_referenced = Vec::new();
    let mut seen_calls = std::collections::HashSet::new();
    let mut seen_strings = std::collections::HashSet::new();

    for b in &blocks_resp.blocks {
        instructions_count += b.instructions.len();
        for inst in &b.instructions {
            let op_lower = inst.opcode.to_lowercase();
            if op_lower.starts_with("call") {
                let target_name = inst.opcode.split_whitespace().nth(1).unwrap_or(&inst.opcode).to_string();
                if seen_calls.insert(target_name.clone()) {
                    calls.push(target_name);
                }
            }
        }
    }

    // Run radare2 decompilation / disassembly with analysis
    let r2_batch = driver.cmd_batch(&[
        &format!("aa; s {target_hex}; pdc"),
        &format!("aa; pdf @ {target_hex}"),
    ])?;

    let pdc_out = r2_batch.first().map(|s| s.trim()).unwrap_or("");
    let pdf_out = r2_batch.get(1).map(|s| s.trim()).unwrap_or("");

    let mut pseudo_c = if !pdc_out.is_empty() {
        pdc_out.to_string()
    } else if !pdf_out.is_empty() {
        pdf_out.to_string()
    } else {
        String::new()
    };

    // Extract xrefs from function to find referenced strings & data
    if let Ok(xrefs_resp) = analysis::analyze_xrefs(driver, &target_hex, XrefDirection::From, None) {
        for x in &xrefs_resp.xrefs_from {
            if let Ok(str_val) = driver.read_string_at(&x.to_addr_hex) {
                let s_trim = str_val.trim();
                if s_trim.len() >= 3 && seen_strings.insert(s_trim.to_string()) {
                    strings_referenced.push(s_trim.to_string());
                }
            }
        }
    }

    // Extract referenced strings from binary string table
    if let Ok(all_strings) = analysis::list_strings(driver, 4) {
        for s in all_strings.strings {
            let s_text = s.string.trim();
            if s_text.len() < 3 {
                continue;
            }

            // Check if string appears in pseudo_c or pdf output
            if (pseudo_c.contains(s_text) || pdf_out.contains(s_text))
                && seen_strings.insert(s_text.to_string())
            {
                strings_referenced.push(s_text.to_string());
                continue;
            }

            // Check if string address is referenced in block instructions
            let vaddr_hex = format!("{:x}", s.vaddr);
            for b in &blocks_resp.blocks {
                for inst in &b.instructions {
                    if (inst.opcode.contains(&vaddr_hex) || inst.disasm.contains(&vaddr_hex))
                        && seen_strings.insert(s_text.to_string())
                    {
                        strings_referenced.push(s_text.to_string());
                    }
                }
            }
        }
    }

    // Ensure pseudo_c is never empty
    if pseudo_c.is_empty() {
        pseudo_c = format!(
            "// Function {} at 0x{:x}\nvoid {}() {{\n    // {} basic blocks, {} instructions\n}}",
            function_name, function_addr, function_name, blocks_count, instructions_count
        );
    }

    Ok(AgentDecompileData {
        function_name,
        function_addr,
        function_addr_hex: format!("0x{:x}", function_addr),
        size,
        pseudo_c,
        blocks_count,
        instructions_count,
        calls,
        strings_referenced,
    })
}
