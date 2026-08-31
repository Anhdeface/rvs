use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BasicBlocksResponse {
    pub function_name: String,
    pub function_addr: u64,
    pub function_addr_hex: String,
    pub total_blocks: usize,
    pub blocks: Vec<BasicBlockInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BasicBlockInfo {
    pub addr: u64,
    pub addr_hex: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_hex: Option<String>,
    pub num_instructions: usize,
    pub instructions: Vec<InstructionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstructionInfo {
    pub addr: u64,
    pub addr_hex: String,
    pub size: u64,
    pub disasm: String,
    pub opcode: String,
    pub bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub op_type: Option<String>,
}

pub fn analyze_blocks(
    driver: &R2Driver,
    target: &str,
    disasm: bool,
) -> Result<BasicBlocksResponse, AppError> {
    let target_addr = driver.resolve_address(target)?;
    let target_addr_hex = format!("{:#x}", target_addr);

    // Single-pass scoped function analysis: extract basic blocks and disassembly ops together
    let cmd_afb = format!("s {}; af; afbj", target_addr_hex);
    let cmd_pdf = format!("s {}; pdfj", target_addr_hex);
    let batch = driver.cmd_batch(&[&cmd_afb, &cmd_pdf])?;

    let raw_blocks: Vec<serde_json::Value> = R2Driver::parse_json(batch.first().map(|s| s.as_str()).unwrap_or(""))?;
    let pdf_val: serde_json::Value = batch.get(1).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or(serde_json::Value::Null);


    let function_name = pdf_val.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(target)
        .to_string();

    let all_ops = pdf_val.get("ops")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut blocks = Vec::new();

    for b in raw_blocks {
        let addr = b.get("addr").or_else(|| b.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
        let size = b.get("size").and_then(|v| v.as_u64()).unwrap_or(0);

        let jump = b.get("jump").and_then(|v| v.as_u64()).filter(|&j| j != 0 && j != u64::MAX);
        let fail = b.get("fail").and_then(|v| v.as_u64()).filter(|&f| f != 0 && f != u64::MAX);

        let jump_hex = jump.map(|j| format!("{:#x}", j));
        let fail_hex = fail.map(|f| format!("{:#x}", f));

        let mut instructions = Vec::new();

        if disasm {
            for op in &all_ops {
                let op_offset = op.get("addr").or_else(|| op.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
                if op_offset >= addr && op_offset < addr + size {
                    let op_size = op.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                    let opcode = op.get("opcode").or_else(|| op.get("disasm")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let bytes = op.get("bytes").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let family = op.get("family").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let op_type = op.get("type").and_then(|v| v.as_str()).map(|s| s.to_string());

                    instructions.push(InstructionInfo {
                        addr: op_offset,
                        addr_hex: format!("{:#x}", op_offset),
                        size: op_size,
                        disasm: opcode.clone(),
                        opcode,
                        bytes,
                        family,
                        op_type,
                    });
                }
            }
        }

        let num_instructions = if !instructions.is_empty() {
            instructions.len()
        } else {
            b.get("ninstr").and_then(|v| v.as_u64()).unwrap_or(0) as usize
        };

        blocks.push(BasicBlockInfo {
            addr,
            addr_hex: format!("{:#x}", addr),
            size,
            jump,
            jump_hex,
            fail,
            fail_hex,
            num_instructions,
            instructions,
        });
    }

    Ok(BasicBlocksResponse {
        function_name,
        function_addr: target_addr,
        function_addr_hex: target_addr_hex,
        total_blocks: blocks.len(),
        blocks,
    })
}
