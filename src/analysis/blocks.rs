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

#[derive(Debug, Deserialize)]
struct RawR2Block {
    #[serde(default)]
    addr: Option<u64>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    jump: Option<u64>,
    #[serde(default)]
    fail: Option<u64>,
    #[serde(default)]
    ninstr: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawR2Pdf {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ops: Vec<RawR2Op>,
}

#[derive(Debug, Deserialize)]
struct RawR2Op {
    #[serde(default)]
    addr: Option<u64>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    opcode: Option<String>,
    #[serde(default)]
    disasm: Option<String>,
    #[serde(default)]
    bytes: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default, rename = "type")]
    op_type: Option<String>,
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

    let raw_blocks: Vec<RawR2Block> = R2Driver::parse_json(batch.first().map(|s| s.as_str()).unwrap_or(""))?;
    let pdf_val: Option<RawR2Pdf> = batch.get(1).and_then(|s| R2Driver::parse_json(s).ok());

    let (function_name, mut all_ops) = if let Some(pdf) = pdf_val {
        (pdf.name.unwrap_or_else(|| target.to_string()), pdf.ops)
    } else {
        (target.to_string(), Vec::new())
    };

    if disasm && !all_ops.is_empty() {
        all_ops.sort_by_key(|op| op.addr.or(op.offset).unwrap_or(0));
    }

    let mut blocks = Vec::with_capacity(raw_blocks.len());

    for b in raw_blocks {
        let addr = b.addr.or(b.offset).unwrap_or(0);
        let size = b.size.unwrap_or(0);

        let jump = b.jump.filter(|&j| j != 0 && j != u64::MAX);
        let fail = b.fail.filter(|&f| f != 0 && f != u64::MAX);

        let jump_hex = jump.map(|j| format!("{:#x}", j));
        let fail_hex = fail.map(|f| format!("{:#x}", f));

        let mut instructions = Vec::new();

        if disasm && !all_ops.is_empty() {
            let start = all_ops.partition_point(|op| op.addr.or(op.offset).unwrap_or(0) < addr);
            let end = all_ops.partition_point(|op| op.addr.or(op.offset).unwrap_or(0) < addr + size);

            if start < end && start < all_ops.len() {
                let slice = &all_ops[start..end];
                instructions.reserve(slice.len());
                for op in slice {
                    let op_offset = op.addr.or(op.offset).unwrap_or(0);
                    let op_size = op.size.unwrap_or(0);
                    let opcode_str = op.opcode.as_deref().or(op.disasm.as_deref()).unwrap_or("");

                    instructions.push(InstructionInfo {
                        addr: op_offset,
                        addr_hex: format!("{:#x}", op_offset),
                        size: op_size,
                        disasm: opcode_str.to_string(),
                        opcode: opcode_str.to_string(),
                        bytes: op.bytes.clone().unwrap_or_default(),
                        family: op.family.clone(),
                        op_type: op.op_type.clone(),
                    });
                }
            }
        }

        let num_instructions = if !instructions.is_empty() {
            instructions.len()
        } else {
            b.ninstr.unwrap_or(0) as usize
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
