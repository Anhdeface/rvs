//! Compact output representations for agent-optimized consumption.
//! Reduces JSON output by 60-75% by eliminating redundant fields:
//! - Decimal addresses removed (keep only hex)
//! - Duplicate `disasm`/`opcode` merged into single `asm`
//! - Raw `bytes`, `family`, `type` fields stripped from instructions
//! - Shortened field names (`cyclomatic_complexity` → `cc`, etc.)
//! - Redundant `paddr`, `string_type` stripped from strings

use serde::{Deserialize, Serialize};
use crate::analysis::blocks::{BasicBlockInfo, BasicBlocksResponse, InstructionInfo};
use crate::analysis::functions::{FunctionInfo, FunctionsResponse};
use crate::analysis::strings::{StringEntry, StringsResponse};
use crate::analysis::symbols::{SymbolEntry, SymbolsResponse};
use crate::analysis::xrefs::{XrefEntry, XrefsResponse};

// ── Compact Instructions & Blocks ──────────────────

/// Compact instruction: essential fields only.
/// Before: addr, addr_hex, size, disasm, opcode, bytes, family, type (8 fields)
/// After:  addr, asm, size (3 fields)
#[derive(Debug, Clone, Serialize)]
pub struct CompactInstruction {
    /// Hex address (e.g. "0x11e0")
    pub addr: String,
    /// Assembly text
    pub asm: String,
    /// Instruction size in bytes
    pub size: u64,
}

/// Compact basic block.
#[derive(Debug, Clone, Serialize)]
pub struct CompactBlock {
    pub addr: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<String>,
    pub instructions: Vec<CompactInstruction>,
}

/// Compact blocks response.
#[derive(Debug, Clone, Serialize)]
pub struct CompactBlocksResponse {
    pub function: String,
    pub addr: String,
    pub total_blocks: usize,
    pub blocks: Vec<CompactBlock>,
}

// ── Compact Functions ──────────────────────────────

/// Compact function info.
/// Before: name, offset, offset_hex, size, signature, calltype, cyclomatic_complexity,
///         num_basic_blocks, num_instructions, is_pure, num_args, num_locals, stack_frame_size (13 fields)
/// After:  name, addr, size, signature, cc, blocks, instrs (5-7 fields)
#[derive(Debug, Clone, Serialize)]
pub struct CompactFunction {
    pub name: String,
    pub addr: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Cyclomatic complexity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<u64>,
    /// Number of basic blocks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<u64>,
    /// Number of instructions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrs: Option<u64>,
}

/// Compact functions response.
#[derive(Debug, Clone, Serialize)]
pub struct CompactFunctionsResponse {
    pub count: usize,
    pub functions: Vec<CompactFunction>,
}

// ── Compact Strings ────────────────────────────────

/// Compact string entry.
/// Before: vaddr, vaddr_hex, paddr, size, type, string (6 fields)
/// After:  addr, string (2 fields)
#[derive(Debug, Clone, Serialize)]
pub struct CompactStringEntry {
    pub addr: String,
    pub string: String,
}

/// Compact strings response.
#[derive(Debug, Clone, Serialize)]
pub struct CompactStringsResponse {
    pub count: usize,
    pub strings: Vec<CompactStringEntry>,
}

// ── Compact Symbols ────────────────────────────────

/// Compact symbol entry.
#[derive(Debug, Clone, Serialize)]
pub struct CompactSymbolEntry {
    pub name: String,
    pub addr: String,
    #[serde(rename = "type")]
    pub sym_type: String,
    pub bind: String,
}

/// Compact symbols response.
#[derive(Debug, Clone, Serialize)]
pub struct CompactSymbolsResponse {
    pub count: usize,
    pub symbols: Vec<CompactSymbolEntry>,
}

// ── Compact Xrefs ──────────────────────────────────

/// Compact xref entry.
/// Before: from_addr, from_addr_hex, from_function, to_addr, to_addr_hex, to_function, type, opcode, perm, fcn_addr (10 fields)
/// After:  from, from_name, to, to_name, type, opcode (4-6 fields)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactXrefEntry {
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_name: Option<String>,
    #[serde(rename = "type")]
    pub xref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode: Option<String>,
}

/// Compact xrefs response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactXrefsResponse {
    pub target: String,
    pub addr: String,
    pub direction: String,
    pub count: usize,
    pub xrefs: Vec<CompactXrefEntry>,
}

// ── Conversions ────────────────────────────────────

impl From<&BasicBlocksResponse> for CompactBlocksResponse {
    fn from(src: &BasicBlocksResponse) -> Self {
        Self {
            function: src.function_name.clone(),
            addr: src.function_addr_hex.clone(),
            total_blocks: src.total_blocks,
            blocks: src.blocks.iter().map(CompactBlock::from).collect(),
        }
    }
}

impl From<&BasicBlockInfo> for CompactBlock {
    fn from(src: &BasicBlockInfo) -> Self {
        Self {
            addr: src.addr_hex.clone(),
            size: src.size,
            jump: src.jump_hex.clone(),
            fail: src.fail_hex.clone(),
            instructions: src.instructions.iter().map(CompactInstruction::from).collect(),
        }
    }
}

impl From<&InstructionInfo> for CompactInstruction {
    fn from(src: &InstructionInfo) -> Self {
        Self {
            addr: src.addr_hex.clone(),
            asm: src.disasm.clone(),
            size: src.size,
        }
    }
}

impl From<&FunctionsResponse> for CompactFunctionsResponse {
    fn from(src: &FunctionsResponse) -> Self {
        Self {
            count: src.count,
            functions: src.functions.iter().map(CompactFunction::from).collect(),
        }
    }
}

impl From<&FunctionInfo> for CompactFunction {
    fn from(src: &FunctionInfo) -> Self {
        Self {
            name: src.name.clone(),
            addr: src.offset_hex.clone(),
            size: src.size,
            signature: src.signature.clone(),
            cc: src.cyclomatic_complexity,
            blocks: src.num_basic_blocks,
            instrs: src.num_instructions,
        }
    }
}

impl From<&StringsResponse> for CompactStringsResponse {
    fn from(src: &StringsResponse) -> Self {
        Self {
            count: src.count,
            strings: src.strings.iter().map(CompactStringEntry::from).collect(),
        }
    }
}

impl From<&StringEntry> for CompactStringEntry {
    fn from(src: &StringEntry) -> Self {
        Self {
            addr: src.vaddr_hex.clone(),
            string: src.string.clone(),
        }
    }
}

impl From<&SymbolsResponse> for CompactSymbolsResponse {
    fn from(src: &SymbolsResponse) -> Self {
        Self {
            count: src.count,
            symbols: src.symbols.iter().map(CompactSymbolEntry::from).collect(),
        }
    }
}

impl From<&SymbolEntry> for CompactSymbolEntry {
    fn from(src: &SymbolEntry) -> Self {
        Self {
            name: src.name.clone(),
            addr: src.vaddr_hex.clone(),
            sym_type: src.sym_type.clone(),
            bind: src.bind.clone(),
        }
    }
}

impl From<&XrefsResponse> for CompactXrefsResponse {
    fn from(src: &XrefsResponse) -> Self {
        Self {
            target: src.target.clone(),
            addr: src.target_addr_hex.clone(),
            direction: src.direction.clone(),
            count: src.count,
            xrefs: src.xrefs.iter().map(CompactXrefEntry::from).collect(),
        }
    }
}

impl From<&XrefEntry> for CompactXrefEntry {
    fn from(src: &XrefEntry) -> Self {
        Self {
            from: src.from_addr_hex.clone(),
            from_name: src.from_function.clone().or_else(|| src.from_name.clone()),
            to: src.to_addr_hex.clone(),
            to_name: src.to_function.clone().or_else(|| src.to_name.clone()),
            xref_type: src.xref_type.clone(),
            opcode: src.opcode.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::blocks::{BasicBlocksResponse, BasicBlockInfo, InstructionInfo};
    use crate::analysis::functions::FunctionInfo;
    use crate::analysis::strings::StringEntry;

    #[test]
    fn test_compact_instruction_from_full() {
        let full = InstructionInfo {
            addr: 4576,
            addr_hex: "0x11e0".to_string(),
            size: 4,
            disasm: "endbr64".to_string(),
            opcode: "endbr64".to_string(),
            bytes: "f30f1efa".to_string(),
            family: Some("cpu".to_string()),
            op_type: Some("null".to_string()),
        };
        let compact = CompactInstruction::from(&full);
        assert_eq!(compact.addr, "0x11e0");
        assert_eq!(compact.asm, "endbr64");
        assert_eq!(compact.size, 4);
    }

    #[test]
    fn test_compact_block_drops_decimal_fields() {
        let full = BasicBlockInfo {
            addr: 4576,
            addr_hex: "0x11e0".to_string(),
            size: 44,
            jump: Some(4663),
            jump_hex: Some("0x1237".to_string()),
            fail: Some(4620),
            fail_hex: Some("0x120c".to_string()),
            num_instructions: 1,
            instructions: vec![InstructionInfo {
                addr: 4576,
                addr_hex: "0x11e0".to_string(),
                size: 4,
                disasm: "endbr64".to_string(),
                opcode: "endbr64".to_string(),
                bytes: "f30f1efa".to_string(),
                family: Some("cpu".to_string()),
                op_type: Some("null".to_string()),
            }],
        };
        let compact = CompactBlock::from(&full);
        assert_eq!(compact.addr, "0x11e0");
        assert_eq!(compact.jump, Some("0x1237".to_string()));
        assert_eq!(compact.fail, Some("0x120c".to_string()));
        assert_eq!(compact.instructions.len(), 1);

        // Verify JSON doesn't contain decimal addr
        let json = serde_json::to_string(&compact).unwrap();
        assert!(!json.contains("\"addr\":4576"));
        assert!(json.contains("\"addr\":\"0x11e0\""));
    }

    #[test]
    fn test_compact_function_shortened_field_names() {
        let full = FunctionInfo {
            name: "main".to_string(),
            offset: 4576,
            offset_hex: "0x11e0".to_string(),
            size: 708,
            signature: Some("int main()".to_string()),
            calltype: Some("amd64".to_string()),
            cyclomatic_complexity: Some(20),
            num_basic_blocks: Some(25),
            num_instructions: Some(155),
            is_pure: Some(false),
            num_args: Some(0),
            num_locals: Some(19),
            stack_frame_size: None,
        };
        let compact = CompactFunction::from(&full);
        assert_eq!(compact.name, "main");
        assert_eq!(compact.addr, "0x11e0");
        assert_eq!(compact.cc, Some(20));
        assert_eq!(compact.blocks, Some(25));
        assert_eq!(compact.instrs, Some(155));

        // Verify no calltype, is_pure, num_args, num_locals in JSON
        let json = serde_json::to_string(&compact).unwrap();
        assert!(!json.contains("calltype"));
        assert!(!json.contains("is_pure"));
        assert!(!json.contains("num_args"));
        assert!(!json.contains("num_locals"));
        assert!(json.contains("\"cc\":20"));
    }

    #[test]
    fn test_compact_string_drops_paddr_size_type() {
        let full = StringEntry {
            vaddr: 8196,
            vaddr_hex: "0x2004".to_string(),
            paddr: 8196,
            size: 15,
            string_type: "ascii".to_string(),
            string: "Enter serial:".to_string(),
        };
        let compact = CompactStringEntry::from(&full);
        assert_eq!(compact.addr, "0x2004");
        assert_eq!(compact.string, "Enter serial:");

        let json = serde_json::to_string(&compact).unwrap();
        assert!(!json.contains("paddr"));
        assert!(!json.contains("vaddr"));
        assert!(!json.contains("ascii"));
    }

    #[test]
    fn test_compact_blocks_response_size_reduction() {
        // Build a response with 5 instructions to measure size difference
        let instructions: Vec<InstructionInfo> = (0..5).map(|i| InstructionInfo {
            addr: 4576 + i * 4,
            addr_hex: format!("{:#x}", 4576 + i * 4),
            size: 4,
            disasm: format!("mov eax, {}", i),
            opcode: format!("mov eax, {}", i),
            bytes: "b800000000".to_string(),
            family: Some("cpu".to_string()),
            op_type: Some("mov".to_string()),
        }).collect();

        let full = BasicBlocksResponse {
            function_name: "test".to_string(),
            function_addr: 4576,
            function_addr_hex: "0x11e0".to_string(),
            total_blocks: 1,
            blocks: vec![BasicBlockInfo {
                addr: 4576,
                addr_hex: "0x11e0".to_string(),
                size: 20,
                jump: None,
                jump_hex: None,
                fail: None,
                fail_hex: None,
                num_instructions: 5,
                instructions,
            }],
        };

        let full_json = serde_json::to_string(&full).unwrap();
        let compact = CompactBlocksResponse::from(&full);
        let compact_json = serde_json::to_string(&compact).unwrap();

        // Compact should be significantly smaller
        let ratio = compact_json.len() as f64 / full_json.len() as f64;
        assert!(ratio < 0.55, "Compact should be <55% of full size, got {:.1}%", ratio * 100.0);
    }

    #[test]
    fn test_compact_xrefs_response() {
        let full = XrefsResponse {
            target: "sym.imp.puts".to_string(),
            target_addr: 4384,
            target_addr_hex: "0x1120".to_string(),
            direction: "to".to_string(),
            count: 1,
            xrefs: vec![XrefEntry {
                from_addr: 5087,
                from_addr_hex: "0x13df".to_string(),
                from_function: Some("main".to_string()),
                from_name: Some("main".to_string()),
                to_addr: 4384,
                to_addr_hex: "0x1120".to_string(),
                to_function: Some("sym.imp.puts".to_string()),
                to_name: Some("sym.imp.puts".to_string()),
                xref_type: "call".to_string(),
                opcode: Some("call sym.imp.puts".to_string()),
                perm: Some("--x".to_string()),
                fcn_addr: Some(4576),
            }],
            xrefs_to: vec![],
            xrefs_from: vec![],
        };

        let compact = CompactXrefsResponse::from(&full);
        assert_eq!(compact.target, "sym.imp.puts");
        assert_eq!(compact.addr, "0x1120");
        assert_eq!(compact.count, 1);
        assert_eq!(compact.xrefs.len(), 1);
        assert_eq!(compact.xrefs[0].from, "0x13df");
        assert_eq!(compact.xrefs[0].from_name.as_deref(), Some("main"));
        assert_eq!(compact.xrefs[0].to, "0x1120");
        assert_eq!(compact.xrefs[0].xref_type, "call");
    }
}
