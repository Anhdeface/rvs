//! Compact output representations for agent-optimized consumption.
//! Reduces JSON output by 60-75% by eliminating redundant fields:
//! - Decimal addresses removed (keep only hex)
//! - Duplicate `disasm`/`opcode` merged into single `asm`
//! - Raw `bytes`, `family`, `type` fields stripped from instructions
//! - Shortened field names (`cyclomatic_complexity` → `cc`, `size` → `sz`, `num_basic_blocks` → `bb`, etc.)
//! - Redundant `paddr`, `string_type` stripped from strings
//! - Key-value map representation for strings ("0xaddr" -> "string")
//! - Full register dumps omitted in dynamic stepping and compact emulation
//! - Redundant instruction pointer register diffs suppressed in dynamic trace

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::agent::dynamic::AgentEmulateData;
use crate::agent::flow::AgentFlowData;
use crate::agent::triage::AgentTriageData;
use crate::agent::xrefs::AgentXrefsData;
use crate::analysis::blocks::{BasicBlockInfo, BasicBlocksResponse, InstructionInfo};
use crate::analysis::dynamic::{
    DynamicEmulateResponse, DynamicStepResponse, DynamicTraceResponse, RegisterDiff, ReturnValueInfo,
};
use crate::analysis::frame::{FrameBoundary, FunctionFrameInfo, PrologueEpilogueResponse};
use crate::analysis::functions::{FunctionInfo, FunctionsResponse};
use crate::analysis::graph::GraphResponse;
use crate::analysis::info::BinaryInfo;
use crate::analysis::strings::{StringEntry, StringsResponse};
use crate::analysis::symbols::{SymbolEntry, SymbolsResponse};
use crate::analysis::xrefs::{XrefEntry, XrefsResponse};

// ── Compact Instructions & Blocks ──────────────────

/// Compact instruction: essential fields only.
/// Before: addr, addr_hex, size, disasm, opcode, bytes, family, type (8 fields)
/// After:  addr, asm, size (3 fields)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactInstruction {
    /// Hex address (e.g. "0x11e0")
    pub addr: String,
    /// Assembly text
    pub asm: String,
    /// Instruction size in bytes
    pub size: u64,
}

/// Compact basic block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
/// After:  name, addr, sz, signature, cc, bb, ins (5-7 fields)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactFunction {
    pub name: String,
    pub addr: String,
    #[serde(rename = "sz")]
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Cyclomatic complexity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<u64>,
    /// Number of basic blocks
    #[serde(rename = "bb", skip_serializing_if = "Option::is_none")]
    pub blocks: Option<u64>,
    /// Number of instructions
    #[serde(rename = "ins", skip_serializing_if = "Option::is_none")]
    pub instrs: Option<u64>,
}

/// Compact functions response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactFunctionsResponse {
    pub count: usize,
    pub functions: Vec<CompactFunction>,
}

impl CompactFunction {
    pub fn from_info(src: &FunctionInfo, detail: bool) -> Self {
        Self {
            name: src.name.clone(),
            addr: src.offset_hex.clone(),
            size: src.size,
            signature: if detail { src.signature.clone() } else { None },
            cc: src.cyclomatic_complexity,
            blocks: src.num_basic_blocks,
            instrs: if detail { src.num_instructions } else { None },
        }
    }
}

impl From<&FunctionInfo> for CompactFunction {
    fn from(src: &FunctionInfo) -> Self {
        Self::from_info(src, false)
    }
}

impl CompactFunctionsResponse {
    pub fn from_response(src: &FunctionsResponse, detail: bool) -> Self {
        Self {
            count: src.count,
            functions: src.functions.iter().map(|f| CompactFunction::from_info(f, detail)).collect(),
        }
    }
}

impl From<&FunctionsResponse> for CompactFunctionsResponse {
    fn from(src: &FunctionsResponse) -> Self {
        Self::from_response(src, false)
    }
}

// ── Compact Strings ────────────────────────────────

/// Compact string entry (legacy/helper).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactStringEntry {
    pub addr: String,
    pub string: String,
}

/// Compact strings response: key-value map "0xaddr" -> "string" for token reduction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactStringsResponse {
    pub count: usize,
    pub strings: BTreeMap<String, String>,
}

impl From<&StringsResponse> for CompactStringsResponse {
    fn from(src: &StringsResponse) -> Self {
        let mut map = BTreeMap::new();
        for s in &src.strings {
            map.insert(s.vaddr_hex.clone(), s.string.clone());
        }
        Self {
            count: src.count,
            strings: map,
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

// ── Compact Symbols ────────────────────────────────

/// Compact symbol entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactSymbolEntry {
    pub name: String,
    pub addr: String,
    #[serde(rename = "t", alias = "type")]
    pub sym_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
}

/// Compact symbols response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactSymbolsResponse {
    pub count: usize,
    pub symbols: Vec<CompactSymbolEntry>,
}

impl From<&SymbolEntry> for CompactSymbolEntry {
    fn from(src: &SymbolEntry) -> Self {
        let bind = if src.bind.eq_ignore_ascii_case("LOCAL") || src.bind.is_empty() {
            None
        } else {
            Some(src.bind.clone())
        };
        Self {
            name: src.name.clone(),
            addr: src.vaddr_hex.clone(),
            sym_type: src.sym_type.clone(),
            bind,
        }
    }
}

impl From<SymbolEntry> for CompactSymbolEntry {
    fn from(src: SymbolEntry) -> Self {
        let bind = if src.bind.eq_ignore_ascii_case("LOCAL") || src.bind.is_empty() {
            None
        } else {
            Some(src.bind)
        };
        Self {
            name: src.name,
            addr: src.vaddr_hex,
            sym_type: src.sym_type,
            bind,
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

impl From<SymbolsResponse> for CompactSymbolsResponse {
    fn from(src: SymbolsResponse) -> Self {
        Self {
            count: src.count,
            symbols: src.symbols.into_iter().map(CompactSymbolEntry::from).collect(),
        }
    }
}

// ── Compact Binary Info ────────────────────────────

/// Compact binary info representation preserving essential decision signals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactBinaryInfo {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub entry_point_hex: String,
    pub security: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endian: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

impl From<&BinaryInfo> for CompactBinaryInfo {
    fn from(src: &BinaryInfo) -> Self {
        let mut sec = Vec::new();
        if src.security.canary { sec.push("canary".to_string()); }
        if src.security.nx { sec.push("nx".to_string()); }
        if src.security.pic { sec.push("pic".to_string()); }
        if src.security.relro != "none" && !src.security.relro.is_empty() {
            sec.push(format!("relro:{}", src.security.relro));
        }
        if src.security.stripped { sec.push("stripped".to_string()); }

        let endian = if src.endian != "little" && !src.endian.is_empty() {
            Some(src.endian.clone())
        } else {
            None
        };
        let os = if src.os != "linux" && !src.os.is_empty() {
            Some(src.os.clone())
        } else {
            None
        };

        Self {
            format: src.format.clone(),
            arch: src.arch.clone(),
            bits: src.bits,
            entry_point_hex: src.entry_point_hex.clone(),
            security: sec,
            endian,
            os,
        }
    }
}

// ── Compact Graph ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactGraphEdge {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub edge_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactGraphResponse {
    #[serde(rename = "type")]
    pub graph_type: String,
    pub target: String,
    pub nodes: usize,
    pub edges: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<Vec<CompactGraphEdge>>,
}

impl From<&GraphResponse> for CompactGraphResponse {
    fn from(src: &GraphResponse) -> Self {
        if src.graph_type == "callgraph" {
            Self {
                graph_type: src.graph_type.clone(),
                target: src.target.clone(),
                nodes: src.nodes.len(),
                edges: src.edges.len(),
                calls: src.adjacency.clone(),
                flow: None,
            }
        } else {
            let flow_edges = src.edges.iter().map(|e| CompactGraphEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                edge_type: e.edge_type.clone(),
            }).collect();
            Self {
                graph_type: src.graph_type.clone(),
                target: src.target.clone(),
                nodes: src.nodes.len(),
                edges: src.edges.len(),
                calls: None,
                flow: Some(flow_edges),
            }
        }
    }
}

// ── Compact Prologue/Epilogue ──────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactFrameBoundary {
    pub pattern: String,
    pub start: String,
    pub end: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactFunctionFrame {
    pub name: String,
    pub addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prologue: Option<CompactFrameBoundary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epilogue: Option<CompactFrameBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactPrologueEpilogueResponse {
    pub count: usize,
    pub functions: Vec<CompactFunctionFrame>,
}

impl From<&FrameBoundary> for CompactFrameBoundary {
    fn from(src: &FrameBoundary) -> Self {
        Self {
            pattern: src.pattern.clone(),
            start: src.start_addr_hex.clone(),
            end: src.end_addr_hex.clone(),
            size: src.size,
            instrs: src.instructions.iter().map(|i| i.opcode.clone()).collect(),
        }
    }
}

impl From<&FunctionFrameInfo> for CompactFunctionFrame {
    fn from(src: &FunctionFrameInfo) -> Self {
        Self {
            name: src.name.clone(),
            addr: src.addr_hex.clone(),
            prologue: src.prologue.as_ref().map(CompactFrameBoundary::from),
            epilogue: src.epilogue.as_ref().map(CompactFrameBoundary::from),
        }
    }
}

impl From<&PrologueEpilogueResponse> for CompactPrologueEpilogueResponse {
    fn from(src: &PrologueEpilogueResponse) -> Self {
        Self {
            count: src.count,
            functions: src.functions.iter().map(CompactFunctionFrame::from).collect(),
        }
    }
}

// ── Compact Agent Schemas ──────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactTriageFunction {
    pub name: String,
    pub addr: String,
    pub sz: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<u64>,
    #[serde(rename = "bb", skip_serializing_if = "Option::is_none")]
    pub blocks: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactAgentTriageData {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub entry: String,
    pub security: Vec<String>,
    pub total_functions: usize,
    pub total_strings: usize,
    pub top_functions: Vec<CompactTriageFunction>,
    pub interesting_strings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recommendations: Vec<String>,
}

impl From<&AgentTriageData> for CompactAgentTriageData {
    fn from(src: &AgentTriageData) -> Self {
        let mut sec = Vec::new();
        if let Some(ref s) = src.security {
            if s.canary == Some(true) { sec.push("canary".to_string()); }
            if s.nx == Some(true) { sec.push("nx".to_string()); }
            if s.pic == Some(true) { sec.push("pic".to_string()); }
            if let Some(ref r) = s.relro {
                if r != "none" && !r.is_empty() { sec.push(format!("relro:{}", r)); }
            }
            if s.stripped == Some(true) { sec.push("stripped".to_string()); }
        }

        let top_functions = src.top_functions.iter().take(5).map(|f| CompactTriageFunction {
            name: f.name.clone(),
            addr: f.addr_hex.clone(),
            sz: f.size,
            cc: f.complexity,
            blocks: f.num_blocks,
        }).collect();

        let interesting_strings = src.interesting_strings.iter().take(10).cloned().collect();
        let recommendations = src.recommendations.iter().take(2).cloned().collect();

        Self {
            format: src.format.clone(),
            arch: src.arch.clone(),
            bits: src.bits,
            entry: src.entry_point_hex.clone().unwrap_or_else(|| "0x0".to_string()),
            security: sec,
            total_functions: src.total_functions,
            total_strings: src.total_strings,
            top_functions,
            interesting_strings,
            recommendations,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactBranchGate {
    pub addr: String,
    pub cond: String,
    pub branch: String,
    pub jump: String,
    pub fail: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub gate_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactAgentFlowData {
    pub function: String,
    pub addr: String,
    pub total_blocks: usize,
    pub loops: usize,
    pub decision_nodes: Vec<CompactBranchGate>,
    pub exits: Vec<String>,
}

impl From<&AgentFlowData> for CompactAgentFlowData {
    fn from(src: &AgentFlowData) -> Self {
        let decision_nodes = src.decision_nodes.iter().map(|n| CompactBranchGate {
            addr: n.addr_hex.clone(),
            cond: n.condition_instruction.clone(),
            branch: n.branch_instruction.clone(),
            jump: n.jump_target_hex.clone(),
            fail: n.fail_target_hex.clone(),
            gate_type: n.gate_type.clone(),
        }).collect();

        let exits = src.exit_nodes.iter().map(|e| format!("{:#x}", e)).collect();

        Self {
            function: src.function_name.clone(),
            addr: src.function_addr_hex.clone(),
            total_blocks: src.total_blocks,
            loops: src.loop_count,
            decision_nodes,
            exits,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactCaller {
    pub function: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactCallee {
    pub function: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactDataRef {
    pub addr: String,
    #[serde(rename = "type")]
    pub ref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactAgentXrefsData {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    pub callers: Vec<CompactCaller>,
    pub callees: Vec<CompactCallee>,
    pub data_refs: Vec<CompactDataRef>,
}

impl From<&AgentXrefsData> for CompactAgentXrefsData {
    fn from(src: &AgentXrefsData) -> Self {
        let callers = src.callers.iter().map(|c| CompactCaller {
            function: c.function.clone(),
            at: c.call_site_hex.clone(),
        }).collect();

        let callees = src.callees.iter().map(|c| CompactCallee {
            function: c.function.clone(),
            at: c.call_site_hex.clone(),
        }).collect();

        let data_refs = src.data_refs.iter().map(|d| CompactDataRef {
            addr: d.addr_hex.clone(),
            ref_type: d.ref_type.clone(),
            preview: d.value_preview.clone(),
        }).collect();

        Self {
            target: src.target.clone(),
            addr: src.target_addr_hex.clone(),
            callers,
            callees,
            data_refs,
        }
    }
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

// ── Compact Dynamic Emulation & Trace ──────────────

/// Compact register modification representation for agent token budgets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactRegisterDiff {
    pub reg: String,
    #[serde(alias = "before_hex", alias = "before")]
    pub from: String,
    #[serde(alias = "after_hex", alias = "after")]
    pub to: String,
}

impl From<&RegisterDiff> for CompactRegisterDiff {
    fn from(src: &RegisterDiff) -> Self {
        Self {
            reg: src.reg.clone(),
            from: src.before_hex.clone(),
            to: src.after_hex.clone(),
        }
    }
}

/// Compact function return value representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactReturnValue {
    pub reg: String,
    #[serde(alias = "value_hex", alias = "value")]
    pub val: String,
}

impl From<&ReturnValueInfo> for CompactReturnValue {
    fn from(src: &ReturnValueInfo) -> Self {
        Self {
            reg: src.reg.clone(),
            val: src.value_hex.clone(),
        }
    }
}

/// Compact dynamic emulation response for agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactDynamicEmulateResponse {
    pub target: String,
    pub start: String,
    pub r#final: String,
    pub steps: usize,
    pub stop: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ret: Option<CompactReturnValue>,
    pub diff: Vec<CompactRegisterDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_after: Option<String>,
}

impl From<&DynamicEmulateResponse> for CompactDynamicEmulateResponse {
    fn from(src: &DynamicEmulateResponse) -> Self {
        Self {
            target: src.target.clone(),
            start: src.start_addr_hex.clone(),
            r#final: src.final_addr_hex.clone(),
            steps: src.steps_executed,
            stop: src.stop_reason.clone(),
            ret: src.return_value.as_ref().map(CompactReturnValue::from),
            diff: src.register_diff.iter().map(CompactRegisterDiff::from).collect(),
            mem_before: src.memory_before.clone(),
            mem_after: src.memory_after.clone(),
        }
    }
}

/// Compact branch outcome representation for compact agent emulation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactAgentBranchOutcome {
    pub gate_addr_hex: String,
    pub condition_instruction: String,
    pub branch_instruction: String,
    pub taken: bool,
    pub target_addr_hex: String,
}

/// Compact agent emulation summary data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactAgentEmulateData {
    pub function_name: String,
    pub start_addr_hex: String,
    pub final_addr_hex: String,
    pub steps_executed: usize,
    pub stop_reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<CompactReturnValue>,
    pub key_registers_changed: Vec<CompactRegisterDiff>,
    pub branches_encountered: Vec<CompactAgentBranchOutcome>,
}

impl From<&AgentEmulateData> for CompactAgentEmulateData {
    fn from(src: &AgentEmulateData) -> Self {
        Self {
            function_name: src.function_name.clone(),
            start_addr_hex: src.start_addr_hex.clone(),
            final_addr_hex: src.final_addr_hex.clone(),
            steps_executed: src.steps_executed,
            stop_reason: src.stop_reason.clone(),
            return_value: src.return_value.as_ref().map(CompactReturnValue::from),
            key_registers_changed: src.key_registers_changed.iter().map(CompactRegisterDiff::from).collect(),
            branches_encountered: src.branches_encountered.iter().map(|b| CompactAgentBranchOutcome {
                gate_addr_hex: b.gate_addr_hex.clone(),
                condition_instruction: b.condition_instruction.clone(),
                branch_instruction: b.branch_instruction.clone(),
                taken: b.taken,
                target_addr_hex: b.target_addr_hex.clone(),
            }).collect(),
        }
    }
}

/// Compact single step (or N steps) response for agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactDynamicStepResponse {
    pub curr: String,
    pub next: String,
    #[serde(alias = "instruction")]
    pub asm: String,
    pub diff: Vec<CompactRegisterDiff>,
}

impl From<&DynamicStepResponse> for CompactDynamicStepResponse {
    fn from(src: &DynamicStepResponse) -> Self {
        Self {
            curr: src.current_addr_hex.clone(),
            next: src.next_addr_hex.clone(),
            asm: src.instruction.clone(),
            diff: src.reg_changes.iter().map(CompactRegisterDiff::from).collect(),
        }
    }
}

/// A compact trace step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactTraceStep {
    pub step: usize,
    pub addr: String,
    pub asm: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<CompactRegisterDiff>,
}

/// Compact dynamic execution trace response for agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompactDynamicTraceResponse {
    pub target: String,
    pub start: String,
    pub steps: usize,
    pub trace: Vec<CompactTraceStep>,
}

impl From<&DynamicTraceResponse> for CompactDynamicTraceResponse {
    fn from(src: &DynamicTraceResponse) -> Self {
        Self {
            target: src.target.clone(),
            start: src.start_addr_hex.clone(),
            steps: src.total_steps,
            trace: src
                .trace
                .iter()
                .map(|s| {
                    // Suppress redundant instruction pointer register changes that match step address
                    let diff = s
                        .reg_changes
                        .iter()
                        .filter(|d| {
                            let is_redundant_ip = (d.reg == "rip" || d.reg == "eip" || d.reg == "pc")
                                && (d.after == s.addr || d.after_hex == s.addr_hex);
                            !is_redundant_ip
                        })
                        .map(CompactRegisterDiff::from)
                        .collect();

                    CompactTraceStep {
                        step: s.step,
                        addr: s.addr_hex.clone(),
                        asm: s.disasm.clone(),
                        diff,
                    }
                })
                .collect(),
        }
    }
}

// ── Basic Block Conversions ────────────────────────

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

// ── Tests ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::blocks::{BasicBlockInfo, BasicBlocksResponse, InstructionInfo};
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
        let compact = CompactFunction::from_info(&full, true);
        assert_eq!(compact.name, "main");
        assert_eq!(compact.addr, "0x11e0");
        assert_eq!(compact.size, 708);
        assert_eq!(compact.signature, Some("int main()".to_string()));
        assert_eq!(compact.cc, Some(20));
        assert_eq!(compact.blocks, Some(25));
        assert_eq!(compact.instrs, Some(155));

        let default_compact = CompactFunction::from(&full);
        assert_eq!(default_compact.signature, None);
        assert_eq!(default_compact.instrs, None);

        // Verify no calltype, is_pure, num_args, num_locals in JSON
        let json = serde_json::to_string(&compact).unwrap();
        assert!(!json.contains("calltype"));
        assert!(!json.contains("is_pure"));
        assert!(!json.contains("num_args"));
        assert!(!json.contains("num_locals"));
        assert!(json.contains("\"cc\":20"));
        assert!(json.contains("\"sz\":708"));
        assert!(json.contains("\"bb\":25"));
        assert!(json.contains("\"ins\":155"));
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

        let strings_resp = StringsResponse {
            count: 1,
            strings: vec![full],
        };
        let compact_resp = CompactStringsResponse::from(&strings_resp);
        assert_eq!(compact_resp.count, 1);
        assert_eq!(compact_resp.strings.len(), 1);
        assert_eq!(compact_resp.strings.get("0x2004"), Some(&"Enter serial:".to_string()));

        let json = serde_json::to_string(&compact_resp).unwrap();
        assert!(!json.contains("paddr"));
        assert!(!json.contains("vaddr"));
        assert!(!json.contains("ascii"));
        assert!(json.contains("\"0x2004\":\"Enter serial:\""));
    }

    #[test]
    fn test_compact_blocks_response_size_reduction() {
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

    #[test]
    fn test_compact_symbol_entry_omits_local_bind() {
        let local_sym = SymbolEntry {
            name: "test_local".to_string(),
            flagname: "test_local".to_string(),
            vaddr: 4096,
            vaddr_hex: "0x1000".to_string(),
            paddr: 4096,
            size: 32,
            bind: "LOCAL".to_string(),
            sym_type: "FUNC".to_string(),
            is_imported: false,
        };
        let compact = CompactSymbolEntry::from(&local_sym);
        assert_eq!(compact.bind, None);
        assert_eq!(compact.sym_type, "FUNC");
        let json = serde_json::to_string(&compact).unwrap();
        assert!(!json.contains("\"bind\""));
        assert!(json.contains("\"t\":\"FUNC\""));

        let global_sym = SymbolEntry {
            name: "test_global".to_string(),
            flagname: "test_global".to_string(),
            vaddr: 4096,
            vaddr_hex: "0x1000".to_string(),
            paddr: 4096,
            size: 32,
            bind: "GLOBAL".to_string(),
            sym_type: "FUNC".to_string(),
            is_imported: false,
        };
        let compact_global = CompactSymbolEntry::from(global_sym);
        assert_eq!(compact_global.bind, Some("GLOBAL".to_string()));
        let json_global = serde_json::to_string(&compact_global).unwrap();
        assert!(json_global.contains("\"bind\":\"GLOBAL\""));
    }

    #[test]
    fn test_compact_dynamic_step_response() {
        let full = DynamicStepResponse {
            current_addr: 4576,
            current_addr_hex: "0x11e0".to_string(),
            next_addr: 4580,
            next_addr_hex: "0x11e4".to_string(),
            instruction: "push rbx".to_string(),
            steps: 1,
            reg_changes: vec![RegisterDiff {
                reg: "rip".to_string(),
                before: 4576,
                before_hex: "0x11e0".to_string(),
                after: 4580,
                after_hex: "0x11e4".to_string(),
            }],
            final_registers: BTreeMap::new(),
        };
        let compact = CompactDynamicStepResponse::from(&full);
        assert_eq!(compact.curr, "0x11e0");
        assert_eq!(compact.next, "0x11e4");
        assert_eq!(compact.asm, "push rbx");
        assert_eq!(compact.diff.len(), 1);
        assert_eq!(compact.diff[0].from, "0x11e0");
        assert_eq!(compact.diff[0].to, "0x11e4");

        let json = serde_json::to_string(&compact).unwrap();
        assert!(!json.contains("final_registers"));
        assert!(json.contains("\"curr\":\"0x11e0\""));
        assert!(json.contains("\"next\":\"0x11e4\""));
    }

    #[test]
    fn test_compact_dynamic_trace_suppresses_redundant_ip() {
        use crate::analysis::dynamic::TraceStepInfo;

        let full = DynamicTraceResponse {
            target: "main".to_string(),
            start_addr: 4576,
            start_addr_hex: "0x11e0".to_string(),
            total_steps: 1,
            trace: vec![TraceStepInfo {
                step: 1,
                addr: 4580,
                addr_hex: "0x11e4".to_string(),
                disasm: "push rbx".to_string(),
                opcode: "push rbx".to_string(),
                reg_changes: vec![
                    RegisterDiff {
                        reg: "rip".to_string(),
                        before: 4576,
                        before_hex: "0x11e0".to_string(),
                        after: 4580,
                        after_hex: "0x11e4".to_string(),
                    },
                    RegisterDiff {
                        reg: "rsp".to_string(),
                        before: 1000,
                        before_hex: "0x3e8".to_string(),
                        after: 992,
                        after_hex: "0x3e0".to_string(),
                    },
                ],
            }],
        };

        let compact = CompactDynamicTraceResponse::from(&full);
        assert_eq!(compact.trace.len(), 1);
        // "rip" was redundant because after == 4580 (matching addr 4580)
        assert_eq!(compact.trace[0].diff.len(), 1);
        assert_eq!(compact.trace[0].diff[0].reg, "rsp");
    }
}
