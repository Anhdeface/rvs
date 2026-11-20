#![allow(dead_code)]
#![allow(clippy::all)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn default_none<T>() -> Option<T> {
    None
}

/// Standard API Response Envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T = serde_json::Value> {
    pub success: bool,
    pub command: String,
    pub target: String,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub format_version: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default = "default_none")]
    pub data: Option<T>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<ApiError>,
}

/// Standard API Error Details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub exit_code: Option<u8>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    #[serde(default)]
    pub suggestion: Option<String>,
}

/// Payload for `info` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoData {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub endian: String,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub entry_point: Option<u64>,
    #[serde(default)]
    pub entry_point_hex: Option<String>,
    #[serde(default)]
    pub security: Option<SecurityInfo>,
    #[serde(default)]
    pub sections_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    #[serde(default)]
    pub canary: Option<bool>,
    #[serde(default)]
    pub nx: Option<bool>,
    #[serde(default)]
    pub pic: Option<bool>,
    #[serde(default)]
    pub relro: Option<String>,
    #[serde(default)]
    pub stripped: Option<bool>,
}

/// Payload for `analyze functions` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionsData {
    #[serde(default)]
    pub count: usize,
    pub functions: Vec<FunctionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub offset_hex: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub calltype: Option<String>,
    #[serde(default)]
    pub cyclomatic_complexity: Option<u64>,
    #[serde(default)]
    pub num_basic_blocks: Option<u64>,
    #[serde(default)]
    pub num_instructions: Option<u64>,
    #[serde(default)]
    pub is_pure: Option<bool>,
    #[serde(default)]
    pub num_args: Option<u64>,
    #[serde(default)]
    pub num_locals: Option<u64>,
}

/// Payload for `analyze blocks` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksData {
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub function_addr: Option<u64>,
    #[serde(default)]
    pub function_addr_hex: Option<String>,
    #[serde(default)]
    pub total_blocks: Option<usize>,
    pub blocks: Vec<BlockInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub addr: u64,
    #[serde(default)]
    pub addr_hex: Option<String>,
    pub size: u64,
    #[serde(default)]
    pub jump: Option<u64>,
    #[serde(default)]
    pub jump_hex: Option<String>,
    #[serde(default)]
    pub fail: Option<u64>,
    #[serde(default)]
    pub fail_hex: Option<String>,
    #[serde(default)]
    pub num_instructions: Option<usize>,
    #[serde(default)]
    pub instructions: Option<Vec<InstructionInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub addr: u64,
    #[serde(default)]
    pub addr_hex: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub disasm: Option<String>,
    #[serde(default)]
    pub opcode: Option<String>,
    #[serde(default)]
    pub bytes: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(rename = "type", default)]
    pub inst_type: Option<String>,
}

/// Payload for `analyze prologue-epilogue` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrologueEpilogueData {
    #[serde(default)]
    pub count: Option<usize>,
    pub functions: Vec<FunctionFrameInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFrameInfo {
    pub name: String,
    #[serde(default)]
    pub addr: u64,
    #[serde(default)]
    pub addr_hex: Option<String>,
    #[serde(default)]
    pub prologue: Option<FrameSegment>,
    #[serde(default)]
    pub epilogue: Option<FrameSegment>,
    #[serde(default)]
    pub epilogues: Option<Vec<FrameSegment>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameSegment {
    #[serde(default)]
    pub detected: Option<bool>,
    #[serde(default)]
    pub start_addr: Option<u64>,
    #[serde(default)]
    pub start_addr_hex: Option<String>,
    #[serde(default)]
    pub end_addr: Option<u64>,
    #[serde(default)]
    pub end_addr_hex: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub instructions: Option<Vec<FrameInstruction>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameInstruction {
    #[serde(default)]
    pub addr: Option<u64>,
    #[serde(default)]
    pub addr_hex: Option<String>,
    #[serde(default)]
    pub opcode: Option<String>,
    #[serde(default)]
    pub disasm: Option<String>,
    #[serde(default)]
    pub bytes: Option<String>,
}

/// Payload for `analyze graph` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphData {
    #[serde(default)]
    pub graph_type: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub nodes: Option<Vec<GraphNode>>,
    #[serde(default)]
    pub edges: Option<Vec<GraphEdge>>,
    #[serde(default)]
    pub rendered: Option<String>,
    #[serde(default)]
    pub adjacency: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(rename = "type", default)]
    pub node_type: Option<String>,
    #[serde(default)]
    pub addr: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    #[serde(rename = "type", default)]
    pub edge_type: Option<String>,
}

/// Payload for `strings` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsData {
    #[serde(default)]
    pub count: usize,
    pub strings: Vec<StringEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub string: String,
    #[serde(default)]
    pub vaddr: Option<u64>,
    #[serde(default)]
    pub paddr: Option<u64>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub length: Option<usize>,
}

/// Payload for `symbols` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolsData {
    #[serde(default)]
    pub count: usize,
    pub symbols: Vec<SymbolEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    pub name: String,
    #[serde(default)]
    pub flagname: Option<String>,
    #[serde(default)]
    pub vaddr: Option<u64>,
    #[serde(default)]
    pub vaddr_hex: Option<String>,
    #[serde(default)]
    pub paddr: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(rename = "type", default)]
    pub sym_type: Option<String>,
    #[serde(default)]
    pub is_imported: Option<bool>,
}


/// Payload for `patch` commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchData {
    #[serde(default)]
    pub address: Option<u64>,
    #[serde(default)]
    pub address_hex: Option<String>,
    #[serde(default)]
    pub patch_type: Option<String>,
    #[serde(default)]
    pub original_bytes: Option<String>,
    #[serde(default)]
    pub patched_bytes: Option<String>,
    #[serde(default)]
    pub disasm_before: Option<String>,
    #[serde(default)]
    pub disasm_after: Option<String>,
    #[serde(default)]
    pub bytes_modified: Option<usize>,
    #[serde(default)]
    pub backup_path: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
}

/// Payload for `analyze xrefs` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefsData {
    pub target: String,
    #[serde(default)]
    pub target_addr: Option<u64>,
    #[serde(default)]
    pub target_addr_hex: Option<String>,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub xrefs_to: Vec<XrefEntry>,
    #[serde(default)]
    pub xrefs_from: Vec<XrefEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefEntry {
    #[serde(default)]
    pub from_addr: u64,
    #[serde(default)]
    pub from_addr_hex: Option<String>,
    #[serde(default)]
    pub to_addr: u64,
    #[serde(default)]
    pub to_addr_hex: Option<String>,
    #[serde(rename = "type", default)]
    pub xref_type: String,
    #[serde(default)]
    pub from_function: Option<String>,
    #[serde(default)]
    pub to_function: Option<String>,
    #[serde(default)]
    pub opcode: Option<String>,
}

/// Payload for `agent triage` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTriageData {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub endian: String,
    #[serde(default)]
    pub entry_point: Option<u64>,
    #[serde(default)]
    pub entry_point_hex: Option<String>,
    #[serde(default)]
    pub security: Option<SecurityInfo>,
    #[serde(default)]
    pub total_functions: usize,
    #[serde(default)]
    pub total_strings: usize,
    #[serde(default)]
    pub top_functions: Vec<TriageFunctionSummary>,
    #[serde(default)]
    pub interesting_strings: Vec<String>,
    #[serde(default)]
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageFunctionSummary {
    pub name: String,
    #[serde(default)]
    pub addr: u64,
    #[serde(default)]
    pub addr_hex: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub complexity: Option<u64>,
    #[serde(default)]
    pub num_blocks: Option<usize>,
}

/// Payload for `agent decompile` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDecompileData {
    pub function_name: String,
    #[serde(default)]
    pub function_addr: u64,
    #[serde(default)]
    pub function_addr_hex: String,
    #[serde(default)]
    pub size: u64,
    pub pseudo_c: String,
    #[serde(default)]
    pub blocks_count: usize,
    #[serde(default)]
    pub instructions_count: usize,
    #[serde(default)]
    pub calls: Vec<String>,
    #[serde(default)]
    pub strings_referenced: Vec<String>,
}

/// Payload for `agent flow` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFlowData {
    pub function_name: String,
    #[serde(default)]
    pub function_addr: u64,
    #[serde(default)]
    pub function_addr_hex: String,
    #[serde(default)]
    pub total_blocks: usize,
    #[serde(default)]
    pub decision_nodes: Vec<BranchGateNode>,
    #[serde(default)]
    pub exit_nodes: Vec<u64>,
    #[serde(default)]
    pub loop_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchGateNode {
    pub addr: u64,
    pub addr_hex: String,
    #[serde(default)]
    pub condition_instruction: String,
    #[serde(default)]
    pub branch_instruction: String,
    #[serde(default)]
    pub jump_target: u64,
    #[serde(default)]
    pub jump_target_hex: String,
    #[serde(default)]
    pub fail_target: u64,
    #[serde(default)]
    pub fail_target_hex: String,
    #[serde(default)]
    pub gate_type: Option<String>,
}

/// Payload for `agent xrefs` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentXrefsData {
    pub target: String,
    #[serde(default)]
    pub target_addr: Option<u64>,
    #[serde(default)]
    pub target_addr_hex: Option<String>,
    #[serde(default)]
    pub callers: Vec<CallerSummary>,
    #[serde(default)]
    pub callees: Vec<CalleeSummary>,
    #[serde(default)]
    pub data_refs: Vec<DataRefSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerSummary {
    pub function: String,
    #[serde(default)]
    pub call_site: u64,
    #[serde(default)]
    pub call_site_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalleeSummary {
    pub function: String,
    #[serde(default)]
    pub call_site: u64,
    #[serde(default)]
    pub call_site_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRefSummary {
    pub addr: u64,
    pub addr_hex: String,
    pub ref_type: String,
    #[serde(default)]
    pub value_preview: Option<String>,
}

/// Schema for `agent patch-plan` inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPlan {
    pub name: String,
    #[serde(default)]
    pub dry_run: bool,
    pub steps: Vec<PatchPlanStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPatchPlanResult {
    pub plan_name: String,
    pub applied: bool,
    pub dry_run: bool,
    pub total_steps: usize,
    pub steps_executed: usize,
    pub step_results: Vec<PatchStepResult>,
    #[serde(default)]
    pub backup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchStepResult {
    pub step_index: usize,
    pub step_type: String,
    pub addr: u64,
    pub addr_hex: String,
    pub success: bool,
    #[serde(default)]
    pub original_bytes: Option<String>,
    #[serde(default)]
    pub patched_bytes: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

// =============================================================================
// APK and Android Analysis Payload Structures
// =============================================================================

/// Language detection entry in inspect payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageDetectionData {
    pub language: String,
    pub confidence: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// APK Container inspection payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkInspectData {
    #[serde(default)]
    pub source_type: String, // "archive", "directory", "standalone"
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub version_name: Option<String>,
    #[serde(default)]
    pub version_code: Option<u32>,
    #[serde(default)]
    pub has_manifest: bool,
    #[serde(default)]
    pub is_manifest_binary: bool,
    #[serde(default)]
    pub dex_files: Vec<String>,
    #[serde(default)]
    pub native_libraries: std::collections::HashMap<String, Vec<String>>,
    #[serde(default)]
    pub languages: Vec<LanguageDetectionData>,
}

/// Compact APK Container inspection payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactApkInspectData {
    #[serde(default)]
    pub src: String,
    #[serde(default)]
    pub pkg: Option<String>,
    #[serde(default)]
    pub ver: Option<String>,
    #[serde(default)]
    pub code: Option<u32>,
    #[serde(default)]
    pub manifest: bool,
    #[serde(default)]
    pub binary_manifest: bool,
    #[serde(default)]
    pub dex: Vec<String>,
    #[serde(default)]
    pub so: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub langs: Vec<String>,
}

/// APK Manifest payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestInfoData {
    #[serde(default)]
    pub package_name: String,
    #[serde(default)]
    pub version_code: Option<u32>,
    #[serde(default)]
    pub version_name: Option<String>,
    #[serde(default)]
    pub min_sdk_version: Option<u32>,
    #[serde(default)]
    pub target_sdk_version: Option<u32>,
    #[serde(default)]
    pub debuggable: bool,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub activities: Vec<String>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub receivers: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub raw_xml: Option<String>,
}

/// DEX analysis payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexAnalysisData {
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub classes_count: usize,
    #[serde(default)]
    pub methods_count: usize,
    #[serde(default)]
    pub strings_count: usize,
    #[serde(default)]
    pub classes: Vec<DexClassSummaryData>,
    #[serde(default)]
    pub strings: Option<Vec<String>>,
    #[serde(default)]
    pub smali: Option<String>,
    #[serde(default)]
    pub decompiled: Option<String>,
    #[serde(default)]
    pub summary: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexClassSummaryData {
    pub name: String,
    #[serde(default)]
    pub super_class: Option<String>,
    #[serde(default)]
    pub access_flags: u32,
    #[serde(default)]
    pub methods: Vec<DexMethodSummaryData>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub detailed_fields: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub interfaces: Option<Vec<String>>,
    #[serde(default)]
    pub source_file: Option<String>,
    #[serde(default)]
    pub annotations: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub dex_source: Option<String>,
    #[serde(default)]
    pub smali: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMethodSummaryData {
    pub name: String,
    pub signature: String,
    #[serde(default)]
    pub access_flags: u32,
    #[serde(default)]
    pub code_offset: Option<u64>,
    #[serde(default)]
    pub registers_size: Option<u16>,
    #[serde(default)]
    pub insns_size: Option<u32>,
    #[serde(default)]
    pub disassembly: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub cfg: Option<serde_json::Value>,
    #[serde(default)]
    pub xrefs: Option<serde_json::Value>,
    #[serde(default)]
    pub annotations: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub smali: Option<String>,
    #[serde(default)]
    pub decompiled: Option<String>,
}

/// Resources analysis payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesData {
    pub total_resources: usize,
    pub total_assets: usize,
    #[serde(default)]
    pub has_arsc: bool,
    #[serde(default)]
    pub arsc_packages: Vec<ArscPackageData>,
    #[serde(default)]
    pub entries: Option<Vec<ResourceEntryData>>,
    #[serde(default)]
    pub extracted: Option<ExtractedResourceData>,
    #[serde(default)]
    pub dump_dir: Option<String>,
    #[serde(default)]
    pub dumped_files_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArscPackageData {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub types_count: usize,
    #[serde(default)]
    pub string_pool_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntryData {
    pub name: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub entry_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedResourceData {
    pub name: String,
    pub size: usize,
    pub is_xml: bool,
    pub content: String,
}

/// Signature analysis payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureData {
    pub is_signed: bool,
    #[serde(default)]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub signing_block_present: bool,
    #[serde(default)]
    pub signers: Vec<SignerInfoData>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub verification_errors: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// APK unpack payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkUnpackData {
    pub destination: PathBuf,
    pub engine: String,
    pub file_count: usize,
    pub manifest_extracted: bool,
    pub resources_extracted: bool,
    pub smali_generated: bool,
    #[serde(default)]
    pub agent_summary: Option<rvs::apk::container::AgentSummary>,
    #[serde(default)]
    pub repairs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfoData {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub signature_algorithm: String,
    pub sha256_fingerprint: String,
    pub sha1_fingerprint: String,
    #[serde(default)]
    pub md5_fingerprint: Option<String>,
}

/// Native .so JNI payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSoData {
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub abi: Option<String>,
    #[serde(default)]
    pub is_64_bit: bool,
    #[serde(default)]
    pub bits: Option<u32>,
    #[serde(default)]
    pub elf_type: Option<String>,
    #[serde(default)]
    pub endianness: Option<String>,
    #[serde(default)]
    pub entry_point: Option<u64>,
    #[serde(default)]
    pub soname: Option<String>,
    #[serde(default)]
    pub needed_libraries: Vec<String>,
    #[serde(default)]
    pub jni_functions: Vec<JniFunctionData>,
    #[serde(default)]
    pub exported_symbols: Vec<String>,
    #[serde(default)]
    pub imported_symbols: Vec<String>,
    #[serde(default)]
    pub symbols: Vec<NativeSymbolData>,
    #[serde(default)]
    pub register_natives_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JniFunctionData {
    pub name: String,
    #[serde(default)]
    pub demangled_class: Option<String>,
    #[serde(default)]
    pub demangled_method: Option<String>,
    #[serde(default)]
    pub address: u64,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub is_exported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSymbolData {
    pub name: String,
    #[serde(default)]
    pub demangled_name: Option<String>,
    pub address: u64,
    pub size: u64,
    pub sym_type: String,
    pub binding: String,
    pub is_import: bool,
}

/// Compact JNI function payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactJniFunctionData {
    pub name: String,
    #[serde(default)]
    pub cls: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    pub addr: String,
    pub sz: u64,
}

/// Compact Native .so payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactNativeSoData {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub abi: String,
    #[serde(default)]
    pub is_64: bool,
    #[serde(default)]
    pub elf_type: String,
    #[serde(default)]
    pub endian: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub soname: Option<String>,
    #[serde(default)]
    pub deps: Vec<String>,
    #[serde(default)]
    pub jni: Vec<CompactJniFunctionData>,
    #[serde(default)]
    pub exports: Vec<String>,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub reg_natives: bool,
}

/// Fluent builder for synthetic APK containers for integration testing.
pub struct SyntheticApkBuilder {
    temp_dir: TempDir,
    apk_path: PathBuf,
    entries: Vec<(String, Vec<u8>)>,
    fake_encryption_lfh: bool,
    fake_encryption_cd: bool,
    raw_mutations: Vec<Box<dyn FnOnce(&mut Vec<u8>)>>,
}

impl SyntheticApkBuilder {
    pub fn new(name: &str) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir for synthetic APK");
        let apk_path = temp_dir.path().join(name);
        Self {
            temp_dir,
            apk_path,
            entries: Vec::new(),
            fake_encryption_lfh: false,
            fake_encryption_cd: false,
            raw_mutations: Vec::new(),
        }
    }

    pub fn with_file(mut self, path: &str, content: &[u8]) -> Self {
        self.entries.push((path.to_string(), content.to_vec()));
        self
    }

    pub fn with_manifest(self, package: &str) -> Self {
        let manifest = format!("<manifest package=\"{}\" />", package);
        self.with_file("AndroidManifest.xml", manifest.as_bytes())
    }

    pub fn with_dex(self, dex_name: &str, dex_bytes: &[u8]) -> Self {
        self.with_file(dex_name, dex_bytes)
    }

    pub fn with_dex_markers(self, dex_name: &str, markers: &[&str]) -> Self {
        let mut content = b"dex\n035\0".to_vec();
        for m in markers {
            content.extend_from_slice(m.as_bytes());
            content.push(0);
        }
        self.with_file(dex_name, &content)
    }

    pub fn with_asset(self, asset_path: &str, content: &[u8]) -> Self {
        let path = if asset_path.starts_with("assets/") {
            asset_path.to_string()
        } else {
            format!("assets/{}", asset_path)
        };
        self.with_file(&path, content)
    }

    pub fn with_native_so(self, abi: &str, lib_name: &str, elf_bytes: &[u8]) -> Self {
        let path = format!("lib/{}/{}", abi, lib_name);
        self.with_file(&path, elf_bytes)
    }

    pub fn with_react_native(self) -> Self {
        self.with_manifest("com.example.reactnative")
            .with_dex_markers(
                "classes.dex",
                &["Lcom/facebook/react/ReactActivity;", "com.facebook.react.ReactPackage"],
            )
            .with_asset("index.android.bundle", b"var __BUNDLE__ = true;")
            .with_native_so("arm64-v8a", "libreactnativejni.so", b"\x7fELF_libreactnativejni")
            .with_native_so("arm64-v8a", "libhermes.so", b"\x7fELF_libhermes")
    }

    pub fn with_flutter(self) -> Self {
        self.with_manifest("com.example.flutter")
            .with_dex_markers(
                "classes.dex",
                &["Lio/flutter/embedding/android/FlutterActivity;", "io.flutter.embedding.engine.FlutterEngine"],
            )
            .with_asset("flutter_assets/kernel_blob.bin", b"FLUTTER_SNAPSHOT_KERNEL")
            .with_native_so("arm64-v8a", "libflutter.so", b"\x7fELF_libflutter")
            .with_native_so("arm64-v8a", "libapp.so", b"\x7fELF_libapp")
    }

    pub fn with_fake_encryption(mut self, lfh: bool, cd: bool) -> Self {
        self.fake_encryption_lfh = lfh;
        self.fake_encryption_cd = cd;
        self
    }

    pub fn with_path_traversal_entry(self, name: &str, content: &[u8]) -> Self {
        self.with_file(name, content)
    }

    pub fn with_arsc(self, arsc_bytes: &[u8]) -> Self {
        self.with_file("resources.arsc", arsc_bytes)
    }

    pub fn with_andresguard_structure(
        self,
        _resource_id: u32,
        obfuscated_path: &str,
        content: &[u8],
    ) -> Self {
        let dummy_arsc = synthesize_resilient_arsc_bytes(false, false, false);
        self.with_file(obfuscated_path, content)
            .with_arsc(&dummy_arsc)
            .with_manifest("com.example.andresguard")
    }

    pub fn with_raw_mutation<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut Vec<u8>) + 'static,
    {
        self.raw_mutations.push(Box::new(f));
        self
    }

    pub fn build(self) -> (TempDir, PathBuf) {
        use std::io::Write;
        let mut zip_bytes = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            let opt = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, content) in &self.entries {
                zip.start_file(name, opt).expect("Failed to start zip file");
                zip.write_all(content).expect("Failed to write zip content");
            }
            zip.finish().expect("Failed to finish zip file");
        }

        if self.fake_encryption_lfh {
            apply_zip_lfh_fake_encryption(&mut zip_bytes);
        }
        if self.fake_encryption_cd {
            apply_zip_cd_fake_encryption(&mut zip_bytes);
        }
        for mutation in self.raw_mutations {
            mutation(&mut zip_bytes);
        }

        fs::write(&self.apk_path, &zip_bytes).expect("Failed to write apk file");
        (self.temp_dir, self.apk_path)
    }
}

/// Sets GPBF bit 0 (0x0001) in ZIP Local File Headers (LFH) at offset +6
pub fn apply_zip_lfh_fake_encryption(bytes: &mut [u8]) {
    let sig = [0x50, 0x4B, 0x03, 0x04];
    let len = bytes.len();
    let mut i = 0;
    while i + 30 <= len {
        if bytes[i..i + 4] == sig {
            bytes[i + 6] |= 0x01;
            let name_len = u16::from_le_bytes([bytes[i + 26], bytes[i + 27]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[i + 28], bytes[i + 29]]) as usize;
            i += 30 + name_len + extra_len;
        } else {
            i += 1;
        }
    }
}

/// Sets GPBF bit 0 (0x0001) in ZIP Central Directory File Headers (CDFH) at offset +8
pub fn apply_zip_cd_fake_encryption(bytes: &mut [u8]) {
    let sig = [0x50, 0x4B, 0x01, 0x02];
    let len = bytes.len();
    let mut i = 0;
    while i + 46 <= len {
        if bytes[i..i + 4] == sig {
            bytes[i + 8] |= 0x01;
            let name_len = u16::from_le_bytes([bytes[i + 28], bytes[i + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[i + 30], bytes[i + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[i + 32], bytes[i + 33]]) as usize;
            i += 46 + name_len + extra_len + comment_len;
        } else {
            i += 1;
        }
    }
}

/// Synthesize an APK container with fake encryption bit 0 set in LFH, CD, or both
pub fn synthesize_fake_encryption_apk(
    entries: &[(&str, &[u8])],
    lfh_bit: bool,
    cd_bit: bool,
) -> (TempDir, PathBuf) {
    let mut builder = SyntheticApkBuilder::new("fake_encryption.apk")
        .with_fake_encryption(lfh_bit, cd_bit);
    for (name, content) in entries {
        builder = builder.with_file(name, content);
    }
    builder.build()
}

/// Pure-Rust Adler-32 implementation for Dalvik DEX checksum validation
pub fn adler32(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = (s1 + b as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    (s2 << 16) | s1
}

/// Pure-Rust SHA-1 implementation (RFC 3174) for Dalvik DEX header hashing
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Recomputes SHA-1 and Adler-32 checksums in a DEX byte buffer in-place
pub fn recompute_dex_checksums(bytes: &mut [u8]) {
    if bytes.len() < 32 {
        return;
    }
    let sha1_digest = sha1(&bytes[32..]);
    bytes[12..32].copy_from_slice(&sha1_digest);

    let adler = adler32(&bytes[12..]);
    bytes[8..12].copy_from_slice(&adler.to_le_bytes());
}

/// Encodes an unsigned integer as ULEB128
pub fn encode_uleb128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Synthesize a minimal valid DEX file with arbitrary MUTF-8 string sequences
pub fn synthesize_mutf8_dex(strings: &[&[u8]]) -> Vec<u8> {
    let header_size = 0x70usize;
    let string_ids_size = strings.len();
    let string_ids_off = header_size;

    let mut string_data_bytes = Vec::new();
    let mut string_data_offsets = Vec::new();
    let current_data_off = string_ids_off + (string_ids_size * 4);

    for s in strings {
        let utf16_len = s.len() as u32;
        let mut encoded = encode_uleb128(utf16_len);
        encoded.extend_from_slice(s);
        encoded.push(0x00);

        string_data_offsets.push(current_data_off + string_data_bytes.len());
        string_data_bytes.extend_from_slice(&encoded);
    }

    while (string_data_bytes.len() % 4) != 0 {
        string_data_bytes.push(0);
    }

    let map_off = current_data_off + string_data_bytes.len();
    let map_items: [(u16, u16, u32, u32); 4] = [
        (0x0000, 0, 1, 0),
        (0x0001, 0, string_ids_size as u32, string_ids_off as u32),
        (0x2002, 0, string_ids_size as u32, current_data_off as u32),
        (0x1000, 0, 1, map_off as u32),
    ];

    let mut map_data = Vec::new();
    map_data.extend_from_slice(&(map_items.len() as u32).to_le_bytes());
    for (itype, unused, isize, ioff) in map_items {
        map_data.extend_from_slice(&itype.to_le_bytes());
        map_data.extend_from_slice(&unused.to_le_bytes());
        map_data.extend_from_slice(&isize.to_le_bytes());
        map_data.extend_from_slice(&ioff.to_le_bytes());
    }

    let file_size = map_off + map_data.len();
    let data_off = current_data_off;
    let data_size = file_size - current_data_off;

    let mut header = vec![0u8; header_size];
    header[0..8].copy_from_slice(b"dex\n035\0");
    header[0x20..0x24].copy_from_slice(&(file_size as u32).to_le_bytes());
    header[0x24..0x28].copy_from_slice(&(header_size as u32).to_le_bytes());
    header[0x28..0x2C].copy_from_slice(&0x12345678u32.to_le_bytes());
    header[0x34..0x38].copy_from_slice(&(map_off as u32).to_le_bytes());
    header[0x38..0x3C].copy_from_slice(&(string_ids_size as u32).to_le_bytes());
    header[0x3C..0x40].copy_from_slice(&(string_ids_off as u32).to_le_bytes());
    header[0x68..0x6C].copy_from_slice(&(data_size as u32).to_le_bytes());
    header[0x6C..0x70].copy_from_slice(&(data_off as u32).to_le_bytes());

    let mut string_ids_table = Vec::new();
    for soff in string_data_offsets {
        string_ids_table.extend_from_slice(&(soff as u32).to_le_bytes());
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(&header);
    payload.extend_from_slice(&string_ids_table);
    payload.extend_from_slice(&string_data_bytes);
    payload.extend_from_slice(&map_data);

    recompute_dex_checksums(&mut payload);
    payload
}

/// Synthesize a DEX file containing invalid Dalvik opcodes in dead code after return-void
pub fn synthesize_dead_code_dex(dead_bytes: &[u8], corrupt_debug: bool) -> Vec<u8> {
    let src = fixture_path("sample_classes.dex");
    let mut data = fs::read(&src).expect("Failed to read sample_classes.dex fixture");

    let pattern = [0x0e, 0x00];
    if let Some(pos) = data.windows(2).position(|w| w == pattern) {
        let dead_len = dead_bytes.len().min(16);
        let replace_start = pos + 2;
        if replace_start + dead_len <= data.len() {
            data[replace_start..replace_start + dead_len].copy_from_slice(&dead_bytes[..dead_len]);
        }
    }

    if corrupt_debug && data.len() > 107944 {
        data[107940..107944].copy_from_slice(&0x00010000u32.to_le_bytes());
    }

    recompute_dex_checksums(&mut data);
    data
}

/// Synthesize an Android binary resources.arsc table with optional padded header, fake chunks, and corrupt offsets
pub fn synthesize_resilient_arsc_bytes(
    pad_header_size: bool,
    inject_unknown_chunks: bool,
    corrupt_offsets: bool,
) -> Vec<u8> {
    fn build_pool(strings: &[&str], corrupt: bool) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut str_data = Vec::new();

        for s in strings {
            offsets.push(str_data.len() as u32);
            let s_bytes = s.as_bytes();
            str_data.push((s.len() & 0x7F) as u8);
            str_data.push((s_bytes.len() & 0x7F) as u8);
            str_data.extend_from_slice(s_bytes);
            str_data.push(0);
        }
        while (str_data.len() % 4) != 0 {
            str_data.push(0);
        }

        let h_size = 28u16;
        let count = if corrupt {
            0xFFFFu32
        } else {
            strings.len() as u32
        };
        let start = (h_size as usize) + (strings.len() * 4);
        let total = (start + str_data.len()) as u32;

        let mut h = Vec::new();
        h.extend_from_slice(&0x0001u16.to_le_bytes());
        h.extend_from_slice(&h_size.to_le_bytes());
        h.extend_from_slice(&total.to_le_bytes());
        h.extend_from_slice(&count.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0x00000100u32.to_le_bytes());
        h.extend_from_slice(&(start as u32).to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());

        for (idx, &off) in offsets.iter().enumerate() {
            if corrupt && idx == offsets.len() - 1 {
                h.extend_from_slice(&0x7FFFFFFFu32.to_le_bytes());
            } else {
                h.extend_from_slice(&off.to_le_bytes());
            }
        }

        h.extend_from_slice(&str_data);
        h
    }

    let global_pool = build_pool(&["app_name", "SyntheticTarget", "res/values/strings.xml", "r/d/a.png"], corrupt_offsets);
    let type_pool = build_pool(&["attr", "string", "xml", "drawable"], false);
    let key_pool = build_pool(&["app_name", "welcome_message", "api_endpoint", "icon"], false);

    let pkg_h_size = 288u16;
    let type_off = pkg_h_size as u32;
    let key_off = type_off + (type_pool.len() as u32);
    let pkg_total = key_off + (key_pool.len() as u32);

    let pkg_name = "com.example.synthetic.target";
    let mut pkg_name_utf16 = Vec::new();
    for c in pkg_name.encode_utf16() {
        pkg_name_utf16.extend_from_slice(&c.to_le_bytes());
    }
    while pkg_name_utf16.len() < 256 {
        pkg_name_utf16.push(0);
    }
    pkg_name_utf16.truncate(256);

    let mut pkg_chunk = Vec::new();
    pkg_chunk.extend_from_slice(&0x0200u16.to_le_bytes());
    pkg_chunk.extend_from_slice(&pkg_h_size.to_le_bytes());
    pkg_chunk.extend_from_slice(&pkg_total.to_le_bytes());
    pkg_chunk.extend_from_slice(&0x7Fu32.to_le_bytes());
    pkg_chunk.extend_from_slice(&pkg_name_utf16);
    pkg_chunk.extend_from_slice(&type_off.to_le_bytes());
    pkg_chunk.extend_from_slice(&0u32.to_le_bytes());
    pkg_chunk.extend_from_slice(&key_off.to_le_bytes());
    pkg_chunk.extend_from_slice(&0u32.to_le_bytes());
    pkg_chunk.extend_from_slice(&0u32.to_le_bytes());
    pkg_chunk.extend_from_slice(&type_pool);
    pkg_chunk.extend_from_slice(&key_pool);

    let mut unknown_chunks = Vec::new();
    if inject_unknown_chunks {
        unknown_chunks.extend_from_slice(&0x0000u16.to_le_bytes());
        unknown_chunks.extend_from_slice(&8u16.to_le_bytes());
        unknown_chunks.extend_from_slice(&16u32.to_le_bytes());
        unknown_chunks.extend_from_slice(&[0u8; 8]);

        unknown_chunks.extend_from_slice(&0xFFFFu16.to_le_bytes());
        unknown_chunks.extend_from_slice(&8u16.to_le_bytes());
        unknown_chunks.extend_from_slice(&24u32.to_le_bytes());
        unknown_chunks.extend_from_slice(&[0xAAu8; 16]);
    }

    let table_h_size = if pad_header_size { 28u16 } else { 12u16 };
    let table_total = (table_h_size as usize)
        + unknown_chunks.len()
        + global_pool.len()
        + pkg_chunk.len();

    let mut table_header = Vec::new();
    table_header.extend_from_slice(&0x0002u16.to_le_bytes());
    table_header.extend_from_slice(&table_h_size.to_le_bytes());
    table_header.extend_from_slice(&(table_total as u32).to_le_bytes());
    table_header.extend_from_slice(&1u32.to_le_bytes());

    if pad_header_size {
        table_header.extend_from_slice(&[0xCCu8; 16]);
    }

    let mut full_arsc = Vec::new();
    full_arsc.extend_from_slice(&table_header);
    full_arsc.extend_from_slice(&unknown_chunks);
    full_arsc.extend_from_slice(&global_pool);
    full_arsc.extend_from_slice(&pkg_chunk);
    full_arsc
}

/// Synthesize an Android binary resources.arsc table containing mixed UTF-16LE surrogate and ASCII stream
pub fn synthesize_utf16_surrogate_arsc_bytes() -> Vec<u8> {
    let mut arsc = synthesize_resilient_arsc_bytes(false, false, false);
    // Find the package name UTF-16LE characters for "synthetic" and inject unpaired surrogate bytes
    let target: Vec<u8> = "synthetic".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    if let Some(pos) = arsc.windows(target.len()).position(|w| w == target.as_slice()) {
        let surrogate = utf16le_unpaired_low_surrogate();
        arsc[pos..pos + surrogate.len()].copy_from_slice(surrogate);
    }
    arsc
}

/// Helper returning Dalvik MUTF-8 2-byte null encoding (0xC0, 0x80)
pub fn mutf8_two_byte_null() -> &'static [u8] {
    b"\xC0\x80"
}

/// Helper returning Dalvik MUTF-8 6-byte surrogate pair encoding (U+10400)
pub fn mutf8_surrogate_pair() -> &'static [u8] {
    b"\xED\xA0\x81\xED\xB0\x80"
}

/// Helper returning Dalvik MUTF-8 lone high surrogate (U+D800)
pub fn mutf8_lone_high_surrogate() -> &'static [u8] {
    b"\xED\xA0\x80"
}

/// Helper returning Dalvik MUTF-8 lone low surrogate (U+DC00)
pub fn mutf8_lone_low_surrogate() -> &'static [u8] {
    b"\xED\xB0\x80"
}

/// Helper returning UTF-16LE unpaired high surrogate (0xD800 followed by 'A')
pub fn utf16le_unpaired_high_surrogate() -> &'static [u8] {
    &[0x00, 0xD8, 0x41, 0x00]
}

/// Helper returning UTF-16LE unpaired low surrogate (0xDC00 followed by 'B')
pub fn utf16le_unpaired_low_surrogate() -> &'static [u8] {
    &[0x00, 0xDC, 0x42, 0x00]
}

/// Helper returning adversarial string with ANSI CSI color codes
pub fn adversarial_ansi_string() -> &'static str {
    "\x1b[31;1mcom.evil.malicious\x1b[0m"
}

/// Helper returning adversarial string with BiDi Right-to-Left Override (U+202E)
pub fn adversarial_bidi_string() -> &'static str {
    "app_\u{202E}cod.exe\u{202C}.apk"
}

/// Helper returning adversarial string with stacked Zalgo combining diacritics
pub fn adversarial_zalgo_string() -> &'static str {
    "Z\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}\u{0306}\u{0307}\u{0308}\u{0309}algo"
}

/// Helper returning adversarial string with ANSI CSI cursor hiding/showing controls
pub fn adversarial_cursor_hide_string() -> &'static str {
    "\x1b[?25lHiddenPayload\x1b[?25h"
}

/// Helper returning adversarial string with ANSI OSC window title manipulation
pub fn adversarial_osc_title_string() -> &'static str {
    "\x1b]0;PwnedTitle\x07CleanTarget"
}

/// Helper to get the path to test fixtures
pub fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir.join("tests").join("fixtures").join(name);
    if !fixture.exists() {
        // Run compile script if fixture is missing
        let compile_script = manifest_dir
            .join("tests")
            .join("fixtures")
            .join("compile_fixtures.sh");
        if compile_script.exists() {
            let status = Command::new(&compile_script)
                .status()
                .expect("Failed to run compile_fixtures.sh");
            assert!(status.success(), "compile_fixtures.sh failed");
        }
    }
    fixture
}

/// Helper to create a temporary copy of a test fixture for mutating/patching tests
pub fn create_temp_fixture(name: &str) -> (TempDir, PathBuf) {
    let src = fixture_path(name);
    assert!(src.exists(), "Source fixture does not exist: {:?}", src);

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let dest = temp_dir.path().join(name);
    fs::copy(&src, &dest).expect("Failed to copy fixture to temp dir");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms).unwrap();
    }

    (temp_dir, dest)
}

/// Resolve the path to the `rvs` binary
pub fn rvs_bin_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rvs") {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_debug = manifest_dir.join("target").join("debug").join("rvs");
    if target_debug.exists() {
        return target_debug;
    }
    // Fallback: build with cargo
    let status = Command::new("cargo")
        .args(["build", "--bin", "rvs"])
        .current_dir(&manifest_dir)
        .status()
        .expect("Failed to invoke cargo build");
    assert!(status.success(), "cargo build --bin rvs failed");
    target_debug
}

/// Execute `rvs` with arguments and return raw `Output`
pub fn run_rvs(args: &[&str]) -> Output {
    let bin = rvs_bin_path();
    Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {:?} with args {:?}: {}", bin, args, e))
}

/// Execute `rvs` with arguments and parse JSON `ApiResponse<T>`
pub fn run_rvs_json<T: DeserializeOwned>(args: &[&str]) -> (ApiResponse<T>, Output) {
    let output = run_rvs(args);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let response: ApiResponse<T> = match serde_json::from_slice(&output.stdout) {
        Ok(res) => res,
        Err(e) => {
            let clean_stdout = stdout_str.replace('\x1b', "^[");
            let clean_stderr = String::from_utf8_lossy(&output.stderr).replace('\x1b', "^[");
            panic!(
                "Failed to parse JSON response from rvs.\nExit Status: {:?}\nArgs: {:?}\nError: {}\nStdout: {}\nStderr: {}",
                output.status.code(),
                args,
                e,
                clean_stdout,
                clean_stderr
            );
        }
    };
    (response, output)
}

/// Execute a binary (e.g. test fixture or patched binary) and return exit code, stdout, and stderr
pub fn run_target_binary(bin_path: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    for attempt in 0..5 {
        match Command::new(bin_path).args(args).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                return (output.status.code(), stdout, stderr);
            }
            Err(e) if e.raw_os_error() == Some(26) && attempt < 4 => {
                // ETXTBSY ("Text file busy - os error 26"): wait 20ms for kernel file lock to release
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => {
                panic!(
                    "Failed to execute target binary {:?} with args {:?}: {}",
                    bin_path, args, e
                );
            }
        }
    }
    panic!("Failed to execute target binary after retries: {:?}", bin_path);
}

/// Create an `assert_cmd::Command` for opaque-box testing of the `rvs` binary
pub fn assert_cmd_rvs() -> assert_cmd::Command {
    let bin = rvs_bin_path();
    assert_cmd::Command::new(bin)
}

/// Parse JSONL output stream into a vector of deserialized objects
pub fn parse_jsonl<T: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut items = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<T>(trimmed) {
            Ok(item) => items.push(item),
            Err(e) => return Err(format!("Failed to parse line {} as JSON: {}\nLine: {}", idx + 1, e, trimmed)),
        }
    }
    Ok(items)
}

