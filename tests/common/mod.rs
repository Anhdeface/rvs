#![allow(dead_code)]

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

