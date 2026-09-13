use serde::{Deserialize, Serialize};

/// Host environment status for r2frida instrumentation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaEnvStatus {
    pub installed: bool,
    pub radare2_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_path: Option<String>,
    pub supported_uris: Vec<String>,
    pub search_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

/// Dynamic session metadata for attached or spawned Frida processes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaSessionInfo {
    pub target: String,
    pub target_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub connected: bool,
}

// ── Modules, Symbols, Classes Responses ─────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaModuleEntry {
    pub name: String,
    pub base: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaModulesResponse {
    pub target: String,
    pub total: usize,
    pub modules: Vec<FridaModuleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaSymbolEntry {
    pub name: String,
    pub addr: String,
    pub size: u64,
    pub sym_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaSymbolsResponse {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    pub total: usize,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    pub symbols: Vec<FridaSymbolEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaClassEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaClassesResponse {
    pub target: String,
    pub total: usize,
    pub classes: Vec<FridaClassEntry>,
}

// ── Hooks Responses ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaHookResponse {
    pub target: String,
    pub addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub status: String,
    pub hook_type: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaTraceRegsResponse {
    pub target: String,
    pub addr: String,
    pub regs: Vec<String>,
    pub status: String,
    pub hook_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaHookReturnResponse {
    pub target: String,
    pub addr: String,
    pub retval: String,
    pub status: String,
    pub hook_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaHookInfo {
    pub id: u64,
    pub addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default)]
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaHooksListResponse {
    pub target: String,
    pub total: usize,
    pub hooks: Vec<FridaHookInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaHookRemoveResponse {
    pub target: String,
    pub id: String,
    pub removed: bool,
}

// ── Script & RPC Responses ──────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaScriptResponse {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub success: bool,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaRpcResponse {
    pub target: String,
    pub method: String,
    pub success: bool,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

// ── Memory Responses ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaMemReadResponse {
    pub target: String,
    pub addr_hex: String,
    pub length: usize,
    pub hex_bytes: String,
    pub ascii: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FridaMemWriteResponse {
    pub target: String,
    pub addr_hex: String,
    pub bytes_written: usize,
    pub data: String,
    pub verified: bool,
}
