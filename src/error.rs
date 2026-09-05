use thiserror::Error;
use crate::response::ApiError;

/// Domain errors encountered during binary analysis, patching, or CLI operations.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Zero-byte empty file: {0}")]
    ZeroByteFile(String),

    #[error("Invalid or unsupported binary format: {0}")]
    InvalidBinary(String),

    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),

    #[error("Target address '{0}' is out of binary bounds")]
    AddressOutOfBounds(String),

    #[error("Decompilation failed for function '{function}': {reason}")]
    DecompilationFailed {
        function: String,
        reason: String,
    },

    #[error("Control flow analysis failed for function '{function}': {reason}")]
    FlowAnalysisFailed {
        function: String,
        reason: String,
    },

    #[error("Dynamic emulation failed for '{target}': {reason}")]
    EmulationFailed {
        target: String,
        reason: String,
    },

    #[error("Failed to assemble instruction '{instruction}': {details}")]
    AssemblyFailed {
        instruction: String,
        details: String,
    },

    #[error("Invalid hex string '{hex}': {reason}")]
    InvalidHexString {
        hex: String,
        reason: String,
    },

    #[error("String overflow: replacement string length ({replacement_length}) exceeds original length ({original_length}) at address {address}")]
    StringOverflow {
        original_length: usize,
        replacement_length: usize,
        address: String,
    },

    #[error("String not found in binary: '{0}'")]
    StringNotFound(String),

    #[error("Failed to create backup at '{0}'")]
    BackupFailed(String),

    #[error("Post-patch verification failed at address {address}: expected {expected}, found {actual}")]
    VerificationFailed {
        address: String,
        expected: String,
        actual: String,
    },

    #[error("Patch plan error: {0}")]
    PatchPlanError(String),

    #[error("Execution timed out: {0}")]
    Timeout(String),

    #[error("Radare2 execution error: {0}")]
    R2ExecutionError(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl AppError {
    /// Returns the standardized 7-level exit code:
    /// - 0: SUCCESS
    /// - 1: INVALID_ARGUMENT
    /// - 2: FILE_ERROR
    /// - 3: ANALYSIS_ERROR
    /// - 4: PATCH_ERROR
    /// - 5: TIMEOUT_ERROR
    /// - 6: INTERNAL_ERROR
    pub fn exit_code(&self) -> u8 {
        match self {
            AppError::InvalidArgument(_)
            | AppError::PatchPlanError(_) => 1,

            AppError::FileNotFound(_)
            | AppError::PermissionDenied(_)
            | AppError::ZeroByteFile(_) => 2,

            AppError::InvalidBinary(_)
            | AppError::SymbolNotFound(_)
            | AppError::AddressOutOfBounds(_)
            | AppError::DecompilationFailed { .. }
            | AppError::FlowAnalysisFailed { .. }
            | AppError::EmulationFailed { .. } => 3,

            AppError::AssemblyFailed { .. }
            | AppError::InvalidHexString { .. }
            | AppError::StringOverflow { .. }
            | AppError::StringNotFound(_)
            | AppError::BackupFailed(_)
            | AppError::VerificationFailed { .. } => 4,

            AppError::Timeout(_) => 5,

            AppError::IoError(e) => match e.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => 2,
                _ => 6,
            },

            AppError::R2ExecutionError(_)
            | AppError::Internal(_)
            | AppError::JsonError(_) => 6,
        }
    }

    /// Category name matching the exit code taxonomy
    pub fn category(&self) -> &'static str {
        match self.exit_code() {
            1 => "INVALID_ARGUMENT",
            2 => "FILE_ERROR",
            3 => "ANALYSIS_ERROR",
            4 => "PATCH_ERROR",
            5 => "TIMEOUT_ERROR",
            6 => "INTERNAL_ERROR",
            _ => "UNKNOWN_ERROR",
        }
    }

    /// Converts domain `AppError` to structured `ApiError` with actionable suggestion.
    pub fn to_api_error(&self) -> ApiError {
        let cat = self.category().to_string();
        let code_u8 = self.exit_code();

        match self {
            AppError::FileNotFound(msg) => ApiError::new("FILE_NOT_FOUND", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Verify the target file path exists and is accessible."),

            AppError::PermissionDenied(msg) => ApiError::new("PERMISSION_DENIED", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Check read/write permissions for the target binary file."),

            AppError::ZeroByteFile(msg) => ApiError::new("ZERO_BYTE_FILE", format!("File '{msg}' is empty (0 bytes)"))
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Provide a valid non-empty compiled binary."),

            AppError::InvalidBinary(msg) => ApiError::new("INVALID_BINARY", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Ensure the file is a valid executable (ELF, Mach-O, PE)."),

            AppError::SymbolNotFound(sym) => ApiError::new(
                "SYMBOL_NOT_FOUND",
                format!("Function or symbol '{sym}' not found in binary"),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion(format!(
                "Run 'rvs -f <file> analyze functions' or 'symbols' to discover valid symbols. Did you mean sym.{sym}?"
            )),

            AppError::AddressOutOfBounds(addr) => ApiError::new(
                "ADDRESS_OUT_OF_BOUNDS",
                format!("Target address '{addr}' is outside binary section boundaries"),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Inspect valid sections with 'rvs -f <file> info' to check virtual address mapping."),

            AppError::DecompilationFailed { function, reason } => ApiError::with_details(
                "DECOMPILATION_FAILED",
                format!("Failed to decompile function '{function}': {reason}"),
                serde_json::json!({ "function": function, "reason": reason }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Ensure the function exists and contains valid executable instructions."),

            AppError::FlowAnalysisFailed { function, reason } => ApiError::with_details(
                "FLOW_ANALYSIS_FAILED",
                format!("Control flow extraction failed for function '{function}': {reason}"),
                serde_json::json!({ "function": function, "reason": reason }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Check basic blocks using 'rvs -f <file> analyze blocks <func>'."),

            AppError::EmulationFailed { target, reason } => ApiError::with_details(
                "EMULATION_FAILED",
                format!("Dynamic emulation failed for '{target}': {reason}"),
                serde_json::json!({ "target": target, "reason": reason }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Verify target address or function contains executable instructions and preset registers are valid."),

            AppError::AssemblyFailed { instruction, details } => ApiError::with_details(
                "ASSEMBLY_FAILED",
                format!("Failed to assemble instruction '{instruction}'"),
                serde_json::json!({ "instruction": instruction, "details": details }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Check mnemonic syntax and operand bitness (e.g. 'mov eax, 1' or 'jmp 0x1479')."),

            AppError::InvalidHexString { hex, reason } => ApiError::with_details(
                "INVALID_HEX_STRING",
                format!("Invalid hexadecimal input '{hex}': {reason}"),
                serde_json::json!({ "hex": hex, "reason": reason }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Provide an even-length string containing only hex digits [0-9a-fA-F] without 0x prefix."),

            AppError::StringOverflow {
                original_length,
                replacement_length,
                address,
            } => ApiError::with_details(
                "STRING_OVERFLOW",
                format!(
                    "Replacement string length ({replacement_length}) exceeds original length ({original_length}) at {address} with strict length enabled"
                ),
                serde_json::json!({
                    "original_length": original_length,
                    "replacement_length": replacement_length,
                    "address": address
                }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Supply a replacement string <= original length or disable strict length (--strict-length=false)."),

            AppError::StringNotFound(s) => ApiError::new(
                "STRING_NOT_FOUND",
                format!("String '{s}' not found in binary sections"),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Run 'rvs -f <file> strings' to discover strings and their exact addresses."),

            AppError::BackupFailed(path) => ApiError::new(
                "BACKUP_FAILED",
                format!("Failed to create backup copy at '{path}'"),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Ensure destination directory is writable."),

            AppError::VerificationFailed { address, expected, actual } => ApiError::with_details(
                "VERIFICATION_FAILED",
                format!("Post-patch verification failed at {address}"),
                serde_json::json!({ "address": address, "expected": expected, "actual": actual }),
            )
            .with_category(cat)
            .with_exit_code(code_u8)
            .with_suggestion("Inspect permissions or check if target binary section is writable."),

            AppError::PatchPlanError(msg) => ApiError::new("PATCH_PLAN_ERROR", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Validate the patch plan JSON format (name, dry_run, steps with type, addr)."),

            AppError::Timeout(msg) => ApiError::new("TIMEOUT_EXPIRED", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Increase timeout limit using --timeout or scope down the analysis."),

            AppError::R2ExecutionError(msg) => ApiError::new("R2_EXECUTION_ERROR", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Verify radare2 is installed and functional on the system."),

            AppError::InvalidArgument(msg) => ApiError::new("INVALID_ARGUMENT", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Check usage options with 'rvs --help' or review argument parameters."),

            AppError::Internal(msg) => ApiError::new("INTERNAL_ERROR", msg)
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("An internal error occurred. Please file a bug report."),

            AppError::IoError(e) => ApiError::new("IO_ERROR", e.to_string())
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Check filesystem status and file access permissions."),

            AppError::JsonError(e) => ApiError::new("JSON_PARSE_ERROR", e.to_string())
                .with_category(cat)
                .with_exit_code(code_u8)
                .with_suggestion("Ensure the input JSON string is properly formatted and valid."),
        }
    }
}
