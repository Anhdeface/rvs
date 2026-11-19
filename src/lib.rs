pub mod error;
pub mod response;
pub mod cli;
pub mod r2;
pub mod analysis;
pub mod patch;
pub mod compact;
pub mod agent;
pub mod frida;
pub mod debug;
pub mod apk;

pub use cli::{Cli, Commands, FridaCommands, AnalyzeCommands, PatchCommands, AgentCommands, GraphType, GraphFormat, OutputFormat};
pub use error::AppError;
pub use response::{ApiResponse, ApiError};
pub use r2::R2Driver;
pub use analysis::xrefs::{XrefDirection, XrefKindFilter};
pub use agent::*;
pub use frida::*;
pub use apk::{
    detect_elf_abi, is_binary_axml, ApkEntry, ApkPackage, ApkSource, ManifestInfo,
    decode_mutf8_lossy, decode_utf16le_lossy, sanitize_archive_entry_path, sanitize_identifier,
};
