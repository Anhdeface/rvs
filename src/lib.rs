pub mod error;
pub mod response;
pub mod cli;
pub mod r2;
pub mod analysis;
pub mod patch;
pub mod compact;
pub mod agent;

pub use cli::{Cli, Commands, AnalyzeCommands, PatchCommands, AgentCommands, GraphType, GraphFormat, OutputFormat};
pub use error::AppError;
pub use response::{ApiResponse, ApiError};
pub use r2::R2Driver;
pub use analysis::xrefs::{XrefDirection, XrefKindFilter};
pub use agent::*;
