use crate::cli::{Cli, DebugCommands};
use crate::error::AppError;

pub fn handle_debug_command(_cli: &Cli, _cmd: &DebugCommands) -> Result<String, AppError> {
    Err(AppError::InvalidArgument("Native dynamic debugging is not yet implemented".to_string()))
}
