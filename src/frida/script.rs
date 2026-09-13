use std::path::Path;
use std::time::Duration;
use crate::cli::Cli;
use crate::error::AppError;
use crate::frida::driver::FridaDriver;
use crate::frida::target::FridaTarget;
use crate::frida::types::{FridaRpcResponse, FridaScriptResponse};
use crate::response::ApiResponse;

/// Inject and evaluate custom JavaScript or script file (:eval / :.).
pub fn handle_script(
    cli: &Cli,
    target: &str,
    code: Option<&str>,
    file: Option<&Path>,
    timeout: Option<u64>,
) -> Result<String, AppError> {
    // 1. Argument and file existence validation BEFORE driver / env check
    if code.is_none() && file.is_none() {
        return Err(AppError::InvalidArgument(
            "Either --code or --file must be specified for script execution".to_string(),
        ));
    }
    if code.is_some() && file.is_some() {
        return Err(AppError::InvalidArgument(
            "Cannot specify both --code and --file for script execution".to_string(),
        ));
    }

    let (js_payload, file_str) = if let Some(path) = file {
        if !path.exists() {
            return Err(AppError::FileNotFound(path.display().to_string()));
        }
        if path.is_dir() {
            return Err(AppError::FileNotFound(format!(
                "Target script path is a directory, not a file: {}",
                path.display()
            )));
        }
        let metadata = std::fs::metadata(path).map_err(AppError::IoError)?;
        let is_special_device = !metadata.is_file();
        if !is_special_device {
            if metadata.len() == 0 {
                return Err(AppError::ZeroByteFile(path.display().to_string()));
            }
            let content = std::fs::read_to_string(path)?;
            if content.trim().is_empty() {
                return Err(AppError::InvalidArgument(
                    "Script file content cannot be empty".to_string(),
                ));
            }
            (content, Some(path.display().to_string()))
        } else {
            let content = std::fs::read_to_string(path)?;
            (content, Some(path.display().to_string()))
        }
    } else if let Some(c) = code {
        if c.trim().is_empty() {
            return Err(AppError::InvalidArgument("Script code cannot be empty".to_string()));
        }
        (c.to_string(), None)
    } else {
        return Err(AppError::InvalidArgument(
            "Either --file or inline code must be provided".to_string(),
        ));
    };

    // 2. Target validation
    let parsed_target = FridaTarget::parse_attach(target)?;

    // 3. Driver instantiation
    let mut driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;
    if let Some(secs) = timeout.or(cli.timeout) {
        driver = driver.with_timeout(Duration::from_secs(secs));
    }

    // 4. Execute :eval
    let cmd_str = format!(":eval {}", js_payload);
    let raw_output = driver.cmd(&cmd_str)?;

    let lower = raw_output.to_lowercase();
    if lower.contains("syntaxerror")
        || lower.contains("referenceerror")
        || lower.contains("typeerror")
        || (lower.contains("error:") && !lower.contains("0 error"))
        || lower.contains("unhandled exception")
        || lower.contains("throw")
    {
        return Err(AppError::FridaScriptError {
            reason: raw_output.trim().to_string(),
        });
    }

    let parsed_json = serde_json::from_str::<serde_json::Value>(raw_output.trim()).ok();

    let resp_data = FridaScriptResponse {
        target: parsed_target.display_target(),
        script: code.map(|s| s.to_string()),
        file: file_str,
        success: true,
        output: raw_output.trim().to_string(),
        result: parsed_json,
    };

    let resp = ApiResponse::success("frida script", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Invoke an exported Frida RPC method (rpc.exports.<method>).
pub fn handle_rpc(
    cli: &Cli,
    target: &str,
    method: &str,
    args: Option<&str>,
    timeout: Option<u64>,
) -> Result<String, AppError> {
    let trimmed_method = method.trim();
    if trimmed_method.is_empty() {
        return Err(AppError::InvalidArgument("RPC method name cannot be empty".to_string()));
    }
    let mut chars = trimmed_method.chars();
    let first = chars.next().ok_or_else(|| {
        AppError::InvalidArgument("RPC method name cannot be empty".to_string())
    })?;
    if (!first.is_ascii_alphabetic() && first != '_' && first != '$')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return Err(AppError::InvalidArgument(format!(
            "Invalid RPC method name '{method}': must be a valid JavaScript identifier (e.g. 'check_license')"
        )));
    }

    let parsed_target = FridaTarget::parse_attach(target)?;

    let mut driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;
    if let Some(secs) = timeout.or(cli.timeout) {
        driver = driver.with_timeout(Duration::from_secs(secs));
    }

    let invocation = match args {
        Some(a) if !a.trim().is_empty() => {
            let tr = a.trim();
            if tr.starts_with('[') && tr.ends_with(']') {
                format!("JSON.stringify(rpc.exports.{}(...{}))", trimmed_method, tr)
            } else {
                format!("JSON.stringify(rpc.exports.{}({}))", trimmed_method, tr)
            }
        }
        _ => format!("JSON.stringify(rpc.exports.{}())", trimmed_method),
    };

    let cmd_str = format!(":eval {}", invocation);
    let raw_output = driver.cmd(&cmd_str)?;

    let lower = raw_output.to_lowercase();
    if lower.contains("error:") || lower.contains("exception") {
        return Err(AppError::FridaScriptError {
            reason: raw_output.trim().to_string(),
        });
    }

    let parsed_json = serde_json::from_str::<serde_json::Value>(raw_output.trim()).ok();

    let resp_data = FridaRpcResponse {
        target: parsed_target.display_target(),
        method: trimmed_method.to_string(),
        success: true,
        output: raw_output.trim().to_string(),
        result: parsed_json,
    };

    let resp = ApiResponse::success("frida rpc", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn dummy_cli() -> Cli {
        Cli::parse_from(["rvs", "info"])
    }

    #[test]
    fn test_handle_script_dir_fails() {
        let cli = dummy_cli();
        let temp_dir = std::env::temp_dir();
        let err = handle_script(&cli, "0", None, Some(&temp_dir), None).unwrap_err();
        assert!(matches!(err, AppError::FileNotFound(_)));
    }

    #[test]
    fn test_handle_script_empty_file_fails() {
        let cli = dummy_cli();
        let dir = tempfile::tempdir().unwrap();
        let empty_js = dir.path().join("empty.js");
        std::fs::File::create(&empty_js).unwrap();
        let err = handle_script(&cli, "0", None, Some(&empty_js), None).unwrap_err();
        assert!(matches!(err, AppError::ZeroByteFile(_)));
    }

    #[test]
    fn test_handle_script_whitespace_file_fails() {
        let cli = dummy_cli();
        let dir = tempfile::tempdir().unwrap();
        let ws_js = dir.path().join("ws.js");
        std::fs::write(&ws_js, "   \n\t  ").unwrap();
        let err = handle_script(&cli, "0", None, Some(&ws_js), None).unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_handle_rpc_invalid_method_names() {
        let cli = dummy_cli();
        for bad_method in &["", "   ", "123foo", "foo bar", "bad;id", "bad-name", "bad@val"] {
            let err = handle_rpc(&cli, "0", bad_method, None, None).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidArgument(_)),
                "Expected InvalidArgument for {bad_method}, got {err:?}"
            );
        }
    }
}
