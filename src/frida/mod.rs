pub mod detect;
pub mod driver;
pub mod hook;
pub mod memory;
pub mod modules;
pub mod script;
pub mod target;
pub mod types;

pub use detect::{detect_r2frida, is_r2frida_available, probe_r2frida_env};
pub use driver::FridaDriver;
pub use hook::*;
pub use memory::*;
pub use modules::*;
pub use script::*;
pub use target::FridaTarget;
pub use types::*;

use std::time::Duration;
use crate::cli::{Cli, FridaCommands};
use crate::error::AppError;
use crate::response::ApiResponse;

/// Parsed runtime metadata from a target process probe.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TargetProbeInfo {
    pub pid: Option<u32>,
    pub arch: Option<String>,
    pub bits: Option<u32>,
    pub os: Option<String>,
}

/// Dynamically extracts target architecture, bitness, OS, and PID from probe output,
/// falling back to host environment constants if fields are absent.
pub fn parse_target_info(raw: &str) -> TargetProbeInfo {
    let mut info = TargetProbeInfo::default();
    let trimmed = raw.trim();

    if !trimmed.is_empty() {
        // 1. Try parsing JSON format (e.g. from :ij or JSON output)
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            info.pid = val.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32);
            info.arch = val.get("arch").and_then(|v| v.as_str()).map(String::from);
            info.bits = val.get("bits").and_then(|v| v.as_u64()).map(|b| b as u32);
            info.os = val.get("os").and_then(|v| v.as_str()).map(String::from);
        } else {
            // 2. Parse line-by-line key-value format (from :i)
            for line in trimmed.lines() {
                let l = line.trim();
                let (k, v) = if let Some((k, v)) = l.split_once(':') {
                    (k.trim().to_lowercase(), v.trim().to_string())
                } else if let Some((k, v)) = l.split_once(' ') {
                    (k.trim().to_lowercase(), v.trim().to_string())
                } else {
                    continue;
                };

                match k.as_str() {
                    "pid" => info.pid = v.parse::<u32>().ok(),
                    "arch" if !v.is_empty() => info.arch = Some(v),
                    "bits" => info.bits = v.parse::<u32>().ok(),
                    "os" if !v.is_empty() => info.os = Some(v),
                    _ => {}
                }
            }
        }
    }

    // 3. Dynamic host platform fallbacks
    if info.arch.is_none() {
        info.arch = Some(std::env::consts::ARCH.to_string());
    }
    if info.bits.is_none() {
        info.bits = Some(if cfg!(target_pointer_width = "64") { 64 } else { 32 });
    }
    if info.os.is_none() {
        info.os = Some(std::env::consts::OS.to_string());
    }

    info
}

/// Main entry point for dispatching Frida subcommands.
pub fn handle_frida_command(cli: &Cli, cmd: &FridaCommands) -> Result<String, AppError> {
    match cmd {
        FridaCommands::EnvCheck => {
            let status = detect_r2frida()?;
            let resp = ApiResponse::success("frida env-check", "host", status);
            resp.to_json(cli.pretty).map_err(AppError::JsonError)
        }

        FridaCommands::Attach { target, timeout, .. } => {
            let parsed_target = FridaTarget::parse_attach(target)?;
            let uri = parsed_target.to_uri();

            let driver = FridaDriver::new(&uri, cli.quiet)?;
            let driver = if let Some(secs) = timeout.or(cli.timeout) {
                driver.with_timeout(Duration::from_secs(secs))
            } else {
                driver
            };

            // Genuinely execute target process probe via driver
            let raw_info = driver.cmd("i")?;
            let probe = parse_target_info(&raw_info);

            let session_info = FridaSessionInfo {
                target: parsed_target.display_target(),
                target_uri: uri,
                pid: parsed_target.pid().or(probe.pid),
                process_name: parsed_target.process_name(),
                arch: probe.arch,
                bits: probe.bits,
                os: probe.os,
                connected: true,
            };

            let resp = ApiResponse::success("frida attach", parsed_target.display_target(), session_info);
            resp.to_json(cli.pretty).map_err(AppError::JsonError)
        }

        FridaCommands::Spawn { path, args, timeout, .. } => {
            let parsed_target = FridaTarget::parse_spawn(path.clone(), args.clone())?;
            let uri = parsed_target.to_uri();

            let driver = FridaDriver::new(&uri, cli.quiet)?;
            let driver = if let Some(secs) = timeout.or(cli.timeout) {
                driver.with_timeout(Duration::from_secs(secs))
            } else {
                driver
            };

            // Genuinely execute target process spawn probe via driver
            let raw_info = driver.cmd("i")?;
            let probe = parse_target_info(&raw_info);

            let session_info = FridaSessionInfo {
                target: parsed_target.display_target(),
                target_uri: uri,
                pid: probe.pid,
                process_name: parsed_target.process_name(),
                arch: probe.arch,
                bits: probe.bits,
                os: probe.os,
                connected: true,
            };

            let resp = ApiResponse::success("frida spawn", parsed_target.display_target(), session_info);
            resp.to_json(cli.pretty).map_err(AppError::JsonError)
        }

        FridaCommands::Modules { target, filter, limit, offset } => {
            handle_modules(cli, target, filter.as_deref(), *limit, *offset)
        }

        FridaCommands::Symbols {
            target,
            module,
            filter,
            limit,
            offset,
        } => handle_symbols(
            cli,
            target,
            module.as_deref(),
            filter.as_deref(),
            *limit,
            *offset,
        ),

        FridaCommands::Classes { target, filter, limit, offset } => {
            handle_classes(cli, target, filter.as_deref(), *limit, *offset)
        }

        FridaCommands::Hook { target, addr, format } => {
            handle_hook(cli, target, addr, format.as_deref())
        }

        FridaCommands::TraceRegs { target, addr, regs } => {
            handle_trace_regs(cli, target, addr, regs)
        }

        FridaCommands::HookReturn { target, addr, retval } => {
            handle_hook_return(cli, target, addr, retval)
        }

        FridaCommands::HooksList { target } => {
            handle_hooks_list(cli, target)
        }

        FridaCommands::HookRemove { target, id } => {
            handle_hook_remove(cli, target, id)
        }

        FridaCommands::Script {
            target,
            code,
            file,
            timeout,
        } => handle_script(cli, target, code.as_deref(), file.as_deref(), *timeout),

        FridaCommands::Rpc {
            target,
            method,
            args,
            timeout,
        } => handle_rpc(cli, target, method, args.as_deref(), *timeout),

        FridaCommands::MemRead { target, addr, len } => {
            handle_mem_read(cli, target, addr, *len)
        }

        FridaCommands::MemWrite {
            target,
            addr,
            data,
            protect,
        } => handle_mem_write(cli, target, addr, data, *protect),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target_info_json() {
        let json_raw = r#"{"arch": "arm64", "bits": 64, "os": "darwin", "pid": 4321}"#;
        let info = parse_target_info(json_raw);
        assert_eq!(info.arch, Some("arm64".to_string()));
        assert_eq!(info.bits, Some(64));
        assert_eq!(info.os, Some("darwin".to_string()));
        assert_eq!(info.pid, Some(4321));
    }

    #[test]
    fn test_parse_target_info_key_value_colon() {
        let text_raw = "arch: x86_64\nbits: 64\nos: linux\npid: 1234\n";
        let info = parse_target_info(text_raw);
        assert_eq!(info.arch, Some("x86_64".to_string()));
        assert_eq!(info.bits, Some(64));
        assert_eq!(info.os, Some("linux".to_string()));
        assert_eq!(info.pid, Some(1234));
    }

    #[test]
    fn test_parse_target_info_fallback_defaults() {
        let empty_raw = "";
        let info = parse_target_info(empty_raw);
        assert_eq!(info.arch, Some(std::env::consts::ARCH.to_string()));
        assert_eq!(info.os, Some(std::env::consts::OS.to_string()));
        assert_eq!(info.bits, Some(if cfg!(target_pointer_width = "64") { 64 } else { 32 }));
    }
}

