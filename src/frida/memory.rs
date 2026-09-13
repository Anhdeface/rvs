use crate::cli::{Cli, OutputFormat};
use crate::compact::{CompactFridaMemReadResponse, CompactFridaMemWriteResponse};
use crate::error::AppError;
use crate::frida::driver::FridaDriver;
use crate::frida::hook::validate_and_normalize_addr;
use crate::frida::target::FridaTarget;
use crate::frida::types::{FridaMemReadResponse, FridaMemWriteResponse};
use crate::response::ApiResponse;

/// Read live memory bytes from target process address space (:x).
pub fn handle_mem_read(
    cli: &Cli,
    target: &str,
    addr: &str,
    len: usize,
) -> Result<String, AppError> {
    if len == 0 {
        return Err(AppError::InvalidArgument(
            "Memory read length must be greater than 0".to_string(),
        ));
    }
    if len > 1024 * 1024 {
        return Err(AppError::InvalidArgument(
            "Memory read length exceeds maximum allowed limit (1MB)".to_string(),
        ));
    }

    let norm_addr = validate_and_normalize_addr(addr)?;
    let parsed_target = FridaTarget::parse_attach(target)?;
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    let js_code = format!(
        r#"(function() {{
            try {{
                var p = ptr("{}");
                var buf = Memory.readByteArray(p, {});
                if (!buf) return JSON.stringify({{ error: "Memory read returned null" }});
                var u8 = new Uint8Array(buf);
                var hex = "";
                for (var i = 0; i < u8.length; i++) {{
                    var b = u8[i].toString(16);
                    hex += (b.length === 1 ? "0" + b : b);
                }}
                return JSON.stringify({{ hex: hex, len: u8.length }});
            }} catch(e) {{
                return JSON.stringify({{ error: e.toString() }});
            }}
        }})()"#,
        norm_addr, len
    );

    let raw_output = driver.cmd(&format!(":eval {}", js_code))?;
    let val: serde_json::Value = serde_json::from_str(raw_output.trim()).map_err(|_| {
        AppError::MemoryAccessError {
            addr: norm_addr.clone(),
            reason: format!("Unexpected memory read output: {raw_output}"),
        }
    })?;

    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        return Err(AppError::MemoryAccessError {
            addr: norm_addr,
            reason: err.to_string(),
        });
    }

    let hex_bytes = val.get("hex").and_then(|v| v.as_str()).unwrap_or_default();
    let bytes: Vec<u8> = (0..hex_bytes.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= hex_bytes.len() {
                u8::from_str_radix(&hex_bytes[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect();

    let mut ascii = String::with_capacity(bytes.len());
    for &b in &bytes {
        if (0x20..=0x7e).contains(&b) {
            ascii.push(b as char);
        } else {
            ascii.push('.');
        }
    }

    let is_compact = cli.compact || cli.format == OutputFormat::Agent;
    if is_compact {
        let resp_data = CompactFridaMemReadResponse {
            addr: norm_addr,
            hex: hex_bytes.to_string(),
            ascii: Some(ascii),
        };
        let resp = ApiResponse::success("frida mem-read", parsed_target.display_target(), resp_data);
        return resp.to_json(cli.pretty).map_err(AppError::JsonError);
    }

    let resp_data = FridaMemReadResponse {
        target: parsed_target.display_target(),
        addr_hex: norm_addr,
        length: bytes.len(),
        hex_bytes: hex_bytes.to_string(),
        ascii,
    };

    let resp = ApiResponse::success("frida mem-read", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Write raw hex bytes directly into live process memory (:w).
pub fn handle_mem_write(
    cli: &Cli,
    target: &str,
    addr: &str,
    data: &str,
    protect: bool,
) -> Result<String, AppError> {
    // 1. Validate hex string BEFORE driver or env check
    let trimmed = data.trim();
    let clean_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    if clean_hex.is_empty()
        || !clean_hex.len().is_multiple_of(2)
        || !clean_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AppError::InvalidArgument(format!(
            "Invalid hex data string '{data}': must contain only hexadecimal digits with even length"
        )));
    }

    let norm_addr = validate_and_normalize_addr(addr)?;
    let parsed_target = FridaTarget::parse_attach(target)?;
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    let mut bytes = Vec::with_capacity(clean_hex.len() / 2);
    for i in (0..clean_hex.len()).step_by(2) {
        let b = u8::from_str_radix(&clean_hex[i..i + 2], 16).map_err(|e| {
            AppError::InvalidArgument(format!("Failed to parse hex bytes at index {i}: {e}"))
        })?;
        bytes.push(b);
    }
    let byte_count = bytes.len();
    let byte_array_str = format!("{:?}", bytes);

    let js_code = format!(
        r#"(function() {{
            try {{
                var p = ptr("{}");
                var len = {};
                if ({}) {{
                    Memory.protect(p, len, "rwx");
                }}
                Memory.writeByteArray(p, {});
                var readBack = Memory.readByteArray(p, len);
                var u8 = new Uint8Array(readBack);
                var verified = true;
                var exp = {};
                for (var i = 0; i < len; i++) {{
                    if (u8[i] !== exp[i]) {{ verified = false; break; }}
                }}
                return JSON.stringify({{ written: len, verified: verified, success: true }});
            }} catch(e) {{
                return JSON.stringify({{ error: e.toString(), success: false }});
            }}
        }})()"#,
        norm_addr, byte_count, protect, byte_array_str, byte_array_str
    );

    let raw_output = driver.cmd(&format!(":eval {}", js_code))?;
    let val: serde_json::Value = serde_json::from_str(raw_output.trim()).map_err(|_| {
        AppError::MemoryAccessError {
            addr: norm_addr.clone(),
            reason: format!("Unexpected memory write output: {raw_output}"),
        }
    })?;

    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        return Err(AppError::MemoryAccessError {
            addr: norm_addr,
            reason: err.to_string(),
        });
    }

    let verified = val.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);

    let is_compact = cli.compact || cli.format == OutputFormat::Agent;
    if is_compact {
        let resp_data = CompactFridaMemWriteResponse {
            addr: norm_addr,
            bytes: byte_count,
            verified,
        };
        let resp = ApiResponse::success("frida mem-write", parsed_target.display_target(), resp_data);
        return resp.to_json(cli.pretty).map_err(AppError::JsonError);
    }

    let resp_data = FridaMemWriteResponse {
        target: parsed_target.display_target(),
        addr_hex: norm_addr,
        bytes_written: byte_count,
        data: clean_hex.to_string(),
        verified,
    };

    let resp = ApiResponse::success("frida mem-write", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}
