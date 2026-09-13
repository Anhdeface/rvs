use serde::Deserialize;
use serde_json::Value;
use crate::cli::Cli;
use crate::error::AppError;
use crate::frida::driver::FridaDriver;
use crate::frida::target::FridaTarget;
use crate::frida::types::{
    FridaHookInfo, FridaHookRemoveResponse, FridaHookResponse, FridaHookReturnResponse,
    FridaHooksListResponse, FridaTraceRegsResponse,
};
use crate::response::ApiResponse;

#[derive(Debug, Deserialize)]
struct RawHookInfo {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    addr: Option<Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    count: Option<u64>,
}

fn extract_addr_hex(val: &Value) -> String {
    match val {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                format!("{u:#x}")
            } else {
                "0x0".to_string()
            }
        }
        Value::String(s) => {
            if s.starts_with("0x") || s.starts_with("0X") {
                s.to_lowercase()
            } else if let Ok(u) = s.parse::<u64>() {
                format!("{u:#x}")
            } else if let Ok(u) = u64::from_str_radix(s, 16) {
                format!("{u:#x}")
            } else {
                s.clone()
            }
        }
        _ => "0x0".to_string(),
    }
}

/// Validates format specifiers for r2frida argument tracing (:dtf).
pub fn validate_hook_format(fmt: &str) -> Result<(), AppError> {
    const VALID_CHARS: &[char] = &[
        '^', '+', 'i', 'x', 'z', 'w', 'a', 'h', 'O', 'p', 's', 'c', 'v',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    for c in fmt.chars() {
        if !VALID_CHARS.contains(&c) {
            return Err(AppError::InvalidArgument(format!(
                "Invalid format specifier character '{c}' in format string '{fmt}'. Valid characters are: ^, +, i, x, z, w, a, h, O, p, s, c, v."
            )));
        }
    }
    Ok(())
}

/// Validates target address and detects out-of-bounds addresses like 0xffffffffffffffff.
pub fn validate_and_normalize_addr(addr: &str) -> Result<String, AppError> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidArgument("Address cannot be empty".to_string()));
    }

    if trimmed.eq_ignore_ascii_case("0xffffffffffffffff") {
        return Err(AppError::AddressOutOfBounds("0xffffffffffffffff".to_string()));
    }

    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        let hex_part = &trimmed[2..];
        if let Ok(val) = u64::from_str_radix(hex_part, 16) {
            if val == u64::MAX || val > 0x0000_7fff_ffff_ffff {
                return Err(AppError::AddressOutOfBounds(format!("{val:#x}")));
            }
            return Ok(format!("{val:#x}"));
        } else {
            return Err(AppError::InvalidArgument(format!(
                "Invalid hexadecimal address '{trimmed}'"
            )));
        }
    }

    if let Ok(val) = trimmed.parse::<u64>() {
        if val == u64::MAX || val > 0x0000_7fff_ffff_ffff {
            return Err(AppError::AddressOutOfBounds(format!("{val:#x}")));
        }
        return Ok(format!("{val:#x}"));
    }

    // Named symbol (e.g. main, check_token)
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$' || c == '@') {
        return Err(AppError::InvalidArgument(format!(
            "Invalid address or symbol name '{trimmed}': contains illegal characters"
        )));
    }
    Ok(trimmed.to_string())
}

/// Register dynamic function hook to trace arguments (:dtf).
pub fn handle_hook(
    cli: &Cli,
    target: &str,
    addr: &str,
    format: Option<&str>,
) -> Result<String, AppError> {
    // 1. Format validation BEFORE driver or env check
    if let Some(fmt) = format {
        validate_hook_format(fmt)?;
    }

    // 2. Address validation BEFORE driver or env check
    let norm_addr = validate_and_normalize_addr(addr)?;

    // 3. Target validation
    let parsed_target = FridaTarget::parse_attach(target)?;

    // 4. Driver instantiation
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    // 5. Execute :dtf
    let cmd_str = if let Some(fmt) = format {
        format!("dtf {} {}", norm_addr, fmt)
    } else {
        format!("dtf {}", norm_addr)
    };

    let out = driver.cmd(&cmd_str)?;

    let resp_data = FridaHookResponse {
        target: parsed_target.display_target(),
        addr: norm_addr,
        format: format.map(|f| f.to_string()),
        status: "installed".to_string(),
        hook_type: "argument_trace".to_string(),
        message: out.trim().to_string(),
    };

    let resp = ApiResponse::success("frida hook", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Validates an individual register identifier token.
///
/// Across all supported architectures (x86_64, arm, arm64, mips, riscv, ppc, sparc):
/// - Register names are ASCII identifiers starting with an alphabetic character or underscore.
/// - Subsequent characters may be ASCII alphanumeric or underscore.
/// - Length must be between 1 and 16 characters (e.g. rax, x0, w0, r8, r8d, tpidr_el0, sp, pc).
pub fn is_valid_register_name(reg: &str) -> bool {
    if reg.is_empty() || reg.len() > 16 {
        return false;
    }
    let mut chars = reg.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validates and parses a comma-separated register list for register tracing.
pub fn parse_and_validate_regs(regs: &str) -> Result<Vec<String>, AppError> {
    let trimmed_regs = regs.trim();
    if trimmed_regs.is_empty() {
        return Err(AppError::InvalidArgument("Registers list cannot be empty".to_string()));
    }
    let reg_list: Vec<String> = trimmed_regs
        .split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();

    if reg_list.is_empty() {
        return Err(AppError::InvalidArgument(
            "No valid register names specified in --regs".to_string(),
        ));
    }

    const MAX_REGISTERS: usize = 128;
    if reg_list.len() > MAX_REGISTERS {
        return Err(AppError::InvalidArgument(format!(
            "Too many registers specified in --regs: {} (maximum is {MAX_REGISTERS})",
            reg_list.len()
        )));
    }

    for reg in &reg_list {
        if !is_valid_register_name(reg) {
            return Err(AppError::InvalidArgument(format!(
                "Invalid register name '{reg}' in --regs: must be ASCII alphanumeric (e.g. rax, x0)"
            )));
        }
    }

    Ok(reg_list)
}

/// Trace CPU registers on function hit (:dtr).
pub fn handle_trace_regs(
    cli: &Cli,
    target: &str,
    addr: &str,
    regs: &str,
) -> Result<String, AppError> {
    let norm_addr = validate_and_normalize_addr(addr)?;
    let reg_list = parse_and_validate_regs(regs)?;

    let parsed_target = FridaTarget::parse_attach(target)?;
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    let cmd_str = format!("dtr {} {}", norm_addr, reg_list.join(" "));
    let _ = driver.cmd(&cmd_str)?;

    let resp_data = FridaTraceRegsResponse {
        target: parsed_target.display_target(),
        addr: norm_addr,
        regs: reg_list,
        status: "installed".to_string(),
        hook_type: "register_trace".to_string(),
    };

    let resp = ApiResponse::success("frida trace-regs", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Intercept and replace function return value.
pub fn handle_hook_return(
    cli: &Cli,
    target: &str,
    addr: &str,
    retval: &str,
) -> Result<String, AppError> {
    let norm_addr = validate_and_normalize_addr(addr)?;

    let trimmed_ret = retval.trim();
    if trimmed_ret.is_empty() {
        return Err(AppError::InvalidArgument("Return value cannot be empty".to_string()));
    }
    let is_valid_ret = if let Some(hex) = trimmed_ret.strip_prefix("0x").or_else(|| trimmed_ret.strip_prefix("0X")) {
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else if let Some(dec) = trimmed_ret.strip_prefix('-').or_else(|| trimmed_ret.strip_prefix('+')) {
        !dec.is_empty() && dec.chars().all(|c| c.is_ascii_digit())
    } else {
        trimmed_ret.chars().all(|c| c.is_ascii_digit())
    };
    if !is_valid_ret {
        return Err(AppError::InvalidArgument(format!(
            "Invalid return value '{retval}': must be a valid hexadecimal (0x...) or decimal integer"
        )));
    }

    let parsed_target = FridaTarget::parse_attach(target)?;
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    // Construct Frida JavaScript interceptor to replace return value
    let js_code = format!(
        r#"Interceptor.attach(ptr("{}"), {{ onLeave: function(retval) {{ retval.replace(ptr("{}")); }} }});"#,
        norm_addr, trimmed_ret
    );
    let _ = driver.cmd(&format!(":eval {}", js_code))?;

    let resp_data = FridaHookReturnResponse {
        target: parsed_target.display_target(),
        addr: norm_addr,
        retval: trimmed_ret.to_string(),
        status: "installed".to_string(),
        hook_type: "return_replacement".to_string(),
    };

    let resp = ApiResponse::success("frida hook-return", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// List currently active dynamic hooks (:dtj).
pub fn handle_hooks_list(
    cli: &Cli,
    target: &str,
) -> Result<String, AppError> {
    let parsed_target = FridaTarget::parse_attach(target)?;
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    let raw_hooks: Vec<RawHookInfo> = driver.cmdj("dtj").unwrap_or_default();

    let hooks: Vec<FridaHookInfo> = raw_hooks
        .into_iter()
        .enumerate()
        .map(|(idx, h)| {
            let addr = h.addr.as_ref().map(extract_addr_hex).unwrap_or_else(|| "0x0".to_string());
            FridaHookInfo {
                id: h.id.unwrap_or(idx as u64),
                addr,
                name: h.name,
                format: h.format,
                count: h.count.unwrap_or(0),
            }
        })
        .collect();

    let total = hooks.len();
    let resp_data = FridaHooksListResponse {
        target: parsed_target.display_target(),
        total,
        hooks,
    };

    let resp = ApiResponse::success("frida hooks-list", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Remove a registered dynamic hook by ID (:dt-).
pub fn handle_hook_remove(
    cli: &Cli,
    target: &str,
    id: &str,
) -> Result<String, AppError> {
    let trimmed_id = id.trim();
    if trimmed_id.is_empty() {
        return Err(AppError::InvalidArgument("Hook ID cannot be empty".to_string()));
    }
    if trimmed_id != "*" && trimmed_id.parse::<u64>().is_err() {
        return Err(AppError::InvalidArgument(format!(
            "Invalid hook ID '{id}': must be a numeric ID or '*'"
        )));
    }

    let parsed_target = FridaTarget::parse_attach(target)?;
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    let cmd_str = format!("dt- {}", trimmed_id);
    let _ = driver.cmd(&cmd_str)?;

    let resp_data = FridaHookRemoveResponse {
        target: parsed_target.display_target(),
        id: trimmed_id.to_string(),
        removed: true,
    };

    let resp = ApiResponse::success("frida hook-remove", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hook_format_valid_chars() {
        for fmt in &["i", "x", "z", "h", "w", "a", "O", "p", "s", "c", "v", "^", "+", "i2x"] {
            assert!(validate_hook_format(fmt).is_ok());
        }
    }

    #[test]
    fn test_validate_hook_format_invalid_char() {
        let err = validate_hook_format("INVALID_FMT").unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_validate_and_normalize_addr_hex() {
        let norm = validate_and_normalize_addr("0x401000").unwrap();
        assert_eq!(norm, "0x401000");
    }

    #[test]
    fn test_validate_and_normalize_addr_out_of_bounds() {
        let err = validate_and_normalize_addr("0xffffffffffffffff").unwrap_err();
        assert!(matches!(err, AppError::AddressOutOfBounds(_)));
    }

    #[test]
    fn test_parse_and_validate_regs_empty_or_commas() {
        assert!(matches!(parse_and_validate_regs("").unwrap_err(), AppError::InvalidArgument(_)));
        assert!(matches!(parse_and_validate_regs("   ").unwrap_err(), AppError::InvalidArgument(_)));
        assert!(matches!(parse_and_validate_regs(",,,").unwrap_err(), AppError::InvalidArgument(_)));
        assert!(matches!(parse_and_validate_regs(", , ").unwrap_err(), AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_parse_and_validate_regs_valid() {
        let regs = parse_and_validate_regs("rax, rdi, rsi").unwrap();
        assert_eq!(regs, vec!["rax", "rdi", "rsi"]);
    }

    #[test]
    fn test_parse_and_validate_regs_invalid_tokens() {
        for bad in &["invalid@reg!name", "rax;rm", "rax$rbx", ";id", "foo bar", "123", "!rax"] {
            let err = parse_and_validate_regs(bad).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidArgument(_)),
                "Expected InvalidArgument for {bad}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_parse_and_validate_regs_non_ascii() {
        for non_ascii in &["🦀,✨", "rаx", "\x01\x02"] {
            let err = parse_and_validate_regs(non_ascii).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidArgument(_)),
                "Expected InvalidArgument for {non_ascii}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_parse_and_validate_regs_name_too_long() {
        let long_name = "a".repeat(17);
        let err = parse_and_validate_regs(&long_name).unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_parse_and_validate_regs_too_many_registers() {
        let many_regs = (0..129).map(|i| format!("r{i}")).collect::<Vec<_>>().join(",");
        let err = parse_and_validate_regs(&many_regs).unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_parse_and_validate_regs_architectures() {
        assert!(parse_and_validate_regs("rax, eax, ax, al, r8, r8d, r8w, r8b, rip, rflags").is_ok());
        assert!(parse_and_validate_regs("r0, r12, sp, lr, pc, cpsr, x0, x30, w0, w30, xzr, wzr, tpidr_el0, v0, q0").is_ok());
        assert!(parse_and_validate_regs("zero, at, v0, a0, t0, s0, k0, gp, sp, fp, ra").is_ok());
        assert!(parse_and_validate_regs("x0, x31, zero, ra, sp, gp, tp, t0, s0, a0, mstatus, satp").is_ok());
    }

    #[test]
    fn test_is_valid_register_name() {
        assert!(is_valid_register_name("rax"));
        assert!(is_valid_register_name("_custom"));
        assert!(is_valid_register_name("x0"));
        assert!(is_valid_register_name("tpidr_el0"));
        assert!(!is_valid_register_name(""));
        assert!(!is_valid_register_name("0rax"));
        assert!(!is_valid_register_name("rax;rm"));
        assert!(!is_valid_register_name("rax$rbx"));
        assert!(!is_valid_register_name("abcdefghijklmnopq"));
    }

    #[test]
    fn test_validate_and_normalize_addr_symbols() {
        assert!(validate_and_normalize_addr("main").is_ok());
        assert!(validate_and_normalize_addr("sym.check_token").is_ok());
        assert!(validate_and_normalize_addr("_ZN3foo3bar17hE").is_ok());
        assert!(validate_and_normalize_addr("test@plt").is_ok());
        assert!(validate_and_normalize_addr("std::vector").is_ok());

        assert!(matches!(
            validate_and_normalize_addr("bad;addr").unwrap_err(),
            AppError::InvalidArgument(_)
        ));
        assert!(matches!(
            validate_and_normalize_addr("foo bar").unwrap_err(),
            AppError::InvalidArgument(_)
        ));
        assert!(validate_and_normalize_addr("foo$bar").is_ok());
        assert!(matches!(
            validate_and_normalize_addr("bad`cmd`").unwrap_err(),
            AppError::InvalidArgument(_)
        ));
    }
}
