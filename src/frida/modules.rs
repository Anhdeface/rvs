use serde::Deserialize;
use serde_json::Value;
use crate::cli::{Cli, OutputFormat};
use crate::compact::{
    CompactFridaClassesResponse, CompactFridaModule, CompactFridaModulesResponse,
    CompactFridaSymbol, CompactFridaSymbolsResponse,
};
use crate::error::AppError;
use crate::frida::driver::FridaDriver;
use crate::frida::target::FridaTarget;
use crate::frida::types::{
    FridaClassEntry, FridaClassesResponse, FridaModuleEntry, FridaModulesResponse,
    FridaSymbolEntry, FridaSymbolsResponse,
};
use crate::response::ApiResponse;

#[derive(Debug, Deserialize)]
struct RawModule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    base: Option<Value>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSymbol {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    realname: Option<String>,
    #[serde(default)]
    vaddr: Option<u64>,
    #[serde(default)]
    address: Option<Value>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(rename = "type", default)]
    sym_type: Option<String>,
    #[serde(default)]
    bind: Option<String>,
    #[serde(default)]
    module: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawClass {
    #[serde(default, rename = "className")]
    class_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    methods: Vec<String>,
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

/// Enumerate loaded modules in the target process (:ilj).
pub fn handle_modules(
    cli: &Cli,
    target: &str,
    filter: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<String, AppError> {
    // 1. Semantic pagination validation BEFORE driver or env check
    if let Some(l) = limit {
        if l < 0 {
            return Err(AppError::InvalidArgument(format!(
                "--limit must be non-negative, got {l}"
            )));
        }
    }
    if let Some(o) = offset {
        if o < 0 {
            return Err(AppError::InvalidArgument(format!(
                "--offset must be non-negative, got {o}"
            )));
        }
    }

    // 2. Target syntax validation
    let parsed_target = FridaTarget::parse_attach(target)?;

    // 3. Instantiate driver (validates r2frida installation)
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    // 4. Execute :ilj
    let raw_modules: Vec<RawModule> = driver.cmdj("ilj").unwrap_or_default();

    let mut entries = Vec::new();
    for m in raw_modules {
        let name = m.name.unwrap_or_else(|| "unknown".to_string());
        if let Some(f) = filter {
            if !name.contains(f) && !m.path.as_deref().unwrap_or("").contains(f) {
                continue;
            }
        }
        let base_str = m.base.as_ref().map(extract_addr_hex).unwrap_or_else(|| "0x0".to_string());
        entries.push(FridaModuleEntry {
            name,
            base: base_str,
            size: m.size.unwrap_or(0),
            path: m.path,
        });
    }

    let is_compact = cli.compact || cli.format == OutputFormat::Agent;
    let total = entries.len();
    let off = offset.unwrap_or(0) as usize;
    let effective_limit = limit.or(if is_compact { Some(30) } else { None });
    let paginated: Vec<FridaModuleEntry> = if off < entries.len() {
        let after_off = &entries[off..];
        if let Some(lim) = effective_limit {
            after_off.iter().take(lim as usize).cloned().collect()
        } else {
            after_off.to_vec()
        }
    } else {
        Vec::new()
    };

    if is_compact {
        let compact_modules: Vec<CompactFridaModule> = paginated
            .into_iter()
            .map(|m| CompactFridaModule {
                name: m.name,
                base: m.base,
                size: m.size,
            })
            .collect();
        let resp_data = CompactFridaModulesResponse {
            count: compact_modules.len(),
            modules: compact_modules,
        };
        let resp = ApiResponse::success("frida modules", parsed_target.display_target(), resp_data);
        return resp.to_json(cli.pretty).map_err(AppError::JsonError);
    }

    let resp_data = FridaModulesResponse {
        target: parsed_target.display_target(),
        total,
        modules: paginated,
    };
    let resp = ApiResponse::success("frida modules", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Enumerate symbols in target process or specific module (:isj).
pub fn handle_symbols(
    cli: &Cli,
    target: &str,
    module: Option<&str>,
    filter: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<String, AppError> {
    // 1. Semantic pagination validation BEFORE driver or env check
    if let Some(l) = limit {
        if l < 0 {
            return Err(AppError::InvalidArgument(format!(
                "--limit must be non-negative, got {l}"
            )));
        }
    }
    if let Some(o) = offset {
        if o < 0 {
            return Err(AppError::InvalidArgument(format!(
                "--offset must be non-negative, got {o}"
            )));
        }
    }

    // 2. Target syntax validation
    let parsed_target = FridaTarget::parse_attach(target)?;

    if let Some(m) = module {
        let tr = m.trim();
        if tr.is_empty() {
            return Err(AppError::InvalidArgument("Module name cannot be empty".to_string()));
        }
        if m.contains(';') || m.contains('\n') || m.contains('\r') {
            return Err(AppError::InvalidArgument(format!(
                "Invalid module name '{m}': cannot contain command separators or control characters"
            )));
        }
    }

    // 3. Driver instantiation
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    // 4. Query symbols
    let r2_cmd = if let Some(m) = module {
        format!("isj {}", m.trim())
    } else {
        "isj".to_string()
    };

    let raw_symbols: Vec<RawSymbol> = driver.cmdj(&r2_cmd).unwrap_or_default();

    let mut entries = Vec::new();
    for s in raw_symbols {
        let name = s.name.or(s.realname).unwrap_or_else(|| "unknown".to_string());
        if let Some(f) = filter {
            if !name.contains(f) {
                continue;
            }
        }
        let addr = if let Some(v) = s.vaddr {
            format!("{v:#x}")
        } else if let Some(ref a) = s.address {
            extract_addr_hex(a)
        } else if let Some(o) = s.offset {
            format!("{o:#x}")
        } else {
            "0x0".to_string()
        };

        entries.push(FridaSymbolEntry {
            name,
            addr,
            size: s.size.unwrap_or(0),
            sym_type: s.sym_type.unwrap_or_else(|| "FUNC".to_string()),
            bind: s.bind,
            module: s.module,
        });
    }

    let is_compact = cli.compact || cli.format == OutputFormat::Agent;
    let total = entries.len();
    let off = offset.unwrap_or(0) as usize;
    let effective_limit = limit.or(if is_compact { Some(50) } else { None });
    let paginated: Vec<FridaSymbolEntry> = if off < entries.len() {
        let after_off = &entries[off..];
        if let Some(lim) = effective_limit {
            after_off.iter().take(lim as usize).cloned().collect()
        } else {
            after_off.to_vec()
        }
    } else {
        Vec::new()
    };

    if is_compact {
        let compact_symbols: Vec<CompactFridaSymbol> = paginated
            .into_iter()
            .map(|s| CompactFridaSymbol {
                name: s.name,
                addr: s.addr,
                size: if s.size > 0 { Some(s.size) } else { None },
                sym_type: Some(s.sym_type),
            })
            .collect();
        let resp_data = CompactFridaSymbolsResponse {
            count: compact_symbols.len(),
            symbols: compact_symbols,
        };
        let resp = ApiResponse::success("frida symbols", parsed_target.display_target(), resp_data);
        return resp.to_json(cli.pretty).map_err(AppError::JsonError);
    }

    let count = paginated.len();
    let resp_data = FridaSymbolsResponse {
        target: parsed_target.display_target(),
        module: module.map(|m| m.to_string()),
        total,
        count,
        offset: offset.map(|o| o as usize),
        limit: limit.map(|l| l as usize),
        symbols: paginated,
    };
    let resp = ApiResponse::success("frida symbols", parsed_target.display_target(), resp_data);
    resp.to_json(cli.pretty).map_err(AppError::JsonError)
}

/// Enumerate classes in target process (:icj).
pub fn handle_classes(
    cli: &Cli,
    target: &str,
    filter: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<String, AppError> {
    // 1. Semantic pagination validation BEFORE driver or env check
    if let Some(l) = limit {
        if l < 0 {
            return Err(AppError::InvalidArgument(format!(
                "--limit must be non-negative, got {l}"
            )));
        }
    }
    if let Some(o) = offset {
        if o < 0 {
            return Err(AppError::InvalidArgument(format!(
                "--offset must be non-negative, got {o}"
            )));
        }
    }

    // 2. Target syntax validation
    let parsed_target = FridaTarget::parse_attach(target)?;

    // 3. Driver instantiation
    let driver = FridaDriver::new(parsed_target.to_uri(), cli.quiet)?;

    // 4. Execute :icj
    let raw_classes: Vec<RawClass> = driver.cmdj("icj").unwrap_or_default();

    let mut entries = Vec::new();
    for c in raw_classes {
        let name = c.class_name.or(c.name).unwrap_or_else(|| "unknown".to_string());
        if let Some(f) = filter {
            if !name.contains(f) {
                continue;
            }
        }
        entries.push(FridaClassEntry {
            name,
            methods: c.methods,
        });
    }

    let is_compact = cli.compact || cli.format == OutputFormat::Agent;
    let total = entries.len();
    let off = offset.unwrap_or(0) as usize;
    let effective_limit = limit.or(if is_compact { Some(50) } else { None });
    let paginated: Vec<FridaClassEntry> = if off < entries.len() {
        let after_off = &entries[off..];
        if let Some(lim) = effective_limit {
            after_off.iter().take(lim as usize).cloned().collect()
        } else {
            after_off.to_vec()
        }
    } else {
        Vec::new()
    };

    if is_compact {
        let class_names: Vec<String> = paginated.into_iter().map(|c| c.name).collect();
        let resp_data = CompactFridaClassesResponse {
            total: class_names.len(),
            classes: class_names,
        };
        let resp = ApiResponse::success("frida classes", parsed_target.display_target(), resp_data);
        return resp.to_json(cli.pretty).map_err(AppError::JsonError);
    }

    let resp_data = FridaClassesResponse {
        target: parsed_target.display_target(),
        total,
        classes: paginated,
    };
    let resp = ApiResponse::success("frida classes", parsed_target.display_target(), resp_data);
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
    fn test_handle_symbols_invalid_module_separator() {
        let cli = dummy_cli();
        for bad_mod in &["bad;mod", "libfoo\n.so", "test\r", ""] {
            let err = handle_symbols(&cli, "0", Some(bad_mod), None, None, None).unwrap_err();
            assert!(
                matches!(err, AppError::InvalidArgument(_)),
                "Expected InvalidArgument for module {bad_mod:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_handle_modules_negative_pagination() {
        let cli = dummy_cli();
        let err1 = handle_modules(&cli, "0", None, Some(-1), None).unwrap_err();
        assert!(matches!(err1, AppError::InvalidArgument(_)));
        let err2 = handle_modules(&cli, "0", None, None, Some(-5)).unwrap_err();
        assert!(matches!(err2, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_handle_classes_negative_pagination() {
        let cli = dummy_cli();
        let err1 = handle_classes(&cli, "0", None, Some(-1), None).unwrap_err();
        assert!(matches!(err1, AppError::InvalidArgument(_)));
        let err2 = handle_classes(&cli, "0", None, None, Some(-10)).unwrap_err();
        assert!(matches!(err2, AppError::InvalidArgument(_)));
    }
}
