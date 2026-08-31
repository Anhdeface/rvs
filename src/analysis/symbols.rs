use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

/// High-level response for `symbols` command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SymbolsResponse {
    pub count: usize,
    pub symbols: Vec<SymbolEntry>,
}

/// Structured metadata for a binary symbol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolEntry {
    pub name: String,
    pub flagname: String,
    pub vaddr: u64,
    pub vaddr_hex: String,
    pub paddr: u64,
    pub size: u64,
    pub bind: String,
    #[serde(rename = "type")]
    pub sym_type: String,
    pub is_imported: bool,
}

/// Lists all symbols (functions, global variables, imports, constants) with optional name substring filtering.
pub fn list_symbols(driver: &R2Driver, filter: Option<&str>) -> Result<SymbolsResponse, AppError> {
    let raw_symbols: Vec<serde_json::Value> = driver.cmdj("isj")?;
    let mut symbols = Vec::new();

    for s in raw_symbols {
        let name = s
            .get("name")
            .or_else(|| s.get("realname"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if name.is_empty() {
            continue;
        }

        if let Some(f_pat) = filter {
            if !name.contains(f_pat) {
                continue;
            }
        }

        let flagname = s
            .get("flagname")
            .and_then(|v| v.as_str())
            .unwrap_or(&name)
            .to_string();

        let vaddr = s
            .get("vaddr")
            .or_else(|| s.get("offset"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let paddr = s.get("paddr").and_then(|v| v.as_u64()).unwrap_or(0);
        let size = s.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let bind = s
            .get("bind")
            .and_then(|v| v.as_str())
            .unwrap_or("GLOBAL")
            .to_string();
        let sym_type = s
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("NOTYPE")
            .to_string();

        let is_imported = s
            .get("is_imported")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| {
                name.starts_with("sym.imp.")
                    || flagname.starts_with("sym.imp.")
                    || vaddr == 0
                    || bind == "NONE"
            });

        symbols.push(SymbolEntry {
            name,
            flagname,
            vaddr,
            vaddr_hex: format!("{:#x}", vaddr),
            paddr,
            size,
            bind,
            sym_type,
            is_imported,
        });
    }

    Ok(SymbolsResponse {
        count: symbols.len(),
        symbols,
    })
}
