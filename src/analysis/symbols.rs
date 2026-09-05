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

/// Raw typed symbol struct deserialized directly from radare2 `isj` output.
#[derive(Debug, Deserialize)]
pub struct RawR2Symbol {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub realname: Option<String>,
    #[serde(default)]
    pub flagname: Option<String>,
    #[serde(default)]
    pub vaddr: Option<u64>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub paddr: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(rename = "type", default)]
    pub sym_type: Option<String>,
    #[serde(default)]
    pub is_imported: Option<bool>,
}

/// Lists all symbols (functions, global variables, imports, constants) with optional name substring filtering.
pub fn list_symbols(driver: &R2Driver, filter: Option<&str>) -> Result<SymbolsResponse, AppError> {
    let raw_symbols: Vec<RawR2Symbol> = driver.cmdj("isj")?;
    let mut symbols = Vec::with_capacity(raw_symbols.len());

    for raw in raw_symbols {
        let name = match (raw.name, raw.realname) {
            (Some(n), _) if !n.is_empty() => n,
            (_, Some(rn)) if !rn.is_empty() => rn,
            _ => continue,
        };

        if let Some(f_pat) = filter {
            if !name.contains(f_pat) {
                continue;
            }
        }

        let flagname = raw.flagname.unwrap_or_else(|| name.clone());
        let vaddr = raw.vaddr.or(raw.offset).unwrap_or(0);
        let paddr = raw.paddr.unwrap_or(0);
        let size = raw.size.unwrap_or(0);
        let bind = raw.bind.unwrap_or_else(|| "GLOBAL".to_string());
        let sym_type = raw.sym_type.unwrap_or_else(|| "NOTYPE".to_string());
        let is_imported = raw.is_imported.unwrap_or_else(|| {
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

    symbols.shrink_to_fit();
    Ok(SymbolsResponse {
        count: symbols.len(),
        symbols,
    })
}
