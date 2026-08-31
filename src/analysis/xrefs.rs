use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

/// Direction filter for cross-reference analysis
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum XrefDirection {
    #[default]
    All,
    To,
    From,
}

impl std::fmt::Display for XrefDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XrefDirection::All => write!(f, "all"),
            XrefDirection::To => write!(f, "to"),
            XrefDirection::From => write!(f, "from"),
        }
    }
}

/// Kind filter for cross-references
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefKindFilter {
    Call,
    Code,
    Data,
    String,
    Read,
    Write,
}

impl std::fmt::Display for XrefKindFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XrefKindFilter::Call => write!(f, "call"),
            XrefKindFilter::Code => write!(f, "code"),
            XrefKindFilter::Data => write!(f, "data"),
            XrefKindFilter::String => write!(f, "string"),
            XrefKindFilter::Read => write!(f, "read"),
            XrefKindFilter::Write => write!(f, "write"),
        }
    }
}

/// Standard full response for `analyze xrefs`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XrefsResponse {
    pub target: String,
    pub target_addr: u64,
    pub target_addr_hex: String,
    pub direction: String,
    pub count: usize,
    pub xrefs: Vec<XrefEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xrefs_to: Vec<XrefEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xrefs_from: Vec<XrefEntry>,
}

/// Detailed single cross-reference entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct XrefEntry {
    pub from_addr: u64,
    pub from_addr_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    pub to_addr: u64,
    pub to_addr_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_name: Option<String>,
    #[serde(rename = "type")]
    pub xref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcn_addr: Option<u64>,
}

/// Normalizes radare2 raw xref type string to canonical lowercase names
pub fn normalize_xref_type(raw_type: &str) -> String {
    let upper = raw_type.trim().to_uppercase();
    match upper.as_str() {
        "CALL" | "UCALL" | "RCALL" | "ICALL" => "call".to_string(),
        "CODE" | "JMP" | "CJMP" | "ICOD" | "UJMP" | "RJMP" | "IJMP" => "code".to_string(),
        "STRN" | "STRING" => "string".to_string(),
        "DATA" => "data".to_string(),
        "READ" | "DATA_READ" => "read".to_string(),
        "WRITE" | "DATA_WRITE" => "write".to_string(),
        other => other.to_lowercase(),
    }
}

/// Analyzes cross references to and/or from a given target address or symbol.
pub fn analyze_xrefs(
    driver: &R2Driver,
    target: &str,
    direction: XrefDirection,
    kind_filter: Option<XrefKindFilter>,
) -> Result<XrefsResponse, AppError> {
    let target_addr = match driver.resolve_address(target) {
        Ok(addr) if addr == u64::MAX => {
            return Ok(XrefsResponse {
                target: target.to_string(),
                target_addr: addr,
                target_addr_hex: format!("{:#x}", addr),
                direction: direction.to_string(),
                count: 0,
                xrefs: Vec::new(),
                xrefs_to: Vec::new(),
                xrefs_from: Vec::new(),
            });
        }
        Ok(addr) => addr,
        Err(_) => {
            // If symbol cannot be resolved, return clean empty response
            return Ok(XrefsResponse {
                target: target.to_string(),
                target_addr: 0,
                target_addr_hex: "0x0".to_string(),
                direction: direction.to_string(),
                count: 0,
                xrefs: Vec::new(),
                xrefs_to: Vec::new(),
                xrefs_from: Vec::new(),
            });
        }
    };
    let target_addr_hex = format!("{:#x}", target_addr);

    let mut to_entries = Vec::new();
    let mut from_entries = Vec::new();

    // 1. References TO target (axtj)
    if direction == XrefDirection::To || direction == XrefDirection::All {
        let cmd_axt = format!("aaa; axtj @ {}", target_addr_hex);
        let raw_axt: Vec<serde_json::Value> = driver.cmdj(&cmd_axt).unwrap_or_default();

        for item in raw_axt {
            let from = item.get("from").or_else(|| item.get("offset")).or_else(|| item.get("addr")).and_then(|v| v.as_u64()).unwrap_or(0);
            let raw_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let opcode = item.get("opcode").and_then(|v| v.as_str()).map(|s| s.to_string());
            let perm = item.get("perm").and_then(|v| v.as_str()).map(|s| s.to_string());
            let fcn_addr = item.get("fcn_addr").and_then(|v| v.as_u64());
            let fcn_name = item.get("fcn_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let refname = item.get("refname").and_then(|v| v.as_str()).map(|s| s.to_string());

            to_entries.push(XrefEntry {
                from_addr: from,
                from_addr_hex: format!("{:#x}", from),
                from_function: fcn_name.clone(),
                from_name: fcn_name,
                to_addr: target_addr,
                to_addr_hex: target_addr_hex.clone(),
                to_function: refname.clone().or_else(|| Some(target.to_string())),
                to_name: refname.or_else(|| Some(target.to_string())),
                xref_type: norm_type,
                opcode,
                perm,
                fcn_addr,
            });
        }
    }

    // 2. References FROM target (axfj / axffj)
    if direction == XrefDirection::From || direction == XrefDirection::All {
        let cmd_axf = format!("aaa; axfj @ {}", target_addr_hex);
        let raw_axf: Vec<serde_json::Value> = driver.cmdj(&cmd_axf).unwrap_or_default();

        for item in raw_axf {
            let from = item.get("from").or_else(|| item.get("offset")).or_else(|| item.get("addr")).and_then(|v| v.as_u64()).unwrap_or(target_addr);
            let to = item.get("to").or_else(|| item.get("ref")).and_then(|v| v.as_u64()).unwrap_or(0);
            let raw_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let opcode = item.get("opcode").and_then(|v| v.as_str()).map(|s| s.to_string());
            let perm = item.get("perm").and_then(|v| v.as_str()).map(|s| s.to_string());
            let refname = item.get("refname").or_else(|| item.get("name")).and_then(|v| v.as_str()).map(|s| s.to_string());

            from_entries.push(XrefEntry {
                from_addr: from,
                from_addr_hex: format!("{:#x}", from),
                from_function: Some(target.to_string()),
                from_name: Some(target.to_string()),
                to_addr: to,
                to_addr_hex: format!("{:#x}", to),
                to_function: refname.clone(),
                to_name: refname,
                xref_type: norm_type,
                opcode,
                perm,
                fcn_addr: Some(target_addr),
            });
        }

        // Also query function xrefs (axffj)
        let cmd_axff = format!("aaa; axffj @ {}", target_addr_hex);
        if let Ok(raw_axff) = driver.cmdj::<Vec<serde_json::Value>>(&cmd_axff) {
            for item in raw_axff {
                let from = item.get("at").or_else(|| item.get("from")).and_then(|v| v.as_u64()).unwrap_or(0);
                let to = item.get("ref").or_else(|| item.get("to")).and_then(|v| v.as_u64()).unwrap_or(0);
                let raw_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("code");
                let norm_type = normalize_xref_type(raw_type);
                let name = item.get("name").or_else(|| item.get("refname")).and_then(|v| v.as_str()).map(|s| s.to_string());
                let opcode = item.get("opcode").and_then(|v| v.as_str()).map(|s| s.to_string());

                from_entries.push(XrefEntry {
                    from_addr: from,
                    from_addr_hex: format!("{:#x}", from),
                    from_function: Some(target.to_string()),
                    from_name: Some(target.to_string()),
                    to_addr: to,
                    to_addr_hex: format!("{:#x}", to),
                    to_function: name.clone(),
                    to_name: name,
                    xref_type: norm_type,
                    opcode,
                    perm: None,
                    fcn_addr: Some(target_addr),
                });
            }
        }
    }

    // Deduplicate helper
    fn deduplicate(entries: Vec<XrefEntry>) -> Vec<XrefEntry> {
        let mut unique = Vec::new();
        for entry in entries {
            if !unique.iter().any(|e: &XrefEntry| {
                e.from_addr == entry.from_addr && e.to_addr == entry.to_addr && e.xref_type == entry.xref_type
            }) {
                unique.push(entry);
            }
        }
        unique
    }

    let mut to_entries = deduplicate(to_entries);
    let mut from_entries = deduplicate(from_entries);

    // Apply kind filter if present
    if let Some(kind) = kind_filter {
        let kind_str = kind.to_string();
        to_entries.retain(|x| x.xref_type.to_lowercase() == kind_str);
        from_entries.retain(|x| x.xref_type.to_lowercase() == kind_str);
    }

    to_entries.sort_by(|a, b| a.from_addr.cmp(&b.from_addr).then_with(|| a.to_addr.cmp(&b.to_addr)));
    from_entries.sort_by(|a, b| a.from_addr.cmp(&b.from_addr).then_with(|| a.to_addr.cmp(&b.to_addr)));

    let mut all_unique = Vec::new();
    for entry in to_entries.iter().chain(from_entries.iter()) {
        if !all_unique.iter().any(|e: &XrefEntry| {
            e.from_addr == entry.from_addr && e.to_addr == entry.to_addr && e.xref_type == entry.xref_type
        }) {
            all_unique.push(entry.clone());
        }
    }
    all_unique.sort_by(|a, b| a.from_addr.cmp(&b.from_addr).then_with(|| a.to_addr.cmp(&b.to_addr)));

    let count = match direction {
        XrefDirection::To => to_entries.len(),
        XrefDirection::From => from_entries.len(),
        XrefDirection::All => all_unique.len(),
    };

    let xrefs = match direction {
        XrefDirection::To => to_entries.clone(),
        XrefDirection::From => from_entries.clone(),
        XrefDirection::All => all_unique,
    };

    Ok(XrefsResponse {
        target: target.to_string(),
        target_addr,
        target_addr_hex,
        direction: direction.to_string(),
        count,
        xrefs,
        xrefs_to: to_entries,
        xrefs_from: from_entries,
    })
}
