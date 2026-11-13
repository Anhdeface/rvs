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

#[derive(Debug, Deserialize)]
struct RawR2XrefTo {
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    addr: Option<u64>,
    #[serde(default, rename = "type")]
    xref_type: Option<String>,
    #[serde(default)]
    opcode: Option<String>,
    #[serde(default)]
    perm: Option<String>,
    #[serde(default)]
    fcn_addr: Option<u64>,
    #[serde(default)]
    fcn_name: Option<String>,
    #[serde(default)]
    refname: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawR2XrefFrom {
    #[serde(default)]
    from: Option<u64>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    addr: Option<u64>,
    #[serde(default)]
    to: Option<u64>,
    #[serde(default, rename = "ref")]
    ref_addr: Option<u64>,
    #[serde(default, rename = "type")]
    xref_type: Option<String>,
    #[serde(default)]
    opcode: Option<String>,
    #[serde(default)]
    perm: Option<String>,
    #[serde(default)]
    refname: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawR2XrefFcn {
    #[serde(default)]
    at: Option<u64>,
    #[serde(default)]
    from: Option<u64>,
    #[serde(default, rename = "ref")]
    ref_addr: Option<u64>,
    #[serde(default)]
    to: Option<u64>,
    #[serde(default, rename = "type")]
    xref_type: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    refname: Option<String>,
    #[serde(default)]
    opcode: Option<String>,
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

    if direction == XrefDirection::All {
        let cmd_axt = format!("aaa; axtj @ {}", target_addr_hex);
        let cmd_axf = format!("axfj @ {}", target_addr_hex);
        let cmd_axff = format!("axffj @ {}", target_addr_hex);
        let batch = driver.cmd_batch(&[&cmd_axt, &cmd_axf, &cmd_axff])?;

        let raw_axt: Vec<RawR2XrefTo> = batch.first().and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();
        let raw_axf: Vec<RawR2XrefFrom> = batch.get(1).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();
        let raw_axff: Vec<RawR2XrefFcn> = batch.get(2).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();

        for item in raw_axt {
            let from = item.from.or(item.offset).or(item.addr).unwrap_or(0);
            let raw_type = item.xref_type.as_deref().unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let opcode = item.opcode;
            let perm = item.perm;
            let fcn_addr = item.fcn_addr;
            let fcn_name = item.fcn_name;
            let refname = item.refname;

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

        for item in raw_axf {
            let from = item.from.or(item.offset).or(item.addr).unwrap_or(target_addr);
            let to = item.to.or(item.ref_addr).unwrap_or(0);
            let raw_type = item.xref_type.as_deref().unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let opcode = item.opcode;
            let perm = item.perm;
            let refname = item.refname.or(item.name);

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

        for item in raw_axff {
            let from = item.at.or(item.from).unwrap_or(0);
            let to = item.ref_addr.or(item.to).unwrap_or(0);
            let raw_type = item.xref_type.as_deref().unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let name = item.name.or(item.refname);
            let opcode = item.opcode;

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
    } else if direction == XrefDirection::To {
        let cmd_axt = format!("aaa; axtj @ {}", target_addr_hex);
        let raw_axt: Vec<RawR2XrefTo> = driver.cmdj(&cmd_axt).unwrap_or_default();

        for item in raw_axt {
            let from = item.from.or(item.offset).or(item.addr).unwrap_or(0);
            let raw_type = item.xref_type.as_deref().unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let opcode = item.opcode;
            let perm = item.perm;
            let fcn_addr = item.fcn_addr;
            let fcn_name = item.fcn_name;
            let refname = item.refname;

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
    } else {
        let cmd_axf = format!("aaa; axfj @ {}", target_addr_hex);
        let cmd_axff = format!("axffj @ {}", target_addr_hex);
        let batch = driver.cmd_batch(&[&cmd_axf, &cmd_axff])?;

        let raw_axf: Vec<RawR2XrefFrom> = batch.first().and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();
        let raw_axff: Vec<RawR2XrefFcn> = batch.get(1).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();

        for item in raw_axf {
            let from = item.from.or(item.offset).or(item.addr).unwrap_or(target_addr);
            let to = item.to.or(item.ref_addr).unwrap_or(0);
            let raw_type = item.xref_type.as_deref().unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let opcode = item.opcode;
            let perm = item.perm;
            let refname = item.refname.or(item.name);

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

        for item in raw_axff {
            let from = item.at.or(item.from).unwrap_or(0);
            let to = item.ref_addr.or(item.to).unwrap_or(0);
            let raw_type = item.xref_type.as_deref().unwrap_or("code");
            let norm_type = normalize_xref_type(raw_type);
            let name = item.name.or(item.refname);
            let opcode = item.opcode;

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

    #[inline]
    fn xref_type_to_u8(t: &str) -> u8 {
        match t {
            "call" => 1,
            "code" => 2,
            "string" => 3,
            "data" => 4,
            "read" => 5,
            "write" => 6,
            other => other.bytes().fold(0u8, |acc, b| acc.wrapping_mul(31).wrapping_add(b)),
        }
    }

    #[inline]
    fn xref_key(e: &XrefEntry) -> (u64, u64, u8) {
        (e.from_addr, e.to_addr, xref_type_to_u8(&e.xref_type))
    }

    // Deduplicate helper
    fn deduplicate(entries: Vec<XrefEntry>) -> Vec<XrefEntry> {
        let mut seen = std::collections::HashSet::with_capacity(entries.len());
        let mut unique = Vec::with_capacity(entries.len());
        for entry in entries {
            if seen.insert(xref_key(&entry)) {
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

    let (count, xrefs) = match direction {
        XrefDirection::To => (to_entries.len(), to_entries.clone()),
        XrefDirection::From => (from_entries.len(), from_entries.clone()),
        XrefDirection::All => {
            let mut seen = std::collections::HashSet::with_capacity(to_entries.len() + from_entries.len());
            let mut all_unique = Vec::with_capacity(to_entries.len() + from_entries.len());
            for entry in to_entries.iter().chain(from_entries.iter()) {
                if seen.insert(xref_key(entry)) {
                    all_unique.push(entry.clone());
                }
            }
            all_unique.sort_by(|a, b| a.from_addr.cmp(&b.from_addr).then_with(|| a.to_addr.cmp(&b.to_addr)));
            let count = all_unique.len();
            (count, all_unique)
        }
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
