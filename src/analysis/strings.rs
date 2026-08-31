use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StringsResponse {
    pub count: usize,
    pub strings: Vec<StringEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StringEntry {
    pub vaddr: u64,
    pub vaddr_hex: String,
    pub paddr: u64,
    pub size: usize,
    #[serde(rename = "type")]
    pub string_type: String,
    pub string: String,
}

pub fn list_strings(driver: &R2Driver, min_len: usize) -> Result<StringsResponse, AppError> {
    let raw_strings: Vec<serde_json::Value> = driver.cmdj("izj")?;

    let mut strings = Vec::new();

    for s in raw_strings {
        let text = s.get("string").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if text.len() < min_len {
            continue;
        }

        let vaddr = s.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
        let paddr = s.get("paddr").and_then(|v| v.as_u64()).unwrap_or(0);
        let size = s.get("size").and_then(|v| v.as_u64()).unwrap_or(text.len() as u64) as usize;
        let string_type = s.get("type").and_then(|v| v.as_str()).unwrap_or("ascii").to_string();

        strings.push(StringEntry {
            vaddr,
            vaddr_hex: format!("{:#x}", vaddr),
            paddr,
            size,
            string_type,
            string: text,
        });
    }

    Ok(StringsResponse {
        count: strings.len(),
        strings,
    })
}
