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

#[derive(Debug, Deserialize)]
struct RawR2String {
    #[serde(default)]
    string: Option<String>,
    #[serde(default)]
    vaddr: Option<u64>,
    #[serde(default)]
    paddr: Option<u64>,
    #[serde(default)]
    size: Option<usize>,
    #[serde(default, rename = "type")]
    string_type: Option<String>,
}

pub fn list_strings(driver: &R2Driver, min_len: usize) -> Result<StringsResponse, AppError> {
    let raw_strings: Vec<RawR2String> = driver.cmdj("izj")?;

    let mut strings = Vec::with_capacity(raw_strings.len());

    for s in raw_strings {
        let text_ref = s.string.as_deref().unwrap_or("");
        if text_ref.len() < min_len {
            continue;
        }

        let vaddr = s.vaddr.unwrap_or(0);
        let paddr = s.paddr.unwrap_or(0);
        let size = s.size.unwrap_or(text_ref.len());
        let string_type = s.string_type.unwrap_or_else(|| "ascii".to_string());
        let string = s.string.unwrap_or_default();

        strings.push(StringEntry {
            vaddr,
            vaddr_hex: format!("{:#x}", vaddr),
            paddr,
            size,
            string_type,
            string,
        });
    }

    Ok(StringsResponse {
        count: strings.len(),
        strings,
    })
}
