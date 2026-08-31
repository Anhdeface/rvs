use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinaryInfo {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub endian: String,
    pub os: String,
    pub entry_point: u64,
    pub entry_point_hex: String,
    pub security: SecurityMitigations,
    pub sections_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityMitigations {
    pub canary: bool,
    pub nx: bool,
    pub pic: bool,
    pub relro: String,
    pub stripped: bool,
}

pub fn get_binary_info(driver: &R2Driver) -> Result<BinaryInfo, AppError> {
    let batch = driver.cmd_batch(&["iIj", "iej", "iSj"])?;
    let raw_info: serde_json::Value = R2Driver::parse_json(batch.first().map(|s| s.as_str()).unwrap_or(""))?;
    
    // Radare2 iIj output can be nested under "bin" / "core" or directly flat
    let bin_obj = raw_info.get("bin").unwrap_or(&raw_info);
    let core_obj = raw_info.get("core").unwrap_or(&raw_info);

    let format = bin_obj.get("bintype")
        .or_else(|| core_obj.get("format"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let arch = bin_obj.get("arch")
        .and_then(|v| v.as_str())
        .unwrap_or("x86")
        .to_string();

    let bits = bin_obj.get("bits")
        .and_then(|v| v.as_u64())
        .unwrap_or(64) as u32;

    let endian = bin_obj.get("endian")
        .and_then(|v| v.as_str())
        .unwrap_or("little")
        .to_string();

    let os = bin_obj.get("os")
        .and_then(|v| v.as_str())
        .unwrap_or("linux")
        .to_string();

    let baddr = bin_obj.get("baddr").and_then(|v| v.as_u64()).unwrap_or(0);

    // Entry point: try iej or bin.baddr
    let entry_list: Vec<serde_json::Value> = batch.get(1).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();
    let entry_point = entry_list.first()
        .and_then(|e| e.get("vaddr").or_else(|| e.get("paddr")).or_else(|| e.get("offset")).and_then(|v| v.as_u64()))
        .unwrap_or(baddr);

    let canary = bin_obj.get("canary").and_then(|v| v.as_bool()).unwrap_or(false);
    let nx = bin_obj.get("nx").and_then(|v| v.as_bool()).unwrap_or(false);
    let pic = bin_obj.get("pic").and_then(|v| v.as_bool()).unwrap_or(false);
    
    let relro = if let Some(r) = bin_obj.get("relro").and_then(|v| v.as_str()) {
        r.to_string()
    } else if bin_obj.get("relro").and_then(|v| v.as_bool()).unwrap_or(false) {
        "full".to_string()
    } else {
        "none".to_string()
    };

    let stripped = bin_obj.get("stripped")
        .or_else(|| raw_info.get("stripped"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let sections: Vec<serde_json::Value> = batch.get(2).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default();
    let sections_count = sections.len();

    Ok(BinaryInfo {
        format,
        arch,
        bits,
        endian,
        os,
        entry_point,
        entry_point_hex: format!("{:#x}", entry_point),
        security: SecurityMitigations {
            canary,
            nx,
            pic,
            relro,
            stripped,
        },
        sections_count,
    })
}
