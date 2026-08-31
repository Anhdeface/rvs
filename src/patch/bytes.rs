use crate::patch::instruction::PatchResult;
use crate::patch::verify::{create_backup, verify_write};
use crate::r2::R2Driver;
use crate::response::AppError;

pub fn patch_bytes(
    driver: &R2Driver,
    addr: &str,
    hex_bytes: &str,
    backup: bool,
) -> Result<PatchResult, AppError> {
    let clean_hex = hex_bytes
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .replace(' ', "");

    if clean_hex.is_empty() {
        return Err(AppError::InvalidHexString {
            hex: hex_bytes.to_string(),
            reason: "Hex string cannot be empty".to_string(),
        });
    }

    if !clean_hex.len().is_multiple_of(2) {
        return Err(AppError::InvalidHexString {
            hex: hex_bytes.to_string(),
            reason: "Hex string has an odd number of digits".to_string(),
        });
    }

    if !clean_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::InvalidHexString {
            hex: hex_bytes.to_string(),
            reason: "Contains non-hexadecimal characters".to_string(),
        });
    }

    let byte_count = clean_hex.len() / 2;
    let target_addr = driver.resolve_address(addr)?;
    let addr_hex = format!("{:#x}", target_addr);

    let backup_path = if backup {
        Some(create_backup(&driver.binary_path)?.display().to_string())
    } else {
        None
    };

    let orig_bytes = driver.read_bytes_hex(&addr_hex, byte_count)?;
    let disasm_before = driver.cmd(&format!("s {}; pD {}", addr_hex, byte_count)).ok().map(|s| s.trim().to_string());

    let cmd = format!("s {}; wx {}", addr_hex, clean_hex);
    driver.cmd_write(&cmd)?;

    verify_write(driver, &addr_hex, &clean_hex)?;
    let patched_bytes = driver.read_bytes_hex(&addr_hex, byte_count)?;
    let disasm_after = driver.cmd(&format!("s {}; pD {}", addr_hex, byte_count)).ok().map(|s| s.trim().to_string());

    Ok(PatchResult {
        address: target_addr,
        address_hex: addr_hex,
        patch_type: "bytes".to_string(),
        original_bytes: orig_bytes,
        patched_bytes,
        disasm_before,
        disasm_after,
        bytes_modified: byte_count,
        backup_path,
        verified: true,
    })
}
