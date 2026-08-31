use crate::patch::instruction::PatchResult;
use crate::patch::verify::{create_backup, verify_write};
use crate::r2::R2Driver;
use crate::response::AppError;

pub fn patch_string(
    driver: &R2Driver,
    addr: Option<&str>,
    old_string: Option<&str>,
    new_string: &str,
    pad_null: bool,
    strict_length: bool,
    backup: bool,
) -> Result<PatchResult, AppError> {
    let (target_addr, orig_len, orig_str_val) = if let Some(a) = addr {
        let val = driver.resolve_address(a)?;
        let existing = driver.read_string_at(&format!("{:#x}", val))?;
        let len = existing.len();
        (val, len, existing)
    } else if let Some(old_s) = old_string {
        // Search in data section strings (izj)
        let strings: Vec<serde_json::Value> = driver.cmdj("izj")?;
        let found = strings.into_iter().find(|s| {
            s.get("string").and_then(|v| v.as_str()) == Some(old_s)
        });

        if let Some(s) = found {
            let vaddr = s.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
            let size = s.get("size").and_then(|v| v.as_u64()).unwrap_or(old_s.len() as u64) as usize;
            (vaddr, size.saturating_sub(1).max(old_s.len()), old_s.to_string())
        } else {
            // Fallback to literal search
            return Err(AppError::StringNotFound(old_s.to_string()));
        }
    } else {
        return Err(AppError::InvalidArgument("Either --addr or --old must be provided".to_string()));
    };

    let addr_hex = format!("{:#x}", target_addr);

    // Enforce strict length constraint
    if strict_length && new_string.len() > orig_len {
        return Err(AppError::StringOverflow {
            original_length: orig_len,
            replacement_length: new_string.len(),
            address: addr_hex,
        });
    }

    let backup_path = if backup {
        Some(create_backup(&driver.binary_path)?.display().to_string())
    } else {
        None
    };

    // Construct bytes to write
    let mut bytes_to_write = new_string.as_bytes().to_vec();
    bytes_to_write.push(0); // Null terminator

    if pad_null && orig_len > new_string.len() {
        let padding_needed = orig_len - new_string.len();
        bytes_to_write.extend(vec![0u8; padding_needed]);
    }

    let hex_to_write: String = bytes_to_write.iter().map(|b| format!("{:02x}", b)).collect();
    let total_bytes = bytes_to_write.len();

    let orig_bytes = driver.read_bytes_hex(&addr_hex, total_bytes)?;

    let write_cmd = format!("s {}; wx {}", addr_hex, hex_to_write);
    driver.cmd_write(&write_cmd)?;

    verify_write(driver, &addr_hex, &hex_to_write)?;
    let patched_bytes = driver.read_bytes_hex(&addr_hex, total_bytes)?;

    Ok(PatchResult {
        address: target_addr,
        address_hex: addr_hex,
        patch_type: "string".to_string(),
        original_bytes: orig_bytes,
        patched_bytes,
        disasm_before: Some(orig_str_val),
        disasm_after: Some(new_string.to_string()),
        bytes_modified: total_bytes,
        backup_path,
        verified: true,
    })
}
