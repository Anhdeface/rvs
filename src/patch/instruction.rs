use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;
use crate::patch::verify::{create_backup, verify_write};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchResult {
    pub address: u64,
    pub address_hex: String,
    pub patch_type: String,
    pub original_bytes: String,
    pub patched_bytes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disasm_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disasm_after: Option<String>,
    pub bytes_modified: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
    pub verified: bool,
}

pub fn patch_instruction(
    driver: &R2Driver,
    addr: &str,
    assembly: Option<&str>,
    nop_bytes: Option<usize>,
    backup: bool,
) -> Result<PatchResult, AppError> {
    let target_addr = driver.resolve_address(addr)?;
    let addr_hex = format!("{:#x}", target_addr);

    let backup_path = if backup {
        Some(create_backup(&driver.binary_path)?.display().to_string())
    } else {
        None
    };

    if let Some(nops) = nop_bytes {
        if nops == 0 {
            return Err(AppError::InvalidArgument("NOP bytes count must be greater than 0".to_string()));
        }

        let nop_hex = "90".repeat(nops);
        let orig_bytes = driver.read_bytes_hex(&addr_hex, nops)?;
        let disasm_before = driver.cmd(&format!("s {}; pD {}", addr_hex, nops)).ok().map(|s| s.trim().to_string());

        let cmd = format!("s {}; wx {}", addr_hex, nop_hex);
        driver.cmd_write(&cmd)?;

        verify_write(driver, &addr_hex, &nop_hex)?;
        let patched_bytes = driver.read_bytes_hex(&addr_hex, nops)?;
        let disasm_after = driver.cmd(&format!("s {}; pD {}", addr_hex, nops)).ok().map(|s| s.trim().to_string());

        Ok(PatchResult {
            address: target_addr,
            address_hex: addr_hex,
            patch_type: "instruction".to_string(),
            original_bytes: orig_bytes,
            patched_bytes,
            disasm_before,
            disasm_after,
            bytes_modified: nops,
            backup_path,
            verified: true,
        })
    } else if let Some(asm) = assembly {
        let trimmed_asm = asm.trim();
        if trimmed_asm.is_empty() || trimmed_asm.ends_with(',') || trimmed_asm.contains(",,") {
            return Err(AppError::AssemblyFailed {
                instruction: asm.to_string(),
                details: "Invalid or incomplete assembly syntax (empty instruction or trailing comma)".to_string(),
            });
        }

        // Pre-assemble instruction with seek awareness to properly compute relative offsets (jumps, calls, RIP-relative addressing)
        let pa_out = driver.cmd(&format!("s {}; pa {}", addr_hex, trimmed_asm))?;
        let expected_hex = pa_out.trim().to_string();

        if expected_hex.is_empty()
            || expected_hex.contains("ERROR")
            || expected_hex.contains("invalid")
            || expected_hex.contains("Cannot assemble")
            || !expected_hex.chars().all(|c| c.is_ascii_hexdigit())
            || !expected_hex.len().is_multiple_of(2)
        {
            return Err(AppError::AssemblyFailed {
                instruction: asm.to_string(),
                details: pa_out.trim().to_string(),
            });
        }

        let byte_len = expected_hex.len() / 2;
        if byte_len == 0 {
            return Err(AppError::AssemblyFailed {
                instruction: asm.to_string(),
                details: "Assembled machine code had 0 bytes".to_string(),
            });
        }

        let orig_bytes = driver.read_bytes_hex(&addr_hex, byte_len)?;
        let disasm_before = driver.cmd(&format!("s {}; pi 1", addr_hex)).ok().map(|s| s.trim().to_string());

        let cmd = format!("s {}; wa {}", addr_hex, trimmed_asm);
        driver.cmd_write(&cmd)?;

        verify_write(driver, &addr_hex, &expected_hex)?;
        let patched_bytes = driver.read_bytes_hex(&addr_hex, byte_len)?;
        let disasm_after = driver.cmd(&format!("s {}; pi 1", addr_hex)).ok().map(|s| s.trim().to_string());


        Ok(PatchResult {
            address: target_addr,
            address_hex: addr_hex,
            patch_type: "instruction".to_string(),
            original_bytes: orig_bytes,
            patched_bytes,
            disasm_before,
            disasm_after,
            bytes_modified: byte_len,
            backup_path,
            verified: true,
        })
    } else {
        Err(AppError::InvalidArgument("Either --assembly or --nop must be specified".to_string()))
    }
}
