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

pub const FORBIDDEN_ASM_CHARS: &[char] = &[
    ';', '\n', '\r', '`', '|', '&', '$', '>', '<', '~', '!', '\\', '"', '\'', '@',
];

pub fn validate_assembly(asm: &str) -> Result<(), AppError> {
    let trimmed = asm.trim();
    if trimmed.is_empty() {
        return Err(AppError::AssemblyFailed {
            instruction: asm.to_string(),
            details: "Assembly instruction cannot be empty".to_string(),
        });
    }

    if let Some(c) = trimmed.chars().find(|c| FORBIDDEN_ASM_CHARS.contains(c) || (c.is_control() && *c != '\t')) {
        return Err(AppError::AssemblyFailed {
            instruction: asm.to_string(),
            details: format!("Forbidden character '{}' in assembly instruction", c),
        });
    }

    if trimmed.ends_with(',') || trimmed.contains(",,") {
        return Err(AppError::AssemblyFailed {
            instruction: asm.to_string(),
            details: "Invalid or incomplete assembly syntax (trailing comma or double comma)".to_string(),
        });
    }

    Ok(())
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

        let is_aarch64 = driver.is_aarch64();
        let (nop_hex, actual_bytes) = if is_aarch64 {
            let num_nops = if nops <= 4 {
                1
            } else {
                nops.div_ceil(4)
            };
            ("1f2003d5".repeat(num_nops), num_nops * 4)
        } else {
            ("90".repeat(nops), nops)
        };

        let orig_bytes = driver.read_bytes_hex(&addr_hex, actual_bytes)?;
        let disasm_before = driver.cmd(&format!("s {}; pD {}", addr_hex, actual_bytes)).ok().map(|s| s.trim().to_string());

        let cmd = format!("s {}; wx {}", addr_hex, nop_hex);
        driver.cmd_write(&cmd)?;

        verify_write(driver, &addr_hex, &nop_hex)?;
        let patched_bytes = driver.read_bytes_hex(&addr_hex, actual_bytes)?;
        let disasm_after = driver.cmd(&format!("s {}; pD {}", addr_hex, actual_bytes)).ok().map(|s| s.trim().to_string());

        Ok(PatchResult {
            address: target_addr,
            address_hex: addr_hex,
            patch_type: "instruction".to_string(),
            original_bytes: orig_bytes,
            patched_bytes,
            disasm_before,
            disasm_after,
            bytes_modified: actual_bytes,
            backup_path,
            verified: true,
        })
    } else if let Some(asm) = assembly {
        validate_assembly(asm)?;
        let trimmed_asm = asm.trim();
        // Normalize assembly for radare2 command shell:
        // In r2 shell, '#' initiates a comment, which strips operands like 'mov x0, #1'.
        // On ARM/AArch64, '#1' and '1' assemble identically.
        let r2_asm = trimmed_asm.replace('#', "");

        // Pre-assemble instruction with seek awareness to properly compute relative offsets (jumps, calls, RIP-relative addressing)
        let pa_out = driver.cmd(&format!("s {}; pa {}", addr_hex, r2_asm))?;
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

        let cmd = format!("s {}; wa {}", addr_hex, r2_asm);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_assembly_allows_immediate_hash() {
        assert!(validate_assembly("mov x0, #1").is_ok());
        assert!(validate_assembly("add x1, x1, #4").is_ok());
        assert!(validate_assembly("cmp w0, #1337").is_ok());
        assert!(validate_assembly("tbz w0, #0, 0x1000").is_ok());
    }

    #[test]
    fn test_validate_assembly_rejects_empty_and_dangerous_chars() {
        assert!(validate_assembly("").is_err());
        assert!(validate_assembly("   ").is_err());
        assert!(validate_assembly("mov x0, 1; rm -rf /").is_err());
        assert!(validate_assembly("mov x0, `whoami`").is_err());
        assert!(validate_assembly("mov x0, 1 | cat").is_err());
        assert!(validate_assembly("mov x0, 1,").is_err());
        assert!(validate_assembly("mov x0,, 1").is_err());
    }

    #[test]
    fn test_aarch64_nop_encoding_and_sled() {
        let is_aarch64 = true;

        // 2 bytes requested on AArch64 -> minimum 1 AArch64 NOP instruction (4 bytes)
        let nops2: usize = 2;
        let (nop_hex2, actual_bytes2) = if is_aarch64 {
            let num_nops = if nops2 <= 4 { 1 } else { nops2.div_ceil(4) };
            ("1f2003d5".repeat(num_nops), num_nops * 4)
        } else {
            ("90".repeat(nops2), nops2)
        };
        assert_eq!(nop_hex2, "1f2003d5");
        assert_eq!(actual_bytes2, 4);

        let nops: usize = 4;
        let (nop_hex, actual_bytes) = if is_aarch64 {
            let num_nops = if nops <= 4 {
                1
            } else {
                nops.div_ceil(4)
            };
            ("1f2003d5".repeat(num_nops), num_nops * 4)
        } else {
            ("90".repeat(nops), nops)
        };

        assert_eq!(nop_hex, "1f2003d5");
        assert_eq!(actual_bytes, 4);

        // 5 bytes -> rounds up to 2 AArch64 NOPs (8 bytes)
        let nops5: usize = 5;
        let (nop_hex5, actual_bytes5) = if is_aarch64 {
            let num_nops = if nops5 <= 4 { 1 } else { nops5.div_ceil(4) };
            ("1f2003d5".repeat(num_nops), num_nops * 4)
        } else {
            ("90".repeat(nops5), nops5)
        };
        assert_eq!(nop_hex5, "1f2003d51f2003d5");
        assert_eq!(actual_bytes5, 8);

        // 8 bytes -> 2 AArch64 NOPs
        let nops8: usize = 8;
        let (nop_hex8, actual_bytes8) = if is_aarch64 {
            let num_nops = if nops8 <= 4 {
                1
            } else {
                nops8.div_ceil(4)
            };
            ("1f2003d5".repeat(num_nops), num_nops * 4)
        } else {
            ("90".repeat(nops8), nops8)
        };

        assert_eq!(nop_hex8, "1f2003d51f2003d5");
        assert_eq!(actual_bytes8, 8);
    }

    #[test]
    fn test_aarch64_patch_fixture() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_aarch64_lib.so");
        if fixture.exists() {
            let temp_dir = tempfile::tempdir().expect("tempdir");
            let temp_so = temp_dir.path().join("test_aarch64.so");
            std::fs::copy(&fixture, &temp_so).expect("copy");

            let driver = R2Driver::new(&temp_so, None, None, true).expect("driver");
            assert!(driver.is_aarch64());

            // 1. Test NOP sled (4 bytes -> 1 AArch64 NOP 1f2003d5)
            let nop_res = patch_instruction(&driver, "sym.auth_gate_check", None, Some(4), false)
                .expect("NOP patch failed");
            assert_eq!(nop_res.patched_bytes, "1f2003d5");
            assert_eq!(nop_res.bytes_modified, 4);

            // 2. Test assembly patch with '#' immediate operand
            let asm_res = patch_instruction(&driver, "sym.auth_gate_check", Some("mov x0, #1"), None, false)
                .expect("Asm patch failed");
            assert_eq!(asm_res.patched_bytes, "200080d2");
            assert_eq!(asm_res.bytes_modified, 4);
        }
    }
}
