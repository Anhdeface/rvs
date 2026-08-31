mod common;

use common::*;
use std::path::Path;

const TEST_TARGET: &str = "test_target_elf64";

/// Helper to dynamically find instruction address in a function
fn find_instruction_addr(bin_path: &Path, func_name: &str, pattern: &str) -> (u64, String) {
    let bin_str = bin_path.to_str().unwrap();
    let (resp, output) = run_rvs_json::<BlocksData>(&["-f", bin_str, "analyze", "blocks", func_name]);
    assert!(output.status.success(), "Failed to get blocks for {}", func_name);

    let data = resp.data.expect("BlocksData missing");
    for block in &data.blocks {
        if let Some(ref instrs) = block.instructions {
            for inst in instrs {
                let text = inst
                    .disasm
                    .as_deref()
                    .or(inst.opcode.as_deref())
                    .unwrap_or("");
                if text.contains(pattern) {
                    let hex_addr = inst
                        .addr_hex
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", inst.addr));
                    return (inst.addr, hex_addr);
                }
            }
        }
    }
    panic!(
        "Instruction matching pattern '{}' not found in function {}",
        pattern, func_name
    );
}

#[test]
fn test_patch_instruction_assembly_changes_exit_code() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Verify baseline execution (Exit code 10, Auth Failed)
    let (code, stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code, Some(10), "Baseline should fail at auth with code 10");
    assert!(stdout.contains("FAILED: Authentication Failed"));

    // 2. Locate `mov eax, 0` inside check_auth_token
    let (_addr, addr_hex) = find_instruction_addr(&temp_bin, "sym.check_auth_token", "mov eax, 0");

    // 3. Patch instruction to `mov eax, 1`
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        &addr_hex,
        "--assembly",
        "mov eax, 1",
        "--backup",
    ]);

    assert!(output.status.success(), "Patch command failed");
    assert!(resp.success);
    assert_eq!(resp.command, "patch instruction");

    let patch_data = resp.data.expect("PatchData missing");
    if let Some(v) = patch_data.verified {
        assert!(v, "Patch should be verified by backend");
    }
    if let Some(ref orig) = patch_data.original_bytes {
        assert!(orig.contains("b800000000") || !orig.is_empty());
    }

    // 4. Verify backup file was created
    let backup_path = temp_bin.with_extension("bak");
    let alt_backup = format!("{}.bak", bin_str);
    assert!(
        backup_path.exists()
            || Path::new(&alt_backup).exists()
            || patch_data.backup_path.is_some(),
        "Backup file should exist"
    );

    // 5. Execute patched binary -> Should pass auth and fail at license (Exit code 20)
    let (new_code, new_stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(
        new_code,
        Some(20),
        "Patched binary should pass auth and exit with 20 at license check"
    );
    assert!(
        new_stdout.contains("FAILED: Invalid License"),
        "Stdout should indicate license failure: {}",
        new_stdout
    );
    assert!(
        !new_stdout.contains("FAILED: Authentication Failed"),
        "Auth failure should no longer appear"
    );
}

#[test]
fn test_patch_instruction_nop_bypasses_branch() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Locate conditional jump `jne` inside check_auth_token
    let (_addr, addr_hex) = find_instruction_addr(&temp_bin, "sym.check_auth_token", "jne");

    // 2. Patch conditional jump with 2-byte NOP sled
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "instruction", "--addr", &addr_hex, "--nop", "2",
    ]);

    assert!(output.status.success());
    assert!(resp.success);

    let patch_data = resp.data.expect("PatchData missing");
    if let Some(ref patched) = patch_data.patched_bytes {
        assert!(patched.contains("9090"), "Patched bytes should contain NOPs (9090)");
    }

    // 3. Execute binary -> Branch bypassed, auth passes, moves to license check (Exit code 20)
    let (code, stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code, Some(20));
    assert!(stdout.contains("FAILED: Invalid License"));
}

#[test]
fn test_patch_string_replaces_license_key() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Patch auth first to reach license check
    let (_, auth_addr_hex) = find_instruction_addr(&temp_bin, "sym.check_auth_token", "mov eax, 0");
    let _ = run_rvs(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        &auth_addr_hex,
        "--assembly",
        "mov eax, 1",
    ]);

    // 2. Patch license string from "MASTER-PASS-2026" to "DEFAULT_USER_KEY"
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "string",
        "--old",
        "MASTER-PASS-2026",
        "--new",
        "DEFAULT_USER_KEY",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "patch string");

    // 3. Execute binary -> Default input now matches expected key, moves to feature flag (Exit code 30)
    let (code, stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(
        code,
        Some(30),
        "Patched license should advance execution to feature check (code 30)"
    );
    assert!(stdout.contains("FAILED: Feature Disabled"));
    assert!(!stdout.contains("FAILED: Invalid License"));
}

#[test]
fn test_patch_string_strict_length_overflow_protection() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // Attempt to overwrite a 16-char string with a longer string with strict-length enabled
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "string",
        "--old",
        "MASTER-PASS-2026",
        "--new",
        "THIS_IS_A_VERY_LONG_STRING_THAT_EXCEEDS_BUFFER_BOUNDS",
        "--strict-length",
    ]);

    assert!(
        !output.status.success(),
        "Overlong string patch should fail under strict length"
    );
    assert!(!resp.success);
    let err = resp.error.expect("Error payload missing on string overflow");
    assert!(
        err.code == "STRING_OVERFLOW" || err.code.contains("OVERFLOW") || err.code.contains("BOUNDS"),
        "Error code should indicate overflow: {}",
        err.code
    );
}

#[test]
fn test_patch_string_banner_modification() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // Patch system banner string
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "string",
        "--old",
        "STATUS_SYSTEM_LOCKED",
        "--new",
        "STATUS_SYSTEM_ACTIVE",
    ]);

    assert!(output.status.success());
    assert!(resp.success);

    // Execute and verify stdout output
    let (_, stdout, _) = run_target_binary(&temp_bin, &[]);
    assert!(
        stdout.contains("Banner: STATUS_SYSTEM_ACTIVE"),
        "Stdout should reflect modified banner string: {}",
        stdout
    );
}

#[test]
fn test_patch_bytes_raw_hex() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // Locate `mov eax, 0` inside compute_feature_flag
    let (_addr, addr_hex) = find_instruction_addr(&temp_bin, "sym.compute_feature_flag", "mov eax, 0");

    // Patch 5 bytes: b800000000 -> b801000000 (mov eax, 1)
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "bytes", "--addr", &addr_hex, "--hex", "b801000000",
    ]);

    assert!(output.status.success());
    assert!(resp.success);

    let patch_data = resp.data.expect("PatchData missing");
    if let Some(bytes_mod) = patch_data.bytes_modified {
        assert_eq!(bytes_mod, 5, "5 bytes should be modified");
    }
}

#[test]
fn test_patch_bytes_invalid_hex_odd_length() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "bytes", "--addr", "0x401000", "--hex", "909",
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    let err = resp.error.expect("Error expected for odd length hex");
    assert!(
        err.code == "INVALID_HEX_STRING" || err.code.contains("HEX"),
        "Unexpected error code: {}",
        err.code
    );
}

#[test]
fn test_patch_bytes_invalid_hex_characters() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "bytes", "--addr", "0x401000", "--hex", "90ZZ",
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    let err = resp.error.expect("Error expected for invalid hex chars");
    assert!(
        err.code == "INVALID_HEX_STRING" || err.code.contains("HEX"),
        "Unexpected error code: {}",
        err.code
    );
}

#[test]
fn test_patch_instruction_invalid_assembly_error() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        "0x401000",
        "--assembly",
        "invalid_instruction_xyz_op",
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    let err = resp.error.expect("Error expected for invalid assembly opcode");
    assert!(
        err.code == "ASSEMBLY_FAILED" || err.code.contains("ASSEMBL"),
        "Unexpected error code: {}",
        err.code
    );
}

#[test]
fn test_patching_auth_gate_multi_stage_unlock() {
    let (_temp_dir, temp_bin) = create_temp_fixture("auth_gate_elf64");
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Baseline: exit 1 (AUTH_FAIL: Bad Password)
    let (code0, out0, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code0, Some(1));
    assert!(out0.contains("AUTH_FAIL: Bad Password"));

    // 2. Patch check_master_password: mov eax, 0 -> mov eax, 1
    let (_, pwd_addr) = find_instruction_addr(&temp_bin, "sym.check_master_password", "mov eax, 0");
    let (res1, out1) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "instruction", "--addr", &pwd_addr, "--assembly", "mov eax, 1"
    ]);
    assert!(out1.status.success());
    assert!(res1.success);

    // After patch 1: should advance to exit 2 (AUTH_FAIL: Bad PIN)
    let (code1, out1_bin, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code1, Some(2));
    assert!(out1_bin.contains("AUTH_FAIL: Bad PIN"));

    // 3. Patch check_admin_pin: mov eax, 0 -> mov eax, 1
    let (_, pin_addr) = find_instruction_addr(&temp_bin, "sym.check_admin_pin", "mov eax, 0");
    let (res2, out2) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "instruction", "--addr", &pin_addr, "--assembly", "mov eax, 1"
    ]);
    assert!(out2.status.success());
    assert!(res2.success);

    // After patch 2: should advance to exit 3 (AUTH_FAIL: Insufficient Level)
    let (code2, out2_bin, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code2, Some(3));
    assert!(out2_bin.contains("AUTH_FAIL: Insufficient Level"));

    // 4. Patch check_access_level: mov eax, 0 -> mov eax, 1
    let (_, lvl_addr) = find_instruction_addr(&temp_bin, "sym.check_access_level", "mov eax, 0");
    let (res3, out3) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "instruction", "--addr", &lvl_addr, "--assembly", "mov eax, 1"
    ]);
    assert!(out3.status.success());
    assert!(res3.success);

    // After patch 3: all gates bypassed, exit 0 (AUTH_SUCCESS: Access Granted)
    let (code3, out3_bin, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code3, Some(0));
    assert!(out3_bin.contains("AUTH_SUCCESS: Access Granted"));
}

#[test]
fn test_patching_flow_calc_message() {
    let (_temp_dir, temp_bin) = create_temp_fixture("flow_calc_elf64");
    let bin_str = temp_bin.to_str().unwrap();

    // Patch message string
    let (resp, out) = run_rvs_json::<PatchData>(&[
        "-f", bin_str, "patch", "string",
        "--old", "CALC_SUCCESS: All calculations matched",
        "--new", "CALC_SUCCESS: Result was verified ok!"
    ]);
    assert!(out.status.success());
    assert!(resp.success);

    let (code, stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(code, Some(0));
    assert!(stdout.contains("CALC_SUCCESS: Result was verified ok!"));
}

#[test]
fn test_patch_instruction_seek_aware_relative_jump_crackme() {
    let (_temp_dir, temp_bin) = create_temp_fixture("crackme_case");
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Patch conditional branch at 0x13d2 to unconditionally jump to success branch at 0x1479
    let (resp, output) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        "0x13d2",
        "--assembly",
        "jmp 0x1479",
        "--backup",
    ]);

    assert!(output.status.success(), "Patch command failed");
    assert!(resp.success);
    assert_eq!(resp.command, "patch instruction");

    let patch_data = resp.data.expect("PatchData missing");
    assert_eq!(patch_data.verified, Some(true));
    assert_eq!(patch_data.patched_bytes.as_deref(), Some("e9a2000000"));
    assert_eq!(patch_data.bytes_modified, Some(5));

    // 2. Execute patched binary with invalid serial -> should bypass check and output 'Valid serial'
    let mut child = std::process::Command::new(&temp_bin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn patched crackme binary");

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"arbitrary_wrong_serial\n");
    }

    let out = child.wait_with_output().expect("Failed to read stdout");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Valid serial"),
        "Stdout should contain success message: {}",
        stdout
    );
    assert!(
        stdout.contains("Join us"),
        "Stdout should contain final banner: {}",
        stdout
    );
}

