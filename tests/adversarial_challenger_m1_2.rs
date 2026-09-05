use std::io::Write;
use tempfile::NamedTempFile;

use rvs::agent::run_patch_plan;
use rvs::error::AppError;
use rvs::r2::R2Driver;
use rvs::response::ApiResponse;

mod common;
use common::{fixture_path, run_rvs};

const TEST_TARGET: &str = "test_target_elf64";

fn get_driver() -> R2Driver {
    let target = fixture_path(TEST_TARGET);
    R2Driver::new(&target, None, None, true).expect("Failed to initialize test driver")
}

// =========================================================================
// Area 1: Patch Plans with Missing Fields and Edge Cases
// =========================================================================

#[test]
fn test_patch_plan_missing_assembly_dry_run() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing Assembly Plan",
        "dry_run": true,
        "steps": [
            { "type": "instruction", "addr": "0x1000" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing assembly");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'assembly'"),
                "Expected message about missing assembly, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_missing_assembly_live() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing Assembly Plan Live",
        "dry_run": false,
        "steps": [
            { "type": "instruction", "addr": "0x1000" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing assembly in live execution");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'assembly'"),
                "Expected message about missing assembly, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_missing_hex_dry_run() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing Hex Plan",
        "dry_run": true,
        "steps": [
            { "type": "bytes", "addr": "0x1000" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing hex");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'hex'"),
                "Expected message about missing hex, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_missing_hex_live() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing Hex Plan Live",
        "dry_run": false,
        "steps": [
            { "type": "bytes", "addr": "0x1000" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing hex in live execution");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'hex'"),
                "Expected message about missing hex, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_missing_new_string_dry_run() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing String Plan",
        "dry_run": true,
        "steps": [
            { "type": "string", "addr": "0x1000" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing new_string");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'new_string'"),
                "Expected message about missing new_string, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_missing_new_string_live() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing String Plan Live",
        "dry_run": false,
        "steps": [
            { "type": "string", "addr": "0x1000" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing new_string in live execution");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'new_string'"),
                "Expected message about missing new_string, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_unknown_step_types() {
    let driver = get_driver();
    let unknown_types = [
        "quantum_jump",
        "UNKNOWN",
        "execute_payload",
        "123",
        "",
    ];

    for step_t in unknown_types {
        let plan_json = format!(
            r#"{{
                "name": "Unknown Step Type Plan",
                "dry_run": true,
                "steps": [
                    {{ "type": "{step_t}", "addr": "0x1000" }}
                ]
            }}"#
        );

        let res = run_patch_plan(&driver, &plan_json);
        assert!(res.is_err(), "Expected error for unknown step type '{step_t}'");
        match res.unwrap_err() {
            AppError::PatchPlanError(msg) => {
                assert!(
                    msg.contains("Unknown step type"),
                    "Expected 'Unknown step type' in message, got: {msg}"
                );
            }
            other => panic!("Expected PatchPlanError, got {:?}", other),
        }
    }
}

#[test]
fn test_patch_plan_missing_addr() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Missing Addr Plan",
        "dry_run": true,
        "steps": [
            { "type": "instruction", "assembly": "nop" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for missing addr in JSON");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing field `addr`") || msg.contains("Malformed patch plan JSON"),
                "Expected malformed JSON error for missing field `addr`, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_empty_or_whitespace_addr() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Empty Addr Plan",
        "dry_run": true,
        "steps": [
            { "type": "instruction", "addr": "   \t\n  ", "assembly": "nop" }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_err(), "Expected error for whitespace addr");
    match res.unwrap_err() {
        AppError::PatchPlanError(msg) => {
            assert!(
                msg.contains("missing required field 'addr'"),
                "Expected missing required field 'addr' error, got: {msg}"
            );
        }
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }
}

#[test]
fn test_patch_plan_malformed_json_variants() {
    let driver = get_driver();
    let malformed_inputs = [
        "",
        "not json at all",
        "{",
        "{\"name\": \"only name\"}",
        "{\"steps\": []}",
        "[{\"type\": \"instruction\"}]",
        "{\"name\": 12345, \"steps\": []}",
        "{\"name\": \"bad steps\", \"steps\": \"not a list\"}",
    ];

    for input in malformed_inputs {
        let res = run_patch_plan(&driver, input);
        assert!(res.is_err(), "Malformed input should return Err: {input:?}");
        match res.unwrap_err() {
            AppError::PatchPlanError(msg) => {
                assert!(
                    msg.contains("Malformed patch plan JSON"),
                    "Expected 'Malformed patch plan JSON' in {msg}"
                );
            }
            other => panic!("Expected PatchPlanError for input {:?}, got {:?}", input, other),
        }
    }
}

#[test]
fn test_patch_plan_from_file_edges() {
    let driver = get_driver();

    // 1. Valid plan in file
    let mut tmp_valid = NamedTempFile::new().unwrap();
    write!(
        tmp_valid,
        r#"{{"name": "file_plan", "dry_run": true, "steps": [{{"type": "instruction", "addr": "0x11e0", "assembly": "nop"}}]}}"#
    ).unwrap();
    let res_valid = run_patch_plan(&driver, tmp_valid.path().to_str().unwrap());
    assert!(res_valid.is_ok(), "Valid plan from file should succeed");

    // 2. Missing assembly in file
    let mut tmp_invalid = NamedTempFile::new().unwrap();
    write!(
        tmp_invalid,
        r#"{{"name": "file_plan", "dry_run": true, "steps": [{{"type": "instruction", "addr": "0x11e0"}}]}}"#
    ).unwrap();
    let res_invalid = run_patch_plan(&driver, tmp_invalid.path().to_str().unwrap());
    assert!(res_invalid.is_err());
    match res_invalid.unwrap_err() {
        AppError::PatchPlanError(msg) => assert!(msg.contains("missing required field 'assembly'")),
        other => panic!("Expected PatchPlanError, got {:?}", other),
    }

    // 3. Empty file
    let tmp_empty = NamedTempFile::new().unwrap();
    let res_empty = run_patch_plan(&driver, tmp_empty.path().to_str().unwrap());
    assert!(res_empty.is_err());
    match res_empty.unwrap_err() {
        AppError::PatchPlanError(msg) => assert!(msg.contains("Malformed patch plan JSON")),
        other => panic!("Expected PatchPlanError for empty file, got {:?}", other),
    }
}

// =========================================================================
// Area 2: Truncated or Multi-byte UTF-8 Strings in parse_json
// =========================================================================

#[test]
fn test_parse_json_2byte_utf8_char_straddling_byte_200() {
    // 199 ASCII bytes + 2-byte Greek Omega 'Ω' (0xCE 0xA9) = 201 bytes.
    // In raw byte slicing [..200], index 200 falls between 0xCE and 0xA9 -> PANIC.
    // In chars().take(200), taking 200 chars produces valid UTF-8 string -> NO PANIC.
    let mut payload = "x".repeat(199);
    payload.push('Ω');
    payload.push_str(" trailing invalid content");

    let res = R2Driver::parse_json::<serde_json::Value>(&payload);
    assert!(res.is_err(), "Invalid JSON must return Err");
    match res.unwrap_err() {
        AppError::R2ExecutionError(msg) => {
            assert!(msg.contains("Failed to parse JSON"));
            // The preview must contain 'Ω' safely
            assert!(msg.contains('Ω'));
        }
        other => panic!("Expected R2ExecutionError, got {:?}", other),
    }
}

#[test]
fn test_parse_json_3byte_utf8_char_straddling_byte_200() {
    // 3-byte CJK character '中' (0xE4 0xB8 0xAD).
    // Test byte index 200 landing at offset 1 or offset 2 of the 3-byte char.
    for ascii_count in [198, 199] {
        let mut payload = "A".repeat(ascii_count);
        payload.push('中');
        payload.push_str(" invalid json trailing text");

        let res = R2Driver::parse_json::<serde_json::Value>(&payload);
        assert!(res.is_err());
        match res.unwrap_err() {
            AppError::R2ExecutionError(msg) => {
                assert!(msg.contains("Failed to parse JSON"));
                assert!(msg.contains('中'));
            }
            other => panic!("Expected R2ExecutionError, got {:?}", other),
        }
    }
}

#[test]
fn test_parse_json_4byte_utf8_char_straddling_byte_200() {
    // 4-byte Emoji '🦀' (0xF0 0x9F 0xA6 0x80).
    // Test byte index 200 landing at offsets 1, 2, 3 inside the 4-byte sequence.
    for ascii_count in [197, 198, 199] {
        let mut payload = "B".repeat(ascii_count);
        payload.push('🦀');
        payload.push_str(" trailing invalid json");

        let res = R2Driver::parse_json::<serde_json::Value>(&payload);
        assert!(res.is_err());
        match res.unwrap_err() {
            AppError::R2ExecutionError(msg) => {
                assert!(msg.contains("Failed to parse JSON"));
                assert!(msg.contains('🦀'));
            }
            other => panic!("Expected R2ExecutionError, got {:?}", other),
        }
    }
}

#[test]
fn test_parse_json_pure_multibyte_stream_300_chars() {
    // String composed entirely of 3-byte characters (300 chars = 900 bytes).
    // In old [..200], byte 200 is 66 * 3 + 2 -> straddles byte 2 of 67th char -> PANIC.
    // In chars().take(200), takes exactly 200 chars -> NO PANIC.
    let payload: String = "日".repeat(300);

    let res = R2Driver::parse_json::<serde_json::Value>(&payload);
    assert!(res.is_err());
    match res.unwrap_err() {
        AppError::R2ExecutionError(msg) => {
            assert!(msg.contains("Failed to parse JSON"));
            // Ensure preview contains 200 '日'
            let count = msg.chars().filter(|&c| c == '日').count();
            assert_eq!(count, 200, "Preview should contain exactly 200 chars");
        }
        other => panic!("Expected R2ExecutionError, got {:?}", other),
    }
}

#[test]
fn test_parse_json_with_brackets_and_unicode_syntax_error() {
    // String with [ ... ] array brackets, but inner content is broken JSON with Vietnamese unicode
    let payload = "[ 1, 2, 3, \"Tiếng Việt có dấu: đ, ê, ơ\", broken_trailing_identifier ]";
    let res = R2Driver::parse_json::<serde_json::Value>(payload);
    assert!(res.is_err());
    match res.unwrap_err() {
        AppError::R2ExecutionError(msg) => {
            assert!(msg.contains("Failed to parse JSON"));
            assert!(msg.contains("Tiếng Việt"));
        }
        other => panic!("Expected R2ExecutionError, got {:?}", other),
    }
}

#[test]
fn test_parse_json_with_ansi_escapes_and_unicode() {
    // Radare2 error message with ANSI colors and unicode
    let payload = "\x1b[31;1m[ERROR]\x1b[0m Cannot resolve symbol 🚀: Invalid syntax near '🦀'";
    let res = R2Driver::parse_json::<serde_json::Value>(payload);
    assert!(res.is_err());
    match res.unwrap_err() {
        AppError::R2ExecutionError(msg) => {
            assert!(msg.contains("Failed to parse JSON"));
            assert!(!msg.contains("\x1b["));
            assert!(msg.contains("🚀"));
            assert!(msg.contains("🦀"));
        }
        other => panic!("Expected R2ExecutionError, got {:?}", other),
    }
}

// =========================================================================
// Area 3: Strict Adherence to 1..6 Exit Code Taxonomy
// =========================================================================

#[test]
fn test_exit_code_taxonomy_exhaustive_mapping() {
    // Verify EVERY AppError variant produces an exit code in 1..=6 and matches its category

    let cases: Vec<(AppError, u8, &'static str)> = vec![
        // Exit code 1: INVALID_ARGUMENT
        (AppError::InvalidArgument("invalid arg".into()), 1, "INVALID_ARGUMENT"),
        (AppError::PatchPlanError("plan error".into()), 1, "INVALID_ARGUMENT"),

        // Exit code 2: FILE_ERROR
        (AppError::FileNotFound("not found".into()), 2, "FILE_ERROR"),
        (AppError::PermissionDenied("denied".into()), 2, "FILE_ERROR"),
        (AppError::ZeroByteFile("empty".into()), 2, "FILE_ERROR"),
        (AppError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "io not found")), 2, "FILE_ERROR"),
        (AppError::IoError(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "io denied")), 2, "FILE_ERROR"),

        // Exit code 3: ANALYSIS_ERROR
        (AppError::InvalidBinary("bad elf".into()), 3, "ANALYSIS_ERROR"),
        (AppError::SymbolNotFound("main".into()), 3, "ANALYSIS_ERROR"),
        (AppError::AddressOutOfBounds("0xdeadbeef".into()), 3, "ANALYSIS_ERROR"),
        (AppError::DecompilationFailed { function: "foo".into(), reason: "bad cfg".into() }, 3, "ANALYSIS_ERROR"),
        (AppError::FlowAnalysisFailed { function: "foo".into(), reason: "cycles".into() }, 3, "ANALYSIS_ERROR"),
        (AppError::EmulationFailed { target: "foo".into(), reason: "trap".into() }, 3, "ANALYSIS_ERROR"),

        // Exit code 4: PATCH_ERROR
        (AppError::AssemblyFailed { instruction: "nop".into(), details: "err".into() }, 4, "PATCH_ERROR"),
        (AppError::InvalidHexString { hex: "123".into(), reason: "odd".into() }, 4, "PATCH_ERROR"),
        (AppError::StringOverflow { original_length: 5, replacement_length: 10, address: "0x1".into() }, 4, "PATCH_ERROR"),
        (AppError::StringNotFound("secret".into()), 4, "PATCH_ERROR"),
        (AppError::BackupFailed("/tmp/bak".into()), 4, "PATCH_ERROR"),
        (AppError::VerificationFailed { address: "0x1".into(), expected: "aa".into(), actual: "bb".into() }, 4, "PATCH_ERROR"),

        // Exit code 5: TIMEOUT_ERROR
        (AppError::Timeout("r2 command timed out".into()), 5, "TIMEOUT_ERROR"),

        // Exit code 6: INTERNAL_ERROR
        (AppError::R2ExecutionError("r2 crashed".into()), 6, "INTERNAL_ERROR"),
        (AppError::Internal("core dump".into()), 6, "INTERNAL_ERROR"),
        (AppError::JsonError(serde_json::from_str::<serde_json::Value>("bad").unwrap_err()), 6, "INTERNAL_ERROR"),
        (AppError::IoError(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "conn reset")), 6, "INTERNAL_ERROR"),
    ];

    for (err, expected_code, expected_cat) in cases {
        let code = err.exit_code();
        let cat = err.category();
        let api_err = err.to_api_error();

        assert!(
            (1..=6).contains(&code),
            "Exit code must be in 1..=6, got {code} for {:?}", err
        );
        assert_eq!(code, expected_code, "Mismatch exit code for {:?}", err);
        assert_eq!(cat, expected_cat, "Mismatch category for {:?}", err);
        assert_eq!(api_err.exit_code, Some(expected_code));
        assert_eq!(api_err.category.as_deref(), Some(expected_cat));
    }
}

#[test]
fn test_cli_exit_codes_end_to_end() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    // 1. Exit code 1: CLI parse error (invalid flag)
    let out = run_rvs(&["--invalid-flag-12345"]);
    assert_eq!(out.status.code(), Some(1));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(1));
    assert_eq!(resp.error.as_ref().unwrap().category.as_deref(), Some("INVALID_ARGUMENT"));

    // 2. Exit code 1: Missing target binary
    let out = run_rvs(&["info"]);
    assert_eq!(out.status.code(), Some(1));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(1));

    // 3. Exit code 1: Command injection attempt in target address
    let out = run_rvs(&["-f", target_str, "analyze", "blocks", "sym.main; whoami"]);
    assert_eq!(out.status.code(), Some(1));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().code, "INVALID_ARGUMENT");
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(1));

    // 4. Exit code 2: Nonexistent file
    let out = run_rvs(&["-f", "/tmp/nonexistent_file_9999.bin", "info"]);
    assert_eq!(out.status.code(), Some(2));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(2));
    assert_eq!(resp.error.as_ref().unwrap().category.as_deref(), Some("FILE_ERROR"));

    // 5. Exit code 2: Directory target
    let out = run_rvs(&["-f", "/tmp", "info"]);
    assert_eq!(out.status.code(), Some(2));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(2));

    // 6. Exit code 2: Zero-byte file
    let tmp_empty = NamedTempFile::new().unwrap();
    let out = run_rvs(&["-f", tmp_empty.path().to_str().unwrap(), "info"]);
    assert_eq!(out.status.code(), Some(2));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(2));

    // 7. Exit code 3: Nonexistent function in decompile
    let out = run_rvs(&["-f", target_str, "agent", "decompile", "nonexistent_func_xyz"]);
    assert_eq!(out.status.code(), Some(3));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(3));
    assert_eq!(resp.error.as_ref().unwrap().category.as_deref(), Some("ANALYSIS_ERROR"));

    // 8. Exit code 4: Invalid assembly instruction
    let out = run_rvs(&[
        "-f", target_str,
        "patch", "instruction",
        "--addr", "0x1000",
        "--assembly", "bogus_opcode eax, ebx",
    ]);
    assert_eq!(out.status.code(), Some(4));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(4));
    assert_eq!(resp.error.as_ref().unwrap().category.as_deref(), Some("PATCH_ERROR"));

    // 9. Exit code 4: Invalid hex string (odd length)
    let out = run_rvs(&[
        "-f", target_str,
        "patch", "bytes",
        "--addr", "0x1000",
        "--hex", "123",
    ]);
    assert_eq!(out.status.code(), Some(4));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(4));

    // 10. Exit code 4: Invalid hex string (non-hex characters)
    let out = run_rvs(&[
        "-f", target_str,
        "patch", "bytes",
        "--addr", "0x1000",
        "--hex", "12zz",
    ]);
    assert_eq!(out.status.code(), Some(4));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(4));
}
