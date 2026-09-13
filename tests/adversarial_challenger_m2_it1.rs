use rvs::error::AppError;
use rvs::frida::hook::{validate_and_normalize_addr, validate_hook_format};
use rvs::frida::target::FridaTarget;
use std::path::PathBuf;

mod common;
use common::{run_rvs, run_rvs_json, ApiResponse};

// =========================================================================
// 1. Target & URI Parsing Adversarial Stress
// =========================================================================

#[test]
fn test_frida_target_negative_pids() {
    for neg_pid in &["-1", "-9999", "-0", "-2147483648", "-9223372036854775808"] {
        let res = FridaTarget::parse_attach(neg_pid);
        assert!(res.is_err(), "Expected error for negative PID {neg_pid}");
        match res.unwrap_err() {
            AppError::InvalidArgument(msg) => {
                assert!(msg.contains("cannot be negative"));
            }
            other => panic!("Expected InvalidArgument, got {:?}", other),
        }
    }
}

#[test]
fn test_frida_target_malformed_uris() {
    for bad_uri in &[
        "gdb://1234",
        "http://localhost:8080",
        "unknown://target",
        "tcp://127.0.0.1",
        "ssh://root@box",
        "file:///tmp/proc",
    ] {
        let res = FridaTarget::parse_attach(bad_uri);
        assert!(res.is_err(), "Expected error for unsupported URI {bad_uri}");
        match res.unwrap_err() {
            AppError::InvalidArgument(msg) => {
                assert!(msg.contains("Invalid URI scheme"));
            }
            other => panic!("Expected InvalidArgument, got {:?}", other),
        }
    }
}

#[test]
fn test_frida_target_valid_uris_and_pids() {
    assert_eq!(FridaTarget::parse_attach("1234").unwrap(), FridaTarget::Pid(1234));
    assert_eq!(FridaTarget::parse_attach("0").unwrap(), FridaTarget::Pid(0));
    assert_eq!(
        FridaTarget::parse_attach("frida://1234").unwrap(),
        FridaTarget::Uri("frida://1234".to_string())
    );
    assert_eq!(
        FridaTarget::parse_attach("firefox").unwrap(),
        FridaTarget::ProcessName("firefox".to_string())
    );
}

#[test]
fn test_frida_spawn_missing_binary() {
    let res = FridaTarget::parse_spawn(PathBuf::from("/nonexistent/binary/xyz_9999"), vec![]);
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), AppError::FileNotFound(_)));
}

// =========================================================================
// 2. Address Normalization & Boundary Verification
// =========================================================================

#[test]
fn test_address_out_of_bounds() {
    for oob in &["0xffffffffffffffff", "0x800000000000", "0x1000000000000"] {
        let res = validate_and_normalize_addr(oob);
        assert!(res.is_err(), "Expected AddressOutOfBounds for {oob}");
        assert!(matches!(res.unwrap_err(), AppError::AddressOutOfBounds(_)));
    }
}

#[test]
fn test_address_valid_boundaries() {
    assert_eq!(validate_and_normalize_addr("0x0").unwrap(), "0x0");
    assert_eq!(validate_and_normalize_addr("0x1000").unwrap(), "0x1000");
    assert_eq!(validate_and_normalize_addr("0x7fffffffffff").unwrap(), "0x7fffffffffff");
    assert_eq!(validate_and_normalize_addr("main").unwrap(), "main");
}

#[test]
fn test_address_invalid_strings() {
    assert!(matches!(validate_and_normalize_addr("").unwrap_err(), AppError::InvalidArgument(_)));
    assert!(matches!(validate_and_normalize_addr("   ").unwrap_err(), AppError::InvalidArgument(_)));
    assert!(matches!(validate_and_normalize_addr("0xZZZZ").unwrap_err(), AppError::InvalidArgument(_)));
}

// =========================================================================
// 3. Hook Format Specifier Validation
// =========================================================================

#[test]
fn test_hook_format_specifier_characters() {
    for bad_fmt in &["INVALID_FMT", "???", "x!z", "i#x", "format%"] {
        let res = validate_hook_format(bad_fmt);
        assert!(res.is_err(), "Expected error for invalid format {bad_fmt}");
        assert!(matches!(res.unwrap_err(), AppError::InvalidArgument(_)));
    }

    for good_fmt in &["i", "x", "z", "w", "a", "h", "O", "p", "s", "c", "v", "^", "+", "i2x"] {
        assert!(validate_hook_format(good_fmt).is_ok(), "Expected valid format {good_fmt}");
    }
}

// =========================================================================
// 4. CLI Subcommand Invocations & Envelope Conformance
// =========================================================================

#[test]
fn test_cli_negative_pid_attach() {
    let (resp, out): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&["frida", "attach", "-1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!resp.success);
    let err = resp.error.expect("Error object missing");
    assert_eq!(err.category.as_deref(), Some("INVALID_ARGUMENT"));
    assert_eq!(err.exit_code, Some(1));
}

#[test]
fn test_cli_symbols_negative_pagination() {
    let (resp, out): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&["frida", "symbols", "-t", "1234", "--limit", "-10"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!resp.success);
    let err = resp.error.expect("Error object missing");
    assert_eq!(err.category.as_deref(), Some("INVALID_ARGUMENT"));
    assert!(err.message.contains("--limit must be non-negative"));

    let (resp2, out2): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&["frida", "symbols", "-t", "1234", "--offset", "-5"]);
    assert_eq!(out2.status.code(), Some(1));
    assert!(!resp2.success);
    let err2 = resp2.error.expect("Error object missing");
    assert_eq!(err2.category.as_deref(), Some("INVALID_ARGUMENT"));
    assert!(err2.message.contains("--offset must be non-negative"));
}

#[test]
fn test_cli_mem_write_invalid_hex() {
    for bad_hex in &["ZZZZ", "123", "", "0xZZZZ", "90 90"] {
        let (resp, out): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&[
            "frida", "mem-write", "-t", "1234", "-A", "0x1000", "--data", bad_hex,
        ]);
        assert_eq!(out.status.code(), Some(1), "Expected exit 1 for bad hex {bad_hex}");
        assert!(!resp.success);
        let err = resp.error.expect("Error object missing");
        assert_eq!(err.category.as_deref(), Some("INVALID_ARGUMENT"));
        assert!(err.message.contains("Invalid hex data string"));
    }
}

#[test]
fn test_cli_spawn_missing_binary() {
    let (resp, out): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&[
        "frida", "spawn", "/nonexistent/binary/path/xyz",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!resp.success);
    let err = resp.error.expect("Error object missing");
    assert_eq!(err.category.as_deref(), Some("FILE_ERROR"));
    assert_eq!(err.code, "FILE_NOT_FOUND");
}

#[test]
fn test_cli_script_missing_file() {
    let (resp, out): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&[
        "frida", "script", "-t", "1234", "--file", "/nonexistent/script.js",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!resp.success);
    let err = resp.error.expect("Error object missing");
    assert_eq!(err.category.as_deref(), Some("FILE_ERROR"));
    assert_eq!(err.code, "FILE_NOT_FOUND");
}

#[test]
fn test_cli_address_out_of_bounds() {
    let (resp, out): (ApiResponse<serde_json::Value>, _) = run_rvs_json(&[
        "frida", "hook", "-t", "1234", "-A", "0xffffffffffffffff",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!resp.success);
    let err = resp.error.expect("Error object missing");
    assert_eq!(err.category.as_deref(), Some("ANALYSIS_ERROR"));
    assert_eq!(err.code, "ADDRESS_OUT_OF_BOUNDS");
}

#[test]
fn test_cli_missing_mandatory_arguments_fails_gracefully() {
    let out = run_rvs(&["frida", "attach"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(stdout_str.contains("INVALID_ARGUMENT"));
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Failed to parse JSON");
    assert!(!resp.success);
    assert_eq!(resp.error.unwrap().category.as_deref(), Some("INVALID_ARGUMENT"));
}
