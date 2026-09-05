use std::time::Duration;
use tempfile::NamedTempFile;

use rvs::agent::{dynamic::run_agent_emulate, patch_plan::run_patch_plan};
use rvs::analysis::dynamic::{analyze_emulate, analyze_step, analyze_trace, EmulateOptions, TraceOptions};
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
// Area 1: Multi-byte UTF-8 & Emoji Boundary Stress in parse_json and Driver
// =========================================================================

#[test]
fn test_parse_json_emoji_boundary_sliding_window() {
    // Test 4-byte emoji (🦀, 🚀, 🔥, 🌍) placed exactly across character boundary 200
    // at ASCII offsets from 194 to 205.
    let emojis = ["🦀", "🚀", "🔥", "🌍", "✨", "🎉", "👨‍👩‍👧‍👦"];
    for emoji in emojis {
        for ascii_len in 194..=205 {
            let mut payload = "A".repeat(ascii_len);
            payload.push_str(emoji);
            payload.push_str(" trailing_garbage_not_json_12345");

            let res = R2Driver::parse_json::<serde_json::Value>(&payload);
            assert!(res.is_err(), "Payload must be invalid JSON");
            match res.unwrap_err() {
                AppError::R2ExecutionError(msg) => {
                    assert!(msg.contains("Failed to parse JSON from radare2 output"));
                    // Verify the preview is valid UTF-8 string that does not panic
                    assert!(!msg.is_empty());
                }
                other => panic!("Expected R2ExecutionError, got {:?}", other),
            }
        }
    }
}

#[test]
fn test_parse_json_pure_emoji_stream_large() {
    // 500 emojis (2000+ bytes)
    let payload = "🦀".repeat(500);
    let res = R2Driver::parse_json::<serde_json::Value>(&payload);
    assert!(res.is_err());
    match res.unwrap_err() {
        AppError::R2ExecutionError(msg) => {
            assert!(msg.contains("Failed to parse JSON"));
            let crab_count = msg.chars().filter(|&c| c == '🦀').count();
            assert_eq!(crab_count, 200, "Preview should safely take exactly 200 scalar characters");
        }
        other => panic!("Expected R2ExecutionError, got {:?}", other),
    }
}

#[test]
fn test_resolve_address_emoji_symbol_safe_rejection() {
    let driver = get_driver();
    let emoji_targets = ["🚀", "🦀", "sym.🚀", "main_🔥", "0xZZZZ🦀"];
    for target in emoji_targets {
        let res = driver.resolve_address(target);
        assert!(res.is_err(), "Target '{target}' should return error");
        match res.unwrap_err() {
            AppError::SymbolNotFound(s) => {
                assert!(s.contains(target));
            }
            AppError::InvalidArgument(_) => {
                // If rejected as invalid argument, also valid
            }
            other => panic!("Expected SymbolNotFound or InvalidArgument for '{target}', got {:?}", other),
        }
    }
}

// =========================================================================
// Area 2: Empty Patch Plan Steps & Malformed Inputs
// =========================================================================

#[test]
fn test_patch_plan_empty_steps_dry_run() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "Empty Steps Dry Run",
        "dry_run": true,
        "steps": []
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_ok(), "Empty steps in dry run should succeed with 0 steps executed");
    let result = res.unwrap();
    assert_eq!(result.total_steps, 0);
    assert_eq!(result.steps_executed, 0);
    assert!(result.step_results.is_empty());
    assert!(!result.applied);
    assert!(result.dry_run);
    assert!(result.backup_path.is_none());
}

#[test]
fn test_patch_plan_empty_steps_live_run() {
    let target = fixture_path(TEST_TARGET);
    // Create temporary copy for live patching
    let temp_copy = NamedTempFile::new().unwrap();
    std::fs::copy(&target, temp_copy.path()).unwrap();
    let driver = R2Driver::new(temp_copy.path(), None, None, true).unwrap();

    let plan_json = r#"{
        "name": "Empty Steps Live Run",
        "dry_run": false,
        "steps": []
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_ok(), "Empty steps in live run should succeed with 0 steps executed");
    let result = res.unwrap();
    assert_eq!(result.total_steps, 0);
    assert_eq!(result.steps_executed, 0);
    assert!(result.step_results.is_empty());
    assert!(result.applied);
    assert!(!result.dry_run);
    assert!(result.backup_path.is_some());
}

#[test]
fn test_patch_plan_emoji_metadata_and_replacement() {
    let driver = get_driver();
    let plan_json = r#"{
        "name": "🚀 Emoji Patch Plan 🦀",
        "dry_run": true,
        "steps": [
            {
                "type": "string",
                "addr": "sym.main",
                "new_string": "Hello 🦀 World 🌍"
            }
        ]
    }"#;

    let res = run_patch_plan(&driver, plan_json);
    assert!(res.is_ok(), "Emoji string patch plan should succeed in dry run");
    let result = res.unwrap();
    assert_eq!(result.plan_name, "🚀 Emoji Patch Plan 🦀");
    assert_eq!(result.total_steps, 1);
    assert_eq!(result.step_results.len(), 1);
    let step = &result.step_results[0];
    assert!(step.success);
    // Verify patched_bytes contains UTF-8 hex for 🦀 (f09fa680) and 🌍 (f09f8c8d)
    let patched = step.patched_bytes.as_ref().unwrap();
    assert!(patched.contains("f09fa680"), "Must contain 🦀 UTF-8 bytes");
    assert!(patched.contains("f09f8c8d"), "Must contain 🌍 UTF-8 bytes");
}

#[test]
fn test_patch_plan_malformed_step_objects() {
    let driver = get_driver();
    let test_cases = [
        // Completely empty step object
        (r#"{"name": "test", "dry_run": true, "steps": [{}]}"#, "missing field `type`"),
        // Missing addr
        (r#"{"name": "test", "dry_run": true, "steps": [{"type": "instruction"}]}"#, "missing field `addr`"),
        // Empty addr string
        (r#"{"name": "test", "dry_run": true, "steps": [{"type": "instruction", "addr": ""}]}"#, "missing required field 'addr'"),
        // Whitespace addr string
        (r#"{"name": "test", "dry_run": true, "steps": [{"type": "instruction", "addr": "   "}]}"#, "missing required field 'addr'"),
        // Unknown step type
        (r#"{"name": "test", "dry_run": true, "steps": [{"type": "nuke", "addr": "0x1000"}]}"#, "Unknown step type 'nuke'"),
    ];

    for (json_str, expected_msg) in test_cases {
        let res = run_patch_plan(&driver, json_str);
        assert!(res.is_err(), "Expected error for {json_str}");
        match res.unwrap_err() {
            AppError::PatchPlanError(msg) => {
                assert!(msg.contains(expected_msg), "Expected '{expected_msg}' in '{msg}'");
            }
            other => panic!("Expected PatchPlanError, got {:?}", other),
        }
    }
}

// =========================================================================
// Area 3: Zero Steps & Boundary Dynamic Emulation
// =========================================================================

#[test]
fn test_dynamic_emulate_zero_steps() {
    let driver = get_driver();
    let opts = EmulateOptions {
        target: "main".to_string(),
        steps: 0,
        ..Default::default()
    };

    let res = analyze_emulate(&driver, &opts);
    assert!(res.is_ok(), "Zero steps emulation should succeed");
    let data = res.unwrap();
    assert_eq!(data.steps_requested, 0);
    assert_eq!(data.steps_executed, 0);
    assert_eq!(data.register_diff.len(), 0, "No registers should change on 0 steps");
    assert_eq!(data.final_addr, data.start_addr);
}

#[test]
fn test_dynamic_step_zero_count_defaults_to_one() {
    let driver = get_driver();
    let res = analyze_step(&driver, "main", 0, &[]);
    assert!(res.is_ok(), "Count 0 should safely default to 1 step");
    let data = res.unwrap();
    assert_eq!(data.steps, 1);
    assert_ne!(data.current_addr, 0);
}

#[test]
fn test_dynamic_trace_zero_steps_defaults_to_twenty() {
    let driver = get_driver();
    let opts = TraceOptions {
        target: "main".to_string(),
        steps: 0,
        reg_set: vec![],
    };
    let res = analyze_trace(&driver, &opts);
    assert!(res.is_ok(), "Trace steps 0 should safely default to 20 steps");
    let data = res.unwrap();
    assert_eq!(data.total_steps, 20);
}

#[test]
fn test_agent_emulate_zero_steps_defaults_to_hundred() {
    let driver = get_driver();
    let res = run_agent_emulate(&driver, "main", 0, None, vec![], None, 32);
    assert!(res.is_ok(), "Agent emulate steps 0 should safely default to 100");
    let data = res.unwrap();
    assert!(data.steps_executed > 0);
}

// =========================================================================
// Area 4: Timeout Thresholds (--timeout 0, --timeout 10)
// =========================================================================

#[test]
fn test_driver_timeout_threshold_zero_returns_exit_code_5() {
    let target = fixture_path(TEST_TARGET);
    let driver = R2Driver::new(&target, None, None, true)
        .expect("Driver creation")
        .with_timeout(Duration::from_secs(0));

    let res = driver.cmd("?v 1");
    assert!(res.is_err(), "Zero timeout must fail with timeout error");
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), 5, "Timeout error must yield exit code 5");
    assert_eq!(err.category(), "TIMEOUT_ERROR");
    match err {
        AppError::Timeout(msg) => {
            assert!(msg.contains("timed out after 0s"));
        }
        other => panic!("Expected Timeout, got {:?}", other),
    }
}

#[test]
fn test_driver_timeout_threshold_ten_succeeds() {
    let target = fixture_path(TEST_TARGET);
    let driver = R2Driver::new(&target, None, None, true)
        .expect("Driver creation")
        .with_timeout(Duration::from_secs(10));

    let res = driver.cmd("?v 1");
    assert!(res.is_ok(), "10s timeout should comfortably succeed for quick command");
}

// =========================================================================
// Area 5: Zero-Byte Files & Exit Code Taxonomy
// =========================================================================

#[test]
fn test_zero_byte_file_driver_rejection() {
    let empty_file = NamedTempFile::new().unwrap();
    let res = R2Driver::new(empty_file.path(), None, None, true);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.exit_code(), 2, "ZeroByteFile must map to exit code 2");
    assert_eq!(err.category(), "FILE_ERROR");
    match err {
        AppError::ZeroByteFile(path) => {
            assert!(path.contains(empty_file.path().to_str().unwrap()));
        }
        other => panic!("Expected ZeroByteFile, got {:?}", other),
    }
}

#[test]
fn test_cli_negative_steps_and_counts_return_exit_code_1() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let cases: &[&[&str]] = &[
        &["-f", target_str, "dynamic", "emulate", "main", "--steps=-1"],
        &["-f", target_str, "dynamic", "trace", "main", "--steps=-5"],
        &["-f", target_str, "dynamic", "step", "main", "--count=-1"],
        &["-f", target_str, "agent", "emulate", "main", "--steps=-10"],
    ];

    for args in cases {
        let out = run_rvs(args);
        assert_eq!(out.status.code(), Some(1), "Expected exit code 1 for negative step {:?}", args);
        let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
        assert!(!resp.success);
        assert_eq!(resp.error.as_ref().unwrap().exit_code, Some(1));
        assert_eq!(resp.error.as_ref().unwrap().category.as_deref(), Some("INVALID_ARGUMENT"));
    }
}

#[test]
fn test_cli_timeout_0_returns_clean_json_envelope_exit_code_5() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let out = run_rvs(&["-f", target_str, "--timeout", "0", "info"]);
    assert_eq!(out.status.code(), Some(5), "Expected exit code 5 for --timeout 0");
    let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(!resp.success);
    let err = resp.error.expect("Error envelope");
    assert_eq!(err.exit_code, Some(5));
    assert_eq!(err.category.as_deref(), Some("TIMEOUT_ERROR"));
    assert_eq!(err.code, "TIMEOUT_EXPIRED");
    assert!(err.message.contains("timed out"));
    assert!(err.suggestion.is_some());
}

#[test]
fn test_cli_zero_byte_file_returns_clean_json_envelope_exit_code_2() {
    let empty_file = NamedTempFile::new().unwrap();
    let empty_path = empty_file.path().to_str().unwrap();

    let subcommands: &[&[&str]] = &[
        &["info"],
        &["analyze", "functions"],
        &["analyze", "blocks", "main"],
        &["strings"],
        &["symbols"],
        &["dynamic", "emulate", "main"],
        &["agent", "triage"],
        &["agent", "decompile", "main"],
        &["agent", "flow", "main"],
        &["patch", "instruction", "--addr", "0x1000", "--assembly", "nop"],
    ];

    for subcmd in subcommands {
        let mut args = vec!["-f", empty_path];
        args.extend_from_slice(subcmd);
        let out = run_rvs(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "Expected exit code 2 for zero-byte file on {:?}",
            subcmd
        );
        let resp: ApiResponse<serde_json::Value> = serde_json::from_slice(&out.stdout).expect("Valid JSON");
        assert!(!resp.success);
        let err = resp.error.expect("Error envelope");
        assert_eq!(err.exit_code, Some(2));
        assert_eq!(err.category.as_deref(), Some("FILE_ERROR"));
        assert_eq!(err.code, "ZERO_BYTE_FILE");
        assert!(err.suggestion.is_some());
    }
}
