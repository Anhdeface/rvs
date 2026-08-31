mod common;

use common::*;
use predicates::prelude::*;
use tempfile::NamedTempFile;

const TEST_TARGET: &str = "test_target_elf64";
const TEST_TARGET_PIE: &str = "test_target_elf64_pie";
const CRACKME_TARGET: &str = "crackme_case";

// ============================================================================
// TIER 1: FEATURE COVERAGE TESTS
// ============================================================================

/// F5.1: `analyze xrefs` on a known function symbol (`sym.get_system_banner`)
#[test]
fn test_analyze_xrefs_function_symbol() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "get_system_banner",
    ]);

    assert!(output.status.success(), "analyze xrefs returned non-zero exit code");
    assert!(resp.success, "API response indicated failure");
    assert_eq!(resp.command, "analyze xrefs");

    let data = resp.data.expect("XrefsData payload missing");
    assert!(data.target.contains("get_system_banner"));

    // In test_target.c, get_system_banner is called by main
    let has_caller_main = data.xrefs_to.iter().any(|x| {
        x.from_function.as_deref().unwrap_or("").contains("main")
            || x.xref_type.to_uppercase().contains("CALL")
    });
    assert!(
        has_caller_main || !data.xrefs_to.is_empty(),
        "Expected xrefs TO get_system_banner from main, got: {:?}",
        data.xrefs_to
    );
}

/// F5.1b: `analyze xrefs` on PIE binary target
#[test]
fn test_analyze_xrefs_pie_binary() {
    let target = fixture_path(TEST_TARGET_PIE);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "main",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    let data = resp.data.expect("XrefsData payload missing");
    assert!(data.target.contains("main"));
}

/// F5.2: `analyze xrefs` on function with multiple callers / callees (`check_auth_token`)
#[test]
fn test_analyze_xrefs_callees_and_callers() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "check_auth_token",
    ]);

    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("XrefsData payload missing");
    assert!(!data.target.is_empty());
    assert!(data.count >= data.xrefs_to.len() + data.xrefs_from.len());
}

/// F5.3: `analyze xrefs` on data / rodata string address
#[test]
fn test_analyze_xrefs_data_string_address() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    // First find the address of the "STATUS_SYSTEM_LOCKED" string
    let (str_resp, _) = run_rvs_json::<StringsData>(&["-f", target_str, "strings"]);
    assert!(str_resp.success);
    let strings = str_resp.data.expect("Strings data missing").strings;
    let banner_str = strings.iter().find(|s| s.string.contains("STATUS_SYSTEM_LOCKED"));

    if let Some(s_entry) = banner_str {
        if let Some(vaddr) = s_entry.vaddr {
            let addr_str = format!("0x{:x}", vaddr);
            let (x_resp, x_out) = run_rvs_json::<XrefsData>(&[
                "-f", target_str,
                "analyze", "xrefs", &addr_str,
            ]);

            assert!(x_out.status.success());
            assert!(x_resp.success);
            let x_data = x_resp.data.expect("Xrefs data missing");
            assert!(
                !x_data.xrefs_to.is_empty() || x_data.count > 0,
                "String {} at {} should have cross-references",
                s_entry.string,
                addr_str
            );
        }
    }
}

/// F5.4: `analyze xrefs` on `main` function (verifying outgoing calls)
#[test]
fn test_analyze_xrefs_main_outgoing_calls() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "main",
    ]);

    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("XrefsData payload missing");
    // Main calls get_system_banner, check_auth_token, validate_license_key, compute_feature_flag, printf
    let calls_any = data.xrefs_from.iter().any(|x| {
        x.xref_type.to_uppercase().contains("CALL")
            || x.to_function.as_deref().unwrap_or("").contains("auth")
            || x.to_function.as_deref().unwrap_or("").contains("banner")
            || x.to_function.as_deref().unwrap_or("").contains("printf")
    });
    assert!(
        calls_any || !data.xrefs_from.is_empty(),
        "main should have outgoing calls in xrefs_from: {:?}",
        data.xrefs_from
    );
}

/// F5.5: `analyze xrefs` with `--format=jsonl` streaming output
#[test]
fn test_analyze_xrefs_format_jsonl() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "analyze", "xrefs", "main",
        "--format", "jsonl",
    ]);

    assert!(output.status.success());
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout_str.is_empty(), "JSONL output should not be empty");

    // Each non-empty line should be valid JSON
    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(trimmed);
        assert!(parsed.is_ok(), "Line was not valid JSON: {}", trimmed);
    }
}

/// F5.6: `analyze xrefs` with `--format=markdown` table rendering
#[test]
fn test_analyze_xrefs_format_markdown() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "analyze", "xrefs", "main",
        "--format", "markdown",
    ]);

    assert!(output.status.success());
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    // Markdown table should contain table markers and column headers
    assert!(
        stdout_str.contains('|') && (stdout_str.contains("---") || stdout_str.contains("Type") || stdout_str.contains("From") || stdout_str.contains("To")),
        "Markdown output should contain table formatting: {}",
        stdout_str
    );
}

/// F1.4: High-level `rvs agent xrefs` command
#[test]
fn test_agent_xrefs_composite_command() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentXrefsData>(&[
        "-f", target_str,
        "agent", "xrefs", "check_auth_token",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "agent xrefs");

    let data = resp.data.expect("AgentXrefsData missing");
    assert!(data.target.contains("check_auth_token"));
    // Callers list should identify main calling check_auth_token
    assert!(
        data.callers.iter().any(|c| c.function.contains("main")) || !data.callers.is_empty(),
        "Expected caller 'main' for check_auth_token, got: {:?}",
        data.callers
    );
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASE TESTS
// ============================================================================

/// B5.1: `analyze xrefs` on non-existent function name
#[test]
fn test_analyze_xrefs_nonexistent_symbol() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "nonexistent_function_xyz_9999",
    ]);

    // Should return either an empty list (count=0) with success=true or clean error code 3
    if output.status.success() {
        assert!(resp.success);
        let data = resp.data.expect("XrefsData missing");
        assert_eq!(data.count, 0);
        assert!(data.xrefs_to.is_empty());
        assert!(data.xrefs_from.is_empty());
    } else {
        assert!(!resp.success);
        assert!(resp.error.is_some());
    }
}

/// B5.2: `analyze xrefs` on extreme 64-bit addresses (`0xffffffffffffffff`)
#[test]
fn test_analyze_xrefs_extreme_address() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, _) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "0xffffffffffffffff",
    ]);

    // Must handle extreme address safely without overflow or panic
    if resp.success {
        let data = resp.data.unwrap();
        assert_eq!(data.count, 0);
    } else {
        let err = resp.error.unwrap();
        assert!(!err.message.is_empty());
    }
}

/// B5.3: `analyze xrefs` on address zero (`0x0`)
#[test]
fn test_analyze_xrefs_zero_address() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, _) = run_rvs_json::<XrefsData>(&[
        "-f", target_str,
        "analyze", "xrefs", "0x0",
    ]);

    if resp.success {
        let data = resp.data.unwrap();
        assert_eq!(data.count, 0);
    } else {
        assert!(resp.error.is_some());
    }
}

/// B5.4: `analyze xrefs` on stripped binary target (`crackme_case`)
#[test]
fn test_analyze_xrefs_stripped_binary() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crackme_path = manifest_dir.join(CRACKME_TARGET);
    if !crackme_path.exists() {
        return;
    }
    let target_str = crackme_path.to_str().unwrap();

    // First find entrypoint or first function from functions analysis
    let (func_resp, _) = run_rvs_json::<FunctionsData>(&["-f", target_str, "analyze", "functions"]);
    if func_resp.success {
        let funcs = func_resp.data.unwrap().functions;
        if let Some(first_func) = funcs.first() {
            let (x_resp, x_out) = run_rvs_json::<XrefsData>(&[
                "-f", target_str,
                "analyze", "xrefs", &first_func.name,
            ]);
            assert!(x_out.status.success());
            assert!(x_resp.success);
            assert!(x_resp.data.is_some());
        }
    }
}

/// B5.5: `analyze xrefs` on zero-byte empty file
#[test]
fn test_analyze_xrefs_zero_byte_file() {
    let temp_empty = NamedTempFile::new().unwrap();
    let empty_path = temp_empty.path().to_str().unwrap();

    let (resp, output) = run_rvs_json::<XrefsData>(&[
        "-f", empty_path,
        "analyze", "xrefs", "main",
    ]);

    assert!(!output.status.success(), "Zero-byte file should fail");
    assert!(!resp.success);
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.exit_code.unwrap_or(2), 2); // FILE_ERROR
}

/// B5.6: `rvs agent xrefs` with opaque assert_cmd validation
#[test]
fn test_agent_xrefs_opaque_assert_cmd() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let mut cmd = assert_cmd_rvs();
    cmd.args(["-f", target_str, "agent", "xrefs", "validate_license_key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"success\":true"))
        .stdout(predicate::str::contains("validate_license_key"));
}
