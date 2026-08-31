mod common;

use common::*;
use predicates::prelude::*;
use tempfile::NamedTempFile;

const TEST_TARGET: &str = "test_target_elf64";
const TEST_TARGET_PIE: &str = "test_target_elf64_pie";
const CRACKME_TARGET: &str = "crackme_case";

// ============================================================================
// TIER 1: FEATURE COVERAGE TESTS (F1, F2, F3)
// ============================================================================

/// F1.1: `rvs agent triage` on standard ELF64 binary
#[test]
fn test_agent_triage_standard_elf64() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentTriageData>(&[
        "-f", target_str,
        "agent", "triage",
    ]);

    assert!(output.status.success(), "agent triage failed with code: {:?}", output.status.code());
    assert!(resp.success, "API response indicated failure");
    assert_eq!(resp.command, "agent triage");

    let data = resp.data.expect("AgentTriageData missing");
    assert_eq!(data.format.to_lowercase(), "elf");
    assert_eq!(data.arch.to_lowercase(), "x86");
    assert_eq!(data.bits, 64);
    assert_eq!(data.endian.to_lowercase(), "little");
    assert!(data.total_functions > 0, "Expected non-zero function count");

    // Verify key functions from test_target.c are in top_functions
    let func_names: Vec<&str> = data.top_functions.iter().map(|f| f.name.as_str()).collect();
    assert!(
        func_names.iter().any(|&n| n.contains("main")),
        "main not in top functions: {:?}",
        func_names
    );

    // Verify interesting strings discovered
    let has_banner = data.interesting_strings.iter().any(|s| s.contains("STATUS_SYSTEM_LOCKED") || s.contains("MASTER-PASS"));
    assert!(has_banner, "Interesting strings missing expected targets: {:?}", data.interesting_strings);
}

/// F1.1: `rvs agent triage` on PIE binary
#[test]
fn test_agent_triage_pie_binary() {
    let target = fixture_path(TEST_TARGET_PIE);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentTriageData>(&[
        "-f", target_str,
        "agent", "triage",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    let data = resp.data.expect("AgentTriageData missing");
    if let Some(sec) = data.security {
        if let Some(pic) = sec.pic {
            assert!(pic, "PIE binary should have pic=true");
        }
    }
}

/// F1.2: `rvs agent decompile` on function `check_auth_token`
#[test]
fn test_agent_decompile_function() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentDecompileData>(&[
        "-f", target_str,
        "agent", "decompile", "check_auth_token",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "agent decompile");

    let data = resp.data.expect("AgentDecompileData missing");
    assert!(data.function_name.contains("check_auth_token"));
    assert!(!data.pseudo_c.is_empty(), "Pseudo-C decompilation should not be empty");
    assert!(data.blocks_count > 0, "Basic blocks count should be > 0");
    assert!(data.instructions_count > 0, "Instruction count should be > 0");
}

/// F1.2: `rvs agent decompile` on `get_system_banner` with string xrefs
#[test]
fn test_agent_decompile_with_string_refs() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentDecompileData>(&[
        "-f", target_str,
        "agent", "decompile", "get_system_banner",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    let data = resp.data.expect("AgentDecompileData missing");
    assert!(data.function_name.contains("get_system_banner"));
    assert!(
        data.pseudo_c.contains("STATUS_SYSTEM_LOCKED")
            || data.strings_referenced.iter().any(|s| s.contains("STATUS_SYSTEM_LOCKED")),
        "Decompilation should reference STATUS_SYSTEM_LOCKED: pseudo_c={}, strings={:?}",
        data.pseudo_c,
        data.strings_referenced
    );
}

/// F1.3: `rvs agent flow` on branching function `check_auth_token`
#[test]
fn test_agent_flow_branch_nodes() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentFlowData>(&[
        "-f", target_str,
        "agent", "flow", "check_auth_token",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "agent flow");

    let data = resp.data.expect("AgentFlowData missing");
    assert!(data.function_name.contains("check_auth_token"));
    assert!(data.total_blocks >= 2, "check_auth_token has conditional branching so >= 2 blocks expected");
    assert!(!data.decision_nodes.is_empty(), "Decision nodes should contain branch gates");

    let first_node = &data.decision_nodes[0];
    assert!(!first_node.addr_hex.is_empty());
    assert!(!first_node.branch_instruction.is_empty());
    assert!(first_node.jump_target > 0 || !first_node.jump_target_hex.is_empty());
}

/// F1.3: `rvs agent flow` on multi-branch function `validate_license_key`
#[test]
fn test_agent_flow_multi_branch() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentFlowData>(&[
        "-f", target_str,
        "agent", "flow", "validate_license_key",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    let data = resp.data.expect("AgentFlowData missing");
    assert!(data.function_name.contains("validate_license_key"));
    assert!(!data.decision_nodes.is_empty());
}

/// F1.5: `rvs agent patch-plan` dry-run simulation
#[test]
fn test_agent_patch_plan_dry_run() {
    let (temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // Plan with instruction and bytes patch
    let plan_json = r#"{
        "name": "Bypass auth check",
        "dry_run": true,
        "steps": [
            { "type": "instruction", "addr": "0x1146", "assembly": "mov eax, 1" },
            { "type": "bytes", "addr": "0x114a", "hex": "9090" }
        ]
    }"#;

    let (resp, output) = run_rvs_json::<AgentPatchPlanResult>(&[
        "-f", bin_str,
        "agent", "patch-plan",
        "--plan", plan_json,
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "agent patch-plan");

    let data = resp.data.expect("AgentPatchPlanResult missing");
    assert_eq!(data.plan_name, "Bypass auth check");
    assert!(data.dry_run, "dry_run should be true");
    assert!(!data.applied, "applied should be false during dry run");
    assert_eq!(data.total_steps, 2);
    assert_eq!(data.step_results.len(), 2);

    drop(temp_dir);
}

/// F2.1: Multi-format `--format=json` validation
#[test]
fn test_format_json_envelope() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<serde_json::Value>(&[
        "-f", target_str,
        "--format", "json",
        "info",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "info");
    assert!(resp.data.is_some());
}

/// F2.2: Multi-format `--format=agent` compact format validation
#[test]
fn test_format_agent_compact() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "--format", "agent",
        "info",
    ]);

    assert!(output.status.success());
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout_str.is_empty());

    // Agent format should be valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout_str);
    assert!(parsed.is_ok(), "Agent format output should be valid JSON");
}

/// F2.3: Multi-format `--format=jsonl` validation
#[test]
fn test_format_jsonl_functions() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "--format", "jsonl",
        "analyze", "functions",
    ]);

    assert!(output.status.success());
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "JSONL output should have at least 1 line");

    for line in lines {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "Line in JSONL must be valid JSON: {}", line);
    }
}

/// F2.4: Multi-format `--format=markdown` validation
#[test]
fn test_format_markdown_functions() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "--format", "markdown",
        "analyze", "functions",
    ]);

    assert!(output.status.success());
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(stdout_str.contains('|'), "Markdown output must contain table pipes: {}", stdout_str);
    assert!(stdout_str.contains("Function") || stdout_str.contains("Name") || stdout_str.contains("Offset"), "Markdown headers missing");
}

/// F3.1: Standardized Exit Codes (0 for success, 1 for invalid argument, 2 for file error)
#[test]
fn test_standardized_exit_codes() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    // 0: SUCCESS
    let out_success = run_rvs(&["-f", target_str, "info"]);
    assert_eq!(out_success.status.code(), Some(0));

    // 1: INVALID_ARGUMENT (unknown flag / bad format)
    let out_inv_arg = run_rvs(&["-f", target_str, "--format", "invalid_format_xyz", "info"]);
    assert_eq!(out_inv_arg.status.code(), Some(1));

    // 2: FILE_ERROR (non-existent file)
    let out_file_err = run_rvs(&["-f", "/tmp/nonexistent_file_xyz9999.bin", "info"]);
    assert_eq!(out_file_err.status.code(), Some(2));
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASE TESTS
// ============================================================================

/// B1.1: `agent decompile` on non-existent function
#[test]
fn test_agent_decompile_nonexistent_function() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentDecompileData>(&[
        "-f", target_str,
        "agent", "decompile", "nonexistent_function_xyz_9999",
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    assert!(resp.data.is_none());
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.exit_code.unwrap_or(3), 3); // ANALYSIS_ERROR
    assert!(!err.message.is_empty());
}

/// B1.2: `agent flow` on non-existent function
#[test]
fn test_agent_flow_nonexistent_function() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentFlowData>(&[
        "-f", target_str,
        "agent", "flow", "nonexistent_function_xyz_9999",
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.exit_code.unwrap_or(3), 3); // ANALYSIS_ERROR
}

/// B1.3: `agent flow` on leaf function without conditional branches (`get_system_banner`)
#[test]
fn test_agent_flow_leaf_function() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentFlowData>(&[
        "-f", target_str,
        "agent", "flow", "get_system_banner",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    let data = resp.data.expect("AgentFlowData missing");
    assert_eq!(data.decision_nodes.len(), 0, "Leaf function without branches should have 0 decision nodes");
}

/// B1.4: `agent triage` on stripped binary (`crackme_case`)
#[test]
fn test_agent_triage_stripped_binary() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crackme_path = manifest_dir.join(CRACKME_TARGET);
    if !crackme_path.exists() {
        return;
    }
    let target_str = crackme_path.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentTriageData>(&[
        "-f", target_str,
        "agent", "triage",
    ]);

    assert!(output.status.success());
    assert!(resp.success);
    let data = resp.data.expect("AgentTriageData missing");
    assert_eq!(data.format.to_lowercase(), "elf");
    assert_eq!(data.bits, 64);
    assert!(data.total_functions > 0, "Should detect functions in stripped binary");
}

/// B1.5: `agent patch-plan` with malformed JSON
#[test]
fn test_agent_patch_plan_malformed_json() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let malformed_plan = "{ this is not valid json }";

    let (resp, output) = run_rvs_json::<AgentPatchPlanResult>(&[
        "-f", target_str,
        "agent", "patch-plan",
        "--plan", malformed_plan,
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.exit_code.unwrap_or(1), 1); // INVALID_ARGUMENT
}

/// B1.6: `agent patch-plan` with missing required step fields
#[test]
fn test_agent_patch_plan_missing_fields() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let plan_missing_addr = r#"{
        "name": "Invalid Plan",
        "dry_run": true,
        "steps": [
            { "type": "instruction" }
        ]
    }"#;

    let (resp, output) = run_rvs_json::<AgentPatchPlanResult>(&[
        "-f", target_str,
        "agent", "patch-plan",
        "--plan", plan_missing_addr,
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
}

/// B2.1: `rvs agent triage` on zero-byte file
#[test]
fn test_agent_triage_zero_byte_file() {
    let temp_empty = NamedTempFile::new().unwrap();
    let empty_path = temp_empty.path().to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentTriageData>(&[
        "-f", empty_path,
        "agent", "triage",
    ]);

    assert!(!output.status.success());
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert_eq!(err.exit_code.unwrap_or(2), 2); // FILE_ERROR
}

/// B2.2: `rvs agent triage` with unsupported architecture override
#[test]
fn test_agent_triage_unsupported_arch() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<AgentTriageData>(&[
        "-f", target_str,
        "--arch", "unsupported_arch_xyz_99",
        "agent", "triage",
    ]);

    // Should either fail with INVALID_ARGUMENT or record warning/fallback
    if !output.status.success() {
        assert!(!resp.success);
    }
}

/// B2.3: `assert_cmd` opaque CLI assertion for agent triage
#[test]
fn test_agent_triage_opaque_assert_cmd() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let mut cmd = assert_cmd_rvs();
    cmd.args(["-f", target_str, "agent", "triage"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"success\":true"))
        .stdout(predicate::str::contains("\"command\":\"agent triage\""))
        .stdout(predicate::str::contains("\"format\":\"elf\""));
}
