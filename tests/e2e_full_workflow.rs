mod common;

use common::*;
use std::path::Path;

const TEST_TARGET: &str = "test_target_elf64";
const TEST_TARGET_PIE: &str = "test_target_elf64_pie";
const TEST_TARGET_CLANG: &str = "test_target_clang";

/// Helper to locate an instruction address dynamically in a function
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
fn test_tier4_full_agent_unlocking_workflow() {
    let (_temp_dir, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();

    // =========================================================================
    // Step 1: Reconnaissance - Binary Metadata
    // =========================================================================
    let (info_resp, info_out) = run_rvs_json::<InfoData>(&["-f", bin_str, "info"]);
    assert!(info_out.status.success());
    assert!(info_resp.success);
    let info = info_resp.data.expect("InfoData missing");
    assert_eq!(info.format.to_lowercase(), "elf");
    assert_eq!(info.arch.to_lowercase(), "x86");
    assert_eq!(info.bits, 64);

    // =========================================================================
    // Step 2: Function Inventory Discovery
    // =========================================================================
    let (fn_resp, fn_out) = run_rvs_json::<FunctionsData>(&["-f", bin_str, "analyze", "functions"]);
    assert!(fn_out.status.success());
    assert!(fn_resp.success);
    let fn_data = fn_resp.data.expect("FunctionsData missing");

    let required_symbols = [
        "check_auth_token",
        "validate_license_key",
        "compute_feature_flag",
        "get_system_banner",
        "main",
    ];
    for sym in required_symbols {
        assert!(
            fn_data.functions.iter().any(|f| f.name.contains(sym)),
            "Required symbol '{}' was not found in function list",
            sym
        );
    }

    // =========================================================================
    // Step 3: Baseline Execution Verification (Gate 1: Auth Fail -> Exit 10)
    // =========================================================================
    let (base_code, base_stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(base_code, Some(10));
    assert!(base_stdout.contains("Banner: STATUS_SYSTEM_LOCKED"));
    assert!(base_stdout.contains("Auth Status: 0"));
    assert!(base_stdout.contains("FAILED: Authentication Failed"));

    // =========================================================================
    // Step 4: Unlock Gate 1 - Auth Token (Instruction Patch: mov eax, 0 -> mov eax, 1)
    // =========================================================================
    let (_, auth_fail_addr) = find_instruction_addr(&temp_bin, "sym.check_auth_token", "mov eax, 0");
    let (patch1_resp, patch1_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        &auth_fail_addr,
        "--assembly",
        "mov eax, 1",
    ]);
    assert!(patch1_out.status.success());
    assert!(patch1_resp.success);

    // Verify Gate 1 Unlocked: Transitions to Gate 2 (Exit 20, License Fail)
    let (code_g1, out_g1, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(
        code_g1,
        Some(20),
        "Exit code should advance to 20 after auth patch"
    );
    assert!(out_g1.contains("Auth Status: 1"));
    assert!(out_g1.contains("FAILED: Invalid License"));

    // =========================================================================
    // Step 5: Unlock Gate 2 - License Key (String Patch: "MASTER-PASS-2026" -> "DEFAULT_USER_KEY")
    // =========================================================================
    let (str_resp, str_out) = run_rvs_json::<StringsData>(&["-f", bin_str, "strings"]);
    assert!(str_out.status.success());
    assert!(str_resp.success);
    let str_data = str_resp.data.expect("StringsData missing");
    assert!(str_data
        .strings
        .iter()
        .any(|s| s.string.contains("MASTER-PASS-2026")));

    let (patch2_resp, patch2_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "string",
        "--old",
        "MASTER-PASS-2026",
        "--new",
        "DEFAULT_USER_KEY",
    ]);
    assert!(patch2_out.status.success());
    assert!(patch2_resp.success);

    // Verify Gate 2 Unlocked: Transitions to Gate 3 (Exit 30, Feature Fail)
    let (code_g2, out_g2, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(
        code_g2,
        Some(30),
        "Exit code should advance to 30 after license patch"
    );
    assert!(out_g2.contains("License Status: 100"));
    assert!(out_g2.contains("FAILED: Feature Disabled"));

    // =========================================================================
    // Step 6: Unlock Gate 3 - Feature Flag (Hex Bytes Patch: b800000000 -> b801000000)
    // =========================================================================
    let (_, feat_fail_addr) =
        find_instruction_addr(&temp_bin, "sym.compute_feature_flag", "mov eax, 0");
    let (patch3_resp, patch3_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        &feat_fail_addr,
        "--hex",
        "b801000000",
    ]);
    assert!(patch3_out.status.success());
    assert!(patch3_resp.success);

    // =========================================================================
    // Step 7: Final Step - Banner Modification (String Patch: "STATUS_SYSTEM_LOCKED" -> "STATUS_SYSTEM_ACTIVE")
    // =========================================================================
    let (patch4_resp, patch4_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "string",
        "--old",
        "STATUS_SYSTEM_LOCKED",
        "--new",
        "STATUS_SYSTEM_ACTIVE",
    ]);
    assert!(patch4_out.status.success());
    assert!(patch4_resp.success);

    // =========================================================================
    // Step 8: Final Runtime Verification (All Gates Unlocked -> Exit 0)
    // =========================================================================
    let (final_code, final_stdout, _) = run_target_binary(&temp_bin, &[]);
    assert_eq!(
        final_code,
        Some(0),
        "Final exit code must be 0 (All gates unlocked!)"
    );
    assert!(final_stdout.contains("Banner: STATUS_SYSTEM_ACTIVE"));
    assert!(final_stdout.contains("Auth Status: 1"));
    assert!(final_stdout.contains("License Status: 100"));
    assert!(final_stdout.contains("Feature Status: 1"));
    assert!(
        final_stdout.contains("SUCCESS: All security gates unlocked"),
        "Stdout missing success banner: {}",
        final_stdout
    );
}

#[test]
fn test_tier4_callgraph_guided_exploration() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    // 1. Generate JSON Call Graph
    let (graph_resp, graph_out) = run_rvs_json::<GraphData>(&[
        "-f",
        target_str,
        "analyze",
        "graph",
        "--type",
        "callgraph",
        "--format",
        "json",
    ]);
    assert!(graph_out.status.success());
    assert!(graph_resp.success);

    let graph = graph_resp.data.expect("GraphData missing");
    let edges = graph.edges.expect("Edges array missing");

    // 2. Discover all direct callees of main
    let main_callees: Vec<&str> = edges
        .iter()
        .filter(|e| e.from == "main" || e.from.contains("main"))
        .map(|e| e.to.as_str())
        .collect();

    assert!(
        main_callees.iter().any(|c| c.contains("get_system_banner")),
        "main -> get_system_banner call edge missing"
    );
    assert!(
        main_callees.iter().any(|c| c.contains("check_auth_token")),
        "main -> check_auth_token call edge missing"
    );
    assert!(
        main_callees.iter().any(|c| c.contains("validate_license_key")),
        "main -> validate_license_key call edge missing"
    );
    assert!(
        main_callees.iter().any(|c| c.contains("compute_feature_flag")),
        "main -> compute_feature_flag call edge missing"
    );

    // 3. Deep dive into each callee's basic blocks
    for callee in main_callees {
        if callee.contains("imp.") {
            continue; // Skip external library imports
        }
        let (bb_resp, bb_out) =
            run_rvs_json::<BlocksData>(&["-f", target_str, "analyze", "blocks", callee]);
        assert!(bb_out.status.success(), "Failed to get blocks for {}", callee);
        assert!(bb_resp.success);
        let blocks = bb_resp.data.expect("BlocksData missing");
        assert!(!blocks.blocks.is_empty(), "Blocks missing for {}", callee);
    }
}

#[test]
fn test_tier4_multi_compiler_target_consistency() {
    let targets = [TEST_TARGET, TEST_TARGET_PIE, TEST_TARGET_CLANG];

    for target_name in targets {
        let path = fixture_path(target_name);
        if !path.exists() {
            continue;
        }
        let path_str = path.to_str().unwrap();

        // 1. Check Info
        let (info_resp, _) = run_rvs_json::<InfoData>(&["-f", path_str, "info"]);
        assert!(info_resp.success, "Info failed for {}", target_name);

        // 2. Check Functions
        let (fn_resp, _) = run_rvs_json::<FunctionsData>(&["-f", path_str, "analyze", "functions"]);
        assert!(fn_resp.success, "Functions failed for {}", target_name);
        let funcs = fn_resp.data.unwrap();
        assert!(
            funcs.functions.iter().any(|f| f.name.contains("main")),
            "main function missing in {}",
            target_name
        );
        assert!(
            funcs
                .functions
                .iter()
                .any(|f| f.name.contains("check_auth_token")),
            "check_auth_token missing in {}",
            target_name
        );
    }
}

#[test]
fn test_tier4_defensive_error_envelopes() {
    // 1. Missing target file
    let (resp1, out1) = run_rvs_json::<serde_json::Value>(&["-f", "/invalid/path/missing.bin", "info"]);
    assert!(!out1.status.success());
    assert!(!resp1.success);
    assert!(resp1.error.is_some());

    // 2. Invalid function symbol
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();
    let (resp2, out2) = run_rvs_json::<serde_json::Value>(&[
        "-f",
        target_str,
        "analyze",
        "blocks",
        "sym.definitely_not_existing_symbol_999",
    ]);
    assert!(!out2.status.success());
    assert!(!resp2.success);
    assert!(resp2.error.is_some());

    // 3. Invalid assembly opcode
    let (_td, temp_bin) = create_temp_fixture(TEST_TARGET);
    let bin_str = temp_bin.to_str().unwrap();
    let (resp3, out3) = run_rvs_json::<serde_json::Value>(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        "0x401000",
        "--assembly",
        "totally_bogus_mnemonic eax, ebx",
    ]);
    assert!(!out3.status.success());
    assert!(!resp3.success);
    assert!(resp3.error.is_some());

    // 4. Invalid hex string
    let (resp4, out4) = run_rvs_json::<serde_json::Value>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x401000",
        "--hex",
        "deadbeefg",
    ]);
    assert!(!out4.status.success());
    assert!(!resp4.success);
    assert!(resp4.error.is_some());
}
