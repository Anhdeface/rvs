mod common;

use common::*;

const TEST_TARGET: &str = "test_target_elf64";
const TEST_TARGET_PIE: &str = "test_target_elf64_pie";

#[test]
fn test_info_command_elf64() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<InfoData>(&["-f", target_str, "info"]);
    assert!(output.status.success(), "Command returned non-zero exit code");
    assert!(resp.success, "API response indicated failure");
    assert_eq!(resp.command, "info");
    assert!(resp.target.contains(TEST_TARGET));

    let data = resp.data.expect("InfoData payload is missing");
    assert_eq!(data.format.to_lowercase(), "elf");
    assert_eq!(data.arch.to_lowercase(), "x86");
    assert_eq!(data.bits, 64);
    assert_eq!(data.endian.to_lowercase(), "little");

    if let Some(sec) = data.security {
        // ELF compiled with -fno-stack-protector should have canary false, nx true
        if let Some(nx) = sec.nx {
            assert!(nx, "NX should be enabled on modern Linux ELF");
        }
    }
}

#[test]
fn test_info_command_pie_elf64() {
    let target = fixture_path(TEST_TARGET_PIE);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<InfoData>(&["-f", target_str, "info"]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("InfoData payload is missing");
    assert_eq!(data.format.to_lowercase(), "elf");
    assert_eq!(data.bits, 64);
    if let Some(sec) = data.security {
        if let Some(pic) = sec.pic {
            assert!(pic, "PIE binary should have pic=true");
        }
    }
}

#[test]
fn test_info_nonexistent_file() {
    let (resp, output) = run_rvs_json::<InfoData>(&["-f", "/tmp/nonexistent_file_xyz123.bin", "info"]);
    assert!(!output.status.success(), "Expected failure for nonexistent file");
    assert!(!resp.success);
    assert!(resp.data.is_none());
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert!(!err.code.is_empty());
    assert!(!err.message.is_empty());
}

#[test]
fn test_analyze_functions() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<FunctionsData>(&["-f", target_str, "analyze", "functions"]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("FunctionsData payload is missing");
    assert!(!data.functions.is_empty(), "Function list should not be empty");

    let func_names: Vec<&str> = data.functions.iter().map(|f| f.name.as_str()).collect();

    // Verify key functions from test_target.c are discovered
    assert!(
        func_names.iter().any(|&n| n == "main" || n.contains("main")),
        "main function not found in {:?}",
        func_names
    );
    assert!(
        func_names.iter().any(|&n| n.contains("check_auth_token")),
        "check_auth_token not found in {:?}",
        func_names
    );
    assert!(
        func_names.iter().any(|&n| n.contains("validate_license_key")),
        "validate_license_key not found in {:?}",
        func_names
    );
    assert!(
        func_names.iter().any(|&n| n.contains("compute_feature_flag")),
        "compute_feature_flag not found in {:?}",
        func_names
    );
    assert!(
        func_names.iter().any(|&n| n.contains("get_system_banner")),
        "get_system_banner not found in {:?}",
        func_names
    );

    // Validate properties of check_auth_token
    let auth_fn = data
        .functions
        .iter()
        .find(|f| f.name.contains("check_auth_token"))
        .expect("check_auth_token function object missing");
    assert!(auth_fn.size > 0, "Function size should be > 0");
    assert!(auth_fn.offset > 0, "Function offset should be > 0");
}

#[test]
fn test_analyze_functions_filter() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<FunctionsData>(&[
        "-f", target_str, "analyze", "functions", "--filter", "auth",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("FunctionsData payload is missing");
    assert!(!data.functions.is_empty());
    for f in &data.functions {
        assert!(
            f.name.to_lowercase().contains("auth"),
            "Function '{}' does not match filter 'auth'",
            f.name
        );
    }
}

#[test]
fn test_analyze_functions_detail() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<FunctionsData>(&[
        "-f", target_str, "analyze", "functions", "--detail",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("FunctionsData payload is missing");
    let auth_fn = data
        .functions
        .iter()
        .find(|f| f.name.contains("check_auth_token"))
        .expect("check_auth_token function not found");

    // Detailed metadata assertions
    if let Some(cc) = auth_fn.cyclomatic_complexity {
        assert!(cc >= 1, "Cyclomatic complexity should be >= 1");
    }
    if let Some(nbbs) = auth_fn.num_basic_blocks {
        assert!(nbbs >= 2, "check_auth_token should have at least 2 basic blocks");
    }
}

#[test]
fn test_analyze_blocks() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<BlocksData>(&[
        "-f", target_str, "analyze", "blocks", "sym.check_auth_token",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("BlocksData payload is missing");
    assert!(
        !data.blocks.is_empty(),
        "Basic blocks list should not be empty"
    );
    assert!(
        data.blocks.len() >= 2,
        "check_auth_token should have branching blocks"
    );

    // Verify first block contains valid instructions
    let first_block = &data.blocks[0];
    assert!(first_block.size > 0);
    assert!(first_block.addr > 0);

    if let Some(ref instrs) = first_block.instructions {
        assert!(!instrs.is_empty());
        let opcodes: Vec<String> = instrs
            .iter()
            .map(|i| {
                i.disasm
                    .as_deref()
                    .or(i.opcode.as_deref())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        // Should contain prologue push rbp or mov rbp, rsp or cmp
        assert!(
            opcodes.iter().any(|op| op.contains("push") || op.contains("mov") || op.contains("cmp")),
            "Disassembly did not contain expected instructions: {:?}",
            opcodes
        );
    }
}

#[test]
fn test_analyze_blocks_invalid_symbol() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<BlocksData>(&[
        "-f", target_str, "analyze", "blocks", "nonexistent_symbol_12345",
    ]);
    assert!(!output.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_analyze_prologue_epilogue_target() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<PrologueEpilogueData>(&[
        "-f", target_str, "analyze", "prologue-epilogue", "sym.check_auth_token",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("PrologueEpilogueData missing");
    assert!(!data.functions.is_empty());

    let target_fn = &data.functions[0];
    assert!(target_fn.name.contains("check_auth_token"));

    // Verify prologue detection
    if let Some(ref pro) = target_fn.prologue {
        if let Some(detected) = pro.detected {
            assert!(detected, "Prologue should be detected for standard frame function");
        }
        if let Some(ref instrs) = pro.instructions {
            let ops: Vec<String> = instrs
                .iter()
                .map(|i| i.opcode.as_deref().or(i.disasm.as_deref()).unwrap_or("").to_string())
                .collect();
            assert!(
                ops.iter().any(|op| op.contains("push") || op.contains("mov")),
                "Prologue instructions should include push/mov: {:?}",
                ops
            );
        }
    }

    // Verify epilogue detection
    let epilogue = target_fn
        .epilogue
        .as_ref()
        .or_else(|| target_fn.epilogues.as_ref().and_then(|v| v.first()));
    if let Some(epi) = epilogue {
        if let Some(ref instrs) = epi.instructions {
            let ops: Vec<String> = instrs
                .iter()
                .map(|i| i.opcode.as_deref().or(i.disasm.as_deref()).unwrap_or("").to_string())
                .collect();
            assert!(
                ops.iter().any(|op| op.contains("pop") || op.contains("ret") || op.contains("leave")),
                "Epilogue instructions should include pop/ret/leave: {:?}",
                ops
            );
        }
    }
}

#[test]
fn test_analyze_prologue_epilogue_all() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<PrologueEpilogueData>(&[
        "-f", target_str, "analyze", "prologue-epilogue",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("PrologueEpilogueData missing");
    assert!(
        data.functions.len() >= 3,
        "Should analyze frame for multiple functions"
    );
}

#[test]
fn test_analyze_graph_callgraph_json() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<GraphData>(&[
        "-f", target_str, "analyze", "graph", "--type", "callgraph", "--format", "json",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("GraphData missing");
    assert_eq!(
        data.graph_type.as_deref().unwrap_or("callgraph"),
        "callgraph"
    );

    if let Some(ref nodes) = data.nodes {
        let node_ids: Vec<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
        assert!(
            node_ids.iter().any(|&n| n == "main" || n.contains("main")),
            "Nodes should include main: {:?}",
            node_ids
        );
        assert!(
            node_ids.iter().any(|&n| n.contains("check_auth_token")),
            "Nodes should include check_auth_token: {:?}",
            node_ids
        );
    }

    if let Some(ref edges) = data.edges {
        assert!(!edges.is_empty(), "Call graph should have call edges");
        let main_edges: Vec<&GraphEdge> = edges
            .iter()
            .filter(|e| e.from == "main" || e.from.contains("main"))
            .collect();
        assert!(
            !main_edges.is_empty(),
            "Main should have outgoing call edges"
        );
    }
}

#[test]
fn test_analyze_graph_callgraph_ascii() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<GraphData>(&[
        "-f", target_str, "analyze", "graph", "--type", "callgraph", "--format", "ascii",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("GraphData missing");
    let rendered = data.rendered.unwrap_or_default();
    assert!(
        !rendered.is_empty(),
        "ASCII call graph should have rendered text output"
    );
    assert!(
        rendered.contains("main") || rendered.contains("check_auth"),
        "Rendered ASCII graph should contain function names"
    );
}

#[test]
fn test_strings_listing() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<StringsData>(&["-f", target_str, "strings"]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("StringsData missing");
    let strings_list: Vec<&str> = data.strings.iter().map(|s| s.string.as_str()).collect();

    assert!(
        strings_list.iter().any(|&s| s.contains("STATUS_SYSTEM_LOCKED")),
        "Should find banner string in .rodata: {:?}",
        strings_list
    );
    assert!(
        strings_list.iter().any(|&s| s.contains("MASTER-PASS-2026")),
        "Should find license key string in .rodata: {:?}",
        strings_list
    );
    assert!(
        strings_list.iter().any(|&s| s.contains("DEFAULT_USER_KEY")),
        "Should find default key string in .rodata: {:?}",
        strings_list
    );
    assert!(
        strings_list.iter().any(|&s| s.contains("FAILED: Authentication Failed")),
        "Should find failure string: {:?}",
        strings_list
    );
}

#[test]
fn test_strings_min_length_filter() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<StringsData>(&[
        "-f", target_str, "strings", "--min-len", "25",
    ]);
    assert!(output.status.success());
    assert!(resp.success);

    let data = resp.data.expect("StringsData missing");
    for s in &data.strings {
        let len = s.length.unwrap_or(s.string.len());
        assert!(
            len >= 25,
            "String '{}' with len {} is shorter than min-len 25",
            s.string,
            len
        );
    }
}

#[test]
fn test_global_flags_pretty_and_quiet() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&["-f", target_str, "--pretty", "-q", "info"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('\n') && stdout.contains("  \"success\": true"),
        "Pretty printed output should contain indentations and newlines"
    );
    // In quiet mode, stderr should be empty or contain no debug noise
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.trim().is_empty() || !stderr.contains("DEBUG"),
        "Quiet flag should suppress non-error output on stderr"
    );
}

#[test]
fn test_symbols_command_listing_and_filter() {
    let target = fixture_path(TEST_TARGET);
    let target_str = target.to_str().unwrap();

    let (resp, output) = run_rvs_json::<SymbolsData>(&["-f", target_str, "symbols"]);
    assert!(output.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "symbols");

    let data = resp.data.expect("SymbolsData missing");
    assert!(data.count > 0);
    assert!(!data.symbols.is_empty());

    let sym_names: Vec<&str> = data.symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(
        sym_names.iter().any(|&n| n.contains("main")),
        "Symbols should contain main: {:?}",
        sym_names
    );
    assert!(
        sym_names.iter().any(|&n| n.contains("check_auth_token")),
        "Symbols should contain check_auth_token: {:?}",
        sym_names
    );

    // Test filter flag
    let (filter_resp, filter_out) = run_rvs_json::<SymbolsData>(&[
        "-f", target_str, "symbols", "--filter", "auth"
    ]);
    assert!(filter_out.status.success());
    assert!(filter_resp.success);

    let filter_data = filter_resp.data.expect("Filtered SymbolsData missing");
    assert!(!filter_data.symbols.is_empty());
    for s in &filter_data.symbols {
        assert!(s.name.contains("auth"), "Symbol '{}' should match filter 'auth'", s.name);
    }
}

#[test]
fn test_analysis_on_flow_calc_fixture() {
    let target = fixture_path("flow_calc_elf64");
    let target_str = target.to_str().unwrap();

    // 1. Verify function extraction on flow_calc
    let (funcs_resp, funcs_out) = run_rvs_json::<FunctionsData>(&[
        "-f", target_str, "analyze", "functions"
    ]);
    assert!(funcs_out.status.success());
    assert!(funcs_resp.success);

    let funcs_data = funcs_resp.data.unwrap();
    let names: Vec<&str> = funcs_data.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.iter().any(|&n| n.contains("calc_factorial")), "Missing calc_factorial: {:?}", names);
    assert!(names.iter().any(|&n| n.contains("calc_fibonacci")), "Missing calc_fibonacci: {:?}", names);
    assert!(names.iter().any(|&n| n.contains("calc_collatz_steps")), "Missing calc_collatz_steps: {:?}", names);
    assert!(names.iter().any(|&n| n.contains("calc_dispatch")), "Missing calc_dispatch: {:?}", names);

    // 2. Verify basic blocks on calc_dispatch (switch jump table)
    let (bb_resp, bb_out) = run_rvs_json::<BlocksData>(&[
        "-f", target_str, "analyze", "blocks", "sym.calc_dispatch"
    ]);
    assert!(bb_out.status.success());
    assert!(bb_resp.success);
    let bb_data = bb_resp.data.unwrap();
    assert!(bb_data.blocks.len() >= 4, "calc_dispatch should have at least 4 basic blocks");

    // 3. Verify callgraph includes calc_factorial, calc_fibonacci, etc.
    let (cg_resp, cg_out) = run_rvs_json::<GraphData>(&[
        "-f", target_str, "analyze", "graph", "--format", "json"
    ]);
    assert!(cg_out.status.success());
    assert!(cg_resp.success);
    let cg_data = cg_resp.data.unwrap();
    let nodes = cg_data.nodes.unwrap_or_default();
    let node_labels: Vec<&str> = nodes.iter().map(|n| n.label.as_deref().unwrap_or(&n.id)).collect();
    assert!(node_labels.iter().any(|&l| l.contains("calc_factorial")));
}

#[test]
fn test_analysis_on_auth_gate_fixture() {
    let target = fixture_path("auth_gate_elf64");
    let target_str = target.to_str().unwrap();

    // 1. Check strings in auth_gate
    let (str_resp, str_out) = run_rvs_json::<StringsData>(&[
        "-f", target_str, "strings"
    ]);
    assert!(str_out.status.success());
    assert!(str_resp.success);

    let str_data = str_resp.data.unwrap();
    let str_list: Vec<&str> = str_data.strings.iter().map(|s| s.string.as_str()).collect();
    assert!(str_list.iter().any(|&s| s.contains("K3Y-V4L1D-2026")), "Missing password string in auth_gate");
    assert!(str_list.iter().any(|&s| s.contains("AUTH_FAIL: Bad Password")));
    assert!(str_list.iter().any(|&s| s.contains("AUTH_SUCCESS: Access Granted")));

    // 2. Check prologue-epilogue in auth_gate
    let (pe_resp, pe_out) = run_rvs_json::<PrologueEpilogueData>(&[
        "-f", target_str, "analyze", "prologue-epilogue"
    ]);
    assert!(pe_out.status.success());
    assert!(pe_resp.success);
    assert!(!pe_resp.data.unwrap().functions.is_empty());
}


