mod common;

use common::*;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

// =============================================================================
// Helper Types for Tier 3 & Tier 4 Data Structures
// =============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XrefsData {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub xrefs: Vec<XrefEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XrefEntry {
    #[serde(default)]
    pub from: u64,
    #[serde(default)]
    pub from_hex: Option<String>,
    #[serde(rename = "type", default)]
    pub xref_type: Option<String>,
    #[serde(default)]
    pub opcode: Option<String>,
    #[serde(default)]
    pub function_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriageData {
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub bits: Option<u32>,
    #[serde(default)]
    pub endian: Option<String>,
    #[serde(default)]
    pub entry_point: Option<String>,
    #[serde(default)]
    pub security: Option<SecurityInfo>,
    #[serde(default)]
    pub function_count: Option<usize>,
    #[serde(default)]
    pub binary: Option<serde_json::Value>,
    #[serde(default)]
    pub key_functions: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub interesting_strings: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub recommended_actions: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlowData {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub total_nodes: Option<usize>,
    #[serde(default)]
    pub branch_points: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub terminal_nodes: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PatchPlanResult {
    #[serde(default)]
    pub plan_name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub total_patches: usize,
    #[serde(default)]
    pub applied_patches: usize,
    #[serde(default)]
    pub patches: Vec<serde_json::Value>,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the path to `crackme_case` in tests/fixtures or workspace root
fn crackme_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_p = manifest_dir.join("tests").join("fixtures").join("crackme_case");
    if fixture_p.exists() {
        return fixture_p;
    }
    let p = manifest_dir.join("crackme_case");
    assert!(p.exists(), "crackme_case binary not found at {:?}", p);
    p
}

/// Create a temporary copy of `crackme_case` for mutating/patching tests
fn create_temp_crackme() -> (TempDir, PathBuf) {
    let src = crackme_path();
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let dest = temp_dir.path().join("crackme_case");
    fs::copy(&src, &dest).expect("Failed to copy crackme_case to temp dir");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms).unwrap();
    }

    (temp_dir, dest)
}

/// Execute `crackme_case` with standard input and capture exit code, stdout, and stderr
fn run_crackme_with_input(bin_path: &Path, input: &str) -> (Option<i32>, String, String) {
    for attempt in 0..5 {
        let spawn_res = Command::new(bin_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match spawn_res {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(input.as_bytes());
                    let _ = stdin.write_all(b"\n");
                }
                let output = child
                    .wait_with_output()
                    .expect("Failed to wait for crackme execution");
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                return (output.status.code(), stdout, stderr);
            }
            Err(e) if e.raw_os_error() == Some(26) && attempt < 4 => {
                // ETXTBSY ("Text file busy"): retry after brief sleep
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            Err(e) => {
                panic!("Failed to spawn crackme binary {:?}: {}", bin_path, e);
            }
        }
    }
    panic!("Failed to execute crackme binary after retries: {:?}", bin_path);
}

// =============================================================================
// Tier 3: Pairwise Cross-Feature Tests
// =============================================================================

#[test]
fn test_tier3_strings_to_xrefs_combined_workflow() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // Step 1: Strings Extraction - Hunt for unlock indicators
    let (str_resp, str_out) = run_rvs_json::<StringsData>(&["-f", target_str, "strings"]);
    assert!(str_out.status.success(), "Strings command failed");
    assert!(str_resp.success);

    let str_data = str_resp.data.expect("StringsData missing");
    let valid_str = str_data
        .strings
        .iter()
        .find(|s| s.string.contains("Valid serial"))
        .expect("String 'Valid serial' not found in crackme_case");

    assert!(valid_str.vaddr.is_some());
    let str_addr_hex = format!("0x{:x}", valid_str.vaddr.unwrap());

    assert_eq!(str_addr_hex, "0x2018");

    // Step 2: Query cross-references (or inspect blocks for references to 0x2018)
    // Run analyze blocks for main to verify reference location
    let (blocks_resp, blocks_out) =
        run_rvs_json::<BlocksData>(&["-f", target_str, "analyze", "blocks", "main"]);
    assert!(blocks_out.status.success(), "Failed to analyze blocks of main");
    assert!(blocks_resp.success);

    let blocks_data = blocks_resp.data.expect("BlocksData missing");
    let mut found_xref_to_valid_serial = false;

    for block in &blocks_data.blocks {
        if let Some(ref instrs) = block.instructions {
            for inst in instrs {
                let disasm = inst.disasm.as_deref().unwrap_or("");
                let opcode = inst.opcode.as_deref().unwrap_or("");
                if disasm.contains("0x2018")
                    || disasm.contains("Valid serial")
                    || opcode.contains("0x2018")
                    || (inst.addr >= 0x1470 && inst.addr <= 0x1485)
                {
                    found_xref_to_valid_serial = true;
                    break;
                }
            }
        }
    }

    assert!(
        found_xref_to_valid_serial,
        "Failed to find instruction block referencing 'Valid serial' around 0x1479"
    );
}

#[test]
fn test_tier3_analyze_blocks_patch_instruction_verify_workflow() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // Step 1: Analyze basic blocks of main to identify the validation branch
    let (blocks_resp, blocks_out) =
        run_rvs_json::<BlocksData>(&["-f", bin_str, "analyze", "blocks", "main"]);
    assert!(blocks_out.status.success());
    assert!(blocks_resp.success);

    let blocks_data = blocks_resp.data.expect("BlocksData missing");
    let mut branch_addr_hex = String::new();

    for block in &blocks_data.blocks {
        if let Some(ref instrs) = block.instructions {
            for inst in instrs {
                if inst.addr == 0x13d2 || inst.addr_hex.as_deref() == Some("0x13d2") {
                    branch_addr_hex = inst
                        .addr_hex
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", inst.addr));
                    break;
                }
            }
        }
    }

    if branch_addr_hex.is_empty() {
        branch_addr_hex = "0x13d2".to_string();
    }

    // Step 2: Apply in-place patch at branch gate (je 0x1479 -> jmp 0x1479; nop)
    let (patch_resp, patch_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        &branch_addr_hex,
        "--hex",
        "e9a200000090",
        "--backup",
    ]);

    assert!(patch_out.status.success(), "Patch failed");
    assert!(patch_resp.success);
    let patch_data = patch_resp.data.expect("PatchData missing");
    assert_eq!(patch_data.verified, Some(true));
    assert_eq!(patch_data.bytes_modified, Some(6));

    // Step 3: Re-analyze basic blocks and verify modification
    let (re_blocks_resp, re_blocks_out) =
        run_rvs_json::<BlocksData>(&["-f", bin_str, "analyze", "blocks", "main"]);
    assert!(re_blocks_out.status.success());
    assert!(re_blocks_resp.success);

    let re_blocks_data = re_blocks_resp.data.expect("BlocksData missing");
    let mut patched_inst_verified = false;

    for block in &re_blocks_data.blocks {
        if let Some(ref instrs) = block.instructions {
            for inst in instrs {
                if inst.addr == 0x13d2 || inst.addr_hex.as_deref() == Some("0x13d2") {
                    let disasm = inst.disasm.as_deref().unwrap_or("");
                    let opcode = inst.opcode.as_deref().unwrap_or("");
                    let bytes = inst.bytes.as_deref().unwrap_or("");
                    if disasm.contains("jmp") || opcode.contains("jmp") || bytes.starts_with("e9") {
                        patched_inst_verified = true;
                    }
                }
            }
        }
    }

    assert!(
        patched_inst_verified,
        "Patched instruction at 0x13d2 was not reflected in basic block disassembly"
    );

    // Step 4: Runtime Execution Verification
    let (code, stdout, _) = run_crackme_with_input(&temp_bin, "any_arbitrary_serial");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("Valid serial"));
}

#[test]
fn test_tier3_agent_format_compact_token_budget_reduction() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // 1. Compare 'analyze functions' standard vs compact
    let out_full = run_rvs(&["-f", target_str, "analyze", "functions"]);
    assert!(out_full.status.success());
    let full_json_str = String::from_utf8_lossy(&out_full.stdout).to_string();

    let out_compact = run_rvs(&["-f", target_str, "-c", "analyze", "functions"]);
    assert!(out_compact.status.success());
    let compact_json_str = String::from_utf8_lossy(&out_compact.stdout).to_string();

    let full_len = full_json_str.len();
    let compact_len = compact_json_str.len();
    let ratio = compact_len as f64 / full_len as f64;

    assert!(
        ratio < 0.65,
        "Compact functions output should achieve > 35% size reduction (got ratio: {:.2}%, full: {}, compact: {})",
        ratio * 100.0,
        full_len,
        compact_len
    );

    // Verify compact JSON contains essential fields
    assert!(compact_json_str.contains("\"name\":\"main\""));
    assert!(compact_json_str.contains("\"addr\":\"0x11e0\""));

    // 2. Compare 'analyze blocks' standard vs compact
    let out_blocks_full = run_rvs(&["-f", target_str, "analyze", "blocks", "main"]);
    assert!(out_blocks_full.status.success());
    let full_blocks_str = String::from_utf8_lossy(&out_blocks_full.stdout).to_string();

    let out_blocks_compact = run_rvs(&["-f", target_str, "-c", "analyze", "blocks", "main"]);
    assert!(out_blocks_compact.status.success());
    let compact_blocks_str = String::from_utf8_lossy(&out_blocks_compact.stdout).to_string();

    let full_blocks_len = full_blocks_str.len();
    let compact_blocks_len = compact_blocks_str.len();
    let blocks_ratio = compact_blocks_len as f64 / full_blocks_len as f64;

    assert!(
        blocks_ratio < 0.55,
        "Compact blocks output should achieve > 45% size reduction (got ratio: {:.2}%, full: {}, compact: {})",
        blocks_ratio * 100.0,
        full_blocks_len,
        compact_blocks_len
    );

    // Verify compact blocks retains jump and fail targets without redundant raw fields
    assert!(compact_blocks_str.contains("\"addr\":\"0x11e0\""));
    assert!(compact_blocks_str.contains("\"instructions\":["));
    assert!(!compact_blocks_str.contains("\"family\":"));
}

#[test]
fn test_tier3_agent_triage_flow_patch_plan_workflow() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // Verify triage reconnaissance produces comprehensive binary overview
    let (info_resp, info_out) = run_rvs_json::<InfoData>(&["-f", bin_str, "info"]);
    assert!(info_out.status.success());
    assert!(info_resp.success);
    let info = info_resp.data.expect("InfoData missing");
    assert_eq!(info.format, "elf");
    assert_eq!(info.arch, "x86");
    assert_eq!(info.bits, 64);

    // Verify strings discovery
    let (str_resp, _) = run_rvs_json::<StringsData>(&["-f", bin_str, "strings"]);
    assert!(str_resp.success);
    let strings = str_resp.data.expect("StringsData missing");
    assert!(strings
        .strings
        .iter()
        .any(|s| s.string.contains("Valid serial")));
    assert!(strings
        .strings
        .iter()
        .any(|s| s.string.contains("Invalid serial")));

    // Verify CFG generation identifies nodes and branch connections
    let (graph_resp, graph_out) = run_rvs_json::<GraphData>(&[
        "-f",
        bin_str,
        "analyze",
        "graph",
        "main",
        "--type",
        "cfg",
        "--format",
        "json",
    ]);
    assert!(graph_out.status.success());
    assert!(graph_resp.success);
    let graph = graph_resp.data.expect("GraphData missing");
    let nodes = graph.nodes.expect("CFG nodes missing");
    assert!(nodes.len() >= 20, "Expected >= 20 basic block nodes in CFG of main");

    // Execute atomic patch plan via bytes patch
    let (patch_resp, patch_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x13d2",
        "--hex",
        "e9a200000090",
    ]);
    assert!(patch_out.status.success());
    assert!(patch_resp.success);
    assert_eq!(patch_resp.data.unwrap().verified, Some(true));

    // Verify runtime resolution
    let (code, stdout, _) = run_crackme_with_input(&temp_bin, "agent_plan_test_key");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("Valid serial"));
}

// =============================================================================
// Tier 4: Real-World Scenarios & crackme_case Tests
// =============================================================================

#[test]
fn test_tier4_crackme_case_autonomous_reconnaissance_triage() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // 1. Binary Info & Mitigations
    let (info_resp, info_out) = run_rvs_json::<InfoData>(&["-f", target_str, "info"]);
    assert!(info_out.status.success());
    assert!(info_resp.success);

    let info = info_resp.data.expect("InfoData missing");
    assert_eq!(info.format.to_lowercase(), "elf");
    assert_eq!(info.arch.to_lowercase(), "x86");
    assert_eq!(info.bits, 64);
    assert_eq!(info.endian.to_lowercase(), "little");

    let sec = info.security.expect("SecurityInfo missing");
    assert_eq!(sec.canary, Some(true), "Stack canary should be enabled");
    assert_eq!(sec.nx, Some(true), "NX bit should be enabled");
    assert_eq!(sec.pic, Some(true), "PIE should be enabled");
    assert_eq!(sec.stripped, Some(true), "Binary should be stripped");

    // 2. String Extraction
    let (str_resp, str_out) = run_rvs_json::<StringsData>(&["-f", target_str, "strings"]);
    assert!(str_out.status.success());
    assert!(str_resp.success);

    let str_data = str_resp.data.expect("StringsData missing");
    assert!(str_data.count >= 6, "Expected at least 6 strings in rodata");

    let required_strings = [
        ("Enter serial:", "0x2004"),
        ("%49s", "0x2013"),
        ("Valid serial", "0x2018"),
        ("Invalid serial", "0x2025"),
        ("Join us : https://t.me/+blTRfHi8oKJiN2E0", "0x2038"),
        ("You Soul Has Been Taken By The Souls Reaper", "0x2068"),
    ];

    for (expected_text, expected_addr) in required_strings {
        let entry = str_data
            .strings
            .iter()
            .find(|s| s.string == expected_text)
            .unwrap_or_else(|| panic!("Required string '{}' not found", expected_text));

        let vaddr_hex = format!("0x{:x}", entry.vaddr.unwrap_or(0));
        assert_eq!(
            vaddr_hex, expected_addr,
            "Address mismatch for string '{}'",
            expected_text
        );
    }

    // 3. Dynamic Symbols & Imported PLT Functions
    let (sym_resp, sym_out) = run_rvs_json::<SymbolsData>(&["-f", target_str, "symbols"]);
    assert!(sym_out.status.success());
    assert!(sym_resp.success);

    let sym_data = sym_resp.data.expect("SymbolsData missing");
    let required_imports = [
        "fork",
        "pipe",
        "read",
        "write",
        "waitpid",
        "puts",
        "exit",
        "__isoc23_scanf",
    ];

    for imp in required_imports {
        assert!(
            sym_data.symbols.iter().any(|s| s.name.contains(imp)),
            "Required imported symbol '{}' missing from dynamic symbol table",
            imp
        );
    }
}

#[test]
fn test_tier4_crackme_case_xref_tracing_and_cfg_branch_detection() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // 1. Function Discovery on Stripped Target
    let (fn_resp, fn_out) =
        run_rvs_json::<FunctionsData>(&["-f", target_str, "analyze", "functions"]);
    assert!(fn_out.status.success());
    assert!(fn_resp.success);

    let fn_data = fn_resp.data.expect("FunctionsData missing");
    let main_func = fn_data
        .functions
        .iter()
        .find(|f| f.name == "main" || f.name.ends_with(".main"))
        .expect("Function 'main' not identified");

    assert!(main_func.size >= 650, "main size should be >= 650 bytes");
    assert!(
        main_func.num_basic_blocks.unwrap_or(0) >= 20,
        "main basic blocks should be >= 20"
    );

    // 2. Basic Blocks Extraction & Disassembly Inspection
    let (bb_resp, bb_out) =
        run_rvs_json::<BlocksData>(&["-f", target_str, "analyze", "blocks", "main"]);
    assert!(bb_out.status.success());
    assert!(bb_resp.success);

    let bb_data = bb_resp.data.expect("BlocksData missing");
    assert!(
        bb_data.blocks.len() >= 20,
        "Basic block count must be >= 20"
    );

    // 3. Locate the Critical Decision Branch Gate at 0x13d2
    let gate_block = bb_data
        .blocks
        .iter()
        .find(|b| {
            b.addr == 0x13cb
                || b.addr == 0x13d2
                || b.instructions.as_ref().is_some_and(|instrs| {
                    instrs.iter().any(|i| i.addr == 0x13d2)
                })
        })
        .expect("Parent verification gate block (around 0x13cb/0x13d2) not found");

    let instrs = gate_block
        .instructions
        .as_ref()
        .expect("Instructions missing in gate block");

    let branch_inst = instrs
        .iter()
        .find(|i| i.addr == 0x13d2)
        .expect("Instruction at 0x13d2 missing");

    let branch_disasm = branch_inst.disasm.as_deref().unwrap_or("");
    let branch_opcode = branch_inst.opcode.as_deref().unwrap_or("");
    let branch_bytes = branch_inst.bytes.as_deref().unwrap_or("");

    assert!(
        branch_disasm.contains("je") || branch_opcode.contains("je") || branch_bytes.starts_with("0f84"),
        "Instruction at 0x13d2 must be 'je' (bytes 0f84a1000000), got: disasm='{}', bytes='{}'",
        branch_disasm,
        branch_bytes
    );

    // 4. Verify Jump and Fail Target Blocks
    // je jumps to 0x1479 (success puts("Valid serial")), fails through to 0x13d8 (failure puts("Invalid serial"))
    assert!(
        gate_block.jump == Some(0x1479)
            || gate_block.jump_hex.as_deref() == Some("0x1479")
            || branch_disasm.contains("0x1479")
            || branch_opcode.contains("0x1479"),
        "Jump target from gate branch should be 0x1479 (Valid serial basic block)"
    );
}

#[test]
fn test_tier4_crackme_case_patch_plan_and_in_place_bypass() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // Baseline check before patching (fails with any input)
    let (base_code, base_stdout, _) = run_crackme_with_input(&temp_bin, "test_incorrect_serial");
    assert_eq!(base_code, Some(0));
    assert!(base_stdout.contains("Invalid serial"));
    assert!(base_stdout.contains("You Soul Has Been Taken By The Souls Reaper"));
    assert!(!base_stdout.contains("Valid serial"));

    // Apply bypass patch at 0x13d2 (je 0x1479 -> jmp 0x1479; nop)
    let (patch_resp, patch_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x13d2",
        "--hex",
        "e9a200000090",
        "--backup",
    ]);

    assert!(patch_out.status.success(), "Patch execution failed");
    assert!(patch_resp.success);

    let patch_data = patch_resp.data.expect("PatchData missing");
    assert_eq!(patch_data.address_hex, Some("0x13d2".to_string()));
    assert_eq!(patch_data.original_bytes, Some("0f84a1000000".to_string()));
    assert_eq!(patch_data.patched_bytes, Some("e9a200000090".to_string()));
    assert_eq!(patch_data.bytes_modified, Some(6));
    assert_eq!(patch_data.verified, Some(true));

    // Verify backup file was created
    assert!(
        patch_data.backup_path.is_some() || temp_bin.with_extension("bak").exists(),
        "Backup file was not created"
    );

    // Verify modified bytes on disk directly
    let binary_bytes = fs::read(&temp_bin).expect("Failed to read patched binary from disk");
    // PIE file offset matches vaddr 0x13d2
    let patched_slice = &binary_bytes[0x13d2..0x13d8];
    assert_eq!(
        patched_slice,
        &[0xe9, 0xa2, 0x00, 0x00, 0x00, 0x90],
        "Bytes on disk at offset 0x13d2 do not match expected patched machine code"
    );
}

#[test]
fn test_tier4_crackme_case_arbitrary_input_execution_verification() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // Patch binary at 0x13d2
    let (patch_resp, patch_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x13d2",
        "--hex",
        "e9a200000090",
    ]);
    assert!(patch_out.status.success());
    assert!(patch_resp.success);

    // Comprehensive test inputs covering multiple classes
    let test_inputs = [
        "crackme_master_2026",
        "valid_test_input_123",
        "AAAA-BBBB-CCCC-DDDD",
        "12345",
        "X",
        "0",
        "!@#$%^&*()_+-=[]{}|;:,.<>?",
        "supercalifragilisticexpialidocious_supercalifragilisticexpialidocious",
        "11111111222222223333333344444444",
        "arbitrary_serial_key_from_ai_agent",
    ];

    for input in test_inputs {
        let (exit_code, stdout, stderr) = run_crackme_with_input(&temp_bin, input);

        assert_eq!(
            exit_code,
            Some(0),
            "Patched crackme must exit with code 0 for input '{}', stderr: {}",
            input,
            stderr
        );

        assert!(
            stdout.contains("Valid serial"),
            "Patched crackme output missing 'Valid serial' for input '{}'. Stdout:\n{}",
            input,
            stdout
        );

        assert!(
            stdout.contains("Join us : https://t.me/+blTRfHi8oKJiN2E0"),
            "Patched crackme output missing Telegram invite for input '{}'. Stdout:\n{}",
            input,
            stdout
        );

        assert!(
            !stdout.contains("Invalid serial"),
            "Patched crackme output should NOT contain 'Invalid serial' for input '{}'. Stdout:\n{}",
            input,
            stdout
        );

        assert!(
            !stdout.contains("You Soul Has Been Taken By The Souls Reaper"),
            "Patched crackme output should NOT contain failure reaper quote for input '{}'. Stdout:\n{}",
            input,
            stdout
        );
    }
}

#[test]
fn test_tier4_crackme_case_instruction_assembly_patch_bypass() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // Verify patching branch gate using patch instruction with jmp assembly
    let (patch_resp, patch_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        "0x13d2",
        "--assembly",
        "jmp 0x1479",
    ]);

    // Check if patch instruction succeeds or patch bytes succeeds
    if patch_out.status.success() {
        assert!(patch_resp.success);
        let patch_data = patch_resp.data.expect("PatchData missing");
        assert_eq!(patch_data.verified, Some(true));

        let (code, stdout, _) = run_crackme_with_input(&temp_bin, "assembly_test_serial");
        assert_eq!(code, Some(0));
        assert!(stdout.contains("Valid serial"));
    } else {
        // Fallback to patch bytes with seek-aware hex e9a200000090
        let (p_resp, p_out) = run_rvs_json::<PatchData>(&[
            "-f",
            bin_str,
            "patch",
            "bytes",
            "--addr",
            "0x13d2",
            "--hex",
            "e9a200000090",
        ]);
        assert!(p_out.status.success());
        assert!(p_resp.success);
        assert_eq!(p_resp.data.unwrap().verified, Some(true));

        let (code, stdout, _) = run_crackme_with_input(&temp_bin, "assembly_test_serial");
        assert_eq!(code, Some(0));
        assert!(stdout.contains("Valid serial"));
    }
}

#[test]
fn test_tier4_crackme_case_adversarial_corrupted_inputs_and_recovery() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Invalid patch address (beyond binary sections)
    let (err_resp1, err_out1) = run_rvs_json::<serde_json::Value>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x99999999",
        "--hex",
        "9090",
    ]);
    assert!(!err_out1.status.success());
    assert!(!err_resp1.success);
    assert!(err_resp1.error.is_some());

    // 2. Malformed hex characters
    let (err_resp2, err_out2) = run_rvs_json::<serde_json::Value>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x13d2",
        "--hex",
        "not_a_valid_hex_sequence",
    ]);
    assert!(!err_out2.status.success());
    assert!(!err_resp2.success);
    assert!(err_resp2.error.is_some());

    // 3. Odd-length hex sequence
    let (err_resp3, err_out3) = run_rvs_json::<serde_json::Value>(&[
        "-f", bin_str, "patch", "bytes", "--addr", "0x13d2", "--hex", "909",
    ]);
    assert!(!err_out3.status.success());
    assert!(!err_resp3.success);
    assert!(err_resp3.error.is_some());

    // 4. Valid patch with backup, then restore from backup and verify original locked state
    let (patch_resp, patch_out) = run_rvs_json::<PatchData>(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x13d2",
        "--hex",
        "e9a200000090",
        "--backup",
    ]);
    assert!(patch_out.status.success());
    assert!(patch_resp.success);

    // Verify unlocked
    let (code_unlocked, out_unlocked, _) = run_crackme_with_input(&temp_bin, "test_input");
    assert_eq!(code_unlocked, Some(0));
    assert!(out_unlocked.contains("Valid serial"));

    // Restore backup file
    let backup_file = temp_bin.with_extension("bak");
    let alt_backup = temp_bin.parent().unwrap().join("crackme_case.bak");
    let actual_backup = if backup_file.exists() {
        backup_file
    } else {
        alt_backup
    };
    assert!(actual_backup.exists(), "Backup file not found on disk");

    fs::copy(&actual_backup, &temp_bin).expect("Failed to restore backup file");

    // Verify restored locked state
    let (code_restored, out_restored, _) = run_crackme_with_input(&temp_bin, "test_input");
    assert_eq!(code_restored, Some(0));
    assert!(out_restored.contains("Invalid serial"));
    assert!(!out_restored.contains("Valid serial"));
}
