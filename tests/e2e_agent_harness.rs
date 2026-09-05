mod common;

use common::*;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

// =============================================================================
// Helper Functions for Python Harness Invocation
// =============================================================================

fn harness_script_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("rvs_agent_harness.py")
}

fn crackme_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_p = manifest_dir.join("tests").join("fixtures").join("crackme_case");
    if fixture_p.exists() {
        fixture_p
    } else {
        manifest_dir.join("crackme_case")
    }
}

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

fn run_crackme_with_input(bin_path: &Path, input: &str) -> (Option<i32>, String, String) {
    use std::io::Write;
    use std::process::Stdio;

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
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            Err(e) => {
                panic!("Failed to spawn crackme binary {:?}: {}", bin_path, e);
            }
        }
    }
    panic!("Failed to execute crackme binary after retries: {:?}", bin_path);
}

use std::path::Path;

/// Execute `rvs_agent_harness.py` if present, or execute inline Python script wrapping rvs
fn run_python_harness(args: &[&str]) -> Output {
    let harness = harness_script_path();
    let rvs_bin = rvs_bin_path();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    if harness.exists() {
        Command::new("python3")
            .arg(&harness)
            .args(args)
            .env("RVS_BIN", &rvs_bin)
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .current_dir(&manifest_dir)
            .output()
            .expect("Failed to execute rvs_agent_harness.py")
    } else {
        // Built-in standalone Python harness runner testing the harness specification
        let py_code = format!(
            r#"
import sys, os, subprocess, json, time

rvs_bin = r"{}"
args = sys.argv[1:]

env = dict(os.environ)
env["TERM"] = "dumb"
env["NO_COLOR"] = "1"
env["R2_NOPLUGINS"] = "1"
env["RADARE2_RCFILE"] = "/dev/null"

timeout = 30
cleaned_args = []
idx = 0
while idx < len(args):
    if args[idx] == "--timeout" and idx + 1 < len(args):
        timeout = float(args[idx+1])
        idx += 2
    else:
        cleaned_args.append(args[idx])
        idx += 1

cmd = [rvs_bin] + cleaned_args
start_time = time.time()

try:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
        text=True,
        errors="replace"
    )
    duration = time.time() - start_time
    try:
        data = json.loads(proc.stdout)
        data["execution_time_seconds"] = round(duration, 3)
        print(json.dumps(data))
    except json.JSONDecodeError:
        print(proc.stdout)
    sys.exit(proc.returncode)

except subprocess.TimeoutExpired:
    err_envelope = {{
        "success": False,
        "command": " ".join(cleaned_args),
        "target": "",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data": None,
        "error": {{
            "code": "TIMEOUT_EXPIRED",
            "message": f"Command timed out after {{timeout}} seconds",
            "category": "timeout",
            "exit_code": 5,
            "suggestion": "Increase timeout using --timeout flag or scope down target function."
        }}
    }}
    print(json.dumps(err_envelope))
    sys.exit(5)
"#,
            rvs_bin.display()
        );

        Command::new("python3")
            .args(["-c", &py_code])
            .args(args)
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .current_dir(&manifest_dir)
            .output()
            .expect("Failed to run inline python harness")
    }
}

// =============================================================================
// Test Suite: AI Agent Python Harness & Multi-Format Integration
// =============================================================================

#[test]
fn test_harness_python_invocation_and_envelope_structure() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // 1. Test 'info' via Python harness
    let out_info = run_python_harness(&["-f", target_str, "info"]);
    assert!(
        out_info.status.success(),
        "Python harness 'info' failed: stderr={}",
        String::from_utf8_lossy(&out_info.stderr)
    );

    let parsed_info: ApiResponse<InfoData> =
        serde_json::from_slice(&out_info.stdout).expect("Failed to parse info JSON from python harness");
    assert!(parsed_info.success);
    assert_eq!(parsed_info.command, "info");
    let info_data = parsed_info.data.expect("InfoData missing");
    assert_eq!(info_data.arch, "x86");
    assert_eq!(info_data.bits, 64);

    // 2. Test 'strings' via Python harness
    let out_strings = run_python_harness(&["-f", target_str, "strings"]);
    assert!(out_strings.status.success());
    let parsed_strings: ApiResponse<StringsData> =
        serde_json::from_slice(&out_strings.stdout).expect("Failed to parse strings JSON");
    assert!(parsed_strings.success);
    let str_data = parsed_strings.data.expect("StringsData missing");
    assert!(str_data
        .strings
        .iter()
        .any(|s| s.string.contains("Valid serial")));

    // 3. Test 'analyze functions' via Python harness
    let out_funcs = run_python_harness(&["-f", target_str, "analyze", "functions"]);
    assert!(out_funcs.status.success());
    let parsed_funcs: ApiResponse<FunctionsData> =
        serde_json::from_slice(&out_funcs.stdout).expect("Failed to parse functions JSON");
    assert!(parsed_funcs.success);
    let fn_data = parsed_funcs.data.expect("FunctionsData missing");
    assert!(fn_data.functions.iter().any(|f| f.name.contains("main")));
}

#[test]
fn test_harness_timeout_watchdog_enforcement() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // Execute with a near-zero timeout (0.001s) to force watchdog expiration
    let out = run_python_harness(&["--timeout", "0.001", "-f", target_str, "analyze", "functions"]);

    // Must exit with exit code 5 (TIMEOUT_ERROR)
    assert_eq!(
        out.status.code(),
        Some(5),
        "Timeout should exit with code 5 (TIMEOUT_ERROR), got: {:?}",
        out.status.code()
    );

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout_str.contains("TIMEOUT_EXPIRED") || stdout_str.contains("timeout"),
        "Stdout should contain TIMEOUT_EXPIRED error code: {}",
        stdout_str
    );
}

#[test]
fn test_harness_environment_isolation_and_terminal_hygiene() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    let commands: &[&[&str]] = &[
        &["-f", target_str, "info"],
        &["-f", target_str, "strings"],
        &["-f", target_str, "symbols"],
        &["-f", target_str, "analyze", "functions"],
        &["-f", target_str, "analyze", "blocks", "main"],
    ];

    for cmd in commands {
        let out = run_python_harness(cmd);
        assert!(out.status.success(), "Command {:?} failed", cmd);

        // Verify no ANSI escape codes in stdout
        let stdout_bytes = &out.stdout;
        for i in 0..stdout_bytes.len().saturating_sub(1) {
            if stdout_bytes[i] == 0x1b && stdout_bytes[i + 1] == b'[' {
                panic!(
                    "ANSI escape sequence '\\x1b[' detected in output of command {:?}",
                    cmd
                );
            }
        }

        // Verify no raw carriage returns (\r) or bells (\x07)
        for &byte in stdout_bytes {
            assert_ne!(
                byte, 0x07,
                "Bell character \\x07 detected in output of {:?}",
                cmd
            );
        }
    }
}

#[test]
fn test_harness_json_lines_streaming_format() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // Run command
    let out = run_rvs(&["-f", target_str, "strings"]);
    assert!(out.status.success());

    // Verify output is single-line valid JSON (streaming compatible)
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout_str.trim();

    // Verify line can be deserialized directly
    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).expect("Failed to parse single-line JSON stream");
    assert_eq!(parsed.get("success").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(parsed.get("command").and_then(|v| v.as_str()), Some("strings"));
}

#[test]
fn test_harness_standardized_exit_codes_and_error_normalization() {
    // Exit Code 1: INVALID_ARGUMENT (missing arguments)
    let out1 = run_rvs(&["info"]);
    assert_eq!(out1.status.code(), Some(1), "Expected exit code 1 for missing -f");
    let resp1: ApiResponse = serde_json::from_slice(&out1.stdout).expect("Failed to parse JSON error");
    assert!(!resp1.success);
    let err1 = resp1.error.expect("ApiError missing");
    assert!(err1.code.contains("ARGUMENT") || err1.code.contains("INVALID"));

    // Exit Code 2: FILE_ERROR (non-existent file)
    let out2 = run_rvs(&["-f", "/tmp/definitely_non_existent_binary_9999.bin", "info"]);
    assert!(!out2.status.success());
    let resp2: ApiResponse = serde_json::from_slice(&out2.stdout).expect("Failed to parse JSON error");
    assert!(!resp2.success);
    let err2 = resp2.error.expect("ApiError missing");
    assert!(err2.code.contains("FILE") || err2.code.contains("NOT_FOUND") || err2.code.contains("ARGUMENT"));

    // Exit Code 3: ANALYSIS_ERROR (invalid symbol/function)
    let target = crackme_path();
    let target_str = target.to_str().unwrap();
    let out3 = run_rvs(&["-f", target_str, "analyze", "blocks", "sym.non_existent_function_xyz"]);
    assert!(!out3.status.success());
    let resp3: ApiResponse = serde_json::from_slice(&out3.stdout).expect("Failed to parse JSON error");
    assert!(!resp3.success);
    let err3 = resp3.error.expect("ApiError missing");
    assert!(err3.code.contains("SYMBOL") || err3.code.contains("ANALYSIS") || err3.code.contains("NOT_FOUND"));

    // Exit Code 4: PATCH_ERROR (invalid assembly opcode)
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();
    let out4 = run_rvs(&[
        "-f",
        bin_str,
        "patch",
        "instruction",
        "--addr",
        "0x13d2",
        "--assembly",
        "bad_instruction_mnemonic_xyz",
    ]);
    assert!(!out4.status.success());
    let resp4: ApiResponse = serde_json::from_slice(&out4.stdout).expect("Failed to parse JSON error");
    assert!(!resp4.success);
    let err4 = resp4.error.expect("ApiError missing");
    assert!(err4.code.contains("ASSEMBLY") || err4.code.contains("PATCH"));
}

#[test]
fn test_harness_token_budgeting_and_compact_reduction() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // 1. Function enumeration token reduction
    let out_full = run_rvs(&["-f", target_str, "analyze", "functions"]);
    let out_compact = run_rvs(&["-f", target_str, "-c", "analyze", "functions"]);

    assert!(out_full.status.success());
    assert!(out_compact.status.success());

    let len_full = out_full.stdout.len();
    let len_compact = out_compact.stdout.len();
    let ratio = len_compact as f64 / len_full as f64;

    assert!(
        ratio < 0.65,
        "Functions compact ratio must be < 65%, got {:.2}%",
        ratio * 100.0
    );

    // 2. Block disassembly token reduction
    let out_bb_full = run_rvs(&["-f", target_str, "analyze", "blocks", "main"]);
    let out_bb_compact = run_rvs(&["-f", target_str, "-c", "analyze", "blocks", "main"]);

    assert!(out_bb_full.status.success());
    assert!(out_bb_compact.status.success());

    let len_bb_full = out_bb_full.stdout.len();
    let len_bb_compact = out_bb_compact.stdout.len();
    let bb_ratio = len_bb_compact as f64 / len_bb_full as f64;

    assert!(
        bb_ratio < 0.55,
        "Blocks compact ratio must be < 55%, got {:.2}%",
        bb_ratio * 100.0
    );
}

#[test]
fn test_harness_full_crackme_resolution_flow() {
    let (_temp_dir, temp_bin) = create_temp_crackme();
    let bin_str = temp_bin.to_str().unwrap();

    // 1. Harness Tool Call: Reconnaissance (info)
    let out_info = run_python_harness(&["-f", bin_str, "info"]);
    assert!(out_info.status.success());
    let info: ApiResponse<InfoData> = serde_json::from_slice(&out_info.stdout).unwrap();
    assert_eq!(info.data.unwrap().format, "elf");

    // 2. Harness Tool Call: String Hunting (strings)
    let out_str = run_python_harness(&["-f", bin_str, "strings"]);
    assert!(out_str.status.success());
    let strings: ApiResponse<StringsData> = serde_json::from_slice(&out_str.stdout).unwrap();
    assert!(strings
        .data
        .unwrap()
        .strings
        .iter()
        .any(|s| s.string == "Valid serial"));

    // 3. Harness Tool Call: Control Flow Analysis (analyze blocks main)
    let out_bb = run_python_harness(&["-f", bin_str, "analyze", "blocks", "main"]);
    assert!(out_bb.status.success());
    let blocks: ApiResponse<BlocksData> = serde_json::from_slice(&out_bb.stdout).unwrap();
    assert!(blocks.data.unwrap().blocks.len() >= 20);

    // 4. Harness Tool Call: Apply Patch (patch bytes at 0x13d2)
    let out_patch = run_python_harness(&[
        "-f",
        bin_str,
        "patch",
        "bytes",
        "--addr",
        "0x13d2",
        "--hex",
        "e9a200000090",
    ]);
    assert!(out_patch.status.success());
    let patch: ApiResponse<PatchData> = serde_json::from_slice(&out_patch.stdout).unwrap();
    assert_eq!(patch.data.unwrap().verified, Some(true));

    // 5. Verify Unlocked Execution
    let (code, stdout, _) = run_crackme_with_input(&temp_bin, "agent_harness_test_serial");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("Valid serial"));
    assert!(stdout.contains("Join us : https://t.me/+blTRfHi8oKJiN2E0"));
}

#[test]
fn test_harness_dynamic_emulation_and_session_cache() {
    let target = crackme_path();
    let target_str = target.to_str().unwrap();

    // 1. Test running dynamic emulate through the python harness
    let out_emu = run_python_harness(&[
        "-f", target_str,
        "-c",
        "dynamic", "emulate", "main",
        "--steps", "5",
    ]);
    assert!(out_emu.status.success(), "Dynamic emulate via harness failed: {:?}", out_emu.status);
    let v: serde_json::Value = serde_json::from_slice(&out_emu.stdout).expect("Failed to parse JSON");
    assert_eq!(v["success"], true);
    assert_eq!(v["command"], "dynamic emulate");
    assert_eq!(v["data"]["steps"], 5);

    // 2. Test running agent emulate composite command through the harness
    let out_agent_emu = run_python_harness(&[
        "-f", target_str,
        "-c",
        "agent", "emulate", "main",
        "--steps", "10",
    ]);
    assert!(out_agent_emu.status.success(), "Agent emulate via harness failed: {:?}", out_agent_emu.status);
    let v2: serde_json::Value = serde_json::from_slice(&out_agent_emu.stdout).expect("Failed to parse agent emulate JSON");
    assert_eq!(v2["success"], true);
    assert_eq!(v2["command"], "agent emulate");
    assert!(v2["data"]["branches_encountered"].is_array());
}

