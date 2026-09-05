mod common;

use common::*;

const CRACKME_TARGET: &str = "crackme_case";

/// Test 1: Basic dynamic emulation on crackme_case
#[test]
fn test_dynamic_emulate_basic() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "dynamic", "emulate", "main",
        "--steps", "5",
    ]);

    assert!(output.status.success(), "dynamic emulate failed: {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");

    assert_eq!(v["success"], true);
    assert_eq!(v["command"], "dynamic emulate");
    assert_eq!(v["data"]["target"], "main");
    assert_eq!(v["data"]["start_addr_hex"], "0x11e0");
    assert_eq!(v["data"]["final_addr_hex"], "0x11fd");
    assert_eq!(v["data"]["steps_executed"], 5);

    let diff = v["data"]["register_diff"].as_array().expect("register_diff should be array");
    assert!(!diff.is_empty(), "register_diff should not be empty");
    let changed_regs: Vec<&str> = diff.iter().map(|d| d["reg"].as_str().unwrap()).collect();
    assert!(changed_regs.contains(&"rip"), "RIP must be modified");
}

/// Test 2: Compact token-budgeted dynamic emulation
#[test]
fn test_dynamic_emulate_compact() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "--compact",
        "dynamic", "emulate", "main",
        "--steps", "5",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse compact JSON");

    assert_eq!(v["success"], true);
    assert_eq!(v["data"]["start"], "0x11e0");
    assert_eq!(v["data"]["final"], "0x11fd");
    assert_eq!(v["data"]["steps"], 5);
    assert!(v["data"]["initial_registers"].is_null(), "Full registers should be omitted in compact mode");
}

/// Test 3: Markdown format dynamic emulation
#[test]
fn test_dynamic_emulate_markdown() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "--format", "markdown",
        "dynamic", "emulate", "main",
        "--steps", "5",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("### Dynamic Emulation: `main`"));
    assert!(stdout.contains("| Start Address | 0x11e0 |"));
    assert!(stdout.contains("| Final Address | 0x11fd |"));
}

/// Test 4: Dynamic emulation with register preset override
#[test]
fn test_dynamic_emulate_reg_override() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "dynamic", "emulate", "main",
        "-r", "rax=0x1337",
        "--steps", "2",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");

    let ret = &v["data"]["return_value"];
    assert_eq!(ret["reg"], "rax");
    assert_eq!(ret["value"], 4919); // 0x1337 in decimal
}

/// Test 5: Dynamic instruction-level execution trace
#[test]
fn test_dynamic_trace_steps() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "--compact",
        "dynamic", "trace", "main",
        "--steps", "4",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");

    assert_eq!(v["success"], true);
    let trace = v["data"]["trace"].as_array().expect("trace should be array");
    assert_eq!(trace.len(), 4);

    assert_eq!(trace[0]["step"], 0);
    assert_eq!(trace[0]["addr"], "0x11e0");
    assert_eq!(trace[0]["asm"], "endbr64");

    assert_eq!(trace[1]["step"], 1);
    assert_eq!(trace[1]["addr"], "0x11e4");
    assert_eq!(trace[1]["asm"], "push rbx");
}

/// Test 6: Dynamic single step
#[test]
fn test_dynamic_step() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "dynamic", "step", "main",
        "-n", "1",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");

    assert_eq!(v["success"], true);
    assert_eq!(v["data"]["current_addr_hex"], "0x11e0");
    assert_eq!(v["data"]["next_addr_hex"], "0x11e4");
    assert_eq!(v["data"]["instruction"], "endbr64");
}

/// Test 7: Composite Agent Emulate
#[test]
fn test_agent_emulate() {
    let target = fixture_path(CRACKME_TARGET);
    let target_str = target.to_str().unwrap();

    let output = run_rvs(&[
        "-f", target_str,
        "agent", "emulate", "main",
        "--steps", "5",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");

    assert_eq!(v["success"], true);
    assert_eq!(v["command"], "agent emulate");
    assert!(v["data"]["agent_summary"].as_str().unwrap().contains("Emulated target 'main'"));
    assert_eq!(v["data"]["return_value"]["reg"], "rax");
}
