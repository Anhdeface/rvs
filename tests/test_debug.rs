mod common;

use common::*;
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

/// Helper to execute rvs with an isolated Unix domain socket
fn run_rvs_isolated(args: &[&str], socket: &Path) -> Output {
    let bin = rvs_bin_path();
    Command::new(&bin)
        .env("RVS_DEBUG_SOCKET", socket)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {:?} with args {:?}: {}", bin, args, e))
}

/// Integration Test 1: Spawning a target binary under native debug mode
#[test]
fn test_debug_spawn_basic() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let output = run_rvs_isolated(&["dynamic", "debug", "spawn", "/bin/true"], &sock);
    assert!(
        output.status.success(),
        "dynamic debug spawn failed: {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("Valid JSON response expected");

    assert_eq!(v["success"], true);
    assert_eq!(v["command"], "dynamic debug spawn");
    assert_eq!(v["data"]["status"], "stopped");
    assert_eq!(v["data"]["stop_reason"], "entrypoint");

    let session_id = v["data"]["session_id"].as_str().expect("session_id string");
    assert!(session_id.starts_with("dbg_"), "Session ID format dbg_...");

    let pid = v["data"]["pid"].as_u64().expect("PID integer");
    assert!(pid > 0, "PID must be > 0");

    let rip = v["data"]["rip"].as_u64().expect("RIP integer");
    assert!(rip > 0, "RIP must be > 0");

    // Clean up session
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", session_id], &sock);
}

/// Integration Test 2: Breakpoint setting, listing, and stepping workflow
#[test]
fn test_debug_breakpoint_and_step_workflow() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "tests/fixtures/test_target_elf64"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();

    // 1. Add breakpoint at main
    let bp_out = run_rvs_isolated(&["dynamic", "debug", "bp", sid, "main"], &sock);
    assert!(bp_out.status.success(), "Failed to add breakpoint: {:?}", bp_out);
    let bp_v: Value = serde_json::from_str(&String::from_utf8_lossy(&bp_out.stdout)).unwrap();
    assert_eq!(bp_v["success"], true);
    assert!(bp_v["data"]["total_breakpoints"].as_u64().unwrap() >= 1);

    // 2. List breakpoints
    let list_out = run_rvs_isolated(&["dynamic", "debug", "bp", sid, "--action", "list"], &sock);
    assert!(list_out.status.success());
    let list_v: Value = serde_json::from_str(&String::from_utf8_lossy(&list_out.stdout)).unwrap();
    assert_eq!(list_v["data"]["action"], "list");
    let bps = list_v["data"]["breakpoints"].as_array().expect("array of bps");
    assert!(!bps.is_empty());

    // 3. Continue execution until breakpoint
    let cont_out = run_rvs_isolated(&["dynamic", "debug", "continue", sid], &sock);
    assert!(cont_out.status.success());
    let cont_v: Value = serde_json::from_str(&String::from_utf8_lossy(&cont_out.stdout)).unwrap();
    assert_eq!(cont_v["success"], true);
    assert_eq!(cont_v["data"]["status"], "stopped");
    assert_eq!(cont_v["data"]["stop_reason"], "breakpoint");

    // 4. Single step
    let step_out = run_rvs_isolated(&["dynamic", "debug", "step", sid], &sock);
    assert!(step_out.status.success());
    let step_v: Value = serde_json::from_str(&String::from_utf8_lossy(&step_out.stdout)).unwrap();
    assert_eq!(step_v["success"], true);
    assert_eq!(step_v["data"]["status"], "stopped");
    assert_eq!(step_v["data"]["steps_executed"], 1);

    let diff = step_v["data"]["register_diff"].as_array().expect("register_diff array");
    assert!(!diff.is_empty(), "Register diff should record changes");

    // Clean up
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}

/// Integration Test 3: CPU register inspection, modification, and diffing
#[test]
fn test_debug_registers_read_and_mutation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "/bin/true"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();

    // 1. Read registers
    let regs_out = run_rvs_isolated(&["dynamic", "debug", "registers", sid], &sock);
    assert!(regs_out.status.success());
    let regs_v: Value = serde_json::from_str(&String::from_utf8_lossy(&regs_out.stdout)).unwrap();
    assert!(regs_v["data"]["registers"].get("rip").is_some());

    // 2. Modify a register (e.g. rax = 0x1337)
    let set_out = run_rvs_isolated(&["dynamic", "debug", "registers", sid, "--set", "rax=0x1337"], &sock);
    assert!(set_out.status.success());
    let set_v: Value = serde_json::from_str(&String::from_utf8_lossy(&set_out.stdout)).unwrap();
    assert_eq!(set_v["success"], true);

    let modified = set_v["data"]["modified"].as_array().expect("modified array");
    let rax_mod = modified.iter().find(|m| m["reg"] == "rax").expect("rax modified");
    assert_eq!(rax_mod["after_hex"], "0x1337");

    // Clean up
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}

/// Integration Test 4: Memory maps inspection and memory reading
#[test]
fn test_debug_memory_maps_and_reading() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "/bin/true"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();
    let rip_hex = spawn_v["data"]["rip_hex"].as_str().unwrap();

    // 1. Inspect memory maps
    let maps_out = run_rvs_isolated(&["dynamic", "debug", "memory", sid, "--action", "maps"], &sock);
    assert!(maps_out.status.success());
    let maps_v: Value = serde_json::from_str(&String::from_utf8_lossy(&maps_out.stdout)).unwrap();
    assert_eq!(maps_v["data"]["action"], "maps");
    let maps = maps_v["data"]["maps"].as_array().expect("maps array");
    assert!(!maps.is_empty(), "Memory maps must not be empty");

    // 2. Read bytes at rip
    let read_out = run_rvs_isolated(&["dynamic", "debug", "memory", sid, "--action", "read", "--addr", rip_hex, "--len", "16"], &sock);
    assert!(read_out.status.success());
    let read_v: Value = serde_json::from_str(&String::from_utf8_lossy(&read_out.stdout)).unwrap();
    assert_eq!(read_v["data"]["action"], "read");
    let hex_str = read_v["data"]["hex"].as_str().expect("hex string");
    assert!(!hex_str.is_empty(), "Read hex bytes must not be empty");
    assert_eq!(read_v["data"]["length"], 16);

    // Clean up
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}

/// Integration Test 5: Process continuation to clean exit (exit code 0 on /bin/true)
#[test]
fn test_debug_continue_to_exit_success() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "/bin/true"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();

    // Continue until exit
    let cont_out = run_rvs_isolated(&["dynamic", "debug", "continue", sid], &sock);
    // The rvs CLI execution MUST return success exit code 0!
    assert!(cont_out.status.success(), "rvs continue should exit with 0");

    let cont_v: Value = serde_json::from_str(&String::from_utf8_lossy(&cont_out.stdout)).unwrap();
    assert_eq!(cont_v["success"], true);
    assert_eq!(cont_v["data"]["status"], "exited");
    assert_eq!(cont_v["data"]["stop_reason"], "exit");
    assert_eq!(cont_v["data"]["exit_code"], 0);

    // Clean up
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}

/// Integration Test 6: Process continuation to exit code 1 on /bin/false
#[test]
fn test_debug_continue_to_exit_false() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "/bin/false"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();

    // Continue until exit
    let cont_out = run_rvs_isolated(&["dynamic", "debug", "continue", sid], &sock);
    // The rvs CLI execution MUST return success exit code 0!
    assert!(cont_out.status.success(), "rvs continue should exit with 0 for target exit 1");

    let cont_v: Value = serde_json::from_str(&String::from_utf8_lossy(&cont_out.stdout)).unwrap();
    assert_eq!(cont_v["success"], true);
    assert_eq!(cont_v["data"]["status"], "exited");
    assert_eq!(cont_v["data"]["stop_reason"], "exit");
    assert_eq!(cont_v["data"]["exit_code"], 1);

    // Clean up
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}

/// Integration Test 7: Signal exception capture (SIGSEGV) without debugger crashing
#[test]
fn test_debug_signal_crash_handling() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "tests/fixtures/crash_target_elf64"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();

    // Continue execution to trigger crash
    let cont_out = run_rvs_isolated(&["dynamic", "debug", "continue", sid], &sock);
    // The rvs CLI itself MUST return success exit code 0 because crash was captured!
    assert!(cont_out.status.success(), "rvs continue should exit with 0 upon target crash");

    let cont_v: Value = serde_json::from_str(&String::from_utf8_lossy(&cont_out.stdout)).unwrap();
    assert_eq!(cont_v["success"], true);
    assert_eq!(cont_v["data"]["status"], "signaled");
    assert_eq!(cont_v["data"]["stop_reason"], "signal");

    let sig = &cont_v["data"]["signal"];
    assert_eq!(sig["signum"], 11, "SIGSEGV signum must be 11");
    assert_eq!(sig["name"], "SIGSEGV");

    // Clean up
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}

/// Integration Test 8: Non-existent session returns exit code 1 (INVALID_ARGUMENT)
#[test]
fn test_debug_unknown_session_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let output = run_rvs_isolated(&["dynamic", "debug", "continue", "dbg_nonexistent_99999"], &sock);
    assert_eq!(output.status.code(), Some(1), "Expected exit code 1 for invalid session");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).expect("Valid JSON response expected");

    assert_eq!(v["success"], false);
    assert_eq!(v["error"]["exit_code"], 1);
    assert_eq!(v["error"]["category"], "INVALID_ARGUMENT");
    assert_eq!(v["error"]["code"], "DEBUG_SESSION_NOT_FOUND");
}

/// Integration Test 9: Active sessions list and kill
#[test]
fn test_debug_list_sessions_and_kill() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let spawn_out = run_rvs_isolated(&["dynamic", "debug", "spawn", "/bin/true"], &sock);
    assert!(spawn_out.status.success());
    let spawn_v: Value = serde_json::from_str(&String::from_utf8_lossy(&spawn_out.stdout)).unwrap();
    let sid = spawn_v["data"]["session_id"].as_str().unwrap();

    // List sessions
    let list_out = run_rvs_isolated(&["dynamic", "debug", "list-sessions"], &sock);
    assert!(list_out.status.success());
    let list_v: Value = serde_json::from_str(&String::from_utf8_lossy(&list_out.stdout)).unwrap();
    let sessions = list_v["data"]["sessions"].as_array().expect("sessions list");
    let found = sessions.iter().any(|s| s["session_id"] == sid);
    assert!(found, "Created session should appear in list-sessions");

    // Kill session
    let kill_out = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
    assert!(kill_out.status.success());
    let kill_v: Value = serde_json::from_str(&String::from_utf8_lossy(&kill_out.stdout)).unwrap();
    assert_eq!(kill_v["data"]["terminated"], true);

    // Verify session is now gone
    let list_out2 = run_rvs_isolated(&["dynamic", "debug", "list-sessions"], &sock);
    let list_v2: Value = serde_json::from_str(&String::from_utf8_lossy(&list_out2.stdout)).unwrap();
    let sessions2 = list_v2["data"]["sessions"].as_array().unwrap();
    let found2 = sessions2.iter().any(|s| s["session_id"] == sid);
    assert!(!found2, "Killed session must be removed from list");
}

/// Integration Test 10: Compact mode reduces payload and omits verbose fields
#[test]
fn test_debug_compact_spawn_mode() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("dbg.sock");

    let output = run_rvs_isolated(&["--compact", "dynamic", "debug", "spawn", "/bin/true"], &sock);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["success"], true);
    assert!(v["data"]["session"].is_string());
    assert!(v["data"]["pid"].is_number());
    assert!(v["data"]["status"].is_string());
    assert!(v["data"]["rip"].is_string());
    // Full register dump omitted in compact mode
    assert!(v["data"]["registers"].is_null());

    let sid = v["data"]["session"].as_str().unwrap();
    let _ = run_rvs_isolated(&["dynamic", "debug", "kill", sid], &sock);
}
