use rvs::frida::parse_target_info;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

mod common;
use common::{run_rvs, ApiResponse};

// =========================================================================
// Area 1: Target Probe Parsing (parse_target_info) Adversarial Stress
// =========================================================================

#[test]
fn test_parse_target_info_empty_and_whitespace() {
    let host_arch = std::env::consts::ARCH.to_string();
    let host_bits = if cfg!(target_pointer_width = "64") { 64 } else { 32 };
    let host_os = std::env::consts::OS.to_string();

    for input in &["", "   ", "\t\t\t", "\n\r\n", "   \r\n\t  \n  "] {
        let probe = parse_target_info(input);
        assert_eq!(probe.arch, Some(host_arch.clone()), "Input '{input}' failed arch fallback");
        assert_eq!(probe.bits, Some(host_bits), "Input '{input}' failed bits fallback");
        assert_eq!(probe.os, Some(host_os.clone()), "Input '{input}' failed os fallback");
        assert_eq!(probe.pid, None, "Input '{input}' should have None pid");
    }
}

#[test]
fn test_parse_target_info_valid_json() {
    let json_cases = [
        (
            r#"{"arch": "arm64", "bits": 64, "os": "darwin", "pid": 4321}"#,
            Some("arm64"),
            Some(64),
            Some("darwin"),
            Some(4321),
        ),
        (
            r#"{"arch": "x86", "bits": 32, "os": "windows", "pid": 100}"#,
            Some("x86"),
            Some(32),
            Some("windows"),
            Some(100),
        ),
        (
            r#"{"arch": "riscv64", "bits": 64, "os": "linux", "pid": 1}"#,
            Some("riscv64"),
            Some(64),
            Some("linux"),
            Some(1),
        ),
    ];

    for (raw, expected_arch, expected_bits, expected_os, expected_pid) in json_cases {
        let probe = parse_target_info(raw);
        assert_eq!(probe.arch.as_deref(), expected_arch);
        assert_eq!(probe.bits, expected_bits);
        assert_eq!(probe.os.as_deref(), expected_os);
        assert_eq!(probe.pid, expected_pid);
    }
}

#[test]
fn test_parse_target_info_partial_and_corrupt_json() {
    let host_arch = std::env::consts::ARCH.to_string();
    let host_bits = if cfg!(target_pointer_width = "64") { 64 } else { 32 };
    let host_os = std::env::consts::OS.to_string();

    let malformed_cases = [
        r#"{"arch": "arm64", "bits":"#,
        r#"{"arch": "arm64", "bits": 64, "#,
        r#"{"arch": "arm64", "bits": 64, "os": "linux""#,
        r#"{"arch": "arm64",, "bits": 64}"#,
        r#"{arch: arm64, bits: 64}"#,
        r#"{"incomplete": "#,
        r#"{"# ,
        r#"}"#,
        r#"{{{{{"#,
    ];

    for bad_json in &malformed_cases {
        let probe = parse_target_info(bad_json);
        // Under malformed JSON, parse_target_info attempts line-by-line or falls back to host defaults
        // It must NEVER panic!
        assert!(probe.arch.is_some(), "Arch fallback missing for '{bad_json}'");
        assert!(probe.bits.is_some(), "Bits fallback missing for '{bad_json}'");
        assert!(probe.os.is_some(), "OS fallback missing for '{bad_json}'");
    }

    // Completely invalid non-object JSON values
    let non_objects = [
        r#"["arch", "arm64", "bits", 64]"#,
        r#""hello world""#,
        r#"12345"#,
        r#"true"#,
        r#"false"#,
        r#"null"#,
    ];

    for non_obj in &non_objects {
        let probe = parse_target_info(non_obj);
        assert_eq!(probe.arch, Some(host_arch.clone()));
        assert_eq!(probe.bits, Some(host_bits));
        assert_eq!(probe.os, Some(host_os.clone()));
        assert_eq!(probe.pid, None);
    }
}

#[test]
fn test_parse_target_info_json_unexpected_types_and_values() {
    let type_cases = [
        // Wrong types
        r#"{"arch": 123, "bits": "64", "os": true, "pid": "555"}"#,
        // Null values
        r#"{"arch": null, "bits": null, "os": null, "pid": null}"#,
        // Negative / floating numbers
        r#"{"arch": "mips", "bits": -32, "os": "linux", "pid": -10}"#,
        r#"{"arch": "mips", "bits": 32.5, "os": "linux", "pid": 123.45}"#,
        // Overflow numbers
        r#"{"arch": "mips", "bits": 18446744073709551615, "pid": 9999999999999999999999999999}"#,
        // Nested objects
        r#"{"arch": {"nested": "arm64"}, "bits": [64], "os": {}, "pid": []}"#,
    ];

    for case in &type_cases {
        let probe = parse_target_info(case);
        // Must safely parse without panic
        assert!(probe.arch.is_some());
        assert!(probe.bits.is_some());
        assert!(probe.os.is_some());
    }
}

#[test]
fn test_parse_target_info_valid_key_value_colons() {
    let input = "\
arch: aarch64
bits: 64
os: linux
pid: 8765
";
    let probe = parse_target_info(input);
    assert_eq!(probe.arch, Some("aarch64".to_string()));
    assert_eq!(probe.bits, Some(64));
    assert_eq!(probe.os, Some("linux".to_string()));
    assert_eq!(probe.pid, Some(8765));
}

#[test]
fn test_parse_target_info_valid_key_value_spaces() {
    let input = "\
arch x86_64
bits 64
os freebsd
pid 5432
";
    let probe = parse_target_info(input);
    assert_eq!(probe.arch, Some("x86_64".to_string()));
    assert_eq!(probe.bits, Some(64));
    assert_eq!(probe.os, Some("freebsd".to_string()));
    assert_eq!(probe.pid, Some(5432));
}

#[test]
fn test_parse_target_info_mixed_case_tabs_and_extra_spaces() {
    let input = "\
  ArCh:\t\tx86_64   \r
  BiTs:   \t32\r
  OS:\t \tOpenBSD\r
  pId:\t\t1337\r
";
    let probe = parse_target_info(input);
    assert_eq!(probe.arch, Some("x86_64".to_string()));
    assert_eq!(probe.bits, Some(32));
    assert_eq!(probe.os, Some("OpenBSD".to_string()));
    assert_eq!(probe.pid, Some(1337));
}

#[test]
fn test_parse_target_info_lines_with_noise_and_multiple_colons() {
    let input = "\
radare2 probe output
=====================
arch: arm
unrecognized: key: with: multiple: colons
bits: 32
random noise line with no delimiter
os: android
pid: 9000
footer info
";
    let probe = parse_target_info(input);
    assert_eq!(probe.arch, Some("arm".to_string()));
    assert_eq!(probe.bits, Some(32));
    assert_eq!(probe.os, Some("android".to_string()));
    assert_eq!(probe.pid, Some(9000));
}

#[test]
fn test_parse_target_info_unicode_and_special_characters() {
    let input = "\
arch: 🦀-riscv64
bits: 64
os: 🐧-linux
pid: 1234
";
    let probe = parse_target_info(input);
    assert_eq!(probe.arch, Some("🦀-riscv64".to_string()));
    assert_eq!(probe.bits, Some(64));
    assert_eq!(probe.os, Some("🐧-linux".to_string()));
    assert_eq!(probe.pid, Some(1234));
}

#[test]
fn test_parse_target_info_garbage_data_stress() {
    // 10,000 lines of random garbage
    let mut large_garbage = String::with_capacity(100_000);
    for i in 0..10_000 {
        large_garbage.push_str(&format!("gibberish_line_{i} : random_value_{i}\n"));
    }
    large_garbage.push_str("arch: mips\nbits: 32\nos: qnx\npid: 4242\n");

    let t0 = Instant::now();
    let probe = parse_target_info(&large_garbage);
    let duration = t0.elapsed();

    assert_eq!(probe.arch, Some("mips".to_string()));
    assert_eq!(probe.bits, Some(32));
    assert_eq!(probe.os, Some("qnx".to_string()));
    assert_eq!(probe.pid, Some(4242));
    assert!(duration < Duration::from_millis(500), "Garbage parsing took too long: {:?}", duration);
}

#[test]
fn test_parse_target_info_embedded_null_bytes() {
    let input = "arch: x86\0_64\nbits: 64\nos: linux\0_embedded\npid: 1234\n";
    let probe = parse_target_info(input);
    assert!(probe.arch.is_some());
    assert_eq!(probe.bits, Some(64));
    assert!(probe.os.is_some());
    assert_eq!(probe.pid, Some(1234));
}

#[test]
fn test_parse_target_info_repeated_keys_last_wins() {
    let input = "\
arch: arm
bits: 32
os: linux
pid: 100
arch: arm64
bits: 64
os: android
pid: 200
";
    let probe = parse_target_info(input);
    assert_eq!(probe.arch, Some("arm64".to_string()));
    assert_eq!(probe.bits, Some(64));
    assert_eq!(probe.os, Some("android".to_string()));
    assert_eq!(probe.pid, Some(200));
}

// =========================================================================
// Area 2: Subprocess Watchdog & Timeout Handling under Artificial Delays
// =========================================================================

#[allow(dead_code)]
struct MockRadare2Env {
    pub dir: TempDir,
    pub bin_dir: PathBuf,
}

impl MockRadare2Env {
    pub fn new(script_body: &str) -> Self {
        let dir = TempDir::new().expect("Failed to create TempDir");
        let bin_dir = dir.path().to_path_buf();
        let r2_path = bin_dir.join("radare2");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::write(&r2_path, script_body).expect("Failed to write mock radare2");
            let mut perms = fs::metadata(&r2_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&r2_path, perms).unwrap();
        }

        Self { dir, bin_dir }
    }

    pub fn run_with_env(&self, args: &[&str]) -> std::process::Output {
        let rvs_bin = common::rvs_bin_path();
        let path_env = format!("{}:{}", self.bin_dir.display(), std::env::var("PATH").unwrap_or_default());

        Command::new(rvs_bin)
            .args(args)
            .env("PATH", path_env)
            .output()
            .expect("Failed to run rvs with mock radare2 env")
    }
}

#[test]
fn test_driver_timeout_watchdog_enforced_on_hanging_subprocess() {
    // Mock radare2 that advertises frida plugin but hangs on command execution
    let script = r#"#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{"name":"frida","uris":["frida://"]}]'
        exit 0
    fi
done
# exec replaces shell process so child.kill() terminates sleep directly
exec sleep 20
"#;

    let mock = MockRadare2Env::new(script);

    // Test 1: attach with 1-second timeout
    let t0 = Instant::now();
    let out = mock.run_with_env(&["frida", "attach", "1234", "--timeout", "1"]);
    let elapsed = t0.elapsed();

    assert!(elapsed < Duration::from_secs(5), "Attach watchdog took too long: {:?}", elapsed);
    assert_eq!(out.status.code(), Some(5), "Expected exit code 5 (TIMEOUT_ERROR)");

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let resp: ApiResponse<serde_json::Value> = serde_json::from_str(&stdout_str)
        .unwrap_or_else(|e| panic!("Failed to parse JSON: {e}, stdout: {stdout_str}"));
    assert!(!resp.success);
    let err = resp.error.expect("Missing error field in response");
    assert_eq!(err.code, "TIMEOUT_EXPIRED");
    assert_eq!(err.exit_code, Some(5));
    assert_eq!(err.category.as_deref(), Some("TIMEOUT_ERROR"));

    // Test 2: script with 1-second timeout
    let t1 = Instant::now();
    let out_script = mock.run_with_env(&["frida", "script", "-t", "0", "--code", "1+1", "--timeout", "1"]);
    let elapsed_script = t1.elapsed();

    assert!(elapsed_script < Duration::from_secs(5), "Script watchdog took too long: {:?}", elapsed_script);
    assert_eq!(out_script.status.code(), Some(5));
}

#[test]
fn test_driver_timeout_watchdog_with_buffer_flooding_before_hang() {
    // Mock radare2 that outputs 50KB to stdout/stderr and then hangs
    let script = r#"#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{"name":"frida","uris":["frida://"]}]'
        exit 0
    fi
done
# Output 50KB to stdout and stderr before sleeping
python3 -c "import sys; sys.stdout.write('A' * 50000); sys.stderr.write('B' * 20000); sys.stdout.flush(); sys.stderr.flush()"
exec sleep 20
"#;

    let mock = MockRadare2Env::new(script);

    let t0 = Instant::now();
    let out = mock.run_with_env(&["frida", "attach", "1234", "--timeout", "1"]);
    let elapsed = t0.elapsed();

    assert!(elapsed < Duration::from_secs(5), "Buffer-flood watchdog took too long: {:?}", elapsed);
    assert_eq!(out.status.code(), Some(5), "Expected exit code 5 (TIMEOUT_ERROR)");

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let resp: ApiResponse<serde_json::Value> = serde_json::from_str(&stdout_str).unwrap();
    assert_eq!(resp.error.unwrap().code, "TIMEOUT_EXPIRED");
}

#[test]
fn test_driver_permission_denied_organic_detection() {
    // Mock radare2 that simulates permission denied error from kernel/ptrace
    let script = r#"#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{"name":"frida","uris":["frida://"]}]'
        exit 0
    fi
done
echo "ptrace attach failed: Operation not permitted" >&2
exit 1
"#;

    let mock = MockRadare2Env::new(script);
    let out = mock.run_with_env(&["frida", "attach", "1"]);

    // Permission denied maps to exit code 2 (PERMISSION_DENIED)
    assert_eq!(out.status.code(), Some(2));
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let resp: ApiResponse<serde_json::Value> = serde_json::from_str(&stdout_str).unwrap();
    assert!(!resp.success);
    let err = resp.error.unwrap();
    assert_eq!(err.code, "PERMISSION_DENIED");
    assert_eq!(err.exit_code, Some(2));
    assert!(err.message.contains("Permission denied"));
}

#[test]
fn test_driver_successful_target_probe_session_info() {
    // Mock radare2 that returns genuine target info on :i
    let script = r#"#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{"name":"frida","uris":["frida://"]}]'
        exit 0
    fi
    if [ "$arg" = ":i" ]; then
        echo "arch: arm64"
        echo "bits: 64"
        echo "os: linux"
        echo "pid: 7788"
        exit 0
    fi
done
exit 0
"#;

    let mock = MockRadare2Env::new(script);
    let out = mock.run_with_env(&["frida", "attach", "firefox"]);

    assert_eq!(out.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let resp: ApiResponse<serde_json::Value> = serde_json::from_str(&stdout_str).unwrap();
    assert!(resp.success);
    let data = resp.data.expect("Missing data in response");

    assert_eq!(data.get("target").and_then(|v| v.as_str()), Some("firefox"));
    assert_eq!(data.get("arch").and_then(|v| v.as_str()), Some("arm64"));
    assert_eq!(data.get("bits").and_then(|v| v.as_u64()), Some(64));
    assert_eq!(data.get("os").and_then(|v| v.as_str()), Some("linux"));
    assert_eq!(data.get("pid").and_then(|v| v.as_u64()), Some(7788));
    assert_eq!(data.get("connected").and_then(|v| v.as_bool()), Some(true));
}

// =========================================================================
// Area 3: Concurrent Invocations Stress Testing
// =========================================================================

#[test]
fn test_concurrent_frida_subcommands_multi_thread() {
    let pool_size = 32;
    let iterations_per_thread = 2;
    let total_invocations = pool_size * iterations_per_thread;

    let subcmds = [
        vec!["frida", "env-check"],
        vec!["frida", "attach", "1234", "--timeout", "1"],
        vec!["frida", "modules", "-t", "0"],
        vec!["frida", "symbols", "-t", "0"],
        vec!["frida", "classes", "-t", "0"],
        vec!["frida", "hooks-list", "-t", "0"],
        vec!["frida", "hook", "-t", "0", "-A", "0x401000", "--format", "x"],
        vec!["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", "rax,rbx"],
        vec!["frida", "mem-read", "-t", "0", "-A", "0x401000", "--len", "16"],
        vec!["frida", "script", "-t", "0", "--code", "1+1"],
    ];

    let success_counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for thread_idx in 0..pool_size {
        let counter = Arc::clone(&success_counter);
        let cmd = subcmds[thread_idx % subcmds.len()].clone();

        handles.push(thread::spawn(move || {
            for _ in 0..iterations_per_thread {
                let out = run_rvs(&cmd);
                let stdout_str = String::from_utf8_lossy(&out.stdout);
                // Must always produce valid JSON
                let val: serde_json::Value = serde_json::from_str(&stdout_str)
                    .unwrap_or_else(|e| panic!("Thread {thread_idx} bad JSON: {e}, stdout: {stdout_str}"));
                assert!(val.get("command").is_some());
                assert!(val.get("timestamp").is_some());
                assert!(val.get("format_version").is_some());
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked!");
    }

    assert_eq!(success_counter.load(Ordering::SeqCst), total_invocations);
}
