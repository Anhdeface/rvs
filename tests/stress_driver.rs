use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

use rvs::r2::driver::{sanitize_terminal_output, BATCH_DELIMITER};
use rvs::response::AppError;
use rvs::R2Driver;

mod common;
use common::*;

fn get_test_binary() -> PathBuf {
    fixture_path("crackme_case")
}

// =========================================================================
// 1. cmd_batch: Empty, Single, Multiple, and Boundary Tests
// =========================================================================

#[test]
fn test_cmd_batch_empty_commands_array() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let results = driver.cmd_batch(&[]).expect("Empty cmd_batch should succeed");
    assert!(results.is_empty(), "Empty commands slice must return empty results Vec");
}

#[test]
fn test_cmd_batch_single_command() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let single_out = driver.cmd("?e hello_single").expect("cmd failed");
    let batch_out = driver.cmd_batch(&["?e hello_single"]).expect("cmd_batch failed");

    assert_eq!(batch_out.len(), 1);
    assert_eq!(batch_out[0].trim(), single_out.trim());
    assert_eq!(batch_out[0].trim(), "hello_single");
}

#[test]
fn test_cmd_batch_commands_emitting_empty_and_multiline_strings() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    // Commands tested:
    // 1. "s 0x1000" -> produces empty string in r2
    // 2. "?e first_output" -> produces single line
    // 3. "s 0x1050" -> produces empty string
    // 4. "pd 15 @ 0x1000" -> produces 15 lines of disassembly
    // 5. "af" -> produces empty string
    // 6. "px 64 @ 0x1000" -> produces multiline hex dump
    // 7. "?e final_output" -> produces single line
    let commands = [
        "s 0x1000",
        "?e first_output",
        "s 0x1050",
        "pd 15 @ 0x1000",
        "af",
        "px 64 @ 0x1000",
        "?e final_output",
    ];

    let results = driver.cmd_batch(&commands).expect("cmd_batch failed");
    assert_eq!(results.len(), commands.len(), "Results len must match commands len exactly");

    assert_eq!(results[0], "", "s 0x1000 must produce empty string");
    assert_eq!(results[1], "first_output");
    assert_eq!(results[2], "", "s 0x1050 must produce empty string");
    
    // Verify multiline disassembly is preserved
    assert!(results[3].lines().count() >= 10, "pd 15 must have multiple lines");
    assert!(results[3].contains("0x00001000") || results[3].contains("0x1000"), "Disassembly must contain address");

    assert_eq!(results[4], "", "af must produce empty string");

    // Verify multiline hex dump is preserved
    assert!(results[5].lines().count() >= 2, "px 64 must have multiple lines");
    assert!(results[5].contains("0x"), "Hex dump must contain address prefixes");

    assert_eq!(results[6], "final_output");
}

#[test]
fn test_cmd_batch_all_empty_outputs() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let commands = ["s 0x1000", "s 0x1010", "s 0x1020", "s 0x1030"];
    let results = driver.cmd_batch(&commands).expect("cmd_batch failed");

    assert_eq!(results.len(), 4);
    for (i, res) in results.iter().enumerate() {
        assert_eq!(res, "", "Index {} should be empty string", i);
    }
}

#[test]
fn test_cmd_batch_json_queries_integrity() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let queries = ["iIj", "iej", "iSj", "aflj"];
    let batch_results = driver.cmd_batch(&queries).expect("cmd_batch failed");
    assert_eq!(batch_results.len(), 4);

    for (i, json_str) in batch_results.iter().enumerate() {
        let val: Result<serde_json::Value, _> = R2Driver::parse_json(json_str);
        assert!(val.is_ok(), "Query {} ('{}') must parse as valid JSON: {:?}", i, queries[i], val.err());
    }
}

// =========================================================================
// 2. cmd_batch: Scaling & Large Command Sets (10, 50, 100, 250, 500)
// =========================================================================

#[test]
fn test_cmd_batch_scaling_50_commands() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let count = 50;
    let cmd_strings: Vec<String> = (0..count).map(|i| format!("?e token_{:04}", i)).collect();
    let cmd_refs: Vec<&str> = cmd_strings.iter().map(|s| s.as_str()).collect();

    let start = Instant::now();
    let results = driver.cmd_batch(&cmd_refs).expect("cmd_batch 50 failed");
    let elapsed = start.elapsed();

    assert_eq!(results.len(), count);
    for (i, res) in results.iter().enumerate().take(count) {
        assert_eq!(res, &format!("token_{:04}", i), "Mismatch at index {}", i);
    }
    println!("cmd_batch(50) took: {:?}", elapsed);
}

#[test]
fn test_cmd_batch_scaling_100_commands() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let count = 100;
    let cmd_strings: Vec<String> = (0..count).map(|i| format!("?e item_{:04}", i)).collect();
    let cmd_refs: Vec<&str> = cmd_strings.iter().map(|s| s.as_str()).collect();

    let start = Instant::now();
    let results = driver.cmd_batch(&cmd_refs).expect("cmd_batch 100 failed");
    let elapsed = start.elapsed();

    assert_eq!(results.len(), count);
    for (i, res) in results.iter().enumerate().take(count) {
        assert_eq!(res, &format!("item_{:04}", i), "Mismatch at index {}", i);
    }
    println!("cmd_batch(100) took: {:?}", elapsed);
}

#[test]
fn test_cmd_batch_scaling_250_commands() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let count = 250;
    let cmd_strings: Vec<String> = (0..count).map(|i| format!("?e val_{:04}", i)).collect();
    let cmd_refs: Vec<&str> = cmd_strings.iter().map(|s| s.as_str()).collect();

    let start = Instant::now();
    let results = driver.cmd_batch(&cmd_refs).expect("cmd_batch 250 failed");
    let elapsed = start.elapsed();

    assert_eq!(results.len(), count);
    for (i, res) in results.iter().enumerate().take(count) {
        assert_eq!(res, &format!("val_{:04}", i), "Mismatch at index {}", i);
    }
    println!("cmd_batch(250) took: {:?}", elapsed);
}

#[test]
fn test_cmd_batch_scaling_500_commands() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    let count = 500;
    let cmd_strings: Vec<String> = (0..count).map(|i| format!("?e big_{:04}", i)).collect();
    let cmd_refs: Vec<&str> = cmd_strings.iter().map(|s| s.as_str()).collect();

    let start = Instant::now();
    let results = driver.cmd_batch(&cmd_refs).expect("cmd_batch 500 failed");
    let elapsed = start.elapsed();

    assert_eq!(results.len(), count);
    for (i, res) in results.iter().enumerate().take(count) {
        assert_eq!(res, &format!("big_{:04}", i), "Mismatch at index {}", i);
    }
    println!("cmd_batch(500) took: {:?}", elapsed);
}

// =========================================================================
// 3. Delimiter Collision Resilience & Adversarial Binary
// =========================================================================

#[test]
fn test_delimiter_constant_uniqueness_in_normal_r2_output() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true).expect("Driver creation failed");

    // Test a wide variety of standard r2 commands
    let commands = ["iI", "ie", "iS", "is", "iz", "afl", "pdf @ sym.main", "px 128", "?", "e?"];
    for cmd in commands {
        let out = driver.cmd(cmd).expect("cmd failed");
        assert!(
            !out.contains(BATCH_DELIMITER),
            "Command '{}' produced output containing BATCH_DELIMITER!",
            cmd
        );
    }
}

#[test]
fn test_adversarial_binary_containing_batch_delimiter() {
    let temp_dir = TempDir::new().unwrap();
    let adv_bin = temp_dir.path().join("adv_delim.bin");

    // Construct a binary containing the exact BATCH_DELIMITER inside its data
    {
        let mut f = File::create(&adv_bin).unwrap();
        // ELF header + delimiter string
        f.write_all(b"\x7fELF\x02\x01\x01\x00").unwrap();
        f.write_all(vec![0u8; 56].as_slice()).unwrap();
        f.write_all(b"STRING_BEFORE\x00").unwrap();
        f.write_all(BATCH_DELIMITER.as_bytes()).unwrap();
        f.write_all(b"\x00STRING_AFTER\x00").unwrap();
        f.write_all(vec![0x90u8; 100].as_slice()).unwrap();
    }

    let driver = R2Driver::new(&adv_bin, None, None, true).expect("Driver creation failed");

    // 1. If we query non-raw commands, delimiter in binary data doesn't interfere
    let results = driver.cmd_batch(&["?e first", "?e second", "?e third"]).expect("cmd_batch failed");
    assert_eq!(results, vec!["first", "second", "third"]);

    // 2. If a command deliberately outputs the delimiter itself (e.g. `?e ===RVS_CMD_BATCH_BOUNDARY_DELIM===`),
    // split(BATCH_DELIMITER) splits on it.
    // The driver implementation bounds the results to `commands.len()`.
    let delim_cmd = format!("?e {}", BATCH_DELIMITER);
    let batch = driver.cmd_batch(&["?e a", &delim_cmd, "?e c"]);
    assert!(batch.is_ok());
    let res = batch.unwrap();
    assert_eq!(res.len(), 3);
}

// =========================================================================
// 4. Terminal Isolation, ANSI Sanitization & Control Character Filtering
// =========================================================================

#[test]
fn test_sanitize_terminal_output_comprehensive() {
    // 1. ANSI 16 colors & styles
    let ansi_basic = "\x1b[0m\x1b[1mBold\x1b[22m \x1b[31mRed\x1b[39m \x1b[42mGreenBg\x1b[49m";
    assert_eq!(sanitize_terminal_output(ansi_basic), "Bold Red GreenBg");

    // 2. ANSI 256 colors
    let ansi_256 = "\x1b[38;5;208mOrange\x1b[0m \x1b[48;5;21mBlueBg\x1b[0m";
    assert_eq!(sanitize_terminal_output(ansi_256), "Orange BlueBg");

    // 3. ANSI Truecolor (24-bit)
    let ansi_rgb = "\x1b[38;2;255;128;64mTrueColor\x1b[0m";
    assert_eq!(sanitize_terminal_output(ansi_rgb), "TrueColor");

    // 4. Cursor movement & screen clearing
    let cursor_seqs = "\x1b[2J\x1b[H\x1b[10;20H\x1b[1A\x1b[2KCleanContent";
    assert_eq!(sanitize_terminal_output(cursor_seqs), "CleanContent");

    // 5. OSC title sequences
    let osc_bell = "\x1b]0;Evil Terminal Title\x07Actual Text";
    assert_eq!(sanitize_terminal_output(osc_bell), "Actual Text");

    let osc_st = "\x1b]2;Another Title\x1b\\Real Content";
    assert_eq!(sanitize_terminal_output(osc_st), "Real Content");

    // 6. Non-printable control characters stripped while whitespace preserved
    let ctrl_chars = "Line1\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x7f\nLine2\tTabbed\r\nLine3";
    assert_eq!(sanitize_terminal_output(ctrl_chars), "Line1\nLine2\tTabbed\r\nLine3");

    // 7. UTF-8 international characters preserved
    let unicode_text = "Disassembly: 0x1000: jmp 0x2000; 日本語; 🚀; áéíóú";
    assert_eq!(sanitize_terminal_output(unicode_text), unicode_text);
}

#[test]
fn test_parse_json_resilience_to_r2_warning_pollution() {
    // 1. Clean JSON array
    let clean_arr = "[{\"offset\":4096,\"name\":\"sym.main\"}]";
    let parsed: Vec<serde_json::Value> = R2Driver::parse_json(clean_arr).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["name"], "sym.main");

    // 2. Clean JSON object
    let clean_obj = "{\"arch\":\"x86\",\"bits\":64}";
    let parsed_obj: serde_json::Value = R2Driver::parse_json(clean_obj).unwrap();
    assert_eq!(parsed_obj["arch"], "x86");

    // 3. radare2 warnings prepended before JSON
    let polluted = "WARNING: anal.bb.maxsize exceeded\nWARNING: symbol count mismatch\n[{\"offset\":4096}]\n";
    let parsed_polluted: Vec<serde_json::Value> = R2Driver::parse_json(polluted).unwrap();
    assert_eq!(parsed_polluted.len(), 1);
    assert_eq!(parsed_polluted[0]["offset"], 4096);

    // 4. radare2 warnings with ANSI colors wrapping JSON
    let ansi_polluted = "\x1b[33mWARN: invalid rel\x1b[0m\n{\"status\":\"ok\"}\n\x1b[32mLOG: done\x1b[0m";
    let parsed_ansi: serde_json::Value = R2Driver::parse_json(ansi_polluted).unwrap();
    assert_eq!(parsed_ansi["status"], "ok");

    // 5. Empty output -> fallback to [] or {}
    let empty_arr: Vec<serde_json::Value> = R2Driver::parse_json("").unwrap();
    assert!(empty_arr.is_empty());

    let empty_obj: serde_json::Value = R2Driver::parse_json("   \n\t  ").unwrap();
    assert!(empty_obj.is_object() || empty_obj.is_array());
}

// =========================================================================
// 5. Timeout Handling and Process Isolation under Stress
// =========================================================================

#[test]
fn test_timeout_enforcement_and_process_cleanup() {
    let binary = get_test_binary();
    // Configure very short timeout of 100ms
    let driver = R2Driver::new(&binary, None, None, true)
        .expect("Driver creation failed")
        .with_timeout(Duration::from_millis(100));

    let start = Instant::now();
    // "sleep 2" keeps radare2 executing internally
    let result = driver.cmd("sleep 2");
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Hanging command should error due to timeout");
    match result.unwrap_err() {
        AppError::R2ExecutionError(msg) => {
            assert!(msg.contains("timed out"), "Error message must indicate timeout: {}", msg);
        }
        other => panic!("Unexpected error type: {:?}", other),
    }

    // Should timeout around ~100-300ms, definitely not 2000ms
    assert!(elapsed < Duration::from_millis(800), "Execution took too long: {:?}", elapsed);
}

#[test]
fn test_repeated_timeouts_sequential_stability() {
    let binary = get_test_binary();
    let driver = R2Driver::new(&binary, None, None, true)
        .expect("Driver creation failed")
        .with_timeout(Duration::from_millis(80));

    for i in 0..5 {
        let start = Instant::now();
        let res = driver.cmd("sleep 1");
        let elapsed = start.elapsed();

        assert!(res.is_err(), "Iteration {} should fail on timeout", i);
        assert!(elapsed < Duration::from_millis(500), "Iteration {} took {:?}", i, elapsed);
    }
}

// =========================================================================
// 6. High Concurrency Multi-Threaded Stress Test
// =========================================================================

#[test]
fn test_concurrent_driver_access_multi_threaded() {
    let binary = get_test_binary();
    let thread_count = 20;
    let mut handles = Vec::with_capacity(thread_count);

    for thread_id in 0..thread_count {
        let bin_clone = binary.clone();
        let handle = thread::spawn(move || {
            let driver = R2Driver::new(&bin_clone, None, None, true).expect("Driver creation failed");

            // Execute cmd_batch in concurrent thread
            let batch = driver.cmd_batch(&[
                "?e t_start",
                "iIj",
                "iej",
                "?e t_end",
            ]).expect("cmd_batch in thread failed");

            assert_eq!(batch.len(), 4);
            assert_eq!(batch[0], "t_start");
            assert!(batch[1].contains("elf") || batch[1].contains("arch"));
            assert_eq!(batch[3], "t_end");

            // Execute JSON command
            let info: serde_json::Value = driver.cmdj("iIj").expect("cmdj in thread failed");
            assert!(info.is_object());

            thread_id
        });
        handles.push(handle);
    }

    for handle in handles {
        let tid = handle.join().expect("Thread panicked");
        assert!(tid < thread_count);
    }
}

// =========================================================================
// 7. Binary Validation Edge Cases
// =========================================================================

#[test]
fn test_driver_binary_validation_exhaustive() {
    // 1. Non-existent file
    let err_missing = R2Driver::new("/path/that/does/not/exist_12345.bin", None, None, false);
    assert!(err_missing.is_err());
    match err_missing.unwrap_err() {
        AppError::FileNotFound(_) => (),
        other => panic!("Expected FileNotFound, got {:?}", other),
    }

    // 2. Directory as binary
    let err_dir = R2Driver::new("/tmp", None, None, false);
    assert!(err_dir.is_err());
    match err_dir.unwrap_err() {
        AppError::InvalidBinary(msg) => assert!(msg.contains("directory")),
        other => panic!("Expected InvalidBinary, got {:?}", other),
    }

    // 3. 0-byte empty file
    let temp_dir = TempDir::new().unwrap();
    let empty_file = temp_dir.path().join("zero_bytes.bin");
    File::create(&empty_file).unwrap();

    let err_empty = R2Driver::new(&empty_file, None, None, false);
    assert!(err_empty.is_err());
    match err_empty.unwrap_err() {
        AppError::InvalidBinary(msg) => assert!(msg.contains("empty (0 bytes)")),
        other => panic!("Expected InvalidBinary for 0-byte file, got {:?}", other),
    }
}
