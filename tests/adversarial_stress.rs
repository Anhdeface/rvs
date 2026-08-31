use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;

mod common;
use common::*;

/// Test category 1: Malformed / Corrupted binaries, empty files, non-executable files
#[test]
fn test_adversarial_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let empty_file = temp_dir.path().join("empty.bin");
    File::create(&empty_file).unwrap();

    let output = run_rvs(&["-f", empty_file.to_str().unwrap(), "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    
    assert_eq!(resp["command"], "info");
    // Even on empty file, rvs should not panic; either success or failure envelope is returned
    assert!(resp.get("success").is_some());
    assert!(!stdout.contains("panic"), "Output must not contain panic trace");
}

#[test]
fn test_adversarial_truncated_and_corrupt_elf() {
    let temp_dir = TempDir::new().unwrap();
    
    // 1. Truncated 4-byte ELF magic
    let trunc_elf = temp_dir.path().join("trunc.elf");
    {
        let mut f = File::create(&trunc_elf).unwrap();
        f.write_all(b"\x7fELF").unwrap();
    }
    let output = run_rvs(&["-f", trunc_elf.to_str().unwrap(), "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    assert_eq!(resp["command"], "info");
    assert!(!stdout.contains("panic"), "Output must not contain panic trace");

    // 2. Corrupt ELF header with bogus offsets
    let corrupt_elf = temp_dir.path().join("corrupt.elf");
    {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // Little endian
        data[6] = 1; // ELF version
        // Set invalid program header offset
        data[32..40].copy_from_slice(&0xffffffffffffffffu64.to_le_bytes());
        // Set invalid section header offset
        data[40..48].copy_from_slice(&0xffffffffffffffffu64.to_le_bytes());
        let mut f = File::create(&corrupt_elf).unwrap();
        f.write_all(&data).unwrap();
    }

    let output = run_rvs(&["-f", corrupt_elf.to_str().unwrap(), "analyze", "functions"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    assert_eq!(resp["command"], "analyze functions");
    assert!(!stdout.contains("panic"));
}

#[test]
fn test_adversarial_non_executable_text_file() {
    let temp_dir = TempDir::new().unwrap();
    let text_file = temp_dir.path().join("text.txt");
    {
        let mut f = File::create(&text_file).unwrap();
        f.write_all(b"Hello World! This is plain text, not a machine binary.\n").unwrap();
    }

    let output = run_rvs(&["-f", text_file.to_str().unwrap(), "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    assert_eq!(resp["command"], "info");
    assert!(!stdout.contains("panic"));

    let output2 = run_rvs(&["-f", text_file.to_str().unwrap(), "analyze", "functions"]);
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let resp2: serde_json::Value = serde_json::from_str(&stdout2).expect("Must return valid JSON envelope");
    assert_eq!(resp2["command"], "analyze functions");
    assert!(!stdout2.contains("panic"));
}

#[test]
fn test_adversarial_huge_random_binary() {
    let temp_dir = TempDir::new().unwrap();
    let random_bin = temp_dir.path().join("random.bin");
    {
        let mut f = File::create(&random_bin).unwrap();
        // Write 1MB of pseudo-random pseudo-code data
        let pattern = [0x90, 0x55, 0x48, 0x89, 0xe5, 0xc3, 0xeb, 0xfe, 0xcc, 0xff, 0x00, 0x7f];
        let mut chunk = Vec::with_capacity(1024 * 1024);
        for i in 0..(1024 * 1024) {
            chunk.push(pattern[i % pattern.len()]);
        }
        f.write_all(&chunk).unwrap();
    }

    let output = run_rvs(&["-f", random_bin.to_str().unwrap(), "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    assert_eq!(resp["command"], "info");
    assert!(!stdout.contains("panic"));
}

#[test]
fn test_adversarial_directory_as_target() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().to_str().unwrap();

    let output = run_rvs(&["-f", dir_path, "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    assert!(!stdout.contains("panic"));
    // Expect error response because directory is not a valid binary file
    assert_eq!(resp["command"], "info");
}

#[test]
fn test_adversarial_unreadable_file() {
    let temp_dir = TempDir::new().unwrap();
    let unreadable = temp_dir.path().join("unreadable.bin");
    {
        let mut f = File::create(&unreadable).unwrap();
        f.write_all(b"\x7fELF").unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&unreadable, perms).unwrap();
    }

    let output = run_rvs(&["-f", unreadable.to_str().unwrap(), "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("Must return valid JSON envelope");
    assert!(!stdout.contains("panic"));
    assert_eq!(resp["command"], "info");
}

/// Test category 2: Non-existent symbol queries and out-of-bounds addresses
#[test]
fn test_adversarial_symbol_and_address_queries() {
    let fixture = fixture_path("test_target_elf64");

    // 1. Completely bogus symbol
    let (resp, out) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "analyze", "blocks", "sym.totally_non_existent_function_12345"
    ]);
    assert!(!resp.success);
    assert!(!out.status.success());
    assert_eq!(resp.error.as_ref().unwrap().code, "SYMBOL_NOT_FOUND");

    // 2. Out of bounds address 0xdeadbeefcafebabe
    let (resp2, out2) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "analyze", "blocks", "0xdeadbeefcafebabe"
    ]);
    assert!(!out2.status.success() || resp2.data.is_some());
    assert!(resp2.error.is_some() || resp2.data.is_some());

    // 3. Prologue/Epilogue on non-existent symbol
    let (resp3, out3) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "analyze", "prologue-epilogue", "sym.non_existent_func"
    ]);
    assert!(!resp3.success);
    assert!(!out3.status.success());
    assert_eq!(resp3.error.as_ref().unwrap().code, "SYMBOL_NOT_FOUND");

    // 4. Graph CFG on non-existent symbol
    let (resp4, out4) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "analyze", "graph", "sym.non_existent_func", "--type", "cfg"
    ]);
    assert!(!resp4.success);
    assert!(!out4.status.success());
    assert_eq!(resp4.error.as_ref().unwrap().code, "SYMBOL_NOT_FOUND");

    // 5. Functions filter matching nothing
    let (resp5, out5) = run_rvs_json::<FunctionsData>(&[
        "-f", fixture.to_str().unwrap(),
        "analyze", "functions", "--filter", "MATCH_ABSOLUTELY_NOTHING_9999"
    ]);
    assert!(resp5.success);
    assert!(out5.status.success());
    assert_eq!(resp5.data.unwrap().count, 0);

    // 6. Functions filter with regex / special characters
    let (resp6, out6) = run_rvs_json::<FunctionsData>(&[
        "-f", fixture.to_str().unwrap(),
        "analyze", "functions", "--filter", "[[["
    ]);
    assert!(resp6.success);
    assert!(out6.status.success());
    assert_eq!(resp6.data.unwrap().count, 0);

    // 7. Strings with extreme min-len filters
    let (resp7, out7) = run_rvs_json::<StringsData>(&[
        "-f", fixture.to_str().unwrap(),
        "strings", "--min-len", "999999"
    ]);
    assert!(resp7.success);
    assert!(out7.status.success());
    assert_eq!(resp7.data.unwrap().count, 0);
}

/// Test category 3: Odd-length hex strings, invalid assembly, string overflow, injections
#[test]
fn test_adversarial_odd_length_and_malformed_hex() {
    let (_tmp, fixture) = create_temp_fixture("test_target_elf64");

    // Odd-length: single character
    let (resp1, out1) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "bytes", "--addr", "0x1140", "--hex", "a"
    ]);
    assert!(!resp1.success);
    assert!(!out1.status.success());
    assert_eq!(resp1.error.as_ref().unwrap().code, "INVALID_HEX_STRING");

    // Odd-length: 3 characters
    let (resp2, out2) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "bytes", "--addr", "0x1140", "--hex", "abc"
    ]);
    assert!(!resp2.success);
    assert!(!out2.status.success());
    assert_eq!(resp2.error.as_ref().unwrap().code, "INVALID_HEX_STRING");

    // Invalid non-hex characters
    let (resp3, out3) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "bytes", "--addr", "0x1140", "--hex", "zzzz"
    ]);
    assert!(!resp3.success);
    assert!(!out3.status.success());
    assert_eq!(resp3.error.as_ref().unwrap().code, "INVALID_HEX_STRING");

    // Empty hex string
    let (resp4, out4) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "bytes", "--addr", "0x1140", "--hex", ""
    ]);
    assert!(!resp4.success);
    assert!(!out4.status.success());
    assert_eq!(resp4.error.as_ref().unwrap().code, "INVALID_HEX_STRING");
}

#[test]
fn test_adversarial_invalid_assembly_and_nop_edge_cases() {
    let (_tmp, fixture) = create_temp_fixture("test_target_elf64");

    // 1. Completely invalid opcode
    let (resp1, out1) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "instruction", "--addr", "0x1140", "--assembly", "not_a_real_opcode_instruction_1234"
    ]);
    assert!(!resp1.success);
    assert!(!out1.status.success());
    assert_eq!(resp1.error.as_ref().unwrap().code, "ASSEMBLY_FAILED");

    // 2. Syntax error in assembly
    let (resp2, out2) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "instruction", "--addr", "0x1140", "--assembly", "mov , eax"
    ]);
    assert!(!resp2.success);
    assert!(!out2.status.success());
    assert_eq!(resp2.error.as_ref().unwrap().code, "ASSEMBLY_FAILED");


    // 3. NOP count 0
    let (resp3, out3) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "instruction", "--addr", "0x1140", "--nop", "0"
    ]);
    assert!(!resp3.success);
    assert!(!out3.status.success());
    assert_eq!(resp3.error.as_ref().unwrap().code, "INVALID_ARGUMENT");
}

#[test]
fn test_adversarial_string_overflow_and_not_found() {
    let (_tmp, fixture) = create_temp_fixture("test_target_elf64");

    // 1. Strict length overflow protection
    let (resp1, out1) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "string",
        "--old", "STATUS_SYSTEM_LOCKED",
        "--new", "STATUS_SYSTEM_UNLOCKED_SUPER_LONG_PAYLOAD_THAT_WILL_DEFINITELY_OVERFLOW",
        "--strict-length"
    ]);
    assert!(!resp1.success);
    assert!(!out1.status.success());
    assert_eq!(resp1.error.as_ref().unwrap().code, "STRING_OVERFLOW");

    // 2. Non-existent old string
    let (resp2, out2) = run_rvs_json::<serde_json::Value>(&[
        "-f", fixture.to_str().unwrap(),
        "patch", "string",
        "--old", "THIS_STRING_DOES_NOT_EXIST_ANYWHERE_IN_BINARY",
        "--new", "replacement"
    ]);
    assert!(!resp2.success);
    assert!(!out2.status.success());
    assert_eq!(resp2.error.as_ref().unwrap().code, "STRING_NOT_FOUND");
}

/// Test category 4: Real system binaries across ELF64 / ELF32
#[test]
fn test_adversarial_real_system_binaries_ls() {
    let ls_path = if PathBuf::from("/bin/ls").exists() {
        "/bin/ls"
    } else if PathBuf::from("/usr/bin/ls").exists() {
        "/usr/bin/ls"
    } else {
        return;
    };

    // 1. info on /bin/ls
    let (info_resp, info_out) = run_rvs_json::<InfoData>(&["-f", ls_path, "info"]);
    assert!(info_resp.success);
    assert!(info_out.status.success());
    let info = info_resp.data.unwrap();
    assert!(info.format.to_lowercase().contains("elf"));
    assert_eq!(info.bits, 64);

    // 2. analyze functions on /bin/ls
    let (funcs_resp, funcs_out) = run_rvs_json::<FunctionsData>(&["-f", ls_path, "analyze", "functions"]);
    assert!(funcs_resp.success);
    assert!(funcs_out.status.success());
    assert!(funcs_resp.data.unwrap().count > 0);

    // 3. analyze graph on /bin/ls
    let (graph_resp, graph_out) = run_rvs_json::<GraphData>(&[
        "-f", ls_path,
        "analyze", "graph", "--format", "json"
    ]);
    assert!(graph_resp.success);
    assert!(graph_out.status.success());

    // 4. strings on /bin/ls
    let (str_resp, str_out) = run_rvs_json::<StringsData>(&["-f", ls_path, "strings", "--min-len", "8"]);
    assert!(str_resp.success);
    assert!(str_out.status.success());
    assert!(str_resp.data.unwrap().count > 0);
}

#[test]
fn test_adversarial_real_system_binaries_sh() {
    let sh_path = if PathBuf::from("/bin/sh").exists() {
        "/bin/sh"
    } else if PathBuf::from("/usr/bin/sh").exists() {
        "/usr/bin/sh"
    } else {
        return;
    };

    let (info_resp, info_out) = run_rvs_json::<InfoData>(&["-f", sh_path, "info"]);
    assert!(info_resp.success);
    assert!(info_out.status.success());

    let (funcs_resp, funcs_out) = run_rvs_json::<FunctionsData>(&["-f", sh_path, "analyze", "functions", "--filter", "main"]);
    assert!(funcs_resp.success);
    assert!(funcs_out.status.success());
}

#[test]
fn test_adversarial_callgraph_formats_on_system_binary() {
    let sh_path = if PathBuf::from("/bin/sh").exists() {
        "/bin/sh"
    } else {
        return;
    };

    for format in &["json", "ascii", "tree", "dot", "mermaid"] {
        let (resp, out) = run_rvs_json::<GraphData>(&[
            "-f", sh_path,
            "analyze", "graph",
            "--format", format
        ]);
        assert!(resp.success, "Format {} failed", format);
        assert!(out.status.success());
        if *format != "json" {
            assert!(resp.data.as_ref().unwrap().rendered.is_some(), "Format {} rendered output should exist", format);
        }
    }
}
