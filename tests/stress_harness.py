#!/usr/bin/env python3
"""
Empirical stress test harness for `rvs` CLI.
Written by Challenger agent to rigorously probe system binaries, adversarial inputs,
terminal isolation, argument parsing, and binary patching.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import time

RVS_BIN = os.path.abspath("target/debug/rvs")
FIXTURE_ELF = os.path.abspath("tests/fixtures/test_target_elf64")

passed_tests = 0
failed_tests = 0
total_tests = 0
findings = []

def run_rvs(args, timeout=20):
    cmd = [RVS_BIN] + args
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env={**os.environ, "TERM": "xterm-256color"}  # Simulate interactive terminal to test isolation
        )
        duration = time.time() - start
        return proc.returncode, proc.stdout.decode('utf-8', errors='replace'), proc.stderr.decode('utf-8', errors='replace'), duration
    except subprocess.TimeoutExpired:
        return -999, "", f"TIMEOUT after {timeout}s", timeout

def check_terminal_cleanliness(stdout_text, stderr_text, label):
    # Check for raw ANSI escape sequences in stdout and stderr
    for text, name in [(stdout_text, "stdout"), (stderr_text, "stderr")]:
        if "\x1b[" in text or "\x1b]" in text or "\x1b(" in text:
            return False, f"{label} {name} contains unescaped ANSI sequence: {repr(text[:100])}"
    
    # Check stderr for Rust unhandled panics or segfaults
    if "panicked at" in stderr_text or "SIGSEGV" in stderr_text:
        return False, f"{label} stderr contains unhandled panic: {repr(stderr_text[:200])}"
        
    return True, ""

def test_case(name, args, expect_success=True, expect_error_code=None, custom_data_check=None, timeout=20):
    global passed_tests, failed_tests, total_tests, findings
    total_tests += 1
    
    code, stdout, stderr, dur = run_rvs(args, timeout=timeout)
    
    if code == -999:
        failed_tests += 1
        msg = f"[FAIL - TIMEOUT] {name} timed out after {dur:.1f}s (args: {' '.join(args)})"
        print(msg)
        findings.append(msg)
        return False
    
    # 1. Check terminal cleanliness
    clean, reason = check_terminal_cleanliness(stdout, stderr, name)
    if not clean:
        failed_tests += 1
        msg = f"[FAIL - TERMINAL POLLUTION] {name}: {reason}"
        print(msg)
        findings.append(msg)
        return False
        
    # 2. Check JSON validity of stdout
    try:
        envelope = json.loads(stdout)
    except Exception as e:
        failed_tests += 1
        msg = f"[FAIL - INVALID JSON] {name}: stdout is not valid JSON ({e}). Raw stdout: {repr(stdout[:200])}"
        print(msg)
        findings.append(msg)
        return False
        
    # 3. Check JSON schema contract
    base_keys = {"success", "command", "target", "timestamp"}
    missing = base_keys - set(envelope.keys())
    if missing:
        failed_tests += 1
        msg = f"[FAIL - SCHEMA MISMATCH] {name}: missing envelope keys {missing}"
        print(msg)
        findings.append(msg)
        return False
        
    # 4. Check success expectations
    if expect_success:
        if not envelope.get("success") or code != 0:
            failed_tests += 1
            msg = f"[FAIL - UNEXPECTED ERROR] {name}: expected success, got success={envelope.get('success')}, code={code}, error={envelope.get('error')}"
            print(msg)
            findings.append(msg)
            return False
        if envelope.get("error") is not None:
            failed_tests += 1
            msg = f"[FAIL - DIRTY ERROR FIELD] {name}: success=true but error is not null ({envelope.get('error')})"
            print(msg)
            findings.append(msg)
            return False
        if "data" not in envelope:
            failed_tests += 1
            msg = f"[FAIL - MISSING DATA FIELD] {name}: success=true but data key missing"
            print(msg)
            findings.append(msg)
            return False
    else:
        if envelope.get("success") or code == 0:
            failed_tests += 1
            msg = f"[FAIL - UNEXPECTED SUCCESS] {name}: expected error, got success=true, code={code}"
            print(msg)
            findings.append(msg)
            return False
        err_obj = envelope.get("error")
        if not isinstance(err_obj, dict) or "code" not in err_obj or "message" not in err_obj:
            failed_tests += 1
            msg = f"[FAIL - INVALID ERROR OBJECT] {name}: error field is not {{code, message}}: {err_obj}"
            print(msg)
            findings.append(msg)
            return False
        if expect_error_code and err_obj["code"] != expect_error_code:
            failed_tests += 1
            msg = f"[FAIL - ERROR CODE MISMATCH] {name}: expected error code {expect_error_code}, got {err_obj['code']}"
            print(msg)
            findings.append(msg)
            return False

    # 5. Custom payload check
    if custom_data_check and envelope.get("success"):
        check_ok, check_msg = custom_data_check(envelope.get("data"))
        if not check_ok:
            failed_tests += 1
            msg = f"[FAIL - PAYLOAD CHECK] {name}: {check_msg}"
            print(msg)
            findings.append(msg)
            return False

    passed_tests += 1
    print(f"[PASS] ({dur:.2f}s) {name}")
    return True

def main():
    print(f"=== Starting Empirical Challenger Stress Test Suite ===")
    print(f"Target Binary: {RVS_BIN}")
    
    # ----------------------------------------------------
    # SECTION 1: Real System Binaries
    # ----------------------------------------------------
    print("\n--- SECTION 1: Real System Binaries ---")
    system_bins = [
        "/bin/ls", "/bin/sh", "/bin/bash", "/bin/cat", "/bin/echo",
        "/bin/date", "/bin/cp", "/usr/bin/env", "/usr/bin/find"
    ]
    available_bins = [b for b in system_bins if os.path.exists(b) and os.path.isfile(b)]
    print(f"Testing on {len(available_bins)} available system binaries: {available_bins}")
    
    for sbin in available_bins:
        sname = os.path.basename(sbin)
        # Info
        test_case(f"System Binary ({sname}) - info", ["-f", sbin, "info"], expect_success=True,
                  custom_data_check=lambda d: (bool(d.get("arch") and d.get("bits")), "arch/bits missing"))
        
        # Analyze functions
        test_case(f"System Binary ({sname}) - analyze functions", ["-f", sbin, "analyze", "functions"], expect_success=True,
                  custom_data_check=lambda d: (isinstance(d.get("functions"), list) and d.get("count", 0) > 0, "functions list empty"))
        
        # Analyze functions filter
        test_case(f"System Binary ({sname}) - analyze functions --filter main", ["-f", sbin, "analyze", "functions", "--filter", "main"], expect_success=True)
        
        # Analyze functions detail
        test_case(f"System Binary ({sname}) - analyze functions --filter main --detail", ["-f", sbin, "analyze", "functions", "--filter", "main", "--detail"], expect_success=True)

        # Analyze blocks entry0
        test_case(f"System Binary ({sname}) - analyze blocks entry0", ["-f", sbin, "analyze", "blocks", "entry0"], expect_success=True,
                  custom_data_check=lambda d: (isinstance(d.get("blocks"), list), "blocks not a list"))

        # Analyze prologue-epilogue on entry0
        test_case(f"System Binary ({sname}) - analyze prologue-epilogue entry0", ["-f", sbin, "analyze", "prologue-epilogue", "entry0"], expect_success=True,
                  custom_data_check=lambda d: (isinstance(d.get("functions"), list), "functions not a list"))
                  
        # Callgraph formats (JSON, ASCII, Tree, Dot, Mermaid)
        test_case(f"System Binary ({sname}) - analyze graph --format json",
                  ["-f", sbin, "analyze", "graph", "--format", "json"],
                  expect_success=True,
                  custom_data_check=lambda d: (isinstance(d.get("nodes"), list) and isinstance(d.get("edges"), list), "nodes/edges missing"))

        for fmt in ["ascii", "tree", "dot", "mermaid"]:
            test_case(f"System Binary ({sname}) - analyze graph --format {fmt}",
                      ["-f", sbin, "analyze", "graph", "--format", fmt],
                      expect_success=True,
                      custom_data_check=lambda d: (bool(d.get("rendered")), f"rendered output missing for {fmt}"))
                      
        # Strings
        test_case(f"System Binary ({sname}) - strings --min-len 8", ["-f", sbin, "strings", "--min-len", "8"], expect_success=True,
                  custom_data_check=lambda d: (isinstance(d.get("strings"), list), "strings list missing"))
                  
        # Symbols
        test_case(f"System Binary ({sname}) - symbols", ["-f", sbin, "symbols"], expect_success=True,
                  custom_data_check=lambda d: (isinstance(d.get("symbols"), list), "symbols list missing"))

    # ----------------------------------------------------
    # SECTION 2: Adversarial / Boundary Inputs
    # ----------------------------------------------------
    print("\n--- SECTION 2: Adversarial & Boundary Inputs ---")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Non-existent file
        non_existent = os.path.join(tmpdir, "non_existent_file.bin")
        test_case("Adversarial: Non-existent file", ["-f", non_existent, "info"], expect_success=False, expect_error_code="FILE_NOT_FOUND")
        
        # Directory as target
        test_case("Adversarial: Directory as target", ["-f", tmpdir, "info"], expect_success=False, expect_error_code="FILE_NOT_FOUND")
        
        # Empty file (0 bytes) - rejects with ZERO_BYTE_FILE (File Error, code 2)
        empty_file = os.path.join(tmpdir, "empty.bin")
        open(empty_file, "wb").close()
        test_case("Adversarial: Empty file (0 bytes) - info", ["-f", empty_file, "info"], expect_success=False, expect_error_code="ZERO_BYTE_FILE")
        test_case("Adversarial: Empty file (0 bytes) - analyze functions", ["-f", empty_file, "analyze", "functions"], expect_success=False, expect_error_code="ZERO_BYTE_FILE")
        test_case("Adversarial: Empty file (0 bytes) - analyze graph", ["-f", empty_file, "analyze", "graph"], expect_success=False, expect_error_code="ZERO_BYTE_FILE")
        test_case("Adversarial: Empty file (0 bytes) - strings", ["-f", empty_file, "strings"], expect_success=False, expect_error_code="ZERO_BYTE_FILE")
        
        # 1-byte file
        one_byte = os.path.join(tmpdir, "one_byte.bin")
        with open(one_byte, "wb") as f:
            f.write(b"\x7f")
        test_case("Adversarial: 1-byte file - info", ["-f", one_byte, "info"], expect_success=True)
        
        # 4-byte truncated ELF
        elf4 = os.path.join(tmpdir, "elf4.bin")
        with open(elf4, "wb") as f:
            f.write(b"\x7fELF")
        test_case("Adversarial: 4-byte truncated ELF - info", ["-f", elf4, "info"], expect_success=True)
        test_case("Adversarial: 4-byte truncated ELF - analyze graph", ["-f", elf4, "analyze", "graph"], expect_success=True)
        
        # Corrupted ELF Header (64 bytes of junk)
        corrupt_elf = os.path.join(tmpdir, "corrupt_elf.bin")
        with open(corrupt_elf, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\xff" * 48)
        test_case("Adversarial: Corrupted ELF header - info", ["-f", corrupt_elf, "info"], expect_success=True)
        test_case("Adversarial: Corrupted ELF header - analyze functions", ["-f", corrupt_elf, "analyze", "functions"], expect_success=True)
        test_case("Adversarial: Corrupted ELF header - analyze graph", ["-f", corrupt_elf, "analyze", "graph"], expect_success=True)

        # Pure ASCII text file
        text_file = os.path.join(tmpdir, "plain_text.txt")
        with open(text_file, "w") as f:
            f.write("This is not a binary file. It is just plain text content for testing purposes.")
        test_case("Adversarial: Plain text file - info", ["-f", text_file, "info"], expect_success=True)
        test_case("Adversarial: Plain text file - strings", ["-f", text_file, "strings"], expect_success=True)
        test_case("Adversarial: Plain text file - analyze graph", ["-f", text_file, "analyze", "graph"], expect_success=True)
        
        # Random binary blob (500 KB)
        rand_file = os.path.join(tmpdir, "random_blob.bin")
        with open(rand_file, "wb") as f:
            f.write(os.urandom(500 * 1024))
        test_case("Adversarial: 500KB Random blob - info", ["-f", rand_file, "info"], expect_success=True)
        test_case("Adversarial: 500KB Random blob - analyze functions", ["-f", rand_file, "analyze", "functions"], expect_success=True)
        test_case("Adversarial: 500KB Random blob - analyze graph", ["-f", rand_file, "analyze", "graph"], expect_success=True)

        # Filename with spaces, symbols and unicode
        weird_name = os.path.join(tmpdir, "weird file name (test) [v1.0] #1.bin")
        shutil.copyfile(FIXTURE_ELF, weird_name)
        test_case("Adversarial: Path with spaces and special chars - info", ["-f", weird_name, "info"], expect_success=True)
        test_case("Adversarial: Path with spaces and special chars - analyze graph", ["-f", weird_name, "analyze", "graph"], expect_success=True)

    # ----------------------------------------------------
    # SECTION 3: CLI Argument Grammar & Error Envelope
    # ----------------------------------------------------
    print("\n--- SECTION 3: CLI Argument Grammar & Error Envelope ---")
    
    # Missing global -f flag
    test_case("CLI Grammar: Missing -f flag (info)", ["info"], expect_success=False, expect_error_code="INVALID_ARGUMENT")
    test_case("CLI Grammar: Missing -f flag (analyze functions)", ["analyze", "functions"], expect_success=False, expect_error_code="INVALID_ARGUMENT")
    test_case("CLI Grammar: Missing -f flag (patch instruction)", ["patch", "instruction", "--addr", "0x1000", "--assembly", "nop"], expect_success=False, expect_error_code="INVALID_ARGUMENT")
    
    # Flag placed after subcommand: `rvs info -f <path>`
    test_case("CLI Grammar: -f flag placed AFTER subcommand", ["info", "-f", FIXTURE_ELF], expect_success=True)
    test_case("CLI Grammar: -f flag placed BEFORE subcommand", ["-f", FIXTURE_ELF, "info"], expect_success=True)
    
    # Global pretty and quiet flags
    test_case("CLI Flags: --pretty and -q flags", ["--pretty", "-q", "-f", FIXTURE_ELF, "info"], expect_success=True)
    
    # Non-existent symbol in analyze blocks
    test_case("Symbol Resolution: Non-existent symbol (analyze blocks)", ["-f", FIXTURE_ELF, "analyze", "blocks", "sym.non_existent_function_xyz123"],
              expect_success=False, expect_error_code="SYMBOL_NOT_FOUND")

    # ANSI injection in CLI arguments
    ansi_arg = "\x1b[31mFAKE_INJECTION\x1b[0m"
    test_case("Adversarial: ANSI injection in filter argument", ["-f", FIXTURE_ELF, "analyze", "functions", "--filter", ansi_arg], expect_success=True)

    # ----------------------------------------------------
    # SECTION 4: Binary Patching Engine Stress Tests
    # ----------------------------------------------------
    print("\n--- SECTION 4: Patching Engine Stress Tests ---")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        patch_target = os.path.join(tmpdir, "target_to_patch")
        shutil.copyfile(FIXTURE_ELF, patch_target)
        os.chmod(patch_target, 0o755)
        
        # 1. Invalid assembly instruction
        test_case("Patching: Invalid assembly syntax error",
                  ["-f", patch_target, "patch", "instruction", "--addr", "sym.main", "--assembly", "not_a_valid_instruction_opcode_xyz"],
                  expect_success=False, expect_error_code="ASSEMBLY_FAILED")
                  
        # 2. NOP 0 bytes error
        test_case("Patching: NOP 0 bytes validation error",
                  ["-f", patch_target, "patch", "instruction", "--addr", "sym.main", "--nop", "0"],
                  expect_success=False, expect_error_code="INVALID_ARGUMENT")
                  
        # 3. Valid instruction patch with backup
        test_case("Patching: Valid instruction patch with --backup",
                  ["-f", patch_target, "patch", "instruction", "--addr", "sym.main", "--assembly", "nop", "--backup"],
                  expect_success=True,
                  custom_data_check=lambda d: (os.path.exists(patch_target + ".bak"), "Backup file was not created"))
                  
        # 4. Valid NOP patch
        test_case("Patching: Valid NOP patch (4 bytes)",
                  ["-f", patch_target, "patch", "instruction", "--addr", "sym.main", "--nop", "4"],
                  expect_success=True)
                  
        # 5. Invalid hex string (odd length)
        test_case("Patching: Odd length hex bytes error",
                  ["-f", patch_target, "patch", "bytes", "--addr", "sym.main", "--hex", "909"],
                  expect_success=False, expect_error_code="INVALID_HEX_STRING")
                  
        # 6. Invalid hex string (non-hex chars)
        test_case("Patching: Non-hex characters error",
                  ["-f", patch_target, "patch", "bytes", "--addr", "sym.main", "--hex", "90ZZ88"],
                  expect_success=False, expect_error_code="INVALID_HEX_STRING")
                  
        # 7. Valid raw hex patch
        test_case("Patching: Valid raw hex patch",
                  ["-f", patch_target, "patch", "bytes", "--addr", "sym.main", "--hex", "90909090"],
                  expect_success=True,
                  custom_data_check=lambda d: (d.get("verified") is True, "Verification flag not true"))
                  
        # 8. String patch: not found
        test_case("Patching: String not found error",
                  ["-f", patch_target, "patch", "string", "--old", "STRING_THAT_DOES_NOT_EXIST_XYZ_12345", "--new", "REPLACEMENT"],
                  expect_success=False, expect_error_code="STRING_NOT_FOUND")
                  
        # 9. String patch: strict-length overflow error
        test_case("Patching: String strict-length overflow error",
                  ["-f", patch_target, "patch", "string", "--old", "STATUS_SYSTEM_LOCKED", "--new", "Super long replacement string exceeding length by far", "--strict-length"],
                  expect_success=False, expect_error_code="STRING_OVERFLOW")
                  
        # 10. String patch: valid replacement
        test_case("Patching: Valid string patch",
                  ["-f", patch_target, "patch", "string", "--old", "STATUS_SYSTEM_LOCKED", "--new", "STATUS_SYSTEM_ACTIVE"],
                  expect_success=True,
                  custom_data_check=lambda d: (d.get("verified") is True, "String patch verification not true"))

    # ----------------------------------------------------
    # Summary
    # ----------------------------------------------------
    print(f"\n==========================================")
    print(f"Stress Test Suite Summary:")
    print(f"Total Tests Run: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    print(f"==========================================")
    
    if failed_tests > 0:
        print("\nFailures / Findings:")
        for f in findings:
            print(f" - {f}")
        sys.exit(1)
    else:
        print("\nALL STRESS TESTS PASSED EMPIRICALLY!")
        sys.exit(0)

if __name__ == "__main__":
    main()
