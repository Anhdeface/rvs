//! Integration tests for Round 2 Challenger:
//! Empirically stress-testing Rust target URI generation and parsing in `src/frida/target.rs`.
//!
//! Coverage:
//! 1. Adversarial argument quoting: empty string `""`, tabs `\t`, newlines `\n`, quotes `\"`,
//!    spaces, multiple empty strings `["", "", "foo"]`, and non-collapsing verification.
//! 2. Target URI parsing boundaries: positive PIDs (`+1234`), bare URIs (`frida://`, `frida:///`),
//!    invalid schemes (`gdb://`, `http://`, etc.), huge PIDs (> u32::MAX), negative PIDs.
//! 3. FridaTarget methods: display_target, pid, process_name.

use std::path::PathBuf;
use rvs::error::AppError;
use rvs::frida::driver::FridaDriver;
use rvs::frida::target::FridaTarget;

// =========================================================================
// Area 1: Adversarial Argument Quoting in FridaTarget::to_uri
// =========================================================================

#[test]
fn test_to_uri_single_empty_string_arg() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec!["".to_string()],
    };
    let uri = target.to_uri();
    assert_eq!(uri, "frida://spawn/local////bin/test \"\"");
}

#[test]
fn test_to_uri_multiple_empty_strings_not_collapsed() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec!["".to_string(), "".to_string(), "foo".to_string()],
    };
    let uri = target.to_uri();
    // Verify that empty strings are each formatted as `""` and preserved with single space delimiters
    assert_eq!(uri, "frida://spawn/local////bin/test \"\" \"\" foo");
}

#[test]
fn test_to_uri_consecutive_empty_strings_boundary() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec!["".to_string(), "".to_string(), "".to_string()],
    };
    let uri = target.to_uri();
    assert_eq!(uri, "frida://spawn/local////bin/test \"\" \"\" \"\"");

    // Verify token count when split on space (taking quoting into account)
    let parts: Vec<&str> = uri.split(' ').collect();
    // Should be ["frida://spawn/local////bin/test", "\"\"", "\"\"", "\"\""]
    assert_eq!(parts.len(), 4);
    assert_eq!(parts[1], "\"\"");
    assert_eq!(parts[2], "\"\"");
    assert_eq!(parts[3], "\"\"");
}

#[test]
fn test_to_uri_interspersed_empty_strings() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/echo"),
        args: vec![
            "alpha".to_string(),
            "".to_string(),
            "beta".to_string(),
            "".to_string(),
            "gamma".to_string(),
        ],
    };
    let uri = target.to_uri();
    assert_eq!(uri, "frida://spawn/local////bin/echo alpha \"\" beta \"\" gamma");
}

#[test]
fn test_to_uri_tab_character_quoting() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec!["\t".to_string(), "tab\there".to_string(), "\t\t".to_string()],
    };
    let uri = target.to_uri();
    assert_eq!(
        uri,
        "frida://spawn/local////bin/test \"\t\" \"tab\there\" \"\t\t\""
    );
}

#[test]
fn test_to_uri_newline_character_quoting() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec!["\n".to_string(), "line1\nline2".to_string(), "\r\n".to_string()],
    };
    let uri = target.to_uri();
    assert_eq!(
        uri,
        "frida://spawn/local////bin/test \"\n\" \"line1\nline2\" \"\r\n\""
    );
}

#[test]
fn test_to_uri_quote_escaping_and_wrapping() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec![
            "\"".to_string(),
            "quote\"in\"middle".to_string(),
            "\"fully_wrapped\"".to_string(),
        ],
    };
    let uri = target.to_uri();
    assert_eq!(
        uri,
        "frida://spawn/local////bin/test \"\\\"\" \"quote\\\"in\\\"middle\" \"\\\"fully_wrapped\\\"\""
    );
}

#[test]
fn test_to_uri_spaces_quoting() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/test"),
        args: vec![
            " ".to_string(),
            "hello world".to_string(),
            "   three   spaces   ".to_string(),
        ],
    };
    let uri = target.to_uri();
    assert_eq!(
        uri,
        "frida://spawn/local////bin/test \" \" \"hello world\" \"   three   spaces   \""
    );
}

#[test]
fn test_to_uri_complex_mixed_adversarial_arguments() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/usr/bin/app"),
        args: vec![
            "".to_string(),
            "simple".to_string(),
            "with space".to_string(),
            "tab\targ".to_string(),
            "newline\narg".to_string(),
            "quoted\"value".to_string(),
            "all\t \n\"combined\"".to_string(),
            "".to_string(),
        ],
    };
    let uri = target.to_uri();
    let expected = "frida://spawn/local////usr/bin/app \"\" simple \"with space\" \"tab\targ\" \"newline\narg\" \"quoted\\\"value\" \"all\t \n\\\"combined\\\"\" \"\"";
    assert_eq!(uri, expected);
}

#[test]
fn test_to_uri_empty_args_no_trailing_space() {
    let target = FridaTarget::Spawn {
        path: PathBuf::from("/bin/ls"),
        args: vec![],
    };
    let uri = target.to_uri();
    assert_eq!(uri, "frida://spawn/local////bin/ls");
    assert!(!uri.ends_with(' '));
}

// =========================================================================
// Area 2: Target URI Parsing Boundaries (FridaTarget::parse_attach)
// =========================================================================

#[test]
fn test_parse_attach_positive_pids_standard() {
    let target = FridaTarget::parse_attach("+1234").expect("Failed to parse positive PID +1234");
    assert_eq!(target, FridaTarget::Pid(1234));
    assert_eq!(target.to_uri(), "frida://1234");
    assert_eq!(target.pid(), Some(1234));
}

#[test]
fn test_parse_attach_positive_pids_extremes() {
    // +0
    let t0 = FridaTarget::parse_attach("+0").expect("Failed to parse +0");
    assert_eq!(t0, FridaTarget::Pid(0));

    // +1
    let t1 = FridaTarget::parse_attach("+1").expect("Failed to parse +1");
    assert_eq!(t1, FridaTarget::Pid(1));

    // Leading zeros with +
    let t_zeros = FridaTarget::parse_attach("+00042").expect("Failed to parse +00042");
    assert_eq!(t_zeros, FridaTarget::Pid(42));

    // Maximum u32 value with +
    let max_u32_str = format!("+{}", u32::MAX);
    let t_max = FridaTarget::parse_attach(&max_u32_str).expect("Failed to parse +u32::MAX");
    assert_eq!(t_max, FridaTarget::Pid(u32::MAX));
}

#[test]
fn test_parse_attach_positive_pid_with_whitespace() {
    let target = FridaTarget::parse_attach("   +9999   ").expect("Failed to parse padded +9999");
    assert_eq!(target, FridaTarget::Pid(9999));
}

#[test]
fn test_parse_attach_positive_pid_fallback_cases() {
    // Solo '+' is not a valid number, falls back to process name "+"
    let solo_plus = FridaTarget::parse_attach("+").expect("Failed on solo +");
    assert_eq!(solo_plus, FridaTarget::ProcessName("+".to_string()));

    // Double '+' is not digits, falls back to process name
    let double_plus = FridaTarget::parse_attach("++1234").expect("Failed on ++1234");
    assert_eq!(double_plus, FridaTarget::ProcessName("++1234".to_string()));

    // Plus with non-digit suffix
    let plus_alpha = FridaTarget::parse_attach("+proc123").expect("Failed on +proc123");
    assert_eq!(plus_alpha, FridaTarget::ProcessName("+proc123".to_string()));
}

#[test]
fn test_parse_attach_bare_frida_uris_rejected() {
    let bare_cases = [
        "frida://",
        "frida:///",
        "frida:////",
        "frida://///",
        "   frida://   ",
        "   frida:///   ",
    ];

    for case in bare_cases {
        let err = FridaTarget::parse_attach(case)
            .expect_err(&format!("Bare URI '{case}' must be rejected"));
        match err {
            AppError::R2FridaNotInstalled(msg) => {
                assert!(
                    msg.contains("Frida URI must specify a target"),
                    "Expected specific error message for '{case}', got: {msg}"
                );
            }
            other => panic!("Expected R2FridaNotInstalled for '{case}', got: {:?}", other),
        }
    }
}

#[test]
fn test_parse_attach_invalid_uri_schemes() {
    let invalid_schemes = [
        "gdb://",
        "gdb://1234",
        "http://localhost:8080",
        "https://example.com/target",
        "tcp://127.0.0.1:27042",
        "file:///bin/sh",
        "ssh://root@localhost",
        "frida_attach://1234",
        "unknown://proc",
    ];

    for uri in invalid_schemes {
        let err = FridaTarget::parse_attach(uri)
            .expect_err(&format!("Invalid scheme '{uri}' must be rejected"));
        match err {
            AppError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("Invalid URI scheme"),
                    "Error must mention 'Invalid URI scheme' for '{uri}', got: {msg}"
                );
                assert!(
                    msg.contains("Only 'frida://' URIs are supported"),
                    "Error must state only frida:// URIs are supported for '{uri}', got: {msg}"
                );
            }
            other => panic!("Expected InvalidArgument for '{uri}', got: {:?}", other),
        }
    }
}

#[test]
fn test_parse_attach_huge_pids_overflow() {
    let huge_pids = [
        "9999999999999999999999999999999999999999",
        "+9999999999999999999999999999999999999999",
        "4294967296", // u32::MAX + 1
        "+4294967296",
        "18446744073709551615", // u64::MAX
        "+18446744073709551615",
        "18446744073709551616", // u64::MAX + 1
        "+18446744073709551616",
    ];

    for pid_str in huge_pids {
        let err = FridaTarget::parse_attach(pid_str)
            .expect_err(&format!("Huge PID '{pid_str}' must return overflow error"));
        match err {
            AppError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("exceeds maximum allowable PID value"),
                    "Error must indicate PID overflow for '{pid_str}', got: {msg}"
                );
            }
            other => panic!("Expected InvalidArgument for '{pid_str}', got: {:?}", other),
        }
    }
}

#[test]
fn test_parse_attach_negative_pids_rejected() {
    let negative_cases = ["-1", "-1234", "-999999", "-0", "-+1234"];
    for case in negative_cases {
        let err = FridaTarget::parse_attach(case)
            .expect_err(&format!("Negative PID '{case}' must be rejected"));
        match err {
            AppError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("cannot be negative"),
                    "Expected negative PID error for '{case}', got: {msg}"
                );
            }
            other => panic!("Expected InvalidArgument for '{case}', got: {:?}", other),
        }
    }
}

#[test]
fn test_parse_attach_empty_or_whitespace_target() {
    let empty_cases = ["", "   ", "\t", "\n", "\r\n"];
    for case in empty_cases {
        let err = FridaTarget::parse_attach(case)
            .expect_err(&format!("Empty target '{case}' must be rejected"));
        match err {
            AppError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("Target cannot be empty"),
                    "Expected 'Target cannot be empty' for '{case}', got: {msg}"
                );
            }
            other => panic!("Expected InvalidArgument for '{case}', got: {:?}", other),
        }
    }
}

#[test]
fn test_parse_attach_valid_frida_uris() {
    let valid_uris = [
        "frida://1234",
        "frida://attach/local//firefox",
        "frida://spawn/local///bin/ls",
        "frida://attach/remote/192.168.1.1:27042//target",
    ];

    for uri in valid_uris {
        let target = FridaTarget::parse_attach(uri)
            .expect(&format!("Valid URI '{uri}' should parse successfully"));
        assert_eq!(target, FridaTarget::Uri(uri.to_string()));
        assert_eq!(target.to_uri(), uri);
        assert_eq!(target.display_target(), uri);
    }
}

// =========================================================================
// Area 3: FridaDriver Bare URI and Empty Input Handling
// =========================================================================

#[test]
fn test_frida_driver_new_bare_uri_immediate_error() {
    let bare_cases = ["frida://", "frida:///", "   frida://   "];
    for case in bare_cases {
        let err = FridaDriver::new(case, true)
            .expect_err(&format!("FridaDriver::new must reject bare URI '{case}' immediately"));
        match err {
            AppError::R2FridaNotInstalled(msg) => {
                assert!(msg.contains("Frida URI must specify a target"));
            }
            other => panic!("Expected R2FridaNotInstalled for '{case}', got: {:?}", other),
        }
    }
}

#[test]
fn test_frida_driver_new_empty_string_error() {
    let err = FridaDriver::new("", true).expect_err("FridaDriver::new must reject empty target");
    match err {
        AppError::InvalidArgument(msg) => {
            assert!(msg.contains("Target URI or PID cannot be empty"));
        }
        other => panic!("Expected InvalidArgument, got: {:?}", other),
    }
}

// =========================================================================
// Area 4: FridaTarget Accessors Integrity
// =========================================================================

#[test]
fn test_target_accessors_and_display() {
    let pid_target = FridaTarget::Pid(5678);
    assert_eq!(pid_target.display_target(), "5678");
    assert_eq!(pid_target.pid(), Some(5678));
    assert_eq!(pid_target.process_name(), None);
    assert_eq!(pid_target.to_uri(), "frida://5678");

    let proc_target = FridaTarget::ProcessName("calculator".to_string());
    assert_eq!(proc_target.display_target(), "calculator");
    assert_eq!(proc_target.pid(), None);
    assert_eq!(proc_target.process_name(), Some("calculator".to_string()));
    assert_eq!(proc_target.to_uri(), "frida://attach/local//calculator");

    let spawn_target = FridaTarget::Spawn {
        path: PathBuf::from("/usr/bin/python3"),
        args: vec!["-v".to_string()],
    };
    assert_eq!(spawn_target.display_target(), "/usr/bin/python3");
    assert_eq!(spawn_target.pid(), None);
    assert_eq!(spawn_target.process_name(), Some("python3".to_string()));
    assert_eq!(
        spawn_target.to_uri(),
        "frida://spawn/local////usr/bin/python3 -v"
    );
}
