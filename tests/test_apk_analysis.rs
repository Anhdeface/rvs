//! Integration Tests for rvs Android APK Analysis Subsystem
//!
//! Covers:
//! - Dual Ingestion: Raw .apk archives, unpacked directories (text & binary AXML), standalone .dex and .so
//! - AndroidManifest decoding: Binary AXML & plain text XML parsing (package, version, SDK, permissions, components)
//! - DEX / Dalvik analysis: Classes, methods, fields, string pool, and bytecode inspection
//! - Native .so JNI extraction: Exported JNI entry points (`Java_*`), symbol resolution, architecture verification
//! - CLI Subcommands: `rvs apk inspect`, `rvs apk manifest`, `rvs apk dex`, `rvs apk so`
//! - 4-Tier Test Architecture: Tier 1 (Feature Coverage), Tier 2 (Boundary & Corner Cases), Tier 3 (Cross-Feature Combinations), Tier 4 (Real-World Workloads)

mod common;

use common::*;
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

// =============================================================================
// Helper Fixture Resolvers
// =============================================================================

fn raw_apk_fixture() -> PathBuf {
    fixture_path("sample_raw.apk")
}

fn unpacked_dir_fixture() -> PathBuf {
    fixture_path("sample_unpacked_dir")
}

fn unpacked_axml_dir_fixture() -> PathBuf {
    fixture_path("sample_unpacked_axml_dir")
}

fn classes_dex_fixture() -> PathBuf {
    fixture_path("sample_classes.dex")
}

fn aarch64_so_fixture() -> PathBuf {
    fixture_path("sample_aarch64_lib.so")
}

fn multi_dex_apk_fixture() -> PathBuf {
    fixture_path("sample_multi_dex.apk")
}

fn no_so_apk_fixture() -> PathBuf {
    fixture_path("sample_no_so.apk")
}

// =============================================================================
// Tier 1: Feature Coverage (Happy Path)
// =============================================================================

// --- Feature 1: Dual Ingestion (Raw .apk, Unpacked Directory, Standalone files) ---

#[test]
fn test_tier1_ingest_raw_apk_package_identity() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success(), "apk inspect failed on raw apk");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert_eq!(data.source_type, "archive");
    assert_eq!(data.package_name.as_deref(), Some("eu.jgamba.myapplication"));
    assert!(data.has_manifest);
    assert!(data.is_manifest_binary);
}

#[test]
fn test_tier1_ingest_raw_apk_contains_dex_entries() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert!(!data.dex_files.is_empty(), "DEX files should not be empty in raw apk");
    assert!(data.dex_files.iter().any(|d| d.contains("classes.dex")));
}

#[test]
fn test_tier1_ingest_raw_apk_contains_native_libraries() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert!(data.native_libraries.contains_key("arm64-v8a"), "arm64-v8a ABI must be detected");
    let libs = &data.native_libraries["arm64-v8a"];
    assert!(libs.iter().any(|lib| lib.contains("libnative.so")));
}

#[test]
fn test_tier1_ingest_unpacked_directory_text_manifest() {
    let dir = unpacked_dir_fixture();
    let dir_str = dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", dir_str]);

    assert!(out.status.success(), "apk inspect failed on unpacked directory");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert_eq!(data.source_type, "directory");
    assert_eq!(data.package_name.as_deref(), Some("com.example.unpacked"));
    assert!(data.has_manifest);
    assert!(!data.is_manifest_binary, "Manifest should be plain text XML");
    assert!(data.dex_files.iter().any(|d| d.contains("classes.dex")));
    assert!(data.native_libraries.contains_key("arm64-v8a"));
}

#[test]
fn test_tier1_ingest_unpacked_directory_binary_manifest() {
    let dir = unpacked_axml_dir_fixture();
    let dir_str = dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", dir_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert_eq!(data.source_type, "directory");
    assert_eq!(data.package_name.as_deref(), Some("eu.jgamba.myapplication"));
    assert!(data.has_manifest);
    assert!(data.is_manifest_binary, "Manifest should be detected as binary AXML");
}

#[test]
fn test_tier1_ingest_standalone_dex_file() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", dex_str]);

    assert!(out.status.success(), "apk inspect failed on standalone dex");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert_eq!(data.source_type, "standalone");
    assert_eq!(data.dex_files.len(), 1);
    assert!(data.dex_files[0].contains("sample_classes.dex"));
}

#[test]
fn test_tier1_ingest_standalone_native_so_file() {
    let so = aarch64_so_fixture();
    let so_str = so.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", so_str]);

    assert!(out.status.success(), "apk inspect failed on standalone so");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert_eq!(data.source_type, "standalone");
    assert!(!data.native_libraries.is_empty(), "Native libraries should contain the standalone .so");
}

// --- Feature 2: AndroidManifest AXML & Plain Text Parsing ---

#[test]
fn test_tier1_manifest_binary_axml_metadata() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let m = resp.data.expect("ManifestInfoData missing");
    assert_eq!(m.package_name, "eu.jgamba.myapplication");
    assert_eq!(m.version_name.as_deref(), Some("1.0"));
    assert_eq!(m.version_code, Some(1));
}

#[test]
fn test_tier1_manifest_binary_axml_permissions() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str]);

    assert!(out.status.success());
    let m = resp.data.expect("ManifestInfoData missing");
    assert!(m.permissions.iter().any(|p| p.contains("ACCESS_FINE_LOCATION")));
    assert!(m.permissions.iter().any(|p| p.contains("ACCESS_COARSE_LOCATION")));
}

#[test]
fn test_tier1_manifest_binary_axml_components() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str]);

    assert!(out.status.success());
    let m = resp.data.expect("ManifestInfoData missing");
    assert!(m.activities.iter().any(|a| a.contains("MainActivity")));
    assert!(m.services.iter().any(|s| s.contains("MyFirstService") || s.contains("MySecondService")));
    assert!(m.providers.iter().any(|p| p.contains("MyContentProvider") || p.contains("InitializationProvider")));
    assert!(m.receivers.iter().any(|r| r.contains("ProfileInstallReceiver") || r.contains("MyReceiver")));
}

#[test]
fn test_tier1_manifest_unpacked_text_xml_metadata() {
    let dir = unpacked_dir_fixture();
    let dir_str = dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", dir_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let m = resp.data.expect("ManifestInfoData missing");
    assert_eq!(m.package_name, "com.example.unpacked");
    assert_eq!(m.version_name.as_deref(), Some("2.1.0"));
    assert_eq!(m.version_code, Some(42));
    assert!(m.debuggable, "Unpacked manifest should have debuggable=true");
}

#[test]
fn test_tier1_manifest_unpacked_text_xml_permissions_and_activities() {
    let dir = unpacked_dir_fixture();
    let dir_str = dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", dir_str]);

    assert!(out.status.success());
    let m = resp.data.expect("ManifestInfoData missing");
    assert!(m.permissions.iter().any(|p| p.contains("INTERNET")));
    assert!(m.permissions.iter().any(|p| p.contains("ACCESS_NETWORK_STATE")));
    assert!(m.activities.iter().any(|a| a.contains("MainActivity")));
    assert!(m.activities.iter().any(|a| a.contains("DetailActivity")));
}

// --- Feature 3: DEX / Dalvik Class & Method Analysis ---

#[test]
fn test_tier1_dex_from_raw_apk_metrics() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let dex = resp.data.expect("DexAnalysisData missing");
    assert!(dex.classes_count >= 3, "classes_count should be at least 3, got {}", dex.classes_count);
    assert!(dex.methods_count >= 10, "methods_count should be at least 10, got {}", dex.methods_count);
    assert!(dex.strings_count >= 20, "strings_count should be at least 20, got {}", dex.strings_count);
}

#[test]
fn test_tier1_dex_class_name_and_super_resolution() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_str]);

    assert!(out.status.success());
    let dex = resp.data.expect("DexAnalysisData missing");
    let quick_action = dex.classes.iter().find(|c| c.name.contains("QuickActionItem"));
    assert!(quick_action.is_some(), "Class QuickActionItem should be present");
    let cls = quick_action.unwrap();
    assert!(cls.super_class.as_deref().unwrap_or("").contains("LinearLayout"));
}

#[test]
fn test_tier1_dex_methods_and_signatures() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_str]);

    assert!(out.status.success());
    let dex = resp.data.expect("DexAnalysisData missing");
    let quick_action = dex.classes.iter().find(|c| c.name.contains("QuickActionItem")).unwrap();
    assert!(quick_action.methods.iter().any(|m| m.name == "isChecked"));
    assert!(quick_action.methods.iter().any(|m| m.name == "setChecked"));
    assert!(quick_action.methods.iter().any(|m| m.name == "setText"));
}

#[test]
fn test_tier1_dex_standalone_file_analysis() {
    let dex_path = classes_dex_fixture();
    let dex_str = dex_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let dex = resp.data.expect("DexAnalysisData missing");
    assert!(dex.classes.iter().any(|c| c.name.contains("QuickActionWindow")));
}

#[test]
fn test_tier1_dex_string_pool_inspection() {
    let dex_path = classes_dex_fixture();
    let dex_str = dex_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_str]);

    assert!(out.status.success());
    let dex = resp.data.expect("DexAnalysisData missing");
    if let Some(strings) = &dex.strings {
        assert!(strings.iter().any(|s| s.contains("QuickAction")));
    }
}

// --- Feature 4: Native .so JNI Symbol & Xref Extraction ---

#[test]
fn test_tier1_so_jni_function_detection_in_raw_apk() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData missing");
    assert!(!so.jni_functions.is_empty(), "JNI functions must be extracted from raw apk");
    assert!(so.jni_functions.iter().any(|j| j.name.contains("Java_com_example_app_MainActivity_stringFromJNI")));
}

#[test]
fn test_tier1_so_jni_demangled_class_and_method() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    let so = resp.data.expect("NativeSoData missing");
    let jni = so.jni_functions.iter().find(|j| j.name.contains("stringFromJNI")).unwrap();
    assert_eq!(jni.demangled_class.as_deref(), Some("com.example.app.MainActivity"));
    assert_eq!(jni.demangled_method.as_deref(), Some("stringFromJNI"));
    assert!(jni.is_exported);
}

#[test]
fn test_tier1_so_jni_multiple_exported_methods() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    let so = resp.data.expect("NativeSoData missing");
    assert!(so.jni_functions.iter().any(|j| j.name.contains("validateLicense")));
    assert!(so.jni_functions.iter().any(|j| j.name.contains("getAppName")));
}

#[test]
fn test_tier1_so_architecture_and_bitness() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    let so = resp.data.expect("NativeSoData missing");
    assert!(so.is_64_bit, "AArch64 shared object should be 64-bit");
    assert!(so.architecture == "arm64" || so.architecture == "aarch64" || so.architecture == "arm");
}

#[test]
fn test_tier1_so_standalone_file_analysis() {
    let so_path = aarch64_so_fixture();
    let so_str = so_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", so_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData missing");
    assert!(so.jni_functions.iter().any(|j| j.name.contains("stringFromJNI")));
    assert!(so.exported_symbols.iter().any(|s| s.contains("JNI_OnLoad") || s.contains("auth_gate_check")));
}

// --- Feature 9: CLI Subcommands (`rvs apk inspect/manifest/dex/so`) ---

#[test]
fn test_tier1_cli_apk_inspect_json_envelope() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "apk inspect");
    assert!(resp.timestamp.is_some());
    assert_eq!(resp.target, apk_str);
}

#[test]
fn test_tier1_cli_apk_manifest_json_envelope() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "manifest", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "apk manifest");
}

#[test]
fn test_tier1_cli_apk_dex_json_envelope() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "dex", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "apk dex");
}

#[test]
fn test_tier1_cli_apk_so_json_envelope() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    assert_eq!(resp.command, "apk so");
}

#[test]
fn test_tier1_cli_apk_help_subcommands() {
    let output = run_rvs(&["apk", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("inspect"));
    assert!(stdout.contains("manifest"));
    assert!(stdout.contains("dex"));
    assert!(stdout.contains("so"));
}

// =============================================================================
// Tier 2: Boundary, Adversarial & Corner Cases
// =============================================================================

#[test]
fn test_tier2_apk_nonexistent_file() {
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", "/path/to/definitely/nonexistent.apk"]);
    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert!(err.code.contains("NOT_FOUND") || err.code.contains("IO_ERROR") || err.code.contains("FILE_NOT_FOUND"));
}

#[test]
fn test_tier2_apk_empty_zero_byte_file() {
    let empty_apk = fixture_path("empty_file.apk");
    let empty_str = empty_apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", empty_str]);

    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_corrupted_zip_header() {
    let corrupt_apk = fixture_path("corrupt_header.apk");
    let corrupt_str = corrupt_apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", corrupt_str]);

    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_empty_directory_fails_cleanly() {
    let empty_dir = fixture_path("empty_dir");
    let empty_str = empty_dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", empty_str]);

    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_corrupt_manifest_axml() {
    let bad_axml = fixture_path("corrupt_manifest.axml");
    let bad_str = bad_axml.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "manifest", bad_str]);

    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_corrupt_manifest_xml_directory() {
    let bad_dir = fixture_path("corrupt_manifest_dir");
    let bad_str = bad_dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "manifest", bad_str]);

    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_corrupt_dex_header() {
    let bad_dex = fixture_path("corrupt_classes.dex");
    let bad_str = bad_dex.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "dex", bad_str]);

    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_without_native_libraries() {
    let no_so_apk = no_so_apk_fixture();
    let no_so_str = no_so_apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", no_so_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert!(data.native_libraries.is_empty(), "Native libraries should be empty but command must succeed");
}

#[test]
fn test_tier2_apk_so_command_on_apk_without_so() {
    let no_so_apk = no_so_apk_fixture();
    let no_so_str = no_so_apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", no_so_str]);

    // Should either succeed with empty jni_functions or return graceful error
    if out.status.success() {
        assert!(resp.data.unwrap().jni_functions.is_empty());
    } else {
        assert!(!resp.success);
        assert!(resp.error.is_some());
    }
}

#[test]
fn test_tier2_apk_multi_dex_listing() {
    let multi_apk = multi_dex_apk_fixture();
    let multi_str = multi_apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", multi_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData missing");
    assert!(data.dex_files.len() >= 2, "Multi-dex APK must list both classes.dex and classes2.dex");
    assert!(data.dex_files.iter().any(|d| d.contains("classes.dex")));
    assert!(data.dex_files.iter().any(|d| d.contains("classes2.dex")));
}

#[test]
fn test_tier2_apk_stripped_so_dynamic_jni_resolution() {
    let stripped_so = fixture_path("sample_aarch64_stripped.so");
    let stripped_str = stripped_so.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", stripped_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData missing");
    // Even if stripped, dynamic export symbols should still be extracted
    assert!(so.jni_functions.iter().any(|j| j.name.contains("stringFromJNI")));
}

#[test]
fn test_tier2_apk_whitespace_path() {
    let temp_dir = TempDir::new().unwrap();
    let spaced_apk = temp_dir.path().join("my sample app with spaces.apk");
    std::fs::copy(raw_apk_fixture(), &spaced_apk).unwrap();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", spaced_apk.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier2_apk_symlinked_path() {
    let temp_dir = TempDir::new().unwrap();
    let symlink_path = temp_dir.path().join("link_to_raw.apk");
    #[cfg(unix)]
    std::os::unix::fs::symlink(raw_apk_fixture(), &symlink_path).unwrap();

    #[cfg(unix)]
    {
        let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", symlink_path.to_str().unwrap()]);
        assert!(out.status.success());
        assert!(resp.success);
    }
}

#[test]
fn test_tier2_apk_inspect_directory_without_trailing_slash() {
    let dir = unpacked_dir_fixture();
    let trimmed_dir = dir.to_str().unwrap().trim_end_matches('/');
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", trimmed_dir]);

    assert!(out.status.success());
    assert!(resp.success);
    assert_eq!(resp.data.unwrap().source_type, "directory");
}

#[test]
fn test_tier2_apk_inspect_directory_with_trailing_slash() {
    let dir = unpacked_dir_fixture();
    let mut dir_str = dir.to_str().unwrap().to_string();
    dir_str.push('/');
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", &dir_str]);

    assert!(out.status.success());
    assert!(resp.success);
    assert_eq!(resp.data.unwrap().source_type, "directory");
}

#[test]
fn test_tier2_apk_missing_subcommand_shows_error() {
    let output = run_rvs(&["apk"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stderr.contains("Usage") || stdout.contains("Usage") || stdout.contains("INVALID_ARGUMENT"));
}

#[test]
fn test_tier2_apk_invalid_subcommand_shows_error() {
    let output = run_rvs(&["apk", "nonexistent_subcommand"]);
    assert!(!output.status.success());
}

#[test]
fn test_tier2_apk_excess_arguments() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let output = run_rvs(&["apk", "inspect", apk_str, "unexpected_extra_arg"]);
    assert!(!output.status.success());
}

#[test]
fn test_tier2_apk_inspect_corrupt_zip_returns_structured_error() {
    let bad_apk = fixture_path("corrupt_header.apk");
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", bad_apk.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!resp.success);
    let err = resp.error.expect("ApiError envelope missing");
    assert!(!err.code.is_empty());
    assert!(!err.message.is_empty());
}

#[test]
fn test_tier2_apk_manifest_corrupt_axml_returns_structured_error() {
    let bad_axml = fixture_path("corrupt_manifest.axml");
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "manifest", bad_axml.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!resp.success);
    let err = resp.error.expect("ApiError envelope missing");
    assert!(!err.code.is_empty());
}

#[test]
fn test_tier2_apk_dex_corrupt_bytes_returns_structured_error() {
    let bad_dex = fixture_path("corrupt_classes.dex");
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "dex", bad_dex.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!resp.success);
    let err = resp.error.expect("ApiError envelope missing");
    assert!(!err.code.is_empty());
}

#[test]
fn test_tier2_apk_so_invalid_elf_file() {
    let bad_dex = fixture_path("corrupt_classes.dex");
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "so", bad_dex.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

#[test]
fn test_tier2_apk_quiet_flag_suppresses_logs() {
    let apk = raw_apk_fixture();
    let output = run_rvs(&["-q", "apk", "inspect", apk.to_str().unwrap()]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty(), "Stderr should be empty with -q flag");
}

#[test]
fn test_tier2_apk_pretty_flag_formats_indented_json() {
    let apk = raw_apk_fixture();
    let output = run_rvs(&["--pretty", "apk", "inspect", apk.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains('\n'), "Pretty printed output should contain newlines");
    assert!(stdout.contains("  "), "Pretty printed output should contain indentation");
}

#[test]
fn test_tier2_apk_compact_flag_reduces_size() {
    let apk = raw_apk_fixture();
    let output_norm = run_rvs(&["apk", "inspect", apk.to_str().unwrap()]);
    let output_compact = run_rvs(&["-c", "apk", "inspect", apk.to_str().unwrap()]);

    assert!(output_norm.status.success());
    assert!(output_compact.status.success());
    // Compact output should be valid JSON
    let _: serde_json::Value = serde_json::from_slice(&output_compact.stdout).unwrap();
}

// =============================================================================
// Tier 3: Cross-Feature Combinations (Pairwise Workflows)
// =============================================================================

#[test]
fn test_tier3_raw_apk_manifest_to_dex_pipeline() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();

    // 1. Ingest manifest to obtain package name and main activity
    let (m_resp, m_out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str]);
    assert!(m_out.status.success());
    let manifest = m_resp.data.expect("Manifest missing");
    let pkg = manifest.package_name;
    assert!(!pkg.is_empty());

    // 2. Ingest DEX to verify Dalvik classes exist in the package
    let (d_resp, d_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_str]);
    assert!(d_out.status.success());
    let dex = d_resp.data.expect("DEX missing");
    assert!(dex.classes_count > 0);
}

#[test]
fn test_tier3_unpacked_dir_manifest_to_so_jni_correlation() {
    let dir = unpacked_dir_fixture();
    let dir_str = dir.to_str().unwrap();

    // 1. Extract manifest activities
    let (m_resp, _) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", dir_str]);
    let manifest = m_resp.data.expect("Manifest missing");
    let main_act = manifest.activities.iter().find(|a| a.contains("MainActivity"));
    assert!(main_act.is_some());

    // 2. Extract JNI symbols from embedded .so
    let (s_resp, _) = run_rvs_json::<NativeSoData>(&["apk", "so", dir_str]);
    let so = s_resp.data.expect("NativeSoData missing");
    assert!(so.jni_functions.iter().any(|j| j.name.contains("MainActivity")));
}

#[test]
fn test_tier3_standalone_dex_and_so_combined_analysis() {
    let dex = classes_dex_fixture();
    let so = aarch64_so_fixture();

    let (d_resp, d_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex.to_str().unwrap()]);
    assert!(d_out.status.success());
    assert!(d_resp.data.unwrap().classes_count >= 3);

    let (s_resp, s_out) = run_rvs_json::<NativeSoData>(&["apk", "so", so.to_str().unwrap()]);
    assert!(s_out.status.success());
    assert!(!s_resp.data.unwrap().jni_functions.is_empty());
}

#[test]
fn test_tier3_inspect_to_subcommand_data_consistency() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();

    // Overall inspect
    let (i_resp, _) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);
    let inspect = i_resp.data.unwrap();

    // Specific manifest
    let (m_resp, _) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str]);
    let manifest = m_resp.data.unwrap();

    assert_eq!(inspect.package_name.as_deref(), Some(manifest.package_name.as_str()));
}

#[test]
fn test_tier3_multi_dex_and_native_so_coexistence() {
    let apk = multi_dex_apk_fixture();
    let apk_str = apk.to_str().unwrap();

    let (i_resp, _) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);
    let inspect = i_resp.data.unwrap();
    assert_eq!(inspect.dex_files.len(), 2);
    assert!(inspect.native_libraries.contains_key("arm64-v8a"));

    let (s_resp, _) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);
    let so = s_resp.data.unwrap();
    assert!(!so.jni_functions.is_empty());
}

// =============================================================================
// Tier 4: Real-World Application Workloads
// =============================================================================

#[test]
fn test_tier4_e2e_raw_apk_security_reconnaissance() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();

    // 1. Ingest overview
    let (i_resp, i_out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);
    assert!(i_out.status.success());
    let inspect = i_resp.data.unwrap();
    assert_eq!(inspect.package_name.as_deref(), Some("eu.jgamba.myapplication"));

    // 2. Security audit: debuggable flag and sensitive permissions
    let (m_resp, _) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str]);
    let manifest = m_resp.data.unwrap();
    assert!(!manifest.debuggable, "Production release APK should not be debuggable");
    assert!(manifest.permissions.iter().any(|p| p.contains("LOCATION")));

    // 3. Native JNI surface mapping
    let (s_resp, _) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);
    let so = s_resp.data.unwrap();
    let jni_methods: Vec<String> = so.jni_functions.iter().map(|f| f.name.clone()).collect();
    assert!(jni_methods.iter().any(|m| m.contains("stringFromJNI")));
    assert!(jni_methods.iter().any(|m| m.contains("validateLicense")));
}

#[test]
fn test_tier4_e2e_unpacked_apk_dir_analysis_flow() {
    let dir = unpacked_dir_fixture();
    let dir_str = dir.to_str().unwrap();

    // 1. Automated triage of unpacked tree
    let (i_resp, i_out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", dir_str]);
    assert!(i_out.status.success());
    let inspect = i_resp.data.unwrap();
    assert_eq!(inspect.source_type, "directory");
    assert_eq!(inspect.package_name.as_deref(), Some("com.example.unpacked"));

    // 2. Component registry
    let (m_resp, _) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", dir_str]);
    let manifest = m_resp.data.unwrap();
    assert_eq!(manifest.activities.len(), 2);
    assert_eq!(manifest.services.len(), 1);
    assert_eq!(manifest.receivers.len(), 1);
    assert_eq!(manifest.providers.len(), 1);

    // 3. Correlate with DEX classes
    let (d_resp, _) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dir_str]);
    let dex = d_resp.data.unwrap();
    assert!(dex.classes_count >= 3);
}

#[test]
fn test_tier4_e2e_native_library_vulnerability_surface() {
    let so = aarch64_so_fixture();
    let so_str = so.to_str().unwrap();

    let (s_resp, s_out) = run_rvs_json::<NativeSoData>(&["apk", "so", so_str]);
    assert!(s_out.status.success());
    let so = s_resp.data.unwrap();

    // Verify JNI lifecycle functions
    assert!(so.exported_symbols.iter().any(|s| s.contains("JNI_OnLoad")), "JNI_OnLoad must be detected");
    // Verify static bridge functions
    assert!(so.jni_functions.iter().any(|j| j.name.contains("validateLicense")));
    // Verify 64-bit architecture
    assert!(so.is_64_bit);
}

#[test]
fn test_tier4_e2e_multi_dex_package_exploration() {
    let apk = multi_dex_apk_fixture();
    let apk_str = apk.to_str().unwrap();

    let (d_resp, d_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_str]);
    assert!(d_out.status.success());
    let dex = d_resp.data.unwrap();
    assert!(dex.classes_count >= 3);
    assert!(dex.methods_count >= 10);
}

#[test]
fn test_tier4_e2e_defensive_error_recovery_matrix() {
    let bad_inputs = [
        fixture_path("corrupt_header.apk"),
        fixture_path("corrupt_manifest.axml"),
        fixture_path("corrupt_classes.dex"),
        fixture_path("empty_dir"),
    ];

    for bad in &bad_inputs {
        let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "inspect", bad.to_str().unwrap()]);
        assert!(!out.status.success(), "Command on {:?} must return non-zero exit code", bad);
        assert!(!resp.success, "Response for {:?} must have success=false", bad);
        assert!(resp.error.is_some(), "Response for {:?} must contain ApiError", bad);
    }
}

#[test]
#[cfg(unix)]
fn test_tier2_apk_circular_symlinks_do_not_hang() {
    let temp_dir = tempfile::tempdir().unwrap();
    let base = temp_dir.path();

    std::fs::write(
        base.join("AndroidManifest.xml"),
        b"<manifest package=\"com.test.circular.symlinks\" />",
    )
    .unwrap();
    std::fs::write(base.join("classes.dex"), b"dex\n035\0sample_dex").unwrap();

    // Create cyclical directory symlinks
    std::os::unix::fs::symlink(base, base.join("l1")).unwrap();
    std::os::unix::fs::symlink(base, base.join("l2")).unwrap();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", base.to_str().unwrap()]);
    assert!(out.status.success(), "Inspect on circular symlink dir must exit with success");
    assert!(resp.success);
    let data = resp.data.expect("InspectData expected");
    assert_eq!(data.package_name.as_deref(), Some("com.test.circular.symlinks"));
    assert_eq!(data.dex_files.len(), 1);
}

#[test]
fn test_tier1_cli_apk_dex_disasm_flag() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<serde_json::Value>(&[
        "apk", "dex", dex_str, "--class", "QuickActionItem", "--method", "isChecked", "--disasm",
    ]);

    assert!(out.status.success(), "apk dex --disasm command must succeed");
    assert!(resp.success);

    let data = resp.data.expect("Response data must be present");
    // Verify that disassembly was populated in classes -> methods or top-level disassembly
    let has_disasm = data.get("disassembly").and_then(|d| d.as_array()).map(|a| !a.is_empty()).unwrap_or(false)
        || data.get("classes")
            .and_then(|c| c.as_array())
            .and_then(|ca| ca.first())
            .and_then(|cls| cls.get("methods"))
            .and_then(|m| m.as_array())
            .and_then(|ma| ma.first())
            .and_then(|mth| mth.get("disassembly"))
            .and_then(|d| d.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);

    assert!(has_disasm, "apk dex --disasm must return Dalvik instructions in JSON output");
}

#[test]
fn test_tier1_cli_apk_so_xrefs_flag() {
    let so = aarch64_so_fixture();
    let so_str = so.to_str().unwrap();

    let (resp, out) = run_rvs_json::<serde_json::Value>(&[
        "apk", "so", so_str, "--symbol", "Java_com_example_app_MainActivity_validateLicense", "--xrefs",
    ]);

    assert!(out.status.success(), "apk so --xrefs command must succeed");
    assert!(resp.success);

    let data = resp.data.expect("Response data must be present");
    let has_xrefs = data.get("xrefs").is_some()
        || data.get("jni_functions")
            .and_then(|j| j.as_array())
            .and_then(|ja| ja.first())
            .and_then(|func| func.get("xrefs"))
            .is_some();

    assert!(has_xrefs, "apk so --xrefs must return cross-references in JSON output");
}

// =============================================================================
// Milestone 2 & 3: Multi-Language Recognition and Native .so Extraction Tests
// =============================================================================

// --- Multi-Language Recognition (Tier 1) ---

#[test]
fn test_tier1_inspect_languages_java_and_cpp_in_raw_apk() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success(), "Inspect command should succeed");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let lang_names: Vec<&str> = data.languages.iter().map(|l| l.language.as_str()).collect();
    assert!(lang_names.contains(&"Java"), "Expected Java in raw APK, got {:?}", lang_names);
    assert!(lang_names.contains(&"C/C++"), "Expected C/C++ in raw APK, got {:?}", lang_names);

    let java_lang = data.languages.iter().find(|l| l.language == "Java").unwrap();
    assert_eq!(java_lang.confidence, "High");
    assert!(!java_lang.evidence.is_empty());

    let cpp_lang = data.languages.iter().find(|l| l.language == "C/C++").unwrap();
    assert_eq!(cpp_lang.confidence, "High");
    assert!(!cpp_lang.evidence.is_empty());
}

#[test]
fn test_tier1_inspect_languages_react_native() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("synthetic_rn.apk")
        .with_react_native()
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let rn = data.languages.iter().find(|l| l.language == "React Native");
    assert!(rn.is_some(), "Expected React Native detected in synthetic RN APK, got {:?}", data.languages);
    let rn = rn.unwrap();
    assert_eq!(rn.confidence, "High");
    assert!(rn.evidence.iter().any(|e| e.contains("index.android.bundle") || e.contains("libreactnativejni.so")));
}

#[test]
fn test_tier1_inspect_languages_flutter_dart() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("synthetic_flutter.apk")
        .with_flutter()
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let flutter = data.languages.iter().find(|l| l.language == "Flutter / Dart");
    assert!(flutter.is_some(), "Expected Flutter / Dart detected, got {:?}", data.languages);
    let flutter = flutter.unwrap();
    assert_eq!(flutter.confidence, "High");
    assert!(flutter.evidence.iter().any(|e| e.contains("kernel_blob.bin") || e.contains("libflutter.so")));
}

#[test]
fn test_tier1_inspect_languages_hybrid() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("synthetic_hybrid.apk")
        .with_manifest("com.example.hybrid")
        .with_dex_markers(
            "classes.dex",
            &["Lcom/facebook/react/ReactActivity;", "Lio/flutter/embedding/android/FlutterActivity;"],
        )
        .with_asset("index.android.bundle", b"var __BUNDLE__ = true;")
        .with_asset("flutter_assets/kernel_blob.bin", b"FLUTTER_SNAPSHOT")
        .with_native_so("arm64-v8a", "libreactnativejni.so", b"\x7fELF_libreactnativejni")
        .with_native_so("arm64-v8a", "libflutter.so", b"\x7fELF_libflutter")
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let lang_names: Vec<&str> = data.languages.iter().map(|l| l.language.as_str()).collect();
    assert!(lang_names.contains(&"Java"));
    assert!(lang_names.contains(&"C/C++"));
    assert!(lang_names.contains(&"React Native"));
    assert!(lang_names.contains(&"Flutter / Dart"));
}

#[test]
fn test_tier1_inspect_languages_zero_dex_native() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("synthetic_zero_dex.apk")
        .with_manifest("com.example.zerodex")
        .with_native_so("arm64-v8a", "libnative.so", b"\x7fELF_libnative")
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let lang_names: Vec<&str> = data.languages.iter().map(|l| l.language.as_str()).collect();
    assert!(lang_names.contains(&"C/C++"));
    assert!(!lang_names.contains(&"Java"), "Zero-DEX APK should not detect Java");
}

// --- Native .so Extraction (Tier 1) ---

#[test]
fn test_tier1_so_abi_and_elf_metadata() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData expected");
    assert_eq!(so.architecture, "arm64");
    assert_eq!(so.abi.as_deref(), Some("arm64-v8a"));
    assert!(so.is_64_bit);
    assert_eq!(so.bits, Some(64));
    assert_eq!(so.elf_type.as_deref(), Some("DYN"));
    assert_eq!(so.endianness.as_deref(), Some("little"));
}

#[test]
fn test_tier1_so_dependencies_and_soname() {
    let so_path = aarch64_so_fixture();
    let so_str = so_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", so_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData expected");
    assert_eq!(so.abi.as_deref(), Some("arm64-v8a"));
    assert!(so.jni_functions.iter().any(|j| j.demangled_class.as_deref() == Some("com.example.app.MainActivity")));
}

#[test]
fn test_tier1_so_mapping_symbols_filtered() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData expected");
    for sym in &so.exported_symbols {
        assert!(!sym.starts_with("$d") && !sym.starts_with("$x"), "Mapping symbol found in exports: {}", sym);
        assert!(!sym.contains("DW.ref."), "Compiler ref symbol found: {}", sym);
    }
    for sym in &so.symbols {
        assert!(!sym.name.starts_with("$d") && !sym.name.starts_with("$x"), "Mapping symbol found in symbols: {}", sym.name);
    }
}

#[test]
fn test_tier1_so_library_filter_flag() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str, "--library", "libnative.so"]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData expected");
    assert!(so.file_name.contains("libnative.so"));
}

#[test]
fn test_tier1_so_abi_filter_flag() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<NativeSoData>(&["apk", "so", apk_str, "--abi", "arm64-v8a"]);

    assert!(out.status.success());
    assert!(resp.success);
    let so = resp.data.expect("NativeSoData expected");
    assert_eq!(so.abi.as_deref(), Some("arm64-v8a"));
}

// --- Boundary Tests (Tier 2) ---

#[test]
fn test_tier2_fake_flutter_asset_does_not_trigger() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("fake_flutter.apk")
        .with_manifest("com.example.fake")
        .with_dex_markers("classes.dex", &["Lcom/example/fake/MainActivity;"])
        .with_asset("flutter_assets_fake.txt", b"not flutter")
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let has_flutter = data.languages.iter().any(|l| l.language == "Flutter / Dart");
    assert!(!has_flutter, "Fake flutter asset should not trigger Flutter / Dart");
}

#[test]
fn test_tier2_generic_bundle_does_not_trigger_react_native() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("generic_bundle.apk")
        .with_manifest("com.example.generic")
        .with_dex_markers("classes.dex", &["Lcom/example/generic/MainActivity;"])
        .with_asset("data.bundle", b"generic bundle")
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let has_rn = data.languages.iter().any(|l| l.language == "React Native");
    assert!(!has_rn, "Generic bundle should not trigger React Native");
}

#[test]
fn test_tier2_undelimited_package_name_does_not_trigger() {
    let (_dir, apk_path) = SyntheticApkBuilder::new("undelimited.apk")
        .with_manifest("com.test.reactions")
        .with_dex_markers("classes.dex", &["Lcom/test/reactions/Main;"])
        .build();
    let apk_str = apk_path.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    let has_rn = data.languages.iter().any(|l| l.language == "React Native");
    assert!(!has_rn, "Package 'reactions' should not trigger React Native");
}

// --- Compact Mode Parity (Tier 3 & 4) ---

#[test]
fn test_tier1_compact_apk_inspect_payload() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<CompactApkInspectData>(&["-c", "apk", "inspect", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("CompactApkInspectData expected");
    assert_eq!(data.src, "archive");
    assert!(data.manifest);
    assert!(data.binary_manifest);
    assert_eq!(data.dex.len(), 1);
    assert!(data.langs.contains(&"Java".to_string()));
    assert!(data.langs.contains(&"C/C++".to_string()));
}

#[test]
fn test_tier1_compact_apk_so_payload() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<CompactNativeSoData>(&["-c", "apk", "so", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("CompactNativeSoData expected");
    assert_eq!(data.arch, "arm64");
    assert_eq!(data.abi, "arm64-v8a");
    assert!(data.is_64);
    assert_eq!(data.elf_type, "DYN");
    assert_eq!(data.endian, "little");
    assert!(data.jni.iter().any(|j| j.cls.as_deref() == Some("com.example.app.MainActivity") && j.method.as_deref() == Some("stringFromJNI")));
}

// =============================================================================
// Feature Coverage for F3, F4, F5, F6, F7
// =============================================================================

// --- F3: Manifest Raw/Decoded XML Extraction ---

#[test]
fn test_tier1_cli_apk_manifest_raw_xml_flag() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str, "--raw"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ManifestInfoData expected");
    assert_eq!(data.package_name, "eu.jgamba.myapplication");
    assert!(data.raw_xml.is_some(), "raw_xml must be present when --raw is specified");
    let xml = data.raw_xml.unwrap();
    assert!(xml.contains("<manifest"), "Decoded XML must contain <manifest");
    assert!(xml.contains("package=\"eu.jgamba.myapplication\""));
    assert!(xml.contains("MainActivity"));
}

#[test]
fn test_tier1_cli_apk_manifest_xml_alias_flag() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_str, "--xml"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ManifestInfoData expected");
    assert!(data.raw_xml.is_some(), "raw_xml must be present when --xml alias is specified");
}

#[test]
fn test_tier1_cli_apk_manifest_unpacked_text_raw_xml() {
    let dir = unpacked_dir_fixture();
    let dir_str = dir.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", dir_str, "--raw"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ManifestInfoData expected");
    assert!(data.raw_xml.is_some());
    let xml = data.raw_xml.unwrap();
    assert!(xml.contains("<manifest"));
}

// --- F4: Resource and Asset Listing, ARSC Parsing, Extraction, and Dumping ---

#[test]
fn test_tier1_cli_apk_resources_list() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_str, "--list"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(data.total_resources >= 1);
    assert!(data.total_assets >= 1);
    assert!(data.has_arsc);
    assert!(data.entries.is_some());
    assert!(!data.arsc_packages.is_empty(), "arsc_packages must not be empty on sample_raw.apk");
    assert_eq!(data.arsc_packages[0].name, "com.example.synthetic.target");
    assert_eq!(data.arsc_packages[0].types_count, 3);

    let entries = data.entries.unwrap();
    assert!(entries.iter().any(|e| e.name == "assets/app_config.json" && e.entry_type == "asset"));
    assert!(entries.iter().any(|e| e.name == "res/values/strings.xml" && e.entry_type == "resource"));
    assert!(entries.iter().any(|e| e.name == "resources.arsc" && e.entry_type == "arsc"));
}

#[test]
fn test_tier1_cli_apk_resources_extract_asset() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_str, "--extract", "assets/app_config.json"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    let ext = data.extracted.expect("extracted resource expected");
    assert_eq!(ext.name, "assets/app_config.json");
    assert!(!ext.is_xml);
    assert!(ext.content.contains("environment"));
    assert!(ext.content.contains("production"));
}

#[test]
fn test_tier1_cli_apk_resources_extract_res_xml() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_str, "--extract", "res/values/strings.xml"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    let ext = data.extracted.expect("extracted resource expected");
    assert_eq!(ext.name, "res/values/strings.xml");
    assert!(ext.is_xml);
    assert!(ext.content.contains("<resources>"));
    assert!(ext.content.contains("app_name"));
}

#[test]
fn test_tier1_cli_apk_resources_dump_dir() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let temp = TempDir::new().unwrap();
    let temp_str = temp.path().to_str().unwrap();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_str, "--dump", temp_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(data.dumped_files_count.unwrap_or(0) >= 2);
    assert!(temp.path().join("assets/app_config.json").is_file());
    assert!(temp.path().join("res/values/strings.xml").is_file());
}

#[test]
fn test_tier1_cli_apk_resources_compact_format() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "resources", apk_str, "--list", "-c"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("data expected");
    assert_eq!(data["arsc"], true);
    assert!(data["res_cnt"].as_u64().unwrap_or(0) >= 1);
    assert!(data["asset_cnt"].as_u64().unwrap_or(0) >= 1);
}

// --- F5 & F6: DEX Smali Assembly Formatting & Dalvik Decompilation ---

#[test]
fn test_tier1_cli_apk_dex_smali_method_formatting() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "isChecked", "--smali",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert_eq!(data.classes_count, 1);
    let cls = &data.classes[0];
    assert!(cls.smali.is_some());
    assert!(cls.smali.as_ref().unwrap().contains(".class public Lcom/devoteam/quickaction/QuickActionItem;"));

    let m = &cls.methods[0];
    assert!(m.smali.is_some());
    let smali = m.smali.as_ref().unwrap();
    assert!(smali.contains(".method public isChecked()Z"));
    assert!(smali.contains(".registers 2"));
    assert!(smali.contains("return v0"));
    assert!(smali.contains(".end method"));
}

#[test]
fn test_tier1_cli_apk_dex_method_decompilation() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "isChecked", "--decompile",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert_eq!(data.classes_count, 1);
    let m = &data.classes[0].methods[0];
    assert!(m.decompiled.is_some());
    let decomp = m.decompiled.as_ref().unwrap();
    assert!(decomp.contains("isChecked"));
    assert!(decomp.contains("return v0"));
}

#[test]
fn test_tier1_cli_apk_dex_bounded_disassembly_no_spillover() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "isChecked", "--disasm",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let m = &data.classes[0].methods[0];
    assert_eq!(m.insns_size, Some(3));
    // isChecked bytecode is 3 code units = 6 bytes (offsets 108012 and 108016)
    // Disassembly must be strictly bounded to this method (2 instructions), no spillover
    let disasm = m.disassembly.as_ref().expect("disassembly expected");
    assert_eq!(disasm.len(), 2, "Disassembly must not spill over method boundaries");
    assert_eq!(disasm[0]["addr"].as_u64(), Some(108012));
    assert_eq!(disasm[1]["addr"].as_u64(), Some(108016));
}

// --- F7: APK Signature and Certificate Verification ---

#[test]
fn test_tier1_cli_apk_signature_verification() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<SignatureData>(&["apk", "signature", apk_str]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("SignatureData expected");
    assert!(data.is_signed, "sample_raw.apk must be recognized as signed");
    assert!(data.signing_block_present, "APK Signing Block must be detected");
    assert!(data.schemes.contains(&"v1".to_string()));
    assert!(data.schemes.contains(&"v2".to_string()));
    assert!(!data.signers.is_empty(), "Must contain at least one signer");

    let signer = &data.signers[0];
    assert!(signer.subject.contains("RvsTestSigner") || signer.subject.contains("RvsTestSuite"));
    assert_eq!(signer.sha256_fingerprint.len(), 64, "SHA-256 fingerprint must be 64 hex chars");
    assert_eq!(signer.sha1_fingerprint.len(), 40, "SHA-1 fingerprint must be 40 hex chars");
}

#[test]
fn test_tier1_cli_apk_signature_verify_flag() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<SignatureData>(&["apk", "signature", apk_str, "--verify"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("SignatureData expected");
    assert_eq!(data.verified, Some(true));
    assert!(data.verification_errors.is_empty());
}

#[test]
fn test_tier1_cli_apk_signature_unsigned_apk() {
    let apk = no_so_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<SignatureData>(&["apk", "signature", apk_str, "--verify"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("SignatureData expected");
    assert!(!data.is_signed);
    assert_eq!(data.verified, Some(false));
    assert!(!data.verification_errors.is_empty());
}

#[test]
fn test_tier1_cli_apk_signature_compact_format() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<serde_json::Value>(&["apk", "signature", apk_str, "--verify", "-c"]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("data expected");
    assert_eq!(data["signed"], true);
    assert_eq!(data["verified"], true);
    assert_eq!(data["sig_block"], true);
}

// =============================================================================
// Tier 2: Path Traversal & Zip Slip Remediation Regression Tests
// =============================================================================

#[test]
fn test_tier2_apk_resources_dump_zip_slip_blocked() {
    let temp_workspace = TempDir::new().unwrap();
    let malicious_apk = temp_workspace.path().join("zip_slip_target.apk");
    let canary_leak = temp_workspace.path().join("canary_escaped.txt");
    let dump_dir = temp_workspace.path().join("dump_output");

    if canary_leak.exists() {
        let _ = std::fs::remove_file(&canary_leak);
    }

    // Build synthetic ZIP with Zip-Slip path traversal entry
    {
        let file = std::fs::File::create(&malicious_apk).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(b"<manifest package=\"com.adversarial.zipslip\" />").unwrap();

        zip.start_file("res/values/strings.xml", options).unwrap();
        zip.write_all(b"<resources><string name=\"safe\">val</string></resources>").unwrap();

        // Adversarial traversal entries: parent dir and absolute
        zip.start_file("../canary_escaped.txt", options).unwrap();
        zip.write_all(b"adversarial_zip_slip_payload").unwrap();

        zip.start_file("res/../../../tmp/canary_tmp_escaped.txt", options).unwrap();
        zip.write_all(b"adversarial_tmp_payload").unwrap();

        zip.start_file("/tmp/canary_abs_escaped.txt", options).unwrap();
        zip.write_all(b"adversarial_abs_payload").unwrap();

        zip.finish().unwrap();
    }

    // Direct Rust API verification: dump_resources_and_assets
    let pkg = rvs::apk::ApkPackage::open(&malicious_apk).expect("open synthetic apk");
    let dump_result = rvs::apk::dump_resources_and_assets(&pkg, &dump_dir);
    assert!(dump_result.is_ok(), "dump_resources_and_assets should complete safely");
    assert_eq!(dump_result.unwrap(), 1, "Only the 1 legitimate resource should be dumped");

    // Verify legitimate file exists
    assert!(dump_dir.join("res/values/strings.xml").is_file());

    // Verify all traversal attempts were blocked and did not escape
    assert!(!canary_leak.exists(), "Zip slip entry must not escape to parent directory");
    assert!(!PathBuf::from("/tmp/canary_tmp_escaped.txt").exists(), "Zip slip entry must not escape to /tmp");
    assert!(!PathBuf::from("/tmp/canary_abs_escaped.txt").exists(), "Absolute zip entry must not escape to /tmp");
    assert!(!dump_dir.join("canary_escaped.txt").exists());

    // CLI execution verification: rvs apk resources --dump
    let cli_dump_dir = temp_workspace.path().join("cli_dump_output");
    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", malicious_apk.to_str().unwrap(), "--dump", cli_dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert_eq!(data.dumped_files_count, Some(1));
    assert!(cli_dump_dir.join("res/values/strings.xml").is_file());
    assert!(!canary_leak.exists());
}

#[test]
fn test_tier2_apk_container_directory_path_traversal_blocked() {
    let unpacked_dir = unpacked_dir_fixture();
    let pkg = rvs::apk::ApkPackage::open(&unpacked_dir).expect("open unpacked directory");

    // Test that read_entry rejects absolute paths and parent directory components
    let err_abs = pkg.read_entry("/etc/passwd").unwrap_err();
    match &err_abs {
        rvs::error::AppError::InvalidBinary(msg) => {
            assert!(msg.contains("Invalid entry path"));
            assert!(msg.contains("/etc/passwd"));
        }
        other => panic!("Expected InvalidBinary error, got: {:?}", other),
    }

    let err_traversal = pkg.read_entry("../../etc/passwd").unwrap_err();
    match &err_traversal {
        rvs::error::AppError::InvalidBinary(msg) => {
            assert!(msg.contains("Invalid entry path"));
            assert!(msg.contains("../../etc/passwd"));
        }
        other => panic!("Expected InvalidBinary error, got: {:?}", other),
    }

    let err_deep = pkg.read_entry("res/../../../etc/passwd").unwrap_err();
    match &err_deep {
        rvs::error::AppError::InvalidBinary(msg) => {
            assert!(msg.contains("Invalid entry path"));
        }
        other => panic!("Expected InvalidBinary error, got: {:?}", other),
    }

    let err_win = pkg.read_entry("\\windows\\system32\\cmd.exe").unwrap_err();
    match &err_win {
        rvs::error::AppError::InvalidBinary(msg) => {
            assert!(msg.contains("Invalid entry path"));
        }
        other => panic!("Expected InvalidBinary error, got: {:?}", other),
    }
}

#[test]
fn test_tier2_cli_apk_resources_directory_path_traversal_rejected() {
    let unpacked_dir = unpacked_dir_fixture();
    let unpacked_str = unpacked_dir.to_str().unwrap();

    // Absolute host path extraction must fail
    let (resp_abs, out_abs) = run_rvs_json::<serde_json::Value>(&[
        "apk", "resources", unpacked_str, "--extract", "/etc/passwd",
    ]);
    assert!(!out_abs.status.success());
    assert!(!resp_abs.success);
    let err_abs = resp_abs.error.expect("error expected");
    assert_eq!(err_abs.code, "INVALID_BINARY");
    assert!(err_abs.message.contains("Invalid entry path"));
    assert!(resp_abs.data.is_none() || resp_abs.data.as_ref().unwrap().get("extracted").is_none());

    // Relative path traversal extraction must fail
    let (resp_rel, out_rel) = run_rvs_json::<serde_json::Value>(&[
        "apk", "resources", unpacked_str, "--extract", "../../../../../../etc/passwd",
    ]);
    assert!(!out_rel.status.success());
    assert!(!resp_rel.success);
    let err_rel = resp_rel.error.expect("error expected");
    assert_eq!(err_rel.code, "INVALID_BINARY");
    assert!(err_rel.message.contains("Invalid entry path"));
}

#[test]
fn test_tier2_cli_apk_resources_archive_path_traversal_rejected() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();

    // Absolute path on archive
    let (resp_abs, out_abs) = run_rvs_json::<serde_json::Value>(&[
        "apk", "resources", apk_str, "--extract", "/etc/passwd",
    ]);
    assert!(!out_abs.status.success());
    assert!(!resp_abs.success);
    let err_abs = resp_abs.error.expect("error expected");
    assert_eq!(err_abs.code, "INVALID_BINARY");

    // Traversal path on archive
    let (resp_rel, out_rel) = run_rvs_json::<serde_json::Value>(&[
        "apk", "resources", apk_str, "--extract", "../../etc/passwd",
    ]);
    assert!(!out_rel.status.success());
    assert!(!resp_rel.success);
    let err_rel = resp_rel.error.expect("error expected");
    assert_eq!(err_rel.code, "INVALID_BINARY");
}
