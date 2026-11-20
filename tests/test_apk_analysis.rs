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


// =============================================================================
// Resilient Differential & Anti-Analysis Test Suites (R1 - R6)
// =============================================================================

// =============================================================================
// Tier 1: Feature Coverage (Resilience Primitives & Happy Paths)
// =============================================================================

#[test]
fn test_tier1_resilient_sanitized_identifier_standard_ascii() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_str]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    assert_eq!(data.package_name.as_deref(), Some("eu.jgamba.myapplication"));
    let pkg = data.package_name.as_deref().unwrap_or("");
    assert!(!pkg.contains('\x1b'));
    assert!(!pkg.contains('\u{202E}'));
}

#[test]
fn test_tier1_resilient_mutf8_ascii_strings() {
    let raw_strings: [&[u8]; 3] = [b"com.example.test", b"MainActivity", b"onCreate"];
    let dex_bytes = synthesize_mutf8_dex(&raw_strings);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("classes.dex");
    std::fs::write(&dex_path, &dex_bytes).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert!(data.strings_count >= 3);
    if let Some(ref strs) = data.strings {
        assert!(strs.iter().any(|s| s == "com.example.test"));
        assert!(strs.iter().any(|s| s == "MainActivity"));
    }
}

#[test]
fn test_tier1_resilient_utf16le_standard_strings() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, false, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("standard_arsc.apk")
        .with_manifest("com.example.arsc")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(!data.arsc_packages.is_empty());
    assert!(data.arsc_packages.iter().any(|p| p.name == "com.example.synthetic.target"));
}

#[test]
fn test_tier1_resilient_andresguard_resource_structure() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("andresguard_tier1.apk")
        .with_andresguard_structure(0x7f020000, "r/d/a.png", b"\x89PNG\r\n\x1a\nfake_png")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap(), "--list"]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    let entries = data.entries.expect("ResourcesData entries expected with --list");
    assert!(entries.iter().any(|r| r.name.starts_with("r/")));
}

#[test]
fn test_tier1_resilient_reschunk_standard_header() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, false, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("reschunk_standard_header.apk")
        .with_manifest("com.example.synthetic.target")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Standard ARSC chunk header parsing must succeed");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(data.has_arsc);
    assert!(!data.arsc_packages.is_empty(), "ARSC packages should be parsed from standard header");
    assert!(data.arsc_packages.iter().any(|p| p.name == "com.example.synthetic.target"));
}

#[test]
fn test_tier1_resilient_dalvik_standard_disassembly() {
    let dex = classes_dex_fixture();
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex.to_str().unwrap(), "--class", "Lcom/devoteam/quickaction/QuickActionItem;", "--disasm",
    ]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert!(!data.classes.is_empty());
}

// =============================================================================
// Tier 2: Boundary & Corner Cases (R1 - R6)
// =============================================================================

// --- R1: Terminal and Unicode Sanitization ---

#[test]
fn test_tier2_apk_sanitize_ansi_csi_color_stripping() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("ansi_csi_target.apk")
        .with_manifest(adversarial_ansi_string())
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    let raw_stdout = String::from_utf8_lossy(&out.stdout);
    let raw_stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!raw_stdout.contains("\x1b["), "Stdout must not leak raw ANSI CSI escape sequences");
    assert!(!raw_stderr.contains("\x1b["), "Stderr must not leak raw ANSI CSI escape sequences");
    assert!(resp.success);
    if let Some(data) = resp.data {
        let pkg = data.package_name.as_deref().unwrap_or("");
        assert!(!pkg.contains("\x1b[31;1m"));
        assert!(!pkg.contains("\x1b[0m"));
        assert!(pkg.contains("com.evil.malicious"));
    }
}

#[test]
fn test_tier2_apk_sanitize_ansi_osc_window_title_stripping() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("ansi_osc_target.apk")
        .with_manifest(adversarial_osc_title_string())
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    let raw_stdout = String::from_utf8_lossy(&out.stdout);

    assert!(!raw_stdout.contains("\x1b]0;"), "Stdout must not contain OSC title hijack");
    assert!(!raw_stdout.contains('\x07'), "Stdout must not contain BEL character");
    assert!(resp.success);
    if let Some(data) = resp.data {
        let pkg = data.package_name.as_deref().unwrap_or("");
        assert!(!pkg.contains("\x1b]0;"));
        assert!(pkg.contains("CleanTarget"));
    }
}

#[test]
fn test_tier2_apk_sanitize_bidi_right_to_left_override_neutralized() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("bidi_target.apk")
        .with_manifest(adversarial_bidi_string())
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    let raw_stdout = String::from_utf8_lossy(&out.stdout);

    assert!(!raw_stdout.contains('\u{202E}'), "Stdout must neutralize Right-to-Left Override (U+202E)");
    assert!(resp.success);
    if let Some(data) = resp.data {
        let pkg = data.package_name.as_deref().unwrap_or("");
        assert!(!pkg.contains('\u{202E}'));
    }
}

#[test]
fn test_tier2_apk_sanitize_zalgo_combining_characters_clamped() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("zalgo_target.apk")
        .with_manifest(adversarial_zalgo_string())
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    if let Some(data) = resp.data {
        let pkg = data.package_name.as_deref().unwrap_or("");
        let mut combining_count = 0;
        for c in pkg.chars() {
            if ('\u{0300}'..='\u{036F}').contains(&c) {
                combining_count += 1;
            }
        }
        assert!(combining_count <= 2, "Zalgo diacritics must be clamped to threshold <= 2 per glyph; got {}", combining_count);
    }
}

#[test]
fn test_tier2_apk_sanitize_c0_controls_and_newlines_cleaned() {
    let bad_pkg = "com.adversarial.app\nInjectedHeader: value\r\x08\x07";
    let (_temp, apk_path) = SyntheticApkBuilder::new("c0_controls.apk")
        .with_manifest(bad_pkg)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(resp.success);
    let raw_stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!raw_stdout.contains('\x08'), "Backspace control must be sanitized");
    assert!(!raw_stdout.contains('\x07'), "BEL control must be sanitized");
}

// --- R2: Resilient String Decoding (MUTF-8 and UTF-16LE) ---

#[test]
fn test_tier2_mutf8_two_byte_null_handling() {
    let mut null_str = b"prefix_".to_vec();
    null_str.extend_from_slice(mutf8_two_byte_null());
    null_str.extend_from_slice(b"_suffix");

    let dex_bytes = synthesize_mutf8_dex(&[&null_str]);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("mutf8_null.dex");
    std::fs::write(&dex_path, &dex_bytes).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    if let Some(ref strs) = data.strings {
        assert!(strs.iter().any(|s| s.contains("prefix_") && s.contains("_suffix")));
    }
}

#[test]
fn test_tier2_mutf8_six_byte_surrogate_pair_recombination() {
    let mut surrogate_str = b"deseret_".to_vec();
    surrogate_str.extend_from_slice(mutf8_surrogate_pair());
    surrogate_str.extend_from_slice(b"_end");

    let dex_bytes = synthesize_mutf8_dex(&[&surrogate_str]);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("mutf8_surrogate.dex");
    std::fs::write(&dex_path, &dex_bytes).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let strs = data.strings.expect("DexAnalysisData strings expected");
    assert!(strs.iter().any(|s| s.contains('𐐀')), "MUTF-8 surrogate pair must recombine to U+10400 ('𐐀')");
}

#[test]
fn test_tier2_mutf8_unpaired_lone_surrogate_safe_replacement() {
    let mut lone_str = b"lone_".to_vec();
    lone_str.extend_from_slice(mutf8_lone_high_surrogate());
    lone_str.extend_from_slice(b"_surrogate");

    let dex_bytes = synthesize_mutf8_dex(&[&lone_str]);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("mutf8_lone.dex");
    std::fs::write(&dex_path, &dex_bytes).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let strs = data.strings.expect("DexAnalysisData strings expected");
    assert!(strs.iter().any(|s| s.contains('\u{FFFD}')), "MUTF-8 lone surrogate must be replaced with U+FFFD");
}

#[test]
fn test_tier2_utf16le_unpaired_surrogates_in_arsc() {
    let arsc_bytes = synthesize_utf16_surrogate_arsc_bytes();
    let (_temp, apk_path) = SyntheticApkBuilder::new("arsc_unpaired.apk")
        .with_manifest("com.example.unpaired")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(!data.arsc_packages.is_empty());
}

#[test]
fn test_tier2_utf16le_mixed_surrogate_and_ascii_stream() {
    let raw = utf16le_unpaired_low_surrogate();
    let decoded = rvs::decode_utf16le_lossy(raw);
    assert_eq!(decoded, "\u{FFFD}B");

    let arsc_bytes = synthesize_utf16_surrogate_arsc_bytes();
    let (_temp, apk_path) = SyntheticApkBuilder::new("utf16_mixed_surrogate.apk")
        .with_manifest("com.example.surrogate")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap(), "--list"]);
    assert!(out.status.success(), "Mixed surrogate stream in ARSC must not crash resources subcommand");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(data.has_arsc);
}

// --- R3: ZIP Fake Encryption & Path Traversal ---

#[test]
fn test_tier2_apk_fake_encryption_lfh_bit0() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("fake_enc_lfh.apk")
        .with_manifest("com.example.fake.lfh")
        .with_fake_encryption(true, false)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "APK inspect must tolerate fake encryption in LFH");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    assert_eq!(data.package_name.as_deref(), Some("com.example.fake.lfh"));
}

#[test]
fn test_tier2_apk_fake_encryption_cd_bit0() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("fake_enc_cd.apk")
        .with_manifest("com.example.fake.cd")
        .with_fake_encryption(false, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "APK inspect must tolerate fake encryption in CD");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    assert_eq!(data.package_name.as_deref(), Some("com.example.fake.cd"));
}

#[test]
fn test_tier2_apk_fake_encryption_both_lfh_and_cd_bit0() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("fake_enc_both.apk")
        .with_manifest("com.example.fake.both")
        .with_dex_markers("classes.dex", &["Lcom/example/fake/Main;"])
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "APK inspect must tolerate fake encryption in both LFH and CD");
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    assert_eq!(data.package_name.as_deref(), Some("com.example.fake.both"));
    assert!(!data.dex_files.is_empty());
}

#[test]
fn test_tier2_zip_path_traversal_double_dot_blocked() {
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("dump_output");
    let canary_leak = temp_workspace.path().join("canary_escaped.txt");

    let (_temp, apk_path) = SyntheticApkBuilder::new("path_traversal.apk")
        .with_manifest("com.example.traversal")
        .with_file("res/values/strings.xml", b"<resources/>")
        .with_path_traversal_entry("../../canary_escaped.txt", b"evil_payload")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--dump", dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    assert!(!canary_leak.exists(), "Traversal entry must never escape to parent directory");
}

#[test]
fn test_tier2_zip_os_reserved_characters_and_devices() {
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("reserved_dump");

    let (_temp, apk_path) = SyntheticApkBuilder::new("reserved_names.apk")
        .with_manifest("com.example.reserved")
        .with_file("assets/CON.txt", b"windows_reserved_con")
        .with_file("assets/AUX.json", b"windows_reserved_aux")
        .with_file("assets/NUL.bin", b"windows_reserved_nul")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--dump", dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    assert!(dump_dir.exists(), "Dump directory must be created");
    // Windows reserved device names (CON, AUX, NUL) must be safely stored (e.g. sanitized as _CON.txt or safely created)
    let con_safe = dump_dir.join("assets/_CON.txt").is_file() || dump_dir.join("assets/CON.txt").is_file();
    assert!(con_safe, "Reserved device name 'CON.txt' must be safely dumped in output directory");
}

// --- R4: ResChunk Header and Table Resilience ---

#[test]
fn test_tier2_reschunk_padded_header_size_0x1c() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, false, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("padded_header.apk")
        .with_manifest("com.example.padded")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Padded ResChunk headerSize must be parsed dynamically");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(!data.arsc_packages.is_empty());
}

#[test]
fn test_tier2_reschunk_unknown_chunk_types_0x0000_skipped() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, true, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("unknown_chunks.apk")
        .with_manifest("com.example.unknown")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Unknown chunk types (0x0000, 0xFFFF) must be skipped gracefully");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(!data.arsc_packages.is_empty());
}

#[test]
fn test_tier2_reschunk_unknown_chunk_types_0xffff_skipped() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, true, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("unknown_chunks_ffff.apk")
        .with_manifest("com.example.unknown.ffff")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Unknown chunk type 0xFFFF must be skipped gracefully");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(!data.arsc_packages.is_empty(), "Subsequent packages must be parsed after skipping 0xFFFF");
}

#[test]
fn test_tier2_reschunk_arbitrary_unknown_chunks_skipped() {
    let base_arsc = synthesize_resilient_arsc_bytes(false, false, false);
    // Base ARSC layout: table header (12 bytes), global string pool, package chunk
    // Global string pool chunk size at offset 16..20
    let global_pool_size = u32::from_le_bytes([
        base_arsc[16],
        base_arsc[17],
        base_arsc[18],
        base_arsc[19],
    ]) as usize;
    let pkg_offset = 12 + global_pool_size;
    assert!(pkg_offset <= base_arsc.len());
    assert_eq!(&base_arsc[pkg_offset..pkg_offset + 2], &0x0200u16.to_le_bytes());

    // Inject sequential arbitrary unknown chunks (10x 0x1234 and 10x 0xABCD)
    let mut unknown_chunks = Vec::new();
    for _ in 0..10 {
        // chunk 0x1234: header_size 8, total size 16, payload 8 bytes
        unknown_chunks.extend_from_slice(&0x1234u16.to_le_bytes());
        unknown_chunks.extend_from_slice(&8u16.to_le_bytes());
        unknown_chunks.extend_from_slice(&16u32.to_le_bytes());
        unknown_chunks.extend_from_slice(&[0x42u8; 8]);
    }
    for _ in 0..10 {
        // chunk 0xABCD: header_size 8, total size 16, payload 8 bytes
        unknown_chunks.extend_from_slice(&0xABCDu16.to_le_bytes());
        unknown_chunks.extend_from_slice(&8u16.to_le_bytes());
        unknown_chunks.extend_from_slice(&16u32.to_le_bytes());
        unknown_chunks.extend_from_slice(&[0xDEu8; 8]);
    }

    let new_total = (base_arsc.len() + unknown_chunks.len()) as u32;
    let mut arsc_bytes = Vec::with_capacity(new_total as usize);
    // Table header with updated total size
    arsc_bytes.extend_from_slice(&base_arsc[0..4]);
    arsc_bytes.extend_from_slice(&new_total.to_le_bytes());
    arsc_bytes.extend_from_slice(&base_arsc[8..12]);
    // Global string pool
    arsc_bytes.extend_from_slice(&base_arsc[12..pkg_offset]);
    // Intervening sequential arbitrary unknown chunks
    arsc_bytes.extend_from_slice(&unknown_chunks);
    // Genuine package chunk
    arsc_bytes.extend_from_slice(&base_arsc[pkg_offset..]);

    let (_temp, apk_path) = SyntheticApkBuilder::new("arbitrary_unknown_chunks.apk")
        .with_manifest("com.example.arbitrary.unknown")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Arbitrary unknown chunks (0x1234, 0xABCD) must be skipped cleanly");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(!data.arsc_packages.is_empty(), "Subsequent packages must be parsed after skipping arbitrary unknown chunks");
    assert_eq!(data.arsc_packages[0].name, "com.example.synthetic.target");
    assert_eq!(data.arsc_packages[0].id, 0x7F);
}

#[test]
fn test_tier2_reschunk_string_pool_anomalous_string_count_clamped() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, false, true);
    let (_temp, apk_path) = SyntheticApkBuilder::new("corrupt_pool.apk")
        .with_manifest("com.example.corrupt.pool")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Anomalous string pool count must not crash parser");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(data.has_arsc);
}

#[test]
fn test_tier2_reschunk_string_pool_oob_offset_clamped() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, false, true);
    let (_temp, apk_path) = SyntheticApkBuilder::new("oob_offset_pool.apk")
        .with_manifest("com.example.oob.pool")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Out-of-bounds string offset (0x7FFFFFFF) must be clamped safely without panic");
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    assert!(data.has_arsc);
}

// --- R5: Dalvik / DEX Parser Dead-Code and Debug Info Resilience ---

#[test]
fn test_tier2_dalvik_dead_code_invalid_opcodes_after_return() {
    let dead_dex = synthesize_dead_code_dex(&[0xff, 0xff, 0xef, 0x00], false);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("dead_code.dex");
    std::fs::write(&dex_path, &dead_dex).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success(), "DEX parsing must succeed despite dead code invalid opcodes");
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert_eq!(data.classes_count, 323);
}

#[test]
fn test_tier2_dalvik_dead_code_after_unconditional_goto() {
    let dead_dex = synthesize_dead_code_dex(&[0x28, 0x00, 0x3e, 0x00], false);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("goto_dead.dex");
    std::fs::write(&dex_path, &dead_dex).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier2_dalvik_corrupted_debug_info_stream_graceful() {
    let corrupt_dex = synthesize_dead_code_dex(&[0x0e, 0x00], true);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("corrupt_debug.dex");
    std::fs::write(&dex_path, &corrupt_dex).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success(), "Corrupted debug_info_item must not abort DEX class parsing");
    assert!(resp.success);
}

#[test]
fn test_tier2_dalvik_debug_info_missing_end_sequence() {
    let dead_dex = synthesize_dead_code_dex(&[0x0e, 0x00, 0x01, 0x05], true);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("truncated_debug.dex");
    std::fs::write(&dex_path, &dead_dex).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier2_dalvik_mixed_valid_and_dead_code_blocks() {
    let dead_dex = synthesize_dead_code_dex(&[0xff, 0xfe, 0xfd, 0xfc], false);
    let temp_dir = TempDir::new().unwrap();
    let dex_path = temp_dir.path().join("mixed_blocks.dex");
    std::fs::write(&dex_path, &dead_dex).unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", dex_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

// --- R6: Anti-AndResGuard Compatibility ---

#[test]
fn test_tier2_andresguard_r_directory_resource_discovery() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("andresguard_r.apk")
        .with_manifest("com.example.andresguard.app")
        .with_file("r/d/a.png", b"\x89PNG\r\n\x1a\n")
        .with_file("r/l/b.xml", b"<layout/>")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap(), "--list"]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    let entries = data.entries.expect("ResourcesData entries expected with --list");
    assert!(entries.iter().any(|r| r.name == "r/d/a.png"));
    assert!(entries.iter().any(|r| r.name == "r/l/b.xml"));
}

#[test]
fn test_tier2_andresguard_obfuscated_resource_extraction() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("andresguard_extract.apk")
        .with_manifest("com.example.andresguard.extract")
        .with_file("r/d/icon.png", b"fake_png_icon_data")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--extract", "r/d/icon.png",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier2_andresguard_dump_resources_includes_r_directory() {
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("andresguard_dump");

    let (_temp, apk_path) = SyntheticApkBuilder::new("andresguard_dump.apk")
        .with_manifest("com.example.andresguard.dump")
        .with_file("r/a/a.png", b"icon_a")
        .with_file("r/a/b.png", b"icon_b")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--dump", dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    assert!(dump_dir.join("r/a/a.png").is_file());
    assert!(dump_dir.join("r/a/b.png").is_file());
}

#[test]
fn test_tier2_andresguard_short_single_letter_names_preserved() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, false, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("short_names.apk")
        .with_manifest("com.example.short")
        .with_file("r/d/a.png", b"\x89PNG\r\n\x1a\n")
        .with_file("r/l/b.xml", b"<layout/>")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap(), "--list"]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ResourcesData expected");
    let entries = data.entries.expect("ResourcesData entries expected with --list");
    assert!(entries.iter().any(|r| r.name == "r/d/a.png"), "Short single-letter name 'r/d/a.png' must be preserved");
    assert!(entries.iter().any(|r| r.name == "r/l/b.xml"), "Short single-letter name 'r/l/b.xml' must be preserved");
}

#[test]
fn test_tier2_andresguard_7zip_stored_arsc_compatibility() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(false, false, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("sevenzip_stored.apk")
        .with_manifest("com.example.sevenzip")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

// =============================================================================
// Tier 3: Cross-Feature Combinations (Pairwise & Multi-Interaction)
// =============================================================================

#[test]
fn test_tier3_combo_fake_encryption_and_andresguard_r_dirs() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_enc_andresguard.apk")
        .with_manifest("com.example.combo.enc.andres")
        .with_file("r/d/a.png", b"andres_image")
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_fake_encryption_and_dead_code_dex() {
    let dead_dex = synthesize_dead_code_dex(&[0xff, 0xff, 0xef, 0x00], false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_enc_dead_dex.apk")
        .with_manifest("com.example.combo.enc.dex")
        .with_dex("classes.dex", &dead_dex)
        .with_fake_encryption(true, false)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);

    let (dex_resp, dex_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap(), "--disasm"]);
    assert!(dex_out.status.success());
    assert!(dex_resp.success);
}

#[test]
fn test_tier3_combo_fake_encryption_and_padded_arsc_header() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, false, false);
    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_enc_padded_arsc.apk")
        .with_manifest("com.example.combo.enc.arsc")
        .with_arsc(&arsc_bytes)
        .with_fake_encryption(false, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_andresguard_and_mutf8_null_surrogates() {
    let mut mutf8_str = b"class_".to_vec();
    mutf8_str.extend_from_slice(mutf8_two_byte_null());
    let dex_bytes = synthesize_mutf8_dex(&[&mutf8_str]);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_andres_mutf8.apk")
        .with_manifest("com.example.combo.andres.mutf8")
        .with_file("r/d/icon.png", b"icon_data")
        .with_dex("classes.dex", &dex_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_padded_arsc_and_dead_code_dex_and_ansi_manifest() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, false, false);
    let dead_dex = synthesize_dead_code_dex(&[0xff, 0xff], false);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_padded_dead_ansi.apk")
        .with_manifest(adversarial_ansi_string())
        .with_arsc(&arsc_bytes)
        .with_dex("classes.dex", &dead_dex)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let raw_out = String::from_utf8_lossy(&out.stdout);
    assert!(!raw_out.contains("\x1b[31;1m"));

    let (dex_resp, dex_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap(), "--disasm"]);
    assert!(dex_out.status.success());
    assert!(dex_resp.success);
}

#[test]
fn test_tier3_combo_path_traversal_and_fake_encryption_and_zalgo() {
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("combo_dump");

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_traversal_enc_zalgo.apk")
        .with_manifest(adversarial_zalgo_string())
        .with_path_traversal_entry("../../bad.txt", b"traversal")
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--dump", dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_utf16le_unpaired_surrogates_and_dead_code_dex() {
    let dead_dex = synthesize_dead_code_dex(&[0xff, 0xef], false);
    let arsc_bytes = synthesize_utf16_surrogate_arsc_bytes();

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_utf16_dead_dex.apk")
        .with_manifest("com.example.combo.utf16.dex")
        .with_arsc(&arsc_bytes)
        .with_dex("classes.dex", &dead_dex)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);

    let (dex_resp, dex_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap(), "--disasm"]);
    assert!(dex_out.status.success());
    assert!(dex_resp.success);
}

#[test]
fn test_tier3_combo_andresguard_and_padded_arsc_and_bidi_manifest() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, false, false);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_andres_padded_bidi.apk")
        .with_manifest(adversarial_bidi_string())
        .with_file("r/d/a.png", b"png_data")
        .with_arsc(&arsc_bytes)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(!raw.contains('\u{202E}'));
}

#[test]
fn test_tier3_combo_corrupted_debug_info_and_fake_encryption_and_ansi() {
    let corrupt_dex = synthesize_dead_code_dex(&[0x0e, 0x00], true);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_debug_enc_ansi.apk")
        .with_manifest(adversarial_ansi_string())
        .with_dex("classes.dex", &corrupt_dex)
        .with_fake_encryption(true, false)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(!raw.contains("\x1b[31;1m"), "ANSI escape sequence must be sanitized");

    let (dex_resp, dex_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap(), "--disasm"]);
    assert!(dex_out.status.success());
    assert!(dex_resp.success);
}

#[test]
fn test_tier3_combo_7zip_deflate_and_fake_encryption_and_andresguard() {
    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_7zip_enc_andres.apk")
        .with_manifest("com.example.combo.sevenzip")
        .with_file("r/a/a.xml", b"<view/>")
        .with_fake_encryption(false, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_path_traversal_and_andresguard_r_paths() {
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("dump_andres_traversal");

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_traversal_andres.apk")
        .with_manifest("com.example.combo.trav.andres")
        .with_file("r/d/icon.png", b"icon")
        .with_path_traversal_entry("r/../../../tmp/bad_escape.txt", b"escape")
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--dump", dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    assert!(dump_dir.join("r/d/icon.png").is_file());
}

#[test]
fn test_tier3_combo_mutf8_surrogates_and_utf16_surrogates_and_fake_enc() {
    let surrogate_bytes = mutf8_surrogate_pair();
    let dex_bytes = synthesize_mutf8_dex(&[surrogate_bytes]);
    let arsc_bytes = synthesize_utf16_surrogate_arsc_bytes();

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_surrogates_enc.apk")
        .with_manifest("com.example.combo.surrogates")
        .with_dex("classes.dex", &dex_bytes)
        .with_arsc(&arsc_bytes)
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);

    let (res_resp, res_out) = run_rvs_json::<ResourcesData>(&["apk", "resources", apk_path.to_str().unwrap(), "--list"]);
    assert!(res_out.status.success());
    assert!(res_resp.success);
}

#[test]
fn test_tier3_combo_padded_arsc_and_unknown_chunks_and_fake_encryption() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, true, false);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_padded_unknown_enc.apk")
        .with_manifest("com.example.combo.pad.unk.enc")
        .with_arsc(&arsc_bytes)
        .with_fake_encryption(true, false)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_dead_code_after_goto_and_return_and_corrupt_debug() {
    let dead_dex = synthesize_dead_code_dex(&[0x28, 0x00, 0xff, 0xff], true);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_goto_ret_debug.apk")
        .with_manifest("com.example.combo.goto.ret")
        .with_dex("classes.dex", &dead_dex)
        .build();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap(), "--disasm"]);
    assert!(out.status.success());
    assert!(resp.success);
}

#[test]
fn test_tier3_combo_bidi_manifest_and_zalgo_and_ansi_csi_osc() {
    let complex_adversarial = format!(
        "{}{}{}",
        adversarial_ansi_string(),
        adversarial_bidi_string(),
        adversarial_zalgo_string()
    );

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_super_adversarial.apk")
        .with_manifest(&complex_adversarial)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(!raw.contains("\x1b[31;1m"));
    assert!(!raw.contains('\u{202E}'));
}

#[test]
fn test_tier3_combo_multidex_dead_code_and_fake_encryption_and_andresguard() {
    let dead_dex1 = synthesize_dead_code_dex(&[0xff, 0xff], false);
    let dead_dex2 = synthesize_dead_code_dex(&[0xef, 0x00], false);

    let (_temp, apk_path) = SyntheticApkBuilder::new("combo_multidex_enc_andres.apk")
        .with_manifest("com.example.combo.multidex")
        .with_dex("classes.dex", &dead_dex1)
        .with_dex("classes2.dex", &dead_dex2)
        .with_file("r/d/icon.png", b"icon")
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("ApkInspectData expected");
    assert_eq!(data.dex_files.len(), 2);

    let (dex_resp, dex_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap(), "--disasm"]);
    assert!(dex_out.status.success());
    assert!(dex_resp.success);
}

// =============================================================================
// Tier 4: Real-World Scenarios (5 Comprehensive Workflows)
// =============================================================================

#[test]
fn test_tier4_e2e_anti_analysis_packer_composite() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, true, false);
    let dead_dex = synthesize_dead_code_dex(&[0xff, 0xff, 0xef, 0x00], true);
    let adversarial_pkg = format!("{}\x1b[31m\u{202E}app\x1b[0m", "com.packer.composite.");

    let (_temp, apk_path) = SyntheticApkBuilder::new("scenario1_packer_composite.apk")
        .with_manifest(&adversarial_pkg)
        .with_dex("classes.dex", &dead_dex)
        .with_arsc(&arsc_bytes)
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Scenario 1 packer composite APK inspect must succeed");
    assert!(resp.success);
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(!raw.contains("\x1b[31m"));
    assert!(!raw.contains('\u{202E}'));
    let data = resp.data.expect("ApkInspectData expected");
    assert!(!data.dex_files.is_empty());
}

#[test]
fn test_tier4_e2e_andresguard_production_app() {
    let arsc_bytes = synthesize_resilient_arsc_bytes(true, false, false);
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("andres_prod_dump");

    let (_temp, apk_path) = SyntheticApkBuilder::new("scenario2_andresguard_prod.apk")
        .with_manifest("com.production.andresguard")
        .with_arsc(&arsc_bytes)
        .with_file("r/d/a.png", b"\x89PNG\r\n\x1a\nicon_data")
        .with_file("r/l/b.xml", b"<LinearLayout/>")
        .build();

    let apk_str = apk_path.to_str().unwrap();

    let (resp_dump, out_dump) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_str, "--dump", dump_dir.to_str().unwrap(),
    ]);
    assert!(out_dump.status.success());
    assert!(resp_dump.success);
    assert!(dump_dir.join("r/d/a.png").is_file());
    assert!(dump_dir.join("r/l/b.xml").is_file());

    let (resp_ext, out_ext) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_str, "--extract", "r/d/a.png",
    ]);
    assert!(out_ext.status.success());
    assert!(resp_ext.success);
}

#[test]
fn test_tier4_e2e_malicious_unicode_terminal_hijack() {
    let attack_payload = format!(
        "\x1b[?25l\x1b]0;HIJACK\x07\u{202E}com.attack.terminal.{}\x1b[?25h",
        adversarial_zalgo_string()
    );

    let (_temp, apk_path) = SyntheticApkBuilder::new("scenario3_terminal_hijack.apk")
        .with_manifest(&attack_payload)
        .build();

    let (resp, out) = run_rvs_json::<ManifestInfoData>(&["apk", "manifest", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Scenario 3 terminal hijack attack must be safely neutralized");
    assert!(resp.success);
    let raw = String::from_utf8_lossy(&out.stdout);
    assert!(!raw.contains("\x1b[?25l"));
    assert!(!raw.contains("\x1b]0;HIJACK"));
    assert!(!raw.contains('\u{202E}'));
    assert!(!raw.contains('\x07'));
}

#[test]
fn test_tier4_e2e_corrupted_dex_obfuscator() {
    let mut null_and_surrogate = b"obf_".to_vec();
    null_and_surrogate.extend_from_slice(mutf8_two_byte_null());
    null_and_surrogate.extend_from_slice(mutf8_surrogate_pair());
    null_and_surrogate.extend_from_slice(mutf8_lone_high_surrogate());

    let dex1 = synthesize_mutf8_dex(&[&null_and_surrogate]);
    let dex2 = synthesize_dead_code_dex(&[0xff, 0xff, 0xef, 0x00], true);

    let (_temp, apk_path) = SyntheticApkBuilder::new("scenario4_corrupted_dex.apk")
        .with_manifest("com.obfuscator.multidex")
        .with_dex("classes.dex", &dex1)
        .with_dex("classes2.dex", &dex2)
        .build();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", apk_path.to_str().unwrap()]);
    assert!(out.status.success(), "Scenario 4 corrupted multi-DEX must parse safely");
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert!(data.strings_count >= 1);
}

#[test]
fn test_tier4_e2e_path_traversal_zip_slip_defensive_ejection() {
    let temp_workspace = TempDir::new().unwrap();
    let dump_dir = temp_workspace.path().join("scenario5_sandbox");
    let escape_target = temp_workspace.path().join("etc/passwd");

    let (_temp, apk_path) = SyntheticApkBuilder::new("scenario5_traversal_defense.apk")
        .with_manifest("com.traversal.defense")
        .with_file("res/values/strings.xml", b"<resources><string name=\"safe\">val</string></resources>")
        .with_path_traversal_entry("../../etc/passwd", b"root:x:0:0::/root:/bin/bash")
        .with_path_traversal_entry("res/../../../tmp/bad.xml", b"<bad/>")
        .with_file("assets/CON.txt", b"con_device")
        .with_fake_encryption(true, true)
        .build();

    let (resp, out) = run_rvs_json::<ResourcesData>(&[
        "apk", "resources", apk_path.to_str().unwrap(), "--dump", dump_dir.to_str().unwrap(),
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    assert!(!escape_target.exists(), "Traversal entry must never escape to arbitrary paths");
    assert!(dump_dir.join("res/values/strings.xml").is_file());
}

// =============================================================================
// Feature: Java & Apktool Discovery, Autonomous Unpack, and Smali Ingestion
// =============================================================================

#[test]
fn test_tier1_java_environment_detection() {
    // Java detection
    if let Some(java_bin) = rvs::apk::java::JavaEnvironment::find_java() {
        assert!(java_bin.exists(), "Java binary must exist if found");
        let version_opt = rvs::apk::java::JavaEnvironment::get_java_version(Some(&java_bin));
        assert!(version_opt.is_some(), "Should be able to parse java -version output");
        let version = version_opt.unwrap();
        assert!(
            rvs::apk::java::JavaEnvironment::check_java_version_supported(&version),
            "Host Java version '{}' should be supported (>= 8)",
            version
        );
    }

    // Apktool detection
    if let Some(runner) = rvs::apk::java::JavaEnvironment::find_apktool() {
        assert!(
            runner.executable_path().exists(),
            "Apktool runner executable must exist"
        );
    }
}

#[test]
fn test_tier1_cli_apk_unpack_pure_rust_fallback() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let dest_dir = temp_dir.path().join("out_rust_unpack");
    let dest_str = dest_dir.to_str().unwrap();

    let (resp, out) = run_rvs_json::<ApkUnpackData>(&[
        "apk", "unpack", apk_str, "-o", dest_str, "--no-java", "--force",
    ]);

    assert!(out.status.success(), "rvs apk unpack --no-java should succeed");
    assert!(resp.success);
    let data = resp.data.expect("ApkUnpackData expected");
    assert_eq!(data.engine, "rust-native");
    assert!(data.manifest_extracted, "Manifest must be extracted in pure-Rust mode");
    assert!(data.resources_extracted, "Resources must be extracted in pure-Rust mode");
    assert!(data.smali_generated, "Smali must be generated in pure-Rust mode");
    assert!(data.file_count > 0);

    // Verify disk contents
    let manifest_file = dest_dir.join("AndroidManifest.xml");
    assert!(manifest_file.is_file(), "AndroidManifest.xml must exist on disk");
    let manifest_content = std::fs::read_to_string(&manifest_file).unwrap();
    assert!(manifest_content.contains("<manifest"), "Manifest should be valid decoded XML text");

    let strings_file = dest_dir.join("res/values/strings.xml");
    assert!(strings_file.is_file(), "res/values/strings.xml must exist on disk");
    let strings_content = std::fs::read_to_string(&strings_file).unwrap();
    assert!(strings_content.contains("<resources>"), "strings.xml should have <resources> root");
    assert!(strings_content.contains("</resources>"));

    let smali_dir = dest_dir.join("smali");
    assert!(smali_dir.is_dir(), "smali directory must exist on disk");
    let mut smali_files = Vec::new();
    fn collect_smali(p: &std::path::Path, out: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(p) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_smali(&path, out);
                } else if path.extension().and_then(|s| s.to_str()) == Some("smali") {
                    out.push(path);
                }
            }
        }
    }
    collect_smali(&smali_dir, &mut smali_files);
    assert!(!smali_files.is_empty(), "Smali files should have been generated");

    // Verify native library
    let so_file = dest_dir.join("lib/arm64-v8a/libnative.so");
    assert!(so_file.is_file(), "Native library libnative.so must be extracted");

    // Verify asset
    let asset_file = dest_dir.join("assets/app_config.json");
    assert!(asset_file.is_file(), "Asset app_config.json must be extracted");
}

#[test]
fn test_tier1_cli_apk_unpack_java_accelerated() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let dest_dir = temp_dir.path().join("out_java_unpack");
    let dest_str = dest_dir.to_str().unwrap();

    let (resp, out) = run_rvs_json::<ApkUnpackData>(&[
        "apk", "unpack", apk_str, "-o", dest_str, "--force",
    ]);

    assert!(out.status.success(), "rvs apk unpack should succeed");
    assert!(resp.success);
    let data = resp.data.expect("ApkUnpackData expected");

    // If host has Java + apktool, engine should be java-apktool; otherwise fallback to rust-native
    if rvs::apk::java::JavaEnvironment::find_apktool().is_some() {
        assert_eq!(data.engine, "java-apktool");
    }
    assert!(data.manifest_extracted);
    assert!(data.resources_extracted);
    assert!(data.smali_generated);
    assert!(dest_dir.join("AndroidManifest.xml").is_file());
    assert!(dest_dir.join("smali").is_dir());
}

#[test]
fn test_tier1_cli_apk_inspect_and_dex_on_smali_only_directory() {
    let temp_dir = TempDir::new().unwrap();
    let root = temp_dir.path();
    let smali_sub = root.join("smali").join("com").join("example").join("testapp");
    std::fs::create_dir_all(&smali_sub).unwrap();

    let smali_src = r#".class public Lcom/example/testapp/MyActivity;
.super Landroid/app/Activity;

# fields
.field public static final TAG:Ljava/lang/String; = "MyActivity"

# methods
.method public onCreate(Landroid/os/Bundle;)V
    .registers 2
    return-void
.end method

.method public customHandler(Ljava/lang/String;)I
    .registers 3
    const/4 v0, 0x1
    return v0
.end method
"#;
    std::fs::write(smali_sub.join("MyActivity.smali"), smali_src).unwrap();

    // AndroidManifest.xml
    let manifest_src = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="10"
    android:versionName="1.0.0">
    <application android:debuggable="true">
        <activity android:name=".MyActivity" />
    </application>
</manifest>"#;
    std::fs::write(root.join("AndroidManifest.xml"), manifest_src).unwrap();

    let root_str = root.to_str().unwrap();

    // 1. Test rvs apk inspect on the smali-only unpacked directory
    let (insp_resp, insp_out) = run_rvs_json::<ApkInspectData>(&["apk", "inspect", root_str]);
    assert!(insp_out.status.success(), "Inspect should succeed on smali-only directory");
    assert!(insp_resp.success);
    let insp_data = insp_resp.data.expect("ApkInspectData expected");
    assert_eq!(insp_data.source_type, "directory");
    assert_eq!(insp_data.package_name.as_deref(), Some("com.example.testapp"));
    assert_eq!(insp_data.dex_files, vec!["smali"]);

    let java_detection = insp_data.languages.iter().find(|l| l.language == "Java");
    assert!(java_detection.is_some(), "Java must be detected when smali/ is present");
    let java_detection = java_detection.unwrap();
    assert_eq!(java_detection.confidence, "High");
    assert!(
        java_detection.evidence.iter().any(|e| e.contains("Smali")),
        "Java evidence should cite Smali assembly"
    );

    // 2. Test rvs apk dex on the smali-only unpacked directory
    let (dex_resp, dex_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", root_str]);
    assert!(dex_out.status.success(), "Dex command should succeed on smali-only directory");
    assert!(dex_resp.success);
    let dex_data = dex_resp.data.expect("DexAnalysisData expected");
    assert_eq!(dex_data.classes_count, 1);
    assert_eq!(dex_data.methods_count, 2);
    assert_eq!(dex_data.classes[0].name, "Lcom/example/testapp/MyActivity;");
    assert_eq!(dex_data.classes[0].super_class.as_deref(), Some("Landroid/app/Activity;"));

    // 3. Test filtering with --class and --method
    let (f_resp, f_out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", root_str, "--class", "MyActivity", "--method", "customHandler",
    ]);
    assert!(f_out.status.success());
    let f_data = f_resp.data.expect("Filtered DexAnalysisData expected");
    assert_eq!(f_data.classes_count, 1);
    assert_eq!(f_data.classes[0].methods.len(), 1);
    assert_eq!(f_data.classes[0].methods[0].name, "customHandler");

    // 4. Test --smali output on smali-only directory
    let (s_resp, s_out) = run_rvs_json::<DexAnalysisData>(&["apk", "dex", root_str, "--smali"]);
    assert!(s_out.status.success());
    let s_data = s_resp.data.expect("Smali output expected");
    assert!(s_data.smali.is_some());
    assert!(s_data.smali.unwrap().contains(".class public Lcom/example/testapp/MyActivity;"));
}

#[test]
fn test_tier2_apk_unpack_existing_dir_without_force_fails() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let dest_dir = temp_dir.path().join("non_empty_dir");
    std::fs::create_dir_all(&dest_dir).unwrap();
    std::fs::write(dest_dir.join("existing_file.txt"), b"already exists").unwrap();

    let dest_str = dest_dir.to_str().unwrap();

    // Without --force, unpacking to a non-empty directory must fail cleanly with structured error
    let (resp, out) = run_rvs_json::<serde_json::Value>(&[
        "apk", "unpack", apk_str, "-o", dest_str, "--no-java",
    ]);
    assert!(!out.status.success(), "Unpack without --force to non-empty dir must fail");
    assert!(!resp.success);
    let err = resp.error.expect("Error expected");
    assert!(err.message.contains("--force"));

    // With --force, unpacking must succeed
    let (f_resp, f_out) = run_rvs_json::<ApkUnpackData>(&[
        "apk", "unpack", apk_str, "-o", dest_str, "--no-java", "--force",
    ]);
    assert!(f_out.status.success(), "Unpack with --force must succeed");
    assert!(f_resp.success);
    assert!(dest_dir.join("AndroidManifest.xml").is_file());
}

#[test]
fn test_tier2_java_version_parsing_adversarial_matrix() {
    use rvs::apk::JavaEnvironment;

    // Modern GA releases with '+' build indicator
    assert!(JavaEnvironment::check_java_version_supported("21+35"));
    assert!(JavaEnvironment::check_java_version_supported("17+35-2724"));
    assert!(JavaEnvironment::check_java_version_supported("11+28"));

    // Legacy update indicator notation 'u' / 'U'
    assert!(JavaEnvironment::check_java_version_supported("8u382-b05"));
    assert!(JavaEnvironment::check_java_version_supported("8U123"));
    assert!(JavaEnvironment::check_java_version_supported("8u401"));

    // 'v' prefix variants
    assert!(JavaEnvironment::check_java_version_supported("v21+35"));
    assert!(JavaEnvironment::check_java_version_supported("v17.0.2"));
    assert!(JavaEnvironment::check_java_version_supported("v8u382-b05"));

    // Standard semver & legacy formats
    assert!(JavaEnvironment::check_java_version_supported("21.0.13"));
    assert!(JavaEnvironment::check_java_version_supported("17.0.2"));
    assert!(JavaEnvironment::check_java_version_supported("11.0.11"));
    assert!(JavaEnvironment::check_java_version_supported("1.8.0_312"));
    assert!(JavaEnvironment::check_java_version_supported("1.8"));

    // Unsupported versions (< 8) and malformed inputs
    assert!(!JavaEnvironment::check_java_version_supported("1.7.0_80"));
    assert!(!JavaEnvironment::check_java_version_supported("1.6.0_45"));
    assert!(!JavaEnvironment::check_java_version_supported("7u80"));
    assert!(!JavaEnvironment::check_java_version_supported("invalid"));
    assert!(!JavaEnvironment::check_java_version_supported(""));
}

#[test]
fn test_tier2_apktool_pipe_drain_large_output_and_reap_zombie() {
    use rvs::apk::run_apktool_decode;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    let apk = raw_apk_fixture();
    let temp_dir = TempDir::new().unwrap();
    let mock_bin_dir = temp_dir.path().join("bin");
    std::fs::create_dir_all(&mock_bin_dir).unwrap();

    let dest_dir = temp_dir.path().join("out_decode");
    std::fs::create_dir_all(&dest_dir).unwrap();

    // 1. Test Large Output Draining (>64KB pipe buffer without deadlock)
    let mock_apktool = mock_bin_dir.join("apktool");
    let script_content = r#"#!/bin/sh
# Generate 128KB of output to stdout and stderr
head -c 65536 /dev/zero | tr '\0' 'A'
echo ""
head -c 65536 /dev/zero | tr '\0' 'B' >&2
echo "" >&2
exit 0
"#;
    std::fs::write(&mock_apktool, script_content).unwrap();
    std::fs::set_permissions(&mock_apktool, std::fs::Permissions::from_mode(0o755)).unwrap();

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let test_path = format!("{}:{}", mock_bin_dir.display(), orig_path);
    std::env::set_var("PATH", &test_path);

    let start_time = std::time::Instant::now();
    let decode_result = run_apktool_decode(&apk, &dest_dir, true, Some(Duration::from_secs(5)));
    let elapsed = start_time.elapsed();

    assert!(decode_result.is_ok(), "run_apktool_decode must not deadlock on >64KB output");
    assert!(elapsed < Duration::from_secs(4), "Should complete rapidly without waiting for timeout");

    // 2. Test Timeout and Child Process Reaping (No Zombie Leak)
    let pid_file = temp_dir.path().join("mock_apktool.pid");
    let timeout_script = format!(
        r#"#!/bin/sh
echo $$ > "{}"
sleep 10
exit 0
"#,
        pid_file.display()
    );
    std::fs::write(&mock_apktool, timeout_script).unwrap();

    let timeout_result = run_apktool_decode(&apk, &dest_dir, true, Some(Duration::from_millis(250)));
    assert!(timeout_result.is_err(), "Must return Err on timeout");
    match timeout_result.err().unwrap() {
        rvs::error::AppError::Timeout(msg) => {
            assert!(msg.contains("timed out"), "Expected timeout message, got: {}", msg);
        }
        other => panic!("Expected AppError::Timeout, got: {:?}", other),
    }

    // Verify child process was reaped and is NOT a zombie (<defunct>)
    if pid_file.is_file() {
        let pid_str = std::fs::read_to_string(&pid_file).unwrap();
        let pid = pid_str.trim();
        if !pid.is_empty() {
            // Give kernel a tiny slice to process wait
            std::thread::sleep(Duration::from_millis(50));
            let proc_status_path = format!("/proc/{}/status", pid);
            if let Ok(status) = std::fs::read_to_string(&proc_status_path) {
                assert!(
                    !status.contains("State:\tZ"),
                    "Child process {} must be reaped by wait(), not left as a zombie!\nStatus:\n{}",
                    pid, status
                );
            }
        }
    }

    // Restore original PATH
    std::env::set_var("PATH", orig_path);
}

#[test]
fn test_tier1_unpack_agent_summary_json_and_md_generated() {
    let apk = raw_apk_fixture();
    let apk_str = apk.to_str().unwrap();
    let temp_dir = TempDir::new().unwrap();
    let dest_dir = temp_dir.path().join("out_agent_summary");
    let dest_str = dest_dir.to_str().unwrap();

    let (resp, out) = run_rvs_json::<ApkUnpackData>(&[
        "apk", "unpack", apk_str, "-o", dest_str, "--force", "--no-java",
    ]);

    assert!(out.status.success(), "rvs apk unpack should succeed");
    assert!(resp.success);
    let data = resp.data.expect("ApkUnpackData expected");

    // Check artifacts on disk
    let summary_json_file = dest_dir.join("rvs_agent_summary.json");
    assert!(summary_json_file.is_file(), "rvs_agent_summary.json must exist");
    let json_content = std::fs::read_to_string(&summary_json_file).unwrap();
    assert!(json_content.contains("package_name"), "json must have package_name");
    assert!(json_content.contains("eu.jgamba.myapplication"), "json must have myapplication package");

    let summary_md_file = dest_dir.join("rvs_agent_summary.md");
    assert!(summary_md_file.is_file(), "rvs_agent_summary.md must exist");
    let md_content = std::fs::read_to_string(&summary_md_file).unwrap();
    assert!(md_content.contains("# RVS APK Agent Reconnaissance Summary"), "md header missing");
    assert!(md_content.contains("Attack Surface"), "Attack Surface section missing");
    assert!(md_content.contains("JNI Native Method Cross-References"), "JNI section missing");

    // Check structured data in memory
    let agent_summary = data.agent_summary.expect("agent_summary should be attached");
    assert_eq!(agent_summary.package_name.as_deref(), Some("eu.jgamba.myapplication"));
    assert!(agent_summary.total_classes > 0, "total_classes must be > 0");
    assert!(agent_summary.total_methods > 0, "total_methods must be > 0");
    assert!(agent_summary.native_methods_count > 0, "native_methods_count must be > 0");
    assert!(
        agent_summary.exported_activities.iter().any(|a| a.contains("MainActivity")),
        "MainActivity should be detected as exported"
    );
    assert!(
        agent_summary.jni_cross_references.iter().any(|j| j.dalvik_method.contains("stringFromJNI")),
        "stringFromJNI should be cross-referenced"
    );
}

#[test]
fn test_tier1_jni_cross_referencing_dalvik_to_so() {
    let apk = raw_apk_fixture();
    let pkg = rvs::apk::ApkPackage::open(&apk).expect("open raw apk");
    let dex_results = pkg.analyze_dex(None).expect("analyze dex");
    let native_libs = pkg.analyze_native_libraries().expect("analyze native libs");

    let mut all_classes = Vec::new();
    for d in &dex_results {
        all_classes.extend(d.classes.clone());
    }

    let xrefs = rvs::apk::native_so::cross_reference_classes(&all_classes, &native_libs);
    assert!(!xrefs.is_empty(), "JNI cross references must be found in raw APK");

    let string_from_jni = xrefs.iter().find(|x| x.dalvik_method == "stringFromJNI");
    assert!(string_from_jni.is_some(), "stringFromJNI must be cross-referenced");
    let entry = string_from_jni.unwrap();
    assert_eq!(entry.registration_type, "static_export");
    assert!(entry.native_symbol.as_ref().unwrap().contains("stringFromJNI"));
    assert_eq!(entry.abi.as_deref(), Some("arm64-v8a"));
    assert!(entry.library_path.as_ref().unwrap().contains("libnative.so"));
}

#[test]
fn test_tier2_hybrid_cooperative_post_unpack_manifest_repair() {
    let apk = raw_apk_fixture();
    let pkg = rvs::apk::ApkPackage::open(&apk).expect("open raw apk");
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path().join("coop_repair");

    // Pure-rust unpack
    let summary = pkg.unpack(&dest, false).expect("unpack pure rust");
    assert_eq!(summary.engine, "rust-native");
    assert!(summary.manifest_extracted);
    assert!(dest.join("AndroidManifest.xml").is_file());
    assert!(dest.join("rvs_agent_summary.json").is_file());
    assert!(dest.join("rvs_agent_summary.md").is_file());
}

// =============================================================================
// Milestone 1 Deep Java & Dalvik Core Integration Tests (F1 - F6)
// =============================================================================

#[test]
fn test_tier1_m1_pure_rust_dalvik_disassembly() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "setChecked", "--disasm",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert_eq!(data.classes.len(), 1);
    let cls = &data.classes[0];
    assert_eq!(cls.methods.len(), 1);
    let method = &cls.methods[0];
    assert_eq!(method.name, "setChecked");

    let disasm = method.disassembly.as_ref().expect("disassembly expected");
    assert_eq!(disasm.len(), 5); // iget-boolean, if-eq, iput-boolean, invoke-virtual, return-void

    let ops: Vec<String> = disasm
        .iter()
        .map(|inst| inst["disasm"].as_str().unwrap_or("").to_string())
        .collect();

    assert!(ops[0].starts_with("iget-boolean"));
    assert!(ops[1].starts_with("if-eq"));
    assert!(ops[2].starts_with("iput-boolean"));
    assert!(ops[3].starts_with("invoke-virtual"));
    assert_eq!(ops[4], "return-void");
}

#[test]
fn test_tier1_m1_dalvik_cfg_and_decision_gates() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "setChecked", "--cfg",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let method = &data.classes[0].methods[0];
    let cfg = method.cfg.as_ref().expect("cfg expected");

    assert_eq!(cfg["method_name"].as_str(), Some("setChecked"));
    assert_eq!(cfg["total_blocks"].as_u64(), Some(3));
    assert_eq!(cfg["loop_count"].as_u64(), Some(0));

    let blocks = cfg["blocks"].as_array().expect("blocks array expected");
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0]["id"].as_u64(), Some(0));
    assert_eq!(blocks[1]["id"].as_u64(), Some(1));
    assert_eq!(blocks[2]["id"].as_u64(), Some(2));

    let gates = cfg["decision_gates"].as_array().expect("decision_gates array expected");
    assert_eq!(gates.len(), 1);
    let gate = &gates[0];
    assert_eq!(gate["addr"].as_u64(), Some(108092));
    assert_eq!(gate["gate_type"].as_str(), Some("equality_zero_check"));
    assert!(gate["branch_instruction"].as_str().unwrap().starts_with("if-eq"));
    assert_eq!(gate["jump_target"].as_u64(), Some(108106));
    assert_eq!(gate["fail_target"].as_u64(), Some(108096));
}

#[test]
fn test_tier1_m1_multidex_xrefs_correlation() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "--xrefs",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let cls = &data.classes[0];

    // Find setChecked
    let set_checked = cls.methods.iter().find(|m| m.name == "setChecked").unwrap();
    let xrefs = set_checked.xrefs.as_ref().expect("xrefs expected for setChecked");
    let callers = xrefs["callers"].as_array().expect("callers array");
    assert!(callers.iter().any(|c| c.as_str().unwrap().contains("toggle")));
    // Cross-class caller from QuickActionWindow must be preserved when filtering by class
    assert!(callers.iter().any(|c| c.as_str().unwrap().contains("QuickActionWindow")));

    let callees = xrefs["callees"].as_array().expect("callees array");
    assert!(callees.iter().any(|c| c.as_str().unwrap().contains("refreshDrawableState")));

    // Field access tracking (fields_read and fields_written)
    let fields_read = xrefs["fields_read"].as_array().expect("fields_read array");
    assert!(!fields_read.is_empty(), "fields_read must not be empty for setChecked");
    assert!(fields_read.iter().any(|f| f.as_str().unwrap().contains("QuickActionItem;->mChecked")));

    let fields_written = xrefs["fields_written"].as_array().expect("fields_written array");
    assert!(!fields_written.is_empty(), "fields_written must not be empty for setChecked");
    assert!(fields_written.iter().any(|f| f.as_str().unwrap().contains("QuickActionItem;->mChecked")));

    // Find isChecked
    let is_checked = cls.methods.iter().find(|m| m.name == "isChecked").unwrap();
    let is_checked_xrefs = is_checked.xrefs.as_ref().expect("xrefs expected for isChecked");
    let is_checked_callers = is_checked_xrefs["callers"].as_array().expect("callers array");
    assert!(is_checked_callers.iter().any(|c| c.as_str().unwrap().contains("onCreateDrawableState")));
}

#[test]
fn test_tier1_m1_filtered_caller_retention_and_multidex_xrefs() {
    let multi_apk = multi_dex_apk_fixture();
    let multi_str = multi_apk.to_str().unwrap();

    // Query with both class and method filters: -C QuickActionItem -m setChecked --xrefs
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", multi_str, "-C", "QuickActionItem", "-m", "setChecked", "--xrefs",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert!(!data.classes.is_empty());
    let cls = &data.classes[0];
    assert!(cls.name.contains("QuickActionItem"));

    let method = &cls.methods[0];
    assert_eq!(method.name, "setChecked");
    let xrefs = method.xrefs.as_ref().expect("xrefs expected for filtered method");

    // Callers from external classes and secondary DEX must be retained
    let callers = xrefs["callers"].as_array().expect("callers array");
    assert!(!callers.is_empty(), "Filtered method must retain external callers");
    assert!(
        callers.iter().any(|c| c.as_str().unwrap().contains("QuickActionWindow")),
        "Callers must include QuickActionWindow"
    );

    // Field accesses must be non-empty and accurately track field read/written
    let fields_read = xrefs["fields_read"].as_array().expect("fields_read array");
    assert_eq!(
        fields_read[0].as_str(),
        Some("Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z")
    );

    let fields_written = xrefs["fields_written"].as_array().expect("fields_written array");
    assert_eq!(
        fields_written[0].as_str(),
        Some("Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z")
    );
}

#[test]
fn test_tier1_m1_rich_structural_typing() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "--fields", "--annotations",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let cls = &data.classes[0];

    // Backward compatibility: fields Vec<String>
    assert_eq!(cls.fields, vec!["CHECKED_STATE_SET", "mChecked"]);

    // Rich structural typing: detailed_fields
    let detailed = cls.detailed_fields.as_ref().expect("detailed_fields expected");
    assert_eq!(detailed.len(), 2);

    let f0 = &detailed[0];
    assert_eq!(f0["name"].as_str(), Some("CHECKED_STATE_SET"));
    assert_eq!(f0["type_descriptor"].as_str(), Some("[I"));
    assert_eq!(f0["is_static"].as_bool(), Some(true));

    let f1 = &detailed[1];
    assert_eq!(f1["name"].as_str(), Some("mChecked"));
    assert_eq!(f1["type_descriptor"].as_str(), Some("Z"));
    assert_eq!(f1["is_static"].as_bool(), Some(false));

    // Interfaces and source_file
    let interfaces = cls.interfaces.as_ref().expect("interfaces expected");
    assert!(interfaces.contains(&"Landroid/widget/Checkable;".to_string()));
    assert_eq!(cls.source_file.as_deref(), Some("QuickActionItem.java"));
}

#[test]
fn test_tier1_m1_pure_rust_decompilation() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "setChecked", "--decompile",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let method = &data.classes[0].methods[0];
    let decompiled = method.decompiled.as_ref().expect("decompiled expected");

    assert!(decompiled.contains("public void setChecked(boolean p0)"));
    assert!(decompiled.contains("v0 = v1.mChecked;"));
    assert!(decompiled.contains("if (v0 == v2) goto 0x1a64a;"));
    assert!(decompiled.contains("v1.mChecked = v2;"));
    assert!(decompiled.contains("refreshDrawableState()V(v1);"));
    assert!(decompiled.contains("return;"));
}

#[test]
fn test_tier1_m1_decompilation_unconditional_goto_no_duplicate() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", dex_str, "-C", "QuickActionItem", "-m", "toggle", "--decompile",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let method = &data.classes[0].methods[0];
    let decompiled = method.decompiled.as_ref().expect("decompiled expected");

    assert!(decompiled.contains("public void toggle()"));
    assert!(decompiled.contains("goto 0x1a6be;"));
    // Exactly 1 goto 0x1a6be; statement must be emitted, not 2
    assert_eq!(
        decompiled.matches("goto 0x1a6be;").count(),
        1,
        "Expected exactly 1 'goto 0x1a6be;', found:\n{}",
        decompiled
    );
}

#[test]
fn test_tier1_m1_cli_pagination_and_summary() {
    let multi_apk = multi_dex_apk_fixture();
    let multi_str = multi_apk.to_str().unwrap();

    // Test --summary
    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", multi_str, "--summary",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    let summary = data.summary.expect("summary expected");
    assert_eq!(summary["total_classes"].as_u64(), Some(646));
    assert_eq!(summary["total_methods"].as_u64(), Some(4352));
    assert_eq!(summary["total_fields"].as_u64(), Some(4904));
    assert_eq!(summary["total_strings"].as_u64(), Some(13018));

    // Test pagination: --limit 2 --offset 0
    let (resp1, out1) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", multi_str, "--limit", "2", "--offset", "0",
    ]);
    assert!(out1.status.success());
    let data1 = resp1.data.expect("DexAnalysisData expected");
    assert_eq!(data1.classes.len(), 2);
    let first_class_name = data1.classes[0].name.clone();

    // Test pagination: --limit 2 --offset 2
    let (resp2, out2) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", multi_str, "--limit", "2", "--offset", "2",
    ]);
    assert!(out2.status.success());
    let data2 = resp2.data.expect("DexAnalysisData expected");
    assert_eq!(data2.classes.len(), 2);
    assert_ne!(data2.classes[0].name, first_class_name);
}

#[test]
fn test_tier1_m1_compact_dex_enhancements() {
    let dex = classes_dex_fixture();
    let dex_str = dex.to_str().unwrap();

    let (resp, out) = run_rvs_json::<serde_json::Value>(&[
        "-c", "apk", "dex", dex_str, "-C", "QuickActionItem", "--fields", "--cfg",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("data expected");

    let class_list = data["class_list"].as_array().expect("class_list array");
    assert_eq!(class_list.len(), 1);
    let cls = &class_list[0];
    assert_eq!(cls["name"].as_str(), Some("Lcom/devoteam/quickaction/QuickActionItem;"));
    assert_eq!(cls["super_cls"].as_str(), Some("Landroid/widget/LinearLayout;"));
    assert_eq!(cls["source_file"].as_str(), Some("QuickActionItem.java"));

    let interfaces = cls["interfaces"].as_array().expect("interfaces array");
    assert!(interfaces.iter().any(|i| i.as_str() == Some("Landroid/widget/Checkable;")));

    let detailed_fields = cls["detailed_fields"].as_array().expect("detailed_fields array");
    assert_eq!(detailed_fields.len(), 2);
    assert_eq!(detailed_fields[0]["name"].as_str(), Some("CHECKED_STATE_SET"));
    assert_eq!(detailed_fields[0]["type"].as_str(), Some("[I"));

    let methods = cls["methods"].as_array().expect("methods array");
    let set_checked = methods.iter().find(|m| m["name"].as_str() == Some("setChecked")).unwrap();
    let cfg = &set_checked["cfg"];
    assert_eq!(cfg["bb"].as_u64(), Some(3));
    assert_eq!(cfg["gates"].as_u64(), Some(1));
}

#[test]
fn test_tier2_m1_multidex_classes2_routing() {
    let multi_apk = multi_dex_apk_fixture();
    let pkg = rvs::apk::ApkPackage::open(&multi_apk).expect("open multi dex apk");
    let dex_results = pkg.analyze_dex(None).expect("analyze dex");

    assert_eq!(dex_results.len(), 2);
    assert_eq!(dex_results[0].file_name, "classes.dex");
    assert_eq!(dex_results[1].file_name, "classes2.dex");

    // Check that classes from classes2.dex have correct dex_source
    let classes2_classes: Vec<_> = dex_results[1].classes.iter().collect();
    assert!(!classes2_classes.is_empty(), "classes2.dex must contain classes");
    for cls in &classes2_classes {
        assert_eq!(cls.dex_source.as_deref(), Some("classes2.dex"));
    }

    // Verify multi-DEX CLI disasm on a method in classes2.dex
    let multi_str = multi_apk.to_str().unwrap();
    let class_name = &classes2_classes[0].name;
    let method_name = &classes2_classes[0].methods[0].name;

    let (resp, out) = run_rvs_json::<DexAnalysisData>(&[
        "apk", "dex", multi_str, "-C", class_name, "-m", method_name, "--disasm",
    ]);

    assert!(out.status.success());
    assert!(resp.success);
    let data = resp.data.expect("DexAnalysisData expected");
    assert!(!data.classes.is_empty());
    let target_method = &data.classes[0].methods[0];
    if target_method.code_offset.is_some() {
        let disasm = target_method.disassembly.as_ref().expect("disassembly expected for method in classes2.dex");
        assert!(!disasm.is_empty(), "Method in classes2.dex must disassemble without failure");
    }
}
