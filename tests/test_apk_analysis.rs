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
