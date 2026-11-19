//! APK and Android binary artifact analysis subsystem.
//!
//! Provides dual-mode ingestion for raw `.apk` archives and pre-extracted directory trees,
//! along with AXML binary / plain text AndroidManifest decoding, DEX discovery, and native `.so` library mapping.

pub mod container;
pub mod manifest;
pub mod dex;
pub mod native_so;
pub mod resources;
pub mod signature;
pub mod sanitize;
pub mod java;

pub use java::{run_apktool_decode, run_apktool_decode_options, ApktoolRunner, JavaEnvironment};
pub use sanitize::{
    decode_mutf8_lossy, decode_utf16le_lossy, sanitize_archive_entry_path, sanitize_identifier,
};

pub use container::{
    detect_elf_abi, parse_smali_directory, parse_smali_file, AgentAugmentationSummary,
    AgentSummary, ApkEntry, ApkPackage, ApkSource, ApkUnpackSummary,
};
pub use manifest::{
    decode_raw_manifest, is_binary_axml, is_dangerous_permission, IntentFilterInfo,
    ManifestComponent, ManifestInfo,
};
pub use dex::{
    decompile_dalvik_method, disassemble_dalvik_at, disassemble_dalvik_bounded,
    disassemble_dalvik_method, format_access_flags_class, format_access_flags_method,
    format_class_smali, format_method_smali, parse_dex_bytes, DalvikInstruction,
    DexAnalysisResult, DexClassSummary, DexMethodSummary,
};
pub use native_so::{
    analyze_jni_xrefs, correlate_jni_methods, cross_reference_classes,
    cross_reference_jni_methods, parse_native_so_bytes, unmangle_jni_symbol,
    JniFunction, JniMethodCrossReference, NativeLibraryAnalysis,
};
pub use resources::{
    analyze_apk_resources, dump_resources_and_assets, extract_arsc_strings,
    extract_resource_or_asset, generate_strings_xml, list_resources_and_assets,
    parse_arsc_table, ApkResourcesData, ArscPackageInfo, ArscTypeSpecInfo,
    ExtractedResource, ResourceEntryInfo,
};
pub use signature::{
    check_apk_signing_block, verify_apk_signature, ApkSignatureInfo, ApkSignerInfo,
    APK_SIG_BLOCK_MAGIC,
};
