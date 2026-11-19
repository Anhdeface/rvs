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

pub use sanitize::{
    decode_mutf8_lossy, decode_utf16le_lossy, sanitize_archive_entry_path, sanitize_identifier,
};

pub use container::{detect_elf_abi, ApkEntry, ApkPackage, ApkSource};
pub use manifest::{decode_raw_manifest, is_binary_axml, ManifestInfo};
pub use dex::{
    decompile_dalvik_method, disassemble_dalvik_at, disassemble_dalvik_bounded,
    disassemble_dalvik_method, format_access_flags_class, format_access_flags_method,
    format_class_smali, format_method_smali, parse_dex_bytes, DalvikInstruction,
    DexAnalysisResult, DexClassSummary, DexMethodSummary,
};
pub use native_so::{
    analyze_jni_xrefs, parse_native_so_bytes, unmangle_jni_symbol, JniFunction,
    NativeLibraryAnalysis,
};
pub use resources::{
    analyze_apk_resources, dump_resources_and_assets, extract_resource_or_asset,
    list_resources_and_assets, parse_arsc_table, ApkResourcesData, ArscPackageInfo,
    ArscTypeSpecInfo, ExtractedResource, ResourceEntryInfo,
};
pub use signature::{
    check_apk_signing_block, verify_apk_signature, ApkSignatureInfo, ApkSignerInfo,
    APK_SIG_BLOCK_MAGIC,
};
