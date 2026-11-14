//! APK and Android binary artifact analysis subsystem.
//!
//! Provides dual-mode ingestion for raw `.apk` archives and pre-extracted directory trees,
//! along with AXML binary / plain text AndroidManifest decoding, DEX discovery, and native `.so` library mapping.

pub mod container;
pub mod manifest;
pub mod dex;
pub mod native_so;

pub use container::{detect_elf_abi, ApkEntry, ApkPackage, ApkSource};
pub use manifest::{is_binary_axml, ManifestInfo};
pub use dex::{
    disassemble_dalvik_at, disassemble_dalvik_method, parse_dex_bytes, DalvikInstruction,
    DexAnalysisResult, DexClassSummary, DexMethodSummary,
};
pub use native_so::{
    analyze_jni_xrefs, parse_native_so_bytes, unmangle_jni_symbol, JniFunction,
    NativeLibraryAnalysis,
};
