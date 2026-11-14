//! Native ELF `.so` shared library and JNI analysis subsystem.
//!
//! Provides in-memory parsing of ELF binaries using `goblin = "0.10.7"`, extracting
//! architecture, bitness, dynamic exports, imports, static JNI function mappings
//! (`Java_*` unmangling), dynamic RegisterNatives detection, and cross-reference queries.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::apk::container::ApkPackage;

/// Detected JNI function entry point within a native shared object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JniFunction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled_method: Option<String>,
    pub address: u64,
    pub size: u64,
    pub is_exported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<crate::analysis::xrefs::XrefsResponse>,
}

/// Analysis result for an Android native `.so` shared library.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeLibraryAnalysis {
    pub file_name: String,
    pub architecture: String,
    pub is_64_bit: bool,
    pub jni_functions: Vec<JniFunction>,
    pub exported_symbols: Vec<String>,
    pub imported_symbols: Vec<String>,
    pub register_natives_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<std::collections::HashMap<String, crate::analysis::xrefs::XrefsResponse>>,
}

/// Unmangle a static JNI symbol name conforming to the JNI naming specification.
///
/// Converts e.g.:
/// - `Java_com_example_app_MainActivity_stringFromJNI` -> class `com.example.app.MainActivity`, method `stringFromJNI`
/// - `Java_com_example_app_MainActivity_validateLicense` -> class `com.example.app.MainActivity`, method `validateLicense`
/// - Handles `_1` escaping to `_`
/// - Handles `_2` escaping to `;`
/// - Handles `_3` escaping to `[`
/// - Handles `_0xxxx` Unicode codepoint escapes
/// - Handles `__` overloaded method signature suffix
pub fn unmangle_jni_symbol(symbol: &str) -> (Option<String>, Option<String>) {
    let stripped = if let Some(s) = symbol.strip_prefix("Java_") {
        s
    } else if let Some(s) = symbol.strip_prefix("_Java_") {
        s
    } else {
        return (None, None);
    };

    // If there is an overload signature separator "__", isolate the identifier part
    let (ident_part, _sig_part) = if let Some(idx) = stripped.find("__") {
        (&stripped[..idx], Some(&stripped[idx + 2..]))
    } else {
        (stripped, None)
    };

    // Helper to decode JNI escape sequences inside a token
    fn decode_jni_component(comp: &str) -> String {
        let mut result = String::with_capacity(comp.len());
        let chars: Vec<char> = comp.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '_' && i + 1 < chars.len() {
                match chars[i + 1] {
                    '1' => {
                        result.push('_');
                        i += 2;
                        continue;
                    }
                    '2' => {
                        result.push(';');
                        i += 2;
                        continue;
                    }
                    '3' => {
                        result.push('[');
                        i += 2;
                        continue;
                    }
                    '0' if i + 5 < chars.len() => {
                        let hex_str: String = chars[i + 2..i + 6].iter().collect();
                        if let Ok(code) = u32::from_str_radix(&hex_str, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                result.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                    _ => {}
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        result
    }

    // Split into class packages and method name by unescaped '_'
    let mut segments = Vec::new();
    let mut current_seg = String::new();
    let chars: Vec<char> = ident_part.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '_' {
            // Check if this is an escaped sequence: _1, _2, _3, or _0xxxx
            if i + 1 < chars.len()
                && (chars[i + 1] == '1'
                    || chars[i + 1] == '2'
                    || chars[i + 1] == '3'
                    || (chars[i + 1] == '0' && i + 5 < chars.len()))
            {
                current_seg.push(chars[i]);
                current_seg.push(chars[i + 1]);
                if chars[i + 1] == '0' {
                    current_seg.push(chars[i + 2]);
                    current_seg.push(chars[i + 3]);
                    current_seg.push(chars[i + 4]);
                    current_seg.push(chars[i + 5]);
                    i += 6;
                } else {
                    i += 2;
                }
            } else {
                // Unescaped '_' serves as package/class/method delimiter
                segments.push(decode_jni_component(&current_seg));
                current_seg.clear();
                i += 1;
            }
        } else {
            current_seg.push(chars[i]);
            i += 1;
        }
    }

    if !current_seg.is_empty() {
        segments.push(decode_jni_component(&current_seg));
    }

    if segments.is_empty() {
        return (None, None);
    }

    if segments.len() == 1 {
        return (None, Some(segments.remove(0)));
    }

    let method = segments.pop();
    let class = segments.join(".");
    (Some(class), method)
}

/// Parse raw ELF shared library bytes and extract JNI entry points and metadata.
pub fn parse_native_so_bytes(bytes: &[u8], file_name: &str) -> Result<NativeLibraryAnalysis, AppError> {
    if bytes.is_empty() {
        return Err(AppError::ZeroByteFile(file_name.to_string()));
    }
    if bytes.len() < 4 || !bytes.starts_with(b"\x7fELF") {
        return Err(AppError::InvalidBinary(format!(
            "File '{}' is not a valid ELF binary",
            file_name
        )));
    }

    let elf = goblin::elf::Elf::parse(bytes).map_err(|e| {
        AppError::InvalidBinary(format!("Failed to parse ELF '{}': {}", file_name, e))
    })?;

    let architecture = match elf.header.e_machine {
        goblin::elf::header::EM_AARCH64 => "arm64".to_string(),
        goblin::elf::header::EM_ARM => "arm".to_string(),
        goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
        goblin::elf::header::EM_386 => "x86".to_string(),
        goblin::elf::header::EM_MIPS => "mips".to_string(),
        goblin::elf::header::EM_RISCV => "riscv".to_string(),
        other => format!("unknown({})", other),
    };

    let is_64_bit = elf.is_64;

    let mut exported_set = BTreeSet::new();
    let mut imported_set = BTreeSet::new();
    let mut jni_functions = Vec::new();
    let mut seen_jni = HashSet::new();

    // 1. Process dynamic symbol table (.dynsym) - available even in stripped binaries
    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                continue;
            }

            let is_import = sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize;
            if is_import {
                imported_set.insert(trimmed.to_string());
            } else {
                exported_set.insert(trimmed.to_string());
            }

            if (trimmed.starts_with("Java_") || trimmed.starts_with("_Java_"))
                && !seen_jni.contains(trimmed)
            {
                seen_jni.insert(trimmed.to_string());
                let (demangled_class, demangled_method) = unmangle_jni_symbol(trimmed);
                jni_functions.push(JniFunction {
                    name: trimmed.to_string(),
                    demangled_class,
                    demangled_method,
                    address: sym.st_value,
                    size: sym.st_size,
                    is_exported: !is_import,
                    xrefs: None,
                });
            }
        }
    }

    // 2. Process static symbol table (.symtab) if present
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                continue;
            }

            let is_import = sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize;
            if is_import {
                imported_set.insert(trimmed.to_string());
            } else {
                exported_set.insert(trimmed.to_string());
            }

            if (trimmed.starts_with("Java_") || trimmed.starts_with("_Java_"))
                && !seen_jni.contains(trimmed)
            {
                seen_jni.insert(trimmed.to_string());
                let (demangled_class, demangled_method) = unmangle_jni_symbol(trimmed);
                jni_functions.push(JniFunction {
                    name: trimmed.to_string(),
                    demangled_class,
                    demangled_method,
                    address: sym.st_value,
                    size: sym.st_size,
                    is_exported: !is_import,
                    xrefs: None,
                });
            }
        }
    }

    // 3. Dynamic RegisterNatives detection
    let register_natives_detected = exported_set.contains("RegisterNatives")
        || imported_set.contains("RegisterNatives")
        || bytes.windows(15).any(|w| w == b"RegisterNatives");

    let exported_symbols: Vec<String> = exported_set.into_iter().collect();
    let imported_symbols: Vec<String> = imported_set.into_iter().collect();

    Ok(NativeLibraryAnalysis {
        file_name: file_name.to_string(),
        architecture,
        is_64_bit,
        jni_functions,
        exported_symbols,
        imported_symbols,
        register_natives_detected,
        xrefs: None,
    })
}

/// Analyze cross references to a JNI function using radare2 (`axtj` / `axffj`).
pub fn analyze_jni_xrefs(
    so_path: &Path,
    jni_symbol: &str,
) -> Result<crate::analysis::xrefs::XrefsResponse, AppError> {
    if !so_path.exists() {
        return Err(AppError::FileNotFound(so_path.display().to_string()));
    }
    let driver = crate::r2::R2Driver::new(so_path, None, None, true)?;
    crate::analysis::xrefs::analyze_xrefs(
        &driver,
        jni_symbol,
        crate::analysis::xrefs::XrefDirection::All,
        None,
    )
}

// -----------------------------------------------------------------------------
// ApkPackage Extension Methods for Native Libraries
// -----------------------------------------------------------------------------

impl ApkPackage {
    /// Analyze native `.so` shared libraries contained in this package across all ABIs.
    pub fn analyze_native_libraries(&self) -> Result<Vec<NativeLibraryAnalysis>, AppError> {
        let mut results = Vec::new();
        for entries in self.native_libraries.values() {
            for entry in entries {
                let bytes = self.read_entry(&entry.name)?;
                let analysis = parse_native_so_bytes(&bytes, &entry.name)?;
                results.push(analysis);
            }
        }
        Ok(results)
    }

    /// Analyze a specific native library by entry name or ABI.
    pub fn analyze_native_library(&self, name_or_abi: &str) -> Result<NativeLibraryAnalysis, AppError> {
        for (abi, entries) in &self.native_libraries {
            if abi == name_or_abi {
                if let Some(first) = entries.first() {
                    let bytes = self.read_entry(&first.name)?;
                    return parse_native_so_bytes(&bytes, &first.name);
                }
            }
            for entry in entries {
                if entry.name == name_or_abi || entry.name.ends_with(name_or_abi) {
                    let bytes = self.read_entry(&entry.name)?;
                    return parse_native_so_bytes(&bytes, &entry.name);
                }
            }
        }
        Err(AppError::FileNotFound(format!(
            "Native library '{}' not found in package",
            name_or_abi
        )))
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_aarch64_lib() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_aarch64_lib.so")
    }

    fn fixture_aarch64_stripped() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_aarch64_stripped.so")
    }

    #[test]
    fn test_unmangle_jni_standard() {
        let (cls, meth) = unmangle_jni_symbol("Java_com_example_app_MainActivity_stringFromJNI");
        assert_eq!(cls.as_deref(), Some("com.example.app.MainActivity"));
        assert_eq!(meth.as_deref(), Some("stringFromJNI"));
    }

    #[test]
    fn test_unmangle_jni_underscores() {
        let (cls, meth) = unmangle_jni_symbol("Java_com_example_my_1package_My_1Class_do_1something");
        assert_eq!(cls.as_deref(), Some("com.example.my_package.My_Class"));
        assert_eq!(meth.as_deref(), Some("do_something"));
    }

    #[test]
    fn test_unmangle_jni_overloaded() {
        let (cls, meth) = unmangle_jni_symbol("Java_com_example_Foo_calculate__I");
        assert_eq!(cls.as_deref(), Some("com.example.Foo"));
        assert_eq!(meth.as_deref(), Some("calculate"));
    }

    #[test]
    fn test_unmangle_jni_inner_class_dollar() {
        let (cls, meth) = unmangle_jni_symbol("Java_com_example_Main_00024Inner_work");
        assert_eq!(cls.as_deref(), Some("com.example.Main$Inner"));
        assert_eq!(meth.as_deref(), Some("work"));
    }

    #[test]
    fn test_unmangle_non_jni() {
        let (cls, meth) = unmangle_jni_symbol("helper_add");
        assert!(cls.is_none());
        assert!(meth.is_none());
    }

    #[test]
    fn test_parse_aarch64_so() {
        let so_path = fixture_aarch64_lib();
        assert!(so_path.exists(), "sample_aarch64_lib.so must exist");
        let bytes = std::fs::read(&so_path).unwrap();

        let analysis = parse_native_so_bytes(&bytes, "sample_aarch64_lib.so").unwrap();
        assert!(analysis.is_64_bit, "Must be 64-bit ELF");
        assert_eq!(analysis.architecture, "arm64");

        // Verify JNI functions
        assert!(!analysis.jni_functions.is_empty());
        let string_jni = analysis.jni_functions.iter().find(|j| j.name.contains("stringFromJNI"));
        assert!(string_jni.is_some(), "stringFromJNI must be present");
        let sj = string_jni.unwrap();
        assert_eq!(sj.demangled_class.as_deref(), Some("com.example.app.MainActivity"));
        assert_eq!(sj.demangled_method.as_deref(), Some("stringFromJNI"));
        assert!(sj.is_exported);

        // Verify other exported methods
        assert!(analysis.jni_functions.iter().any(|j| j.name.contains("validateLicense")));
        assert!(analysis.jni_functions.iter().any(|j| j.name.contains("getAppName")));

        // Verify exported symbols
        assert!(analysis.exported_symbols.iter().any(|s| s.contains("JNI_OnLoad")));
        assert!(analysis.exported_symbols.iter().any(|s| s.contains("auth_gate_check")));
    }

    #[test]
    fn test_parse_aarch64_stripped_so() {
        let so_path = fixture_aarch64_stripped();
        assert!(so_path.exists(), "sample_aarch64_stripped.so must exist");
        let bytes = std::fs::read(&so_path).unwrap();

        let analysis = parse_native_so_bytes(&bytes, "sample_aarch64_stripped.so").unwrap();
        assert!(analysis.is_64_bit);
        assert_eq!(analysis.architecture, "arm64");
        // Stripped ELF still has dynamic symbols in .dynsym
        assert!(analysis.jni_functions.iter().any(|j| j.name.contains("stringFromJNI")));
    }

    #[test]
    fn test_parse_invalid_elf() {
        let bad_bytes = b"not an elf binary at all";
        let res = parse_native_so_bytes(bad_bytes, "invalid.so");
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_empty_so() {
        let res = parse_native_so_bytes(&[], "empty.so");
        assert!(res.is_err());
    }

    #[test]
    fn test_apk_package_analyze_native_libraries() {
        let raw_apk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_raw.apk");
        if raw_apk.exists() {
            let pkg = ApkPackage::open(&raw_apk).expect("open raw apk");
            let libs = pkg.analyze_native_libraries().expect("analyze native libraries");
            assert!(!libs.is_empty(), "Native libraries should be present in raw APK");
            assert_eq!(libs[0].architecture, "arm64");
            assert!(libs[0].jni_functions.iter().any(|j| j.name.contains("stringFromJNI")));

            // Specific ABI
            let arm64 = pkg.analyze_native_library("arm64-v8a").expect("find arm64-v8a lib");
            assert_eq!(arm64.architecture, "arm64");

            // Specific file name
            let libnat = pkg.analyze_native_library("libnative.so").expect("find libnative.so");
            assert_eq!(libnat.architecture, "arm64");

            // Missing
            let missing = pkg.analyze_native_library("nonexistent_abi");
            assert!(missing.is_err());
        }
    }

    #[test]
    fn test_apk_package_no_so() {
        let no_so_apk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_no_so.apk");
        if no_so_apk.exists() {
            let pkg = ApkPackage::open(&no_so_apk).expect("open no-so apk");
            let libs = pkg.analyze_native_libraries().expect("analyze no-so libs");
            assert!(libs.is_empty(), "Expected empty native libraries list");
        }
    }

    #[test]
    fn test_analyze_jni_xrefs() {
        let so_path = fixture_aarch64_lib();
        if so_path.exists() {
            let xrefs = analyze_jni_xrefs(&so_path, "Java_com_example_app_MainActivity_validateLicense");
            assert!(xrefs.is_ok(), "Xrefs query for validateLicense should succeed");
        }
    }
}
