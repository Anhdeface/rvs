use std::collections::HashMap;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use super::manifest::{is_binary_axml, ManifestInfo};
use super::sanitize::sanitize_archive_entry_path;

/// The input source representation for Android artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApkSource {
    /// Raw `.apk` or `.zip` archive on disk
    Archive(PathBuf),
    /// Pre-extracted or unpacked APK directory (e.g. from apktool or unzip)
    Directory(PathBuf),
    /// Direct standalone `.dex` or `.so` binary
    Standalone(PathBuf),
}

/// A constituent entry inside an APK package or extracted directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkEntry {
    /// Normalized entry name (e.g. "classes.dex", "lib/arm64-v8a/libnative.so")
    pub name: String,
    /// Uncompressed size in bytes
    pub size: u64,
    /// Absolute or relative path on disk if unpacked/standalone; None if archived
    pub path: Option<PathBuf>,
}

/// Language or framework detected within an Android APK package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageDetection {
    pub language: String,
    pub confidence: String,
    pub evidence: Vec<String>,
}

/// Comprehensive reconnaissance summary generated for downstream AI agents during unpacking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_code: Option<u32>,
    pub debuggable: bool,
    pub total_classes: usize,
    pub total_methods: usize,
    pub native_methods_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dangerous_permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exported_activities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exported_services: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exported_receivers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exported_providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deep_link_schemes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jni_cross_references: Vec<super::native_so::JniMethodCrossReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<LanguageDetection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack_surface_components: Vec<super::manifest::ManifestComponent>,
}

pub type AgentAugmentationSummary = AgentSummary;

/// Structured summary of an APK unpack operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkUnpackSummary {
    pub destination: PathBuf,
    pub engine: String,
    pub file_count: usize,
    pub manifest_extracted: bool,
    pub resources_extracted: bool,
    pub smali_generated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_summary: Option<AgentSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repairs: Vec<String>,
}

/// Unified representation of an ingested Android APK package or standalone component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkPackage {
    pub source: ApkSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_data: Option<Vec<u8>>,
    pub is_manifest_binary: bool,
    pub dex_entries: Vec<ApkEntry>,
    pub native_libraries: HashMap<String, Vec<ApkEntry>>, // abi -> entries
    #[serde(default)]
    pub asset_entries: Vec<ApkEntry>,
    #[serde(default)]
    pub resource_entries: Vec<ApkEntry>,
    #[serde(skip)]
    pub normalized_archive_data: Option<Vec<u8>>,
}

impl ApkPackage {
    /// Ingest and auto-detect an Android target from a file or directory path.
    ///
    /// Supports:
    /// - Raw `.apk` / `.zip` archives (in-memory streaming)
    /// - Unpacked APK directory trees (auto-detecting manifest, DEX, and lib/ ABIs)
    /// - Standalone `.dex` or `.so` files
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AppError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(AppError::FileNotFound(path.display().to_string()));
        }

        if path.is_dir() {
            return Self::open_directory(path);
        }

        let meta = std::fs::metadata(path)?;
        if meta.len() == 0 {
            return Err(AppError::ZeroByteFile(path.display().to_string()));
        }

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let mut header = [0u8; 16];
        let read_len = {
            let mut f = std::fs::File::open(path)?;
            f.read(&mut header).unwrap_or(0)
        };

        let is_elf = read_len >= 4 && &header[..4] == b"\x7fELF";
        let is_dex = read_len >= 4 && &header[..4] == b"dex\n";
        let is_zip = read_len >= 4
            && (&header[..4] == b"PK\x03\x04"
                || &header[..4] == b"PK\x05\x06"
                || &header[..4] == b"PK\x07\x08");

        if ext == "dex" || (is_dex && !is_zip) {
            return Self::open_standalone_dex(path, &file_name, meta.len());
        }

        if ext == "so" || (is_elf && !is_zip) {
            return Self::open_standalone_so(path, &file_name, meta.len());
        }

        // Default or archive
        Self::open_archive(path)
    }

    /// Read raw bytes of an entry by name.
    pub fn read_entry(&self, entry_name: &str) -> Result<Vec<u8>, AppError> {
        let rel = Path::new(entry_name);
        if rel.is_absolute()
            || entry_name.starts_with('/')
            || entry_name.starts_with('\\')
            || rel.components().any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(AppError::InvalidBinary(format!(
                "Invalid entry path '{}'",
                entry_name
            )));
        }

        let sanitized_query = sanitize_archive_entry_path(entry_name);

        match &self.source {
            ApkSource::Archive(path) => {
                if let Some(normalized) = &self.normalized_archive_data {
                    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(normalized.as_slice())).map_err(|e| {
                        AppError::InvalidBinary(format!("Failed to read APK archive '{}': {}", path.display(), e))
                    })?;
                    if let Some(buf) = Self::read_from_archive_inner(&mut archive, entry_name, &sanitized_query)? {
                        return Ok(buf);
                    }
                } else {
                    let file = std::fs::File::open(path)?;
                    match zip::ZipArchive::new(file) {
                        Ok(mut archive) => {
                            match Self::read_from_archive_inner(&mut archive, entry_name, &sanitized_query) {
                                Ok(Some(buf)) => return Ok(buf),
                                Ok(None) => {}
                                Err(AppError::InvalidBinary(ref msg)) if is_password_or_unsupported_error(msg) => {
                                    let raw = std::fs::read(path)?;
                                    let norm = normalize_zip_encryption_flags(&raw);
                                    let mut norm_archive = zip::ZipArchive::new(std::io::Cursor::new(norm)).map_err(|err| {
                                        AppError::InvalidBinary(format!("Failed to read normalized archive: {}", err))
                                    })?;
                                    if let Some(buf) = Self::read_from_archive_inner(&mut norm_archive, entry_name, &sanitized_query)? {
                                        return Ok(buf);
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        Err(zip::result::ZipError::UnsupportedArchive(_)) => {
                            let raw = std::fs::read(path)?;
                            let norm = normalize_zip_encryption_flags(&raw);
                            let mut norm_archive = zip::ZipArchive::new(std::io::Cursor::new(norm)).map_err(|err| {
                                AppError::InvalidBinary(format!("Failed to read normalized archive: {}", err))
                            })?;
                            if let Some(buf) = Self::read_from_archive_inner(&mut norm_archive, entry_name, &sanitized_query)? {
                                return Ok(buf);
                            }
                        }
                        Err(e) => {
                            return Err(AppError::InvalidBinary(format!(
                                "Failed to read APK archive '{}': {}",
                                path.display(),
                                e
                            )));
                        }
                    }
                }

                Err(AppError::FileNotFound(format!(
                    "Entry '{}' not found in APK archive '{}'",
                    entry_name,
                    path.display()
                )))
            }
            ApkSource::Directory(base_dir) => {
                // 1. Direct path join
                let direct_path = base_dir.join(rel);
                let canonical_base = base_dir.canonicalize().unwrap_or_else(|_| base_dir.clone());
                if let Ok(canon_direct) = direct_path.canonicalize() {
                    if !canon_direct.starts_with(&canonical_base) {
                        return Err(AppError::InvalidBinary(format!(
                            "Invalid entry path '{}'",
                            entry_name
                        )));
                    }
                } else if !direct_path.starts_with(base_dir) {
                    return Err(AppError::InvalidBinary(format!(
                        "Invalid entry path '{}'",
                        entry_name
                    )));
                }

                if direct_path.is_file() {
                    return Ok(std::fs::read(&direct_path)?);
                }

                if !sanitized_query.is_empty() && sanitized_query != entry_name {
                    let sanitized_path = base_dir.join(&sanitized_query);
                    if let Ok(canon_sanitized) = sanitized_path.canonicalize() {
                        if canon_sanitized.starts_with(&canonical_base) && sanitized_path.is_file() {
                            return Ok(std::fs::read(&sanitized_path)?);
                        }
                    } else if sanitized_path.starts_with(base_dir) && sanitized_path.is_file() {
                        return Ok(std::fs::read(&sanitized_path)?);
                    }
                }

                // 2. Search in dex_entries
                for entry in &self.dex_entries {
                    if entry.name == entry_name
                        || entry.name == sanitized_query
                        || entry.name.ends_with(entry_name)
                        || (!sanitized_query.is_empty() && entry.name.ends_with(&sanitized_query))
                    {
                        if let Some(p) = &entry.path {
                            if p.is_file() {
                                return Ok(std::fs::read(p)?);
                            }
                        }
                    }
                }

                // 3. Search in native_libraries
                for entries in self.native_libraries.values() {
                    for entry in entries {
                        if entry.name == entry_name
                            || entry.name == sanitized_query
                            || entry.name.ends_with(entry_name)
                            || (!sanitized_query.is_empty() && entry.name.ends_with(&sanitized_query))
                        {
                            if let Some(p) = &entry.path {
                                if p.is_file() {
                                    return Ok(std::fs::read(p)?);
                                }
                            }
                        }
                    }
                }

                // 4. Search in asset_entries
                for entry in &self.asset_entries {
                    if entry.name == entry_name
                        || entry.name == sanitized_query
                        || entry.name.ends_with(entry_name)
                        || (!sanitized_query.is_empty() && entry.name.ends_with(&sanitized_query))
                    {
                        if let Some(p) = &entry.path {
                            if p.is_file() {
                                return Ok(std::fs::read(p)?);
                            }
                        }
                    }
                }

                // 5. Search in resource_entries
                for entry in &self.resource_entries {
                    if entry.name == entry_name
                        || entry.name == sanitized_query
                        || entry.name.ends_with(entry_name)
                        || (!sanitized_query.is_empty() && entry.name.ends_with(&sanitized_query))
                    {
                        if let Some(p) = &entry.path {
                            if p.is_file() {
                                return Ok(std::fs::read(p)?);
                            }
                        }
                    }
                }

                // Manifest special case
                if entry_name == "AndroidManifest.xml" || sanitized_query == "AndroidManifest.xml" {
                    if let Some(data) = &self.manifest_data {
                        return Ok(data.clone());
                    }
                }

                Err(AppError::FileNotFound(format!(
                    "Entry '{}' not found in unpacked directory '{}'",
                    entry_name,
                    base_dir.display()
                )))
            }
            ApkSource::Standalone(path) => {
                let fname = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();

                if entry_name.is_empty()
                    || entry_name == fname
                    || (!sanitized_query.is_empty() && sanitized_query == fname)
                    || entry_name == path.to_string_lossy()
                    || self.dex_entries.iter().any(|e| e.name == entry_name || (!sanitized_query.is_empty() && e.name == sanitized_query))
                    || self
                        .native_libraries
                        .values()
                        .flatten()
                        .any(|e| e.name == entry_name || (!sanitized_query.is_empty() && e.name == sanitized_query))
                    || self.asset_entries.iter().any(|e| e.name == entry_name || (!sanitized_query.is_empty() && e.name == sanitized_query))
                {
                    if path.is_file() {
                        Ok(std::fs::read(path)?)
                    } else {
                        Err(AppError::FileNotFound(path.display().to_string()))
                    }
                } else {
                    Err(AppError::FileNotFound(format!(
                        "Entry '{}' not found in standalone file '{}'",
                        entry_name,
                        path.display()
                    )))
                }
            }
        }
    }

    /// Return names of all DEX files contained in the package.
    pub fn dex_names(&self) -> Vec<String> {
        self.dex_entries.iter().map(|e| e.name.clone()).collect()
    }

    /// Return all distinct ABI architectures in native libraries, sorted.
    pub fn abis(&self) -> Vec<String> {
        let mut list: Vec<String> = self.native_libraries.keys().cloned().collect();
        list.sort();
        list
    }

    /// Parse AndroidManifest if present in the package.
    pub fn manifest_info(&self) -> Result<Option<ManifestInfo>, AppError> {
        match &self.manifest_data {
            Some(data) => Ok(Some(ManifestInfo::parse(data, self.is_manifest_binary)?)),
            None => Ok(None),
        }
    }

    /// Detect programming languages and UI/runtime frameworks inside the APK package.
    ///
    /// Recognizes:
    /// - Java: Dalvik DEX bytecode present, AndroidManifest.xml
    /// - C/C++: Native shared objects in `lib/<abi>/`, JNI export entry points (`Java_*`), libc/libm linkage
    /// - React Native: `libreactnativejni.so`, `libhermes.so`, `libjsc.so`, `libreactnative.so`, `assets/index.android.bundle`, `com.facebook.react` DEX markers
    /// - Flutter / Dart: `libflutter.so`, `libapp.so`, `assets/flutter_assets/`, `io.flutter` DEX markers
    pub fn detect_languages(&self) -> Vec<LanguageDetection> {
        let mut detections = Vec::new();

        // 1. Java Detection: requires Dalvik DEX bytecode (.dex files) or Smali directory structure
        let has_real_dex = self
            .dex_entries
            .iter()
            .any(|e| e.name.ends_with(".dex") || e.name.contains(".dex"));
        let has_smali = self
            .dex_entries
            .iter()
            .any(|e| e.name == "smali" || e.name.starts_with("smali_") || e.name.starts_with("smali/"));

        if has_real_dex || has_smali {
            let mut java_evidence = Vec::new();
            if has_real_dex {
                let names: Vec<String> = self
                    .dex_entries
                    .iter()
                    .filter(|e| e.name.ends_with(".dex") || e.name.contains(".dex"))
                    .map(|e| e.name.clone())
                    .collect();
                java_evidence.push(format!(
                    "Dalvik DEX bytecode present ({} file(s): {})",
                    names.len(),
                    names.join(", ")
                ));
            }
            if has_smali {
                let smali_count = self
                    .dex_entries
                    .iter()
                    .filter(|e| e.name == "smali" || e.name.starts_with("smali_") || e.name.starts_with("smali/"))
                    .count();
                java_evidence.push(format!(
                    "Smali assembly structure present ({} directory/directories)",
                    smali_count
                ));
            }
            if self.manifest_data.is_some() {
                if self.is_manifest_binary {
                    java_evidence.push("AndroidManifest.xml present (binary AXML format)".to_string());
                } else {
                    java_evidence.push("AndroidManifest.xml present (XML text format)".to_string());
                }
            }
            let conf = if self.manifest_data.is_some() || has_smali {
                "High"
            } else {
                "Medium"
            };
            detections.push(LanguageDetection {
                language: "Java".to_string(),
                confidence: conf.to_string(),
                evidence: java_evidence,
            });
        }

        // 2. C/C++ Detection
        if !self.native_libraries.is_empty() {
            let mut cpp_evidence = Vec::new();
            let total_libs: usize = self.native_libraries.values().map(|v| v.len()).sum();
            let abis = self.abis();
            cpp_evidence.push(format!(
                "Native shared libraries present ({} .so file(s) across ABIs: {})",
                total_libs,
                abis.join(", ")
            ));

            let mut jni_count = 0;
            let mut sample_jni = Vec::new();
            let mut has_libc = false;

            for entries in self.native_libraries.values() {
                for entry in entries {
                    if let Ok(bytes) = self.read_entry(&entry.name) {
                        if let Ok(analysis) = super::native_so::parse_native_so_bytes(&bytes, &entry.name) {
                            for jni in &analysis.jni_functions {
                                jni_count += 1;
                                if sample_jni.len() < 3 {
                                    sample_jni.push(jni.name.clone());
                                }
                            }
                            if analysis.needed_libraries.iter().any(|lib| {
                                lib.contains("libc") || lib.contains("libm") || lib.contains("libstdc++")
                            }) {
                                has_libc = true;
                            }
                        }
                    }
                }
            }

            if jni_count > 0 {
                cpp_evidence.push(format!(
                    "JNI function exports detected ({} function(s), e.g. {})",
                    jni_count,
                    sample_jni.join(", ")
                ));
            }
            if has_libc {
                cpp_evidence.push("Dynamic C/C++ runtime linkage (libc/libm/libc++)".to_string());
            }

            detections.push(LanguageDetection {
                language: "C/C++".to_string(),
                confidence: "High".to_string(),
                evidence: cpp_evidence,
            });
        }

        // 3. React Native Detection
        let mut rn_evidence = Vec::new();

        for entries in self.native_libraries.values() {
            for entry in entries {
                let fname = Path::new(&entry.name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&entry.name);
                match fname {
                    "libreactnativejni.so"
                    | "libhermes.so"
                    | "libjsc.so"
                    | "libreactnative.so"
                    | "libfb.so"
                    | "libfolly_runtime.so"
                    | "libturbomodulejsijni.so" => {
                        rn_evidence.push(format!("React Native library marker: {}", entry.name));
                    }
                    _ => {
                        if fname.contains("reactnative") || fname.contains("hermes") {
                            rn_evidence.push(format!("React Native library marker: {}", entry.name));
                        }
                    }
                }
            }
        }

        for entry in &self.asset_entries {
            let norm = entry.name.replace('\\', "/");
            if norm.ends_with("index.android.bundle")
                || norm.ends_with("index.bundle")
                || norm.ends_with("index.android.bundle.hbc")
                || norm.ends_with("index.mobile.bundle")
                || norm.contains("index.android.bundle")
            {
                rn_evidence.push(format!("React Native JavaScript bundle asset: {}", entry.name));
            }
        }

        for dex_entry in &self.dex_entries {
            if let Ok(bytes) = self.read_entry(&dex_entry.name) {
                if let Ok(dex_res) = super::dex::parse_dex_bytes(&bytes, &dex_entry.name) {
                    let has_rn_class = dex_res.classes.iter().any(|c| {
                        c.name.contains("Lcom/facebook/react/")
                            || c.name.contains("com.facebook.react.")
                            || c.name.contains("com/facebook/react/")
                    });
                    let has_rn_string = dex_res.strings.as_ref().is_some_and(|strs| {
                        strs.iter().any(|s| {
                            s.contains("Lcom/facebook/react/")
                                || s.contains("com.facebook.react.")
                                || s.contains("com/facebook/react/")
                        })
                    });
                    if has_rn_class || has_rn_string {
                        rn_evidence.push(format!(
                            "React Native framework marker in DEX '{}': com.facebook.react",
                            dex_entry.name
                        ));
                        break;
                    }
                } else if bytes.windows(20).any(|w| w == b"Lcom/facebook/react/")
                    || bytes.windows(19).any(|w| w == b"com.facebook.react." || w == b"com/facebook/react/")
                {
                    rn_evidence.push(format!(
                        "React Native signature found in DEX '{}': com.facebook.react",
                        dex_entry.name
                    ));
                    break;
                }
            }
        }

        if !rn_evidence.is_empty() {
            detections.push(LanguageDetection {
                language: "React Native".to_string(),
                confidence: "High".to_string(),
                evidence: rn_evidence,
            });
        }

        // 4. Flutter / Dart Detection
        let mut flutter_evidence = Vec::new();

        for entries in self.native_libraries.values() {
            for entry in entries {
                let fname = Path::new(&entry.name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&entry.name);
                match fname {
                    "libflutter.so" => {
                        flutter_evidence.push(format!("Flutter C++ engine library: {}", entry.name));
                    }
                    "libapp.so" => {
                        flutter_evidence.push(format!("Dart compiled AOT snapshot library: {}", entry.name));
                    }
                    _ => {}
                }
            }
        }

        for entry in &self.asset_entries {
            let norm = entry.name.replace('\\', "/");
            let is_flutter_assets_dir = norm.starts_with("assets/flutter_assets/")
                || norm.starts_with("flutter_assets/")
                || norm.contains("/flutter_assets/")
                || norm == "assets/flutter_assets"
                || norm == "flutter_assets";
            if is_flutter_assets_dir
                || norm.ends_with("kernel_blob.bin")
                || norm.ends_with("vm_snapshot_data")
                || norm.ends_with("isolate_snapshot_data")
            {
                flutter_evidence.push(format!("Flutter asset marker: {}", entry.name));
                if flutter_evidence.len() >= 4 {
                    break;
                }
            }
        }

        for dex_entry in &self.dex_entries {
            if let Ok(bytes) = self.read_entry(&dex_entry.name) {
                if let Ok(dex_res) = super::dex::parse_dex_bytes(&bytes, &dex_entry.name) {
                    let has_flutter_class = dex_res.classes.iter().any(|c| {
                        c.name.contains("Lio/flutter/")
                            || c.name.contains("io.flutter.")
                            || c.name.contains("io/flutter/")
                    });
                    let has_flutter_string = dex_res.strings.as_ref().is_some_and(|strs| {
                        strs.iter().any(|s| {
                            s.contains("Lio/flutter/")
                                || s.contains("io.flutter.")
                                || s.contains("io/flutter/")
                        })
                    });
                    if has_flutter_class || has_flutter_string {
                        flutter_evidence.push(format!(
                            "Flutter embedding marker in DEX '{}': io.flutter",
                            dex_entry.name
                        ));
                        break;
                    }
                } else if bytes.windows(12).any(|w| w == b"Lio/flutter/")
                    || bytes.windows(11).any(|w| w == b"io.flutter." || w == b"io/flutter/")
                {
                    flutter_evidence.push(format!(
                        "Flutter signature found in DEX '{}': io.flutter",
                        dex_entry.name
                    ));
                    break;
                }
            }
        }

        if !flutter_evidence.is_empty() {
            detections.push(LanguageDetection {
                language: "Flutter / Dart".to_string(),
                confidence: "High".to_string(),
                evidence: flutter_evidence,
            });
        }

        detections
    }

    /// Return slice of all discovered resource entries (including `res/` and AndResGuard `r/`).
    pub fn resource_entries(&self) -> &[ApkEntry] {
        &self.resource_entries
    }

    /// Safely extracts all package contents to a destination directory,
    /// protecting against Zip Slip path traversal and Windows reserved device names.
    pub fn extract_to<P: AsRef<Path>>(&self, destination: P) -> Result<(), AppError> {
        let dest = destination.as_ref();
        std::fs::create_dir_all(dest)?;
        let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

        match &self.source {
            ApkSource::Archive(path) => {
                if let Some(normalized) = &self.normalized_archive_data {
                    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(normalized.as_slice())).map_err(|e| {
                        AppError::InvalidBinary(format!("Failed to read APK archive '{}': {}", path.display(), e))
                    })?;
                    Self::extract_from_archive_inner(&mut archive, dest, &canonical_dest)?;
                } else {
                    let file = std::fs::File::open(path)?;
                    match zip::ZipArchive::new(file) {
                        Ok(mut archive) => {
                            match Self::extract_from_archive_inner(&mut archive, dest, &canonical_dest) {
                                Ok(()) => return Ok(()),
                                Err(AppError::InvalidBinary(ref msg)) if is_password_or_unsupported_error(msg) => {
                                    let raw = std::fs::read(path)?;
                                    let norm = normalize_zip_encryption_flags(&raw);
                                    let mut norm_archive = zip::ZipArchive::new(std::io::Cursor::new(norm)).map_err(|err| {
                                        AppError::InvalidBinary(format!("Failed to read normalized archive: {}", err))
                                    })?;
                                    Self::extract_from_archive_inner(&mut norm_archive, dest, &canonical_dest)?;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        Err(zip::result::ZipError::UnsupportedArchive(_)) => {
                            let raw = std::fs::read(path)?;
                            let norm = normalize_zip_encryption_flags(&raw);
                            let mut norm_archive = zip::ZipArchive::new(std::io::Cursor::new(norm)).map_err(|err| {
                                AppError::InvalidBinary(format!("Failed to read normalized archive: {}", err))
                            })?;
                            Self::extract_from_archive_inner(&mut norm_archive, dest, &canonical_dest)?;
                        }
                        Err(e) => {
                            return Err(AppError::InvalidBinary(format!(
                                "Failed to open APK archive '{}': {}",
                                path.display(),
                                e
                            )));
                        }
                    }
                }
            }
            ApkSource::Directory(base_dir) => {
                let mut all_files = Vec::new();
                collect_files_recursive(base_dir, &mut all_files)?;

                for file_path in all_files {
                    let rel = file_path
                        .strip_prefix(base_dir)
                        .unwrap_or(&file_path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let sanitized = sanitize_archive_entry_path(&rel);
                    if sanitized.is_empty() {
                        continue;
                    }

                    let target_path = dest.join(&sanitized);
                    if !is_path_safe_descendant(&target_path, dest, &canonical_dest) {
                        continue;
                    }

                    if let Some(parent) = target_path.parent() {
                        std::fs::create_dir_all(parent)?;
                        if let Ok(canon_parent) = parent.canonicalize() {
                            if !canon_parent.starts_with(&canonical_dest) {
                                continue;
                            }
                        }
                    }

                    if let Ok(meta) = std::fs::symlink_metadata(&target_path) {
                        if meta.file_type().is_symlink() {
                            continue;
                        }
                    }

                    std::fs::copy(&file_path, &target_path)?;
                }
            }
            ApkSource::Standalone(path) => {
                let fname = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                let sanitized = sanitize_archive_entry_path(&fname);
                if !sanitized.is_empty() {
                    let target_path = dest.join(&sanitized);
                    if is_path_safe_descendant(&target_path, dest, &canonical_dest) {
                        if let Some(parent) = target_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        if let Ok(meta) = std::fs::symlink_metadata(&target_path) {
                            if meta.file_type().is_symlink() {
                                return Ok(());
                            }
                        }
                        std::fs::copy(path, &target_path)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Unpack and decode the APK package into a fully structured directory containing:
    /// - Human-readable `AndroidManifest.xml` (decoded from binary AXML if needed)
    /// - `res/` directory with decoded XML layouts/drawables and values
    /// - `res/values/strings.xml` reconstructed from `resources.arsc`
    /// - Disassembled Dalvik `.smali` files in `smali/` and `smali_classes2/`
    /// - Native shared libraries in `lib/<abi>/`
    /// - Raw assets in `assets/`
    ///
    /// Implements Unified Cohesive Hybrid Pipeline:
    /// - RVS Master Engine supervision:
    ///   - If `prefer_java` is true and apktool is present: attempt apktool decode.
    ///   - If apktool succeeds, inspect outputs; verify and repair missing/corrupt pieces (manifest, resources, strings, lib, assets).
    ///   - If apktool fails on resources/AXML: cooperatively retry apktool with `-r` (`--no-res`) to salvage smali code, while RVS Rust decodes resources and manifest.
    ///   - If apktool completely fails, smoothly fallback to autonomous pure-Rust extraction.
    ///   - In all modes, RVS automatically performs Agent Augmentation, generating attack surface profile, class indexing, JNI cross-references, and summary artifacts.
    pub fn unpack(&self, destination: &Path, prefer_java: bool) -> Result<ApkUnpackSummary, AppError> {
        if destination.exists() && destination.is_file() {
            return Err(AppError::InvalidBinary(format!(
                "Destination path '{}' is an existing file, not a directory",
                destination.display()
            )));
        }

        let mut repairs = Vec::new();
        let mut engine_used = "rust-native".to_string();
        let mut manifest_extracted = false;
        let mut resources_extracted = false;
        let mut smali_generated = false;
        let mut java_succeeded = false;

        // Tier 1 / Hybrid: Java-accelerated extraction via apktool with cooperative fallback
        if prefer_java {
            if let ApkSource::Archive(apk_path) = &self.source {
                if apk_path.is_file() && super::java::JavaEnvironment::find_apktool().is_some() {
                    // Attempt 1: Standard apktool decode
                    if let Ok(()) = super::java::run_apktool_decode(apk_path, destination, true, None) {
                        java_succeeded = true;
                        engine_used = "java-apktool".to_string();

                        // Master Engine Post-Unpack Verification & Repair:
                        // 1. Verify AndroidManifest.xml
                        let manifest_p = destination.join("AndroidManifest.xml");
                        if !manifest_p.is_file() || std::fs::metadata(&manifest_p).map(|m| m.len() == 0).unwrap_or(true) {
                            if let Some(m_bytes) = &self.manifest_data {
                                if let Ok(xml_str) = super::manifest::decode_raw_manifest(m_bytes) {
                                    let _ = std::fs::write(&manifest_p, xml_str.as_bytes());
                                    repairs.push("manifest_repaired".to_string());
                                }
                            }
                        }

                        // 2. Verify res/ and strings.xml
                        let strings_p = destination.join("res").join("values").join("strings.xml");
                        if !strings_p.is_file() {
                            if let Ok(arsc_bytes) = self.read_entry("resources.arsc") {
                                let strings = super::resources::extract_arsc_strings(&arsc_bytes);
                                if !strings.is_empty() {
                                    let xml = super::resources::generate_strings_xml(&strings);
                                    if let Some(p) = strings_p.parent() {
                                        let _ = std::fs::create_dir_all(p);
                                    }
                                    let _ = std::fs::write(&strings_p, xml.as_bytes());
                                    repairs.push("strings_xml_repaired".to_string());
                                }
                            }
                        }

                        // 3. Ensure assets/ and lib/ are preserved
                        self.repair_missing_assets_and_libs(destination, &mut repairs);
                    } else {
                        // Attempt 2: Cooperative decoding with `-r` (no-res) to salvage smali
                        let _ = std::fs::remove_dir_all(destination);
                        if let Ok(()) = super::java::run_apktool_decode_options(
                            apk_path, destination, true, true, false, None,
                        ) {
                            java_succeeded = true;
                            engine_used = "hybrid-cooperative".to_string();
                            repairs.push("cooperative_no_res_smali_salvaged".to_string());

                            // Rust engine steps in cooperatively to decode manifest, resources, and strings
                            let _ = self.extract_manifest_pure_rust(destination, &mut manifest_extracted);
                            let _ = self.extract_resources_pure_rust(destination, &mut resources_extracted);
                            self.repair_missing_assets_and_libs(destination, &mut repairs);
                        } else {
                            // Clean up destination for pure-Rust extraction
                            let _ = std::fs::remove_dir_all(destination);
                        }
                    }
                }
            }
        }

        // Tier 2: Pure-Rust autonomous fallback extraction (if Java not preferred, missing, or failed)
        if !java_succeeded {
            std::fs::create_dir_all(destination)?;
            self.extract_manifest_pure_rust(destination, &mut manifest_extracted)?;
            self.extract_resources_pure_rust(destination, &mut resources_extracted)?;
            self.extract_assets_and_libs_pure_rust(destination)?;
            self.extract_smali_pure_rust(destination, &mut smali_generated)?;
            engine_used = "rust-native".to_string();
        } else {
            manifest_extracted = destination.join("AndroidManifest.xml").exists();
            resources_extracted = destination.join("res").exists();
            smali_generated = destination.join("smali").exists() || destination.join("smali_classes2").exists();
        }

        // Automatic Agent Augmentation: attack surface, class index, JNI cross-references, artifacts
        let agent_summary = self.generate_and_write_agent_summary(destination);

        let mut final_files = Vec::new();
        let _ = collect_files_recursive(destination, &mut final_files);

        Ok(ApkUnpackSummary {
            destination: destination.to_path_buf(),
            engine: engine_used,
            file_count: final_files.len(),
            manifest_extracted,
            resources_extracted,
            smali_generated,
            agent_summary: Some(agent_summary),
            repairs,
        })
    }

    fn repair_missing_assets_and_libs(&self, destination: &Path, repairs: &mut Vec<String>) {
        let canonical_dest = destination.canonicalize().unwrap_or_else(|_| destination.to_path_buf());
        for entry in &self.asset_entries {
            let sanitized = sanitize_archive_entry_path(&entry.name);
            if sanitized.is_empty() {
                continue;
            }
            let target = destination.join(&sanitized);
            if !target.exists() && is_path_safe_descendant(&target, destination, &canonical_dest) {
                if let Some(p) = target.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                if let Ok(bytes) = self.read_entry(&entry.name) {
                    let _ = std::fs::write(&target, &bytes);
                    if !repairs.contains(&"assets_repaired".to_string()) {
                        repairs.push("assets_repaired".to_string());
                    }
                }
            }
        }

        for entries in self.native_libraries.values() {
            for entry in entries {
                let sanitized = sanitize_archive_entry_path(&entry.name);
                if sanitized.is_empty() {
                    continue;
                }
                let target = destination.join(&sanitized);
                if !target.exists() && is_path_safe_descendant(&target, destination, &canonical_dest) {
                    if let Some(p) = target.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    if let Ok(bytes) = self.read_entry(&entry.name) {
                        let _ = std::fs::write(&target, &bytes);
                        if !repairs.contains(&"native_libs_repaired".to_string()) {
                            repairs.push("native_libs_repaired".to_string());
                        }
                    }
                }
            }
        }
    }

    fn extract_manifest_pure_rust(&self, destination: &Path, manifest_extracted: &mut bool) -> Result<(), AppError> {
        let canonical_dest = destination.canonicalize().unwrap_or_else(|_| destination.to_path_buf());
        if let Some(manifest_bytes) = &self.manifest_data {
            let out_manifest = destination.join("AndroidManifest.xml");
            if is_path_safe_descendant(&out_manifest, destination, &canonical_dest) {
                if self.is_manifest_binary || super::manifest::is_binary_axml(manifest_bytes) {
                    if let Ok(xml_str) = super::manifest::decode_raw_manifest(manifest_bytes) {
                        if std::fs::write(&out_manifest, xml_str.as_bytes()).is_ok() {
                            *manifest_extracted = true;
                        }
                    } else if std::fs::write(&out_manifest, manifest_bytes).is_ok() {
                        *manifest_extracted = true;
                    }
                } else if std::fs::write(&out_manifest, manifest_bytes).is_ok() {
                    *manifest_extracted = true;
                }
            }
        }
        Ok(())
    }

    fn extract_resources_pure_rust(&self, destination: &Path, resources_extracted: &mut bool) -> Result<(), AppError> {
        let canonical_dest = destination.canonicalize().unwrap_or_else(|_| destination.to_path_buf());
        for entry in &self.resource_entries {
            if entry.name == "resources.arsc" {
                continue;
            }
            let sanitized = sanitize_archive_entry_path(&entry.name);
            if sanitized.is_empty() {
                continue;
            }
            let target_path = destination.join(&sanitized);
            if !is_path_safe_descendant(&target_path, destination, &canonical_dest) {
                continue;
            }
            if let Some(parent) = target_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(bytes) = self.read_entry(&entry.name) {
                if (entry.name.ends_with(".xml") || super::manifest::is_binary_axml(&bytes)) && !bytes.is_empty() {
                    if let Ok(decoded) = super::manifest::decode_raw_manifest(&bytes) {
                        if std::fs::write(&target_path, decoded.as_bytes()).is_ok() {
                            *resources_extracted = true;
                            continue;
                        }
                    }
                }
                if std::fs::write(&target_path, &bytes).is_ok() {
                    *resources_extracted = true;
                }
            }
        }

        if let Ok(arsc_bytes) = self.read_entry("resources.arsc") {
            let strings = super::resources::extract_arsc_strings(&arsc_bytes);
            if !strings.is_empty() {
                let xml = super::resources::generate_strings_xml(&strings);
                let strings_path = destination.join("res").join("values").join("strings.xml");
                if is_path_safe_descendant(&strings_path, destination, &canonical_dest) {
                    if let Some(p) = strings_path.parent() {
                        let _ = std::fs::create_dir_all(p);
                    }
                    if std::fs::write(&strings_path, xml.as_bytes()).is_ok() {
                        *resources_extracted = true;
                    }
                }
            }
        }
        Ok(())
    }

    fn extract_assets_and_libs_pure_rust(&self, destination: &Path) -> Result<(), AppError> {
        let canonical_dest = destination.canonicalize().unwrap_or_else(|_| destination.to_path_buf());
        for entry in &self.asset_entries {
            let sanitized = sanitize_archive_entry_path(&entry.name);
            if sanitized.is_empty() {
                continue;
            }
            let target_path = destination.join(&sanitized);
            if !is_path_safe_descendant(&target_path, destination, &canonical_dest) {
                continue;
            }
            if let Some(parent) = target_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(bytes) = self.read_entry(&entry.name) {
                let _ = std::fs::write(&target_path, &bytes);
            }
        }

        for entries in self.native_libraries.values() {
            for entry in entries {
                let sanitized = sanitize_archive_entry_path(&entry.name);
                if sanitized.is_empty() {
                    continue;
                }
                let target_path = destination.join(&sanitized);
                if !is_path_safe_descendant(&target_path, destination, &canonical_dest) {
                    continue;
                }
                if let Some(parent) = target_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(bytes) = self.read_entry(&entry.name) {
                    let _ = std::fs::write(&target_path, &bytes);
                }
            }
        }
        Ok(())
    }

    fn extract_smali_pure_rust(&self, destination: &Path, smali_generated: &mut bool) -> Result<(), AppError> {
        let canonical_dest = destination.canonicalize().unwrap_or_else(|_| destination.to_path_buf());
        for (idx, dex_entry) in self.dex_entries.iter().enumerate() {
            let smali_dirname = if idx == 0 {
                "smali".to_string()
            } else {
                format!("smali_classes{}", idx + 1)
            };
            let smali_root = destination.join(&smali_dirname);
            if let Ok(bytes) = self.read_entry(&dex_entry.name) {
                if let Ok(dex_res) = super::dex::parse_dex_bytes(&bytes, &dex_entry.name) {
                    for c in &dex_res.classes {
                        let raw_name = c.name.trim_matches(|ch| ch == 'L' || ch == ';');
                        let rel_path = format!("{}.smali", raw_name);
                        let target = smali_root.join(&rel_path);
                        if target.starts_with(&smali_root) && is_path_safe_descendant(&target, destination, &canonical_dest) {
                            if let Some(p) = target.parent() {
                                let _ = std::fs::create_dir_all(p);
                            }
                            let smali_text = super::dex::format_class_smali(c);
                            if std::fs::write(&target, smali_text.as_bytes()).is_ok() {
                                *smali_generated = true;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn generate_and_write_agent_summary(&self, destination: &Path) -> AgentSummary {
        // 1. Manifest attack surface analysis
        let manifest_info = {
            let manifest_path = destination.join("AndroidManifest.xml");
            if manifest_path.is_file() {
                if let Ok(bytes) = std::fs::read(&manifest_path) {
                    ManifestInfo::parse(&bytes, super::manifest::is_binary_axml(&bytes)).unwrap_or_default()
                } else {
                    ManifestInfo::default()
                }
            } else if let Some(bytes) = &self.manifest_data {
                ManifestInfo::parse(bytes, self.is_manifest_binary || super::manifest::is_binary_axml(bytes)).unwrap_or_default()
            } else {
                ManifestInfo::default()
            }
        };

        let package_name = if manifest_info.package_name.is_empty() {
            None
        } else {
            Some(manifest_info.package_name.clone())
        };
        let version_name = manifest_info.version_name.clone();
        let version_code = manifest_info.version_code;
        let debuggable = manifest_info.debuggable;
        let dangerous_permissions = manifest_info.dangerous_permissions.clone();

        let mut exported_activities = Vec::new();
        let mut exported_services = Vec::new();
        let mut exported_receivers = Vec::new();
        let mut exported_providers = Vec::new();
        let mut deep_link_schemes = Vec::new();

        for comp in &manifest_info.components {
            if comp.exported {
                match comp.component_type.as_str() {
                    "activity" => {
                        if !exported_activities.contains(&comp.name) {
                            exported_activities.push(comp.name.clone());
                        }
                    }
                    "service" => {
                        if !exported_services.contains(&comp.name) {
                            exported_services.push(comp.name.clone());
                        }
                    }
                    "receiver" if !exported_receivers.contains(&comp.name) => {
                        exported_receivers.push(comp.name.clone());
                    }
                    "provider" if !exported_providers.contains(&comp.name) => {
                        exported_providers.push(comp.name.clone());
                    }
                    _ => {}
                }
            }
            for f in &comp.intent_filters {
                for sch in &f.data_schemes {
                    if !deep_link_schemes.contains(sch) {
                        deep_link_schemes.push(sch.clone());
                    }
                }
            }
        }

        // If components were empty (e.g. basic manifest), fallback to plain activity list
        if exported_activities.is_empty() && manifest_info.components.is_empty() {
            exported_activities = manifest_info.activities.clone();
            exported_services = manifest_info.services.clone();
            exported_receivers = manifest_info.receivers.clone();
            exported_providers = manifest_info.providers.clone();
        }

        // 2. Class & method indexing
        let mut all_classes = Vec::new();
        if let Ok(dex_results) = self.analyze_dex(None) {
            for d in dex_results {
                all_classes.extend(d.classes);
            }
        }

        if all_classes.is_empty() {
            // Try scanning smali directories from destination
            let smali_dir = destination.join("smali");
            if smali_dir.is_dir() {
                if let Ok(smali_res) = parse_smali_directory(&smali_dir) {
                    all_classes.extend(smali_res.classes);
                }
            }
            if let Ok(entries) = std::fs::read_dir(destination) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("smali_classes") {
                            if let Ok(smali_res) = parse_smali_directory(&path) {
                                all_classes.extend(smali_res.classes);
                            }
                        }
                    }
                }
            }
        }

        let total_classes = all_classes.len();
        let mut total_methods = 0;
        let mut native_methods_count = 0;
        for c in &all_classes {
            total_methods += c.methods.len();
            for m in &c.methods {
                if (m.access_flags & 0x0100) != 0 {
                    native_methods_count += 1;
                }
            }
        }

        // 3. Native libraries and JNI cross-referencing
        let mut native_libs = self.analyze_native_libraries().unwrap_or_default();
        if native_libs.is_empty() {
            let lib_dir = destination.join("lib");
            if lib_dir.is_dir() {
                let mut lib_files = Vec::new();
                let _ = collect_files_recursive(&lib_dir, &mut lib_files);
                for lf in lib_files {
                    if lf.extension().and_then(|s| s.to_str()) == Some("so") {
                        if let Ok(bytes) = std::fs::read(&lf) {
                            let fname = lf.file_name().unwrap_or_default().to_string_lossy().to_string();
                            if let Ok(anal) = super::native_so::parse_native_so_bytes(&bytes, &fname) {
                                native_libs.push(anal);
                            }
                        }
                    }
                }
            }
        }

        let jni_cross_references = super::native_so::cross_reference_classes(&all_classes, &native_libs);
        let native_methods_count = native_methods_count.max(jni_cross_references.len());

        // 4. Multi-language detection
        let languages = self.detect_languages();

        let summary = AgentSummary {
            package_name,
            version_name,
            version_code,
            debuggable,
            total_classes,
            total_methods,
            native_methods_count,
            dangerous_permissions,
            exported_activities,
            exported_services,
            exported_receivers,
            exported_providers,
            deep_link_schemes,
            jni_cross_references,
            languages,
            attack_surface_components: manifest_info.components,
        };

        // 5. Generate rvs_agent_summary.json
        if let Ok(json_str) = serde_json::to_string_pretty(&summary) {
            let _ = std::fs::write(destination.join("rvs_agent_summary.json"), json_str.as_bytes());
        }

        // 6. Generate rvs_agent_summary.md
        let mut md = String::new();
        md.push_str("# RVS APK Agent Reconnaissance Summary\n\n");
        md.push_str(&format!("- **Package**: `{}`\n", summary.package_name.as_deref().unwrap_or("unknown")));
        md.push_str(&format!("- **Version**: `{}` (code: {:?})\n", summary.version_name.as_deref().unwrap_or("unknown"), summary.version_code));
        md.push_str(&format!("- **Debuggable**: `{}`\n", summary.debuggable));
        md.push_str(&format!("- **Classes Index**: {} total classes, {} methods ({} native ACC_NATIVE)\n\n", summary.total_classes, summary.total_methods, summary.native_methods_count));

        md.push_str("## Attack Surface\n\n");
        md.push_str(&format!("- **Exported Activities ({})**:\n", summary.exported_activities.len()));
        for a in &summary.exported_activities {
            md.push_str(&format!("  - `{}`\n", a));
        }
        md.push_str(&format!("- **Exported Services ({})**:\n", summary.exported_services.len()));
        for s in &summary.exported_services {
            md.push_str(&format!("  - `{}`\n", s));
        }
        md.push_str(&format!("- **Exported Receivers ({})**:\n", summary.exported_receivers.len()));
        for r in &summary.exported_receivers {
            md.push_str(&format!("  - `{}`\n", r));
        }
        md.push_str(&format!("- **Exported Providers ({})**:\n", summary.exported_providers.len()));
        for p in &summary.exported_providers {
            md.push_str(&format!("  - `{}`\n", p));
        }
        if !summary.deep_link_schemes.is_empty() {
            md.push_str(&format!("- **Deep Link Schemes**: {}\n", summary.deep_link_schemes.join(", ")));
        }
        md.push('\n');

        md.push_str(&format!("## Dangerous Permissions ({})\n\n", summary.dangerous_permissions.len()));
        for perm in &summary.dangerous_permissions {
            md.push_str(&format!("- `{}`\n", perm));
        }
        md.push('\n');

        md.push_str(&format!("## JNI Native Method Cross-References ({})\n\n", summary.jni_cross_references.len()));
        if summary.jni_cross_references.is_empty() {
            md.push_str("_No native methods detected._\n\n");
        } else {
            md.push_str("| Dalvik Class | Dalvik Method | Native Symbol | Library | ABI | Address | Registration |\n");
            md.push_str("|---|---|---|---|---|---|---|\n");
            for jni in &summary.jni_cross_references {
                md.push_str(&format!(
                    "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                    jni.dalvik_class,
                    jni.dalvik_method,
                    jni.native_symbol.as_deref().unwrap_or("-"),
                    jni.library_path.as_deref().unwrap_or("-"),
                    jni.abi.as_deref().unwrap_or("-"),
                    jni.address.map(|a| format!("0x{:x}", a)).unwrap_or_else(|| "-".to_string()),
                    jni.registration_type,
                ));
            }
            md.push('\n');
        }

        md.push_str("## Languages & Frameworks\n\n");
        for lang in &summary.languages {
            md.push_str(&format!("- **{}** (confidence: {}): {}\n", lang.language, lang.confidence, lang.evidence.join(", ")));
        }
        md.push('\n');

        let _ = std::fs::write(destination.join("rvs_agent_summary.md"), md.as_bytes());

        summary
    }

    // --- Internal Ingestion Methods ---

    fn open_archive(path: &Path) -> Result<Self, AppError> {
        let file = std::fs::File::open(path)?;
        match zip::ZipArchive::new(file) {
            Ok(archive) => {
                match Self::open_archive_from_reader(archive, path, None) {
                    Ok(pkg) => Ok(pkg),
                    Err(AppError::InvalidBinary(ref msg)) if is_password_or_unsupported_error(msg) => {
                        Self::open_archive_normalized(path)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(zip::result::ZipError::UnsupportedArchive(_)) => {
                Self::open_archive_normalized(path)
            }
            Err(e) => Err(AppError::InvalidBinary(format!(
                "Failed to open APK archive '{}': {}",
                path.display(),
                e
            ))),
        }
    }

    fn open_archive_normalized(path: &Path) -> Result<Self, AppError> {
        let raw = std::fs::read(path)?;
        let normalized = normalize_zip_encryption_flags(&raw);
        let archive = zip::ZipArchive::new(std::io::Cursor::new(normalized.clone())).map_err(|e| {
            AppError::InvalidBinary(format!(
                "Failed to open normalized APK archive '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::open_archive_from_reader(archive, path, Some(normalized))
    }

    fn open_archive_from_reader<R: Read + Seek>(
        mut archive: zip::ZipArchive<R>,
        path: &Path,
        normalized_data: Option<Vec<u8>>,
    ) -> Result<Self, AppError> {
        let mut manifest_data = None;
        let mut is_manifest_binary = false;
        let mut dex_entries = Vec::new();
        let mut native_libraries: HashMap<String, Vec<ApkEntry>> = HashMap::new();
        let mut asset_entries = Vec::new();
        let mut resource_entries = Vec::new();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(|e| {
                AppError::InvalidBinary(format!(
                    "Failed to read archive entry at index {}: {}",
                    i, e
                ))
            })?;

            let name = entry.name().to_string();
            let sanitized_name = sanitize_archive_entry_path(&name);
            if sanitized_name.is_empty() {
                continue;
            }
            let size = entry.size();

            if sanitized_name == "AndroidManifest.xml" {
                let mut data = Vec::with_capacity(size as usize);
                entry.read_to_end(&mut data).map_err(|e| {
                    AppError::InvalidBinary(format!(
                        "Failed to read AndroidManifest.xml: {}",
                        e
                    ))
                })?;
                is_manifest_binary = is_binary_axml(&data);
                manifest_data = Some(data);
            } else if sanitized_name.ends_with(".dex") {
                dex_entries.push(ApkEntry {
                    name: sanitized_name,
                    size,
                    path: None,
                });
            } else if sanitized_name.starts_with("lib/") {
                let mut abi = extract_abi_from_path(&sanitized_name);
                if abi == "unknown" {
                    let mut data = Vec::with_capacity(size.min(1024) as usize);
                    if std::io::Read::by_ref(&mut entry).take(1024).read_to_end(&mut data).is_ok() {
                        if let Some(detected) = detect_elf_abi(&data) {
                            if detected != "unknown" {
                                abi = detected;
                            }
                        }
                    }
                }
                native_libraries
                    .entry(abi)
                    .or_default()
                    .push(ApkEntry {
                        name: sanitized_name,
                        size,
                        path: None,
                    });
            } else if sanitized_name.starts_with("assets/") {
                asset_entries.push(ApkEntry {
                    name: sanitized_name,
                    size,
                    path: None,
                });
            } else if sanitized_name == "resources.arsc"
                || sanitized_name.starts_with("res/")
                || sanitized_name.starts_with("r/")
            {
                resource_entries.push(ApkEntry {
                    name: sanitized_name,
                    size,
                    path: None,
                });
            }
        }

        dex_entries.sort_by(|a, b| a.name.cmp(&b.name));
        asset_entries.sort_by(|a, b| a.name.cmp(&b.name));
        resource_entries.sort_by(|a, b| a.name.cmp(&b.name));
        for list in native_libraries.values_mut() {
            list.sort_by(|a, b| a.name.cmp(&b.name));
        }

        Ok(Self {
            source: ApkSource::Archive(path.to_path_buf()),
            manifest_data,
            is_manifest_binary,
            dex_entries,
            native_libraries,
            asset_entries,
            resource_entries,
            normalized_archive_data: normalized_data,
        })
    }

    fn open_directory(path: &Path) -> Result<Self, AppError> {
        let mut all_files = Vec::new();
        collect_files_recursive(path, &mut all_files)?;

        let mut manifest_data = None;
        let mut is_manifest_binary = false;
        let mut dex_entries = Vec::new();
        let mut native_libraries: HashMap<String, Vec<ApkEntry>> = HashMap::new();
        let mut asset_entries = Vec::new();
        let mut resource_entries = Vec::new();

        // Check for AndroidManifest.xml: prefer root AndroidManifest.xml
        let root_manifest = path.join("AndroidManifest.xml");
        if root_manifest.is_file() {
            let data = std::fs::read(&root_manifest)?;
            is_manifest_binary = is_binary_axml(&data);
            manifest_data = Some(data);
        } else {
            for file_path in &all_files {
                if file_path.file_name().and_then(|s| s.to_str()) == Some("AndroidManifest.xml") {
                    let data = std::fs::read(file_path)?;
                    is_manifest_binary = is_binary_axml(&data);
                    manifest_data = Some(data);
                    break;
                }
            }
        }

        for file_path in &all_files {
            let meta = std::fs::metadata(file_path)?;
            let size = meta.len();
            let rel = file_path
                .strip_prefix(path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .replace('\\', "/");
            let sanitized_rel = sanitize_archive_entry_path(&rel);
            if sanitized_rel.is_empty() {
                continue;
            }

            let ext = file_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if sanitized_rel.ends_with(".dex") || ext == "dex" {
                dex_entries.push(ApkEntry {
                    name: sanitized_rel,
                    size,
                    path: Some(file_path.clone()),
                });
            } else if sanitized_rel.starts_with("lib/") {
                let mut abi = extract_abi_from_path(&sanitized_rel);
                if abi == "unknown" {
                    if let Some(detected) = detect_elf_abi_from_file(file_path) {
                        abi = detected;
                    }
                }
                native_libraries
                    .entry(abi)
                    .or_default()
                    .push(ApkEntry {
                        name: sanitized_rel,
                        size,
                        path: Some(file_path.clone()),
                    });
            } else if sanitized_rel.starts_with("assets/") {
                asset_entries.push(ApkEntry {
                    name: sanitized_rel,
                    size,
                    path: Some(file_path.clone()),
                });
            } else if sanitized_rel == "resources.arsc"
                || sanitized_rel.starts_with("res/")
                || sanitized_rel.starts_with("r/")
            {
                resource_entries.push(ApkEntry {
                    name: sanitized_rel,
                    size,
                    path: Some(file_path.clone()),
                });
            }
        }

        // If no DEX entries were found, discover smali/ and smali_classes*/ directories
        if dex_entries.is_empty() {
            let mut smali_dirs: HashMap<String, (u64, PathBuf)> = HashMap::new();
            for file_path in &all_files {
                let rel = file_path
                    .strip_prefix(path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let sanitized_rel = sanitize_archive_entry_path(&rel);
                if sanitized_rel.ends_with(".smali") {
                    let root_smali = sanitized_rel.split('/').next().unwrap_or("smali");
                    if root_smali == "smali" || root_smali.starts_with("smali_classes") {
                        let size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
                        let entry = smali_dirs.entry(root_smali.to_string()).or_insert_with(|| {
                            (0, path.join(root_smali))
                        });
                        entry.0 += size;
                    }
                }
            }

            let mut sorted_smali: Vec<_> = smali_dirs.into_iter().collect();
            sorted_smali.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, (size, dir_path)) in sorted_smali {
                dex_entries.push(ApkEntry {
                    name,
                    size,
                    path: Some(dir_path),
                });
            }
        }

        dex_entries.sort_by(|a, b| a.name.cmp(&b.name));
        asset_entries.sort_by(|a, b| a.name.cmp(&b.name));
        resource_entries.sort_by(|a, b| a.name.cmp(&b.name));
        for list in native_libraries.values_mut() {
            list.sort_by(|a, b| a.name.cmp(&b.name));
        }

        Ok(Self {
            source: ApkSource::Directory(path.to_path_buf()),
            manifest_data,
            is_manifest_binary,
            dex_entries,
            native_libraries,
            asset_entries,
            resource_entries,
            normalized_archive_data: None,
        })
    }

    fn open_standalone_dex(path: &Path, file_name: &str, size: u64) -> Result<Self, AppError> {
        let entry = ApkEntry {
            name: file_name.to_string(),
            size,
            path: Some(path.to_path_buf()),
        };
        Ok(Self {
            source: ApkSource::Standalone(path.to_path_buf()),
            manifest_data: None,
            is_manifest_binary: false,
            dex_entries: vec![entry],
            native_libraries: HashMap::new(),
            asset_entries: Vec::new(),
            resource_entries: Vec::new(),
            normalized_archive_data: None,
        })
    }

    fn open_standalone_so(path: &Path, file_name: &str, size: u64) -> Result<Self, AppError> {
        let abi = detect_elf_abi_from_file(path).unwrap_or_else(|| "unknown".to_string());
        let entry = ApkEntry {
            name: file_name.to_string(),
            size,
            path: Some(path.to_path_buf()),
        };
        let mut native_libraries = HashMap::new();
        native_libraries.insert(abi, vec![entry]);

        Ok(Self {
            source: ApkSource::Standalone(path.to_path_buf()),
            manifest_data: None,
            is_manifest_binary: false,
            dex_entries: Vec::new(),
            native_libraries,
            asset_entries: Vec::new(),
            resource_entries: Vec::new(),
            normalized_archive_data: None,
        })
    }

    fn read_from_archive_inner<R: Read + Seek>(
        archive: &mut zip::ZipArchive<R>,
        entry_name: &str,
        sanitized_query: &str,
    ) -> Result<Option<Vec<u8>>, AppError> {
        // 1. Exact match
        if let Ok(mut zip_file) = archive.by_name(entry_name) {
            let mut buf = Vec::with_capacity(zip_file.size() as usize);
            zip_file.read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }

        // 2. Sanitized query match
        if !sanitized_query.is_empty() && sanitized_query != entry_name {
            if let Ok(mut zip_file) = archive.by_name(sanitized_query) {
                let mut buf = Vec::with_capacity(zip_file.size() as usize);
                zip_file.read_to_end(&mut buf)?;
                return Ok(Some(buf));
            }
        }

        // 3. Suffix / normalized match
        let normalized = entry_name.replace('\\', "/");
        let target_suffix = format!("/{}", normalized.trim_start_matches('/'));
        let query_suffix = if !sanitized_query.is_empty() {
            format!("/{}", sanitized_query.trim_start_matches('/'))
        } else {
            String::new()
        };

        for i in 0..archive.len() {
            match archive.by_index(i) {
                Ok(mut zip_file) => {
                    let name = zip_file.name();
                    let has_traversal = name.split(['/', '\\']).any(|s| s.trim() == "..");
                    if has_traversal {
                        continue;
                    }
                    let sanitized_entry = sanitize_archive_entry_path(name);
                    if sanitized_entry.is_empty() {
                        continue;
                    }
                    if name == normalized
                        || name == entry_name
                        || (!sanitized_query.is_empty() && (name == sanitized_query || sanitized_entry == sanitized_query))
                        || (sanitized_entry == entry_name || sanitized_entry == normalized)
                        || (!target_suffix.is_empty() && sanitized_entry.ends_with(&target_suffix))
                        || (!query_suffix.is_empty() && sanitized_entry.ends_with(&query_suffix))
                    {
                        let mut buf = Vec::with_capacity(zip_file.size() as usize);
                        zip_file.read_to_end(&mut buf)?;
                        return Ok(Some(buf));
                    }
                }
                Err(zip::result::ZipError::UnsupportedArchive(msg)) => {
                    return Err(AppError::InvalidBinary(format!("Unsupported archive entry: {}", msg)));
                }
                Err(_) => {}
            }
        }

        Ok(None)
    }

    fn extract_from_archive_inner<R: Read + Seek>(
        archive: &mut zip::ZipArchive<R>,
        dest: &Path,
        canonical_dest: &Path,
    ) -> Result<(), AppError> {
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(|e| {
                AppError::InvalidBinary(format!("Failed to read archive entry at index {}: {}", i, e))
            })?;

            let raw_name = entry.name().to_string();
            let sanitized = sanitize_archive_entry_path(&raw_name);
            if sanitized.is_empty() {
                continue;
            }

            let target_path = dest.join(&sanitized);
            if !is_path_safe_descendant(&target_path, dest, canonical_dest) {
                continue;
            }

            if entry.is_dir() || sanitized.ends_with('/') {
                std::fs::create_dir_all(&target_path)?;
            } else {
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent)?;
                    if let Ok(canon_parent) = parent.canonicalize() {
                        if !canon_parent.starts_with(canonical_dest) {
                            continue;
                        }
                    }
                }

                // Refuse to write through symlinks
                if let Ok(meta) = std::fs::symlink_metadata(&target_path) {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                }

                let mut outfile = std::fs::File::create(&target_path)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }
        Ok(())
    }
}

/// Neutralizes fake encryption flags in a raw ZIP archive buffer.
///
/// Clears bit 0 (`0x0001`, encrypted flag) at offset +6 in Local File Headers (`PK\x03\x04`)
/// and at offset +8 in Central Directory Headers (`PK\x01\x02`).
/// Traverses via End of Central Directory (EOCD) to follow authoritative pointers to avoid
/// corrupting uncompressed STORED payloads that might contain `PK\x03\x04` magic bytes.
/// Falls back to signature scanning if EOCD is damaged or absent.
pub fn normalize_zip_encryption_flags(data: &[u8]) -> Vec<u8> {
    if data.len() < 22 {
        return data.to_vec();
    }

    let mut normalized = data.to_vec();

    // 1. Primary Structural Pass: EOCD-Directed Traversal
    // EOCD record is at least 22 bytes. Max comment length is 65535, so search window is up to 65557 bytes from EOF.
    let min_pos = data.len().saturating_sub(65557);
    let mut eocd_found = false;

    for i in (min_pos..=data.len().saturating_sub(22)).rev() {
        if &data[i..i + 4] == b"PK\x05\x06" {
            let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            if i + 22 + comment_len <= data.len() {
                let cd_count = u16::from_le_bytes([data[i + 10], data[i + 11]]) as usize;
                let cd_size = u32::from_le_bytes([
                    data[i + 12],
                    data[i + 13],
                    data[i + 14],
                    data[i + 15],
                ]) as usize;
                let cd_offset = u32::from_le_bytes([
                    data[i + 16],
                    data[i + 17],
                    data[i + 18],
                    data[i + 19],
                ]) as usize;

                // Validate CD location
                if cd_offset + cd_size <= data.len() {
                    // Check if either cd_size == 0 or signature at cd_offset matches PK\x01\x02
                    if cd_size == 0 || (cd_offset + 4 <= data.len() && &data[cd_offset..cd_offset + 4] == b"PK\x01\x02") {
                        let mut cur = cd_offset;
                        let cd_end = cd_offset + cd_size;
                        let mut walked = 0;

                        while cur + 46 <= cd_end && (cd_count == 0 || walked < cd_count || cd_count == 0xFFFF) {
                            if &data[cur..cur + 4] != b"PK\x01\x02" {
                                break;
                            }

                            // Clear bit 0 in Central Directory header flags (at +8)
                            normalized[cur + 8] &= 0xFE;

                            let name_len = u16::from_le_bytes([data[cur + 28], data[cur + 29]]) as usize;
                            let extra_len = u16::from_le_bytes([data[cur + 30], data[cur + 31]]) as usize;
                            let comment_len = u16::from_le_bytes([data[cur + 32], data[cur + 33]]) as usize;
                            let lfh_offset = u32::from_le_bytes([
                                data[cur + 42],
                                data[cur + 43],
                                data[cur + 44],
                                data[cur + 45],
                            ]) as usize;

                            // Follow relative offset pointer directly to the authentic Local File Header (at +6)
                            if lfh_offset + 30 <= data.len() && &data[lfh_offset..lfh_offset + 4] == b"PK\x03\x04" {
                                normalized[lfh_offset + 6] &= 0xFE;
                            }

                            cur += 46 + name_len + extra_len + comment_len;
                            walked += 1;
                        }

                        eocd_found = true;
                        break;
                    }
                }
            }
        }
    }

    // 2. Secondary Pass: Fallback Signature Scan if EOCD was not found or damaged
    if !eocd_found {
        let mut i = 0;
        while i + 4 <= normalized.len() {
            if &normalized[i..i + 4] == b"PK\x03\x04" && i + 30 <= normalized.len() {
                normalized[i + 6] &= 0xFE;
                i += 4;
            } else if &normalized[i..i + 4] == b"PK\x01\x02" && i + 46 <= normalized.len() {
                normalized[i + 8] &= 0xFE;
                i += 4;
            } else {
                i += 1;
            }
        }
    }

    normalized
}

fn is_password_or_unsupported_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("encrypt")
        || lower.contains("unsupported zip archive")
        || lower.contains("unsupported archive")
}

fn is_path_safe_descendant(target: &Path, dest: &Path, canonical_dest: &Path) -> bool {
    if let Ok(rel) = target.strip_prefix(dest) {
        for c in rel.components() {
            if matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            ) {
                return false;
            }
        }
        if let Ok(canon) = target.canonicalize() {
            if !canon.starts_with(canonical_dest) {
                return false;
            }
        }
        true
    } else {
        false
    }
}

/// Maximum recursion depth allowed during directory traversal to prevent DoS.
const MAX_DIRECTORY_RECURSION_DEPTH: usize = 32;

/// Recursively collect all files within a directory, safely guarding against circular symlinks and deep trees.
pub(crate) fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), AppError> {
    let mut visited_dirs = std::collections::HashSet::new();
    if let Ok(canonical) = std::fs::canonicalize(dir) {
        visited_dirs.insert(canonical);
    }
    collect_files_recursive_inner(dir, files, 0, &mut visited_dirs)
}

fn collect_files_recursive_inner(
    dir: &Path,
    files: &mut Vec<PathBuf>,
    depth: usize,
    visited_dirs: &mut std::collections::HashSet<PathBuf>,
) -> Result<(), AppError> {
    if depth >= MAX_DIRECTORY_RECURSION_DEPTH {
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = entry?;
        let p = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() && !file_type.is_symlink() {
            if let Ok(canonical) = std::fs::canonicalize(&p) {
                if !visited_dirs.insert(canonical) {
                    continue; // Skip already visited directory to prevent recursion loops
                }
            }
            collect_files_recursive_inner(&p, files, depth + 1, visited_dirs)?;
        } else if file_type.is_file() {
            files.push(p);
        } else if file_type.is_symlink() {
            // Do NOT recurse into symlinked directories to prevent infinite loops / DoS.
            // Only collect if symlink resolves to a regular file.
            if let Ok(meta) = std::fs::metadata(&p) {
                if meta.is_file() {
                    files.push(p);
                }
            }
        }
    }
    Ok(())
}

/// Extract ABI architecture name from an archive or relative file path (e.g. "lib/arm64-v8a/libfoo.so").
fn extract_abi_from_path(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').collect();

    // Pattern: lib/<abi>/...
    if parts.len() >= 2 && parts[0] == "lib" {
        return parts[1].to_string();
    }

    // Direct folder: <abi>/...
    const KNOWN_ABIS: &[&str] = &[
        "arm64-v8a",
        "armeabi-v7a",
        "armeabi",
        "x86_64",
        "x86",
        "riscv64",
        "mips",
        "mips64",
    ];
    for part in &parts {
        if KNOWN_ABIS.contains(part) {
            return part.to_string();
        }
    }

    "unknown".to_string()
}

/// Inspect ELF binary header to identify machine architecture as Android ABI string.
fn detect_elf_abi_from_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    detect_elf_abi(&bytes)
}

/// Inspect ELF bytes to map machine architecture to Android ABI string.
pub fn detect_elf_abi(bytes: &[u8]) -> Option<String> {
    if bytes.len() >= 20 && bytes.starts_with(b"\x7fELF") {
        let is_64 = bytes[4] == 2;
        let is_little = bytes[5] == 1;
        let e_machine = if is_little {
            u16::from_le_bytes([bytes[18], bytes[19]])
        } else {
            u16::from_be_bytes([bytes[18], bytes[19]])
        };
        let abi = match e_machine {
            goblin::elf::header::EM_AARCH64 => "arm64-v8a",
            goblin::elf::header::EM_ARM => "armeabi-v7a",
            goblin::elf::header::EM_X86_64 => "x86_64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_RISCV => "riscv64",
            goblin::elf::header::EM_MIPS => {
                if is_64 {
                    "mips64"
                } else {
                    "mips"
                }
            }
            _ => "unknown",
        };
        if abi != "unknown" {
            return Some(abi.to_string());
        }
    }
    if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(bytes) {
        return Some(match elf.header.e_machine {
            goblin::elf::header::EM_AARCH64 => "arm64-v8a".to_string(),
            goblin::elf::header::EM_ARM => "armeabi-v7a".to_string(),
            goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
            goblin::elf::header::EM_386 => "x86".to_string(),
            goblin::elf::header::EM_RISCV => "riscv64".to_string(),
            goblin::elf::header::EM_MIPS => {
                if elf.is_64 {
                    "mips64".to_string()
                } else {
                    "mips".to_string()
                }
            }
            _ => "unknown".to_string(),
        });
    }
    None
}

/// Parse Dalvik class definition from a single `.smali` file.
pub fn parse_smali_file(path: &Path) -> Result<super::dex::DexClassSummary, AppError> {
    let content = std::fs::read_to_string(path)?;
    let mut class_name = String::new();
    let mut super_class = None;
    let mut access_flags = 0u32;
    let mut fields = Vec::new();
    let mut methods = Vec::new();

    let mut current_method_name = String::new();
    let mut current_method_sig = String::new();
    let mut current_method_flags = 0u32;
    let mut current_registers: Option<u16> = None;
    let mut in_method = false;
    let mut current_method_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if in_method {
            current_method_lines.push(line.to_string());
            if trimmed.starts_with(".registers") || trimmed.starts_with(".locals") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(r) = parts[1].parse::<u16>() {
                        current_registers = Some(r);
                    }
                }
            } else if trimmed == ".end method" {
                in_method = false;
                methods.push(super::dex::DexMethodSummary {
                    name: current_method_name.clone(),
                    signature: current_method_sig.clone(),
                    access_flags: current_method_flags,
                    code_offset: None,
                    registers_size: current_registers,
                    insns_size: None,
                    debug_info: None,
                    disassembly: None,
                    smali: Some(current_method_lines.join("\n")),
                    decompiled: None,
                    cfg: None,
                    xrefs: None,
                    annotations: Vec::new(),
                });
                current_method_lines.clear();
            }
            continue;
        }

        if trimmed.starts_with(".class") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                class_name = parts.last().unwrap_or(&"").to_string();
                access_flags = parse_smali_access_flags(&parts[1..parts.len() - 1]);
            }
        } else if trimmed.starts_with(".super") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                super_class = Some(parts[1].to_string());
            }
        } else if trimmed.starts_with(".field") {
            let rest = trimmed.strip_prefix(".field").unwrap_or("").trim();
            fields.push(rest.to_string());
        } else if trimmed.starts_with(".method") {
            in_method = true;
            current_method_lines.clear();
            current_method_lines.push(line.to_string());
            current_registers = None;

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let name_and_sig = parts.last().unwrap_or(&"");
                let flags_slice = &parts[1..parts.len() - 1];
                current_method_flags = parse_smali_access_flags(flags_slice);

                if let Some(paren_idx) = name_and_sig.find('(') {
                    current_method_name = name_and_sig[..paren_idx].to_string();
                    current_method_sig = name_and_sig[paren_idx..].to_string();
                } else {
                    current_method_name = name_and_sig.to_string();
                    current_method_sig = "()V".to_string();
                }
            }
        }
    }

    if class_name.is_empty() {
        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown");
        class_name = format!("L{};", file_stem);
    }

    Ok(super::dex::DexClassSummary {
        name: class_name,
        super_class,
        access_flags,
        methods,
        fields,
        detailed_fields: Vec::new(),
        interfaces: Vec::new(),
        source_file: None,
        annotations: Vec::new(),
        smali: Some(content),
        dex_source: None,
    })
}

fn parse_smali_access_flags(tokens: &[&str]) -> u32 {
    let mut flags = 0u32;
    for tok in tokens {
        match *tok {
            "public" => flags |= 0x0001,
            "private" => flags |= 0x0002,
            "protected" => flags |= 0x0004,
            "static" => flags |= 0x0008,
            "final" => flags |= 0x0010,
            "synchronized" => flags |= 0x0020,
            "volatile" => flags |= 0x0040,
            "transient" => flags |= 0x0080,
            "native" => flags |= 0x0100,
            "interface" => flags |= 0x0200,
            "abstract" => flags |= 0x0400,
            "synthetic" => flags |= 0x1000,
            "constructor" => flags |= 0x10000,
            "declared-synchronized" => flags |= 0x20000,
            _ => {}
        }
    }
    flags
}

/// Recursively collect and parse all `.smali` files in a directory into a DexAnalysisResult.
pub fn parse_smali_directory(dir: &Path) -> Result<super::dex::DexAnalysisResult, AppError> {
    if !dir.exists() {
        return Err(AppError::FileNotFound(dir.display().to_string()));
    }

    let mut smali_files = Vec::new();
    collect_files_recursive(dir, &mut smali_files)?;

    let mut classes = Vec::new();
    let mut strings = Vec::new();

    for file_path in &smali_files {
        if file_path.extension().and_then(|s| s.to_str()) == Some("smali") {
            if let Ok(class_summary) = parse_smali_file(file_path) {
                strings.push(class_summary.name.clone());
                for m in &class_summary.methods {
                    strings.push(m.name.clone());
                }
                for f in &class_summary.fields {
                    strings.push(f.clone());
                }
                classes.push(class_summary);
            }
        }
    }

    classes.sort_by(|a, b| a.name.cmp(&b.name));
    let classes_count = classes.len();
    let methods_count = classes.iter().map(|c| c.methods.len()).sum();
    let strings_count = strings.len();

    let file_name = dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    Ok(super::dex::DexAnalysisResult {
        file_name,
        classes_count,
        methods_count,
        strings_count,
        classes,
        strings: Some(strings),
        disassembly: None,
        smali: None,
        decompiled: None,
        summary: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_open_nonexistent_file_fails() {
        let res = ApkPackage::open("/path/that/definitely/does/not/exist.apk");
        match res {
            Err(AppError::FileNotFound(_)) => {}
            other => panic!("Expected FileNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_open_zero_byte_file_fails() {
        let dir = tempdir().unwrap();
        let empty_path = dir.path().join("empty.apk");
        std::fs::File::create(&empty_path).unwrap();

        let res = ApkPackage::open(&empty_path);
        match res {
            Err(AppError::ZeroByteFile(_)) => {}
            other => panic!("Expected ZeroByteFile, got: {:?}", other),
        }
    }

    #[test]
    fn test_open_standalone_dex() {
        let dir = tempdir().unwrap();
        let dex_path = dir.path().join("classes.dex");
        let dex_content = b"dex\n035\0dummy_dex_content";
        std::fs::write(&dex_path, dex_content).unwrap();

        let pkg = ApkPackage::open(&dex_path).expect("open standalone dex");
        assert_eq!(pkg.source, ApkSource::Standalone(dex_path.clone()));
        assert_eq!(pkg.dex_entries.len(), 1);
        assert_eq!(pkg.dex_entries[0].name, "classes.dex");
        assert_eq!(pkg.dex_entries[0].size, dex_content.len() as u64);
        assert!(pkg.native_libraries.is_empty());
        assert!(pkg.manifest_data.is_none());

        let read = pkg.read_entry("classes.dex").expect("read dex");
        assert_eq!(read, dex_content);
    }

    #[test]
    fn test_open_standalone_so() {
        let fixture_elf = Path::new("tests/fixtures/auth_gate_elf64");
        if fixture_elf.exists() {
            let pkg = ApkPackage::open(fixture_elf).expect("open standalone elf");
            match pkg.source {
                ApkSource::Standalone(_) => {}
                _ => panic!("Expected Standalone source"),
            }
            assert!(pkg.dex_entries.is_empty());
            assert!(!pkg.native_libraries.is_empty());
            let abis = pkg.abis();
            assert!(abis.contains(&"x86_64".to_string()));

            let read = pkg.read_entry("auth_gate_elf64").expect("read standalone so");
            assert!(!read.is_empty());
        }
    }

    #[test]
    fn test_open_synthetic_archive_apk() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("test_app.apk");

        // Create a synthetic ZIP archive
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("AndroidManifest.xml", options).unwrap();
            zip.write_all(b"<manifest package=\"com.test.synthetic\" />").unwrap();

            zip.start_file("classes.dex", options).unwrap();
            zip.write_all(b"dex\n035\0content1").unwrap();

            zip.start_file("classes2.dex", options).unwrap();
            zip.write_all(b"dex\n035\0content2").unwrap();

            zip.start_file("lib/arm64-v8a/libnative.so", options).unwrap();
            zip.write_all(b"\x7fELFdummy_arm64_so").unwrap();

            zip.start_file("lib/x86_64/libnative.so", options).unwrap();
            zip.write_all(b"\x7fELFdummy_x86_64_so").unwrap();

            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open synthetic apk");
        assert_eq!(pkg.source, ApkSource::Archive(apk_path.clone()));
        assert!(pkg.manifest_data.is_some());
        assert!(!pkg.is_manifest_binary); // Plain text XML detected

        assert_eq!(pkg.dex_names(), vec!["classes.dex", "classes2.dex"]);
        assert_eq!(pkg.abis(), vec!["arm64-v8a", "x86_64"]);

        let manifest_bytes = pkg.read_entry("AndroidManifest.xml").expect("read manifest");
        assert_eq!(manifest_bytes, b"<manifest package=\"com.test.synthetic\" />");

        let dex2 = pkg.read_entry("classes2.dex").expect("read classes2.dex");
        assert_eq!(dex2, b"dex\n035\0content2");

        let so_arm64 = pkg.read_entry("lib/arm64-v8a/libnative.so").expect("read so");
        assert_eq!(so_arm64, b"\x7fELFdummy_arm64_so");

        // Test manifest_info
        let minfo = pkg.manifest_info().expect("parse manifest info").expect("manifest present");
        assert_eq!(minfo.package_name, "com.test.synthetic");
    }

    #[test]
    fn test_open_unpacked_directory() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        // Create unpacked tree
        std::fs::write(
            base.join("AndroidManifest.xml"),
            b"<manifest package=\"com.unpacked.tree\" />",
        )
        .unwrap();
        std::fs::write(base.join("classes.dex"), b"dex\n035\0unpacked_dex").unwrap();

        let arm64_dir = base.join("lib").join("arm64-v8a");
        std::fs::create_dir_all(&arm64_dir).unwrap();
        std::fs::write(arm64_dir.join("libmath.so"), b"\x7fELFdummy_libmath").unwrap();

        let pkg = ApkPackage::open(base).expect("open unpacked directory");
        assert_eq!(pkg.source, ApkSource::Directory(base.to_path_buf()));
        assert!(pkg.manifest_data.is_some());
        assert_eq!(pkg.dex_names(), vec!["classes.dex"]);
        assert_eq!(pkg.abis(), vec!["arm64-v8a"]);

        let math_bytes = pkg.read_entry("lib/arm64-v8a/libmath.so").expect("read math so");
        assert_eq!(math_bytes, b"\x7fELFdummy_libmath");

        let minfo = pkg.manifest_info().expect("manifest info").expect("present");
        assert_eq!(minfo.package_name, "com.unpacked.tree");
    }

    #[test]
    fn test_read_entry_suffix_in_archive() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("suffix_test.apk");

        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("lib/arm64-v8a/libunique_target.so", options).unwrap();
            zip.write_all(b"payload_bytes_1234").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        let bytes = pkg.read_entry("libunique_target.so").expect("find by suffix");
        assert_eq!(bytes, b"payload_bytes_1234");

        let err = pkg.read_entry("missing_target.so");
        assert!(matches!(err, Err(AppError::FileNotFound(_))));
    }

    #[test]
    fn test_open_unpacked_directory_with_binary_axml() {
        let sample_path = "/home/quanh/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rusty-axml-0.2.1/tests/assets/AndroidManifest.xml";
        if let Ok(axml_bytes) = std::fs::read(sample_path) {
            let dir = tempdir().unwrap();
            let base = dir.path();

            std::fs::write(base.join("AndroidManifest.xml"), &axml_bytes).unwrap();
            std::fs::write(base.join("classes.dex"), b"dex\n035\0test").unwrap();

            let pkg = ApkPackage::open(base).expect("open directory with binary axml");
            assert!(pkg.is_manifest_binary, "Should detect binary AXML in unpacked directory");
            let info = pkg.manifest_info().expect("parse axml").expect("present");
            assert_eq!(info.package_name, "eu.jgamba.myapplication");
        }
    }

    #[test]
    fn test_unpacked_directory_multi_dex_and_abis() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        std::fs::write(base.join("classes.dex"), b"dex\n035\0dex1").unwrap();
        std::fs::write(base.join("classes2.dex"), b"dex\n035\0dex2").unwrap();
        std::fs::write(base.join("classes3.dex"), b"dex\n035\0dex3").unwrap();

        for abi in &["arm64-v8a", "armeabi-v7a", "x86", "x86_64"] {
            let abi_dir = base.join("lib").join(abi);
            std::fs::create_dir_all(&abi_dir).unwrap();
            std::fs::write(abi_dir.join(format!("lib{}.so", abi)), format!("ELF_{}", abi).as_bytes()).unwrap();
        }

        let pkg = ApkPackage::open(base).expect("open multi dex directory");
        assert_eq!(pkg.dex_names(), vec!["classes.dex", "classes2.dex", "classes3.dex"]);
        assert_eq!(pkg.abis(), vec!["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]);

        let so_data = pkg.read_entry("libx86.so").expect("find by suffix");
        assert_eq!(so_data, b"ELF_x86");
    }

    #[test]
    fn test_standalone_invalid_read_entry_fails() {
        let dir = tempdir().unwrap();
        let dex_path = dir.path().join("classes.dex");
        std::fs::write(&dex_path, b"dex\n035\0standalone").unwrap();

        let pkg = ApkPackage::open(&dex_path).expect("open standalone dex");
        let err = pkg.read_entry("nonexistent_file.dex");
        assert!(matches!(err, Err(AppError::FileNotFound(_))));
    }

    #[test]
    fn test_open_real_fixtures_if_present() {
        let raw_apk = Path::new("tests/fixtures/sample_raw.apk");
        if raw_apk.exists() {
            let pkg = ApkPackage::open(raw_apk).expect("open sample_raw.apk");
            assert!(matches!(pkg.source, ApkSource::Archive(_)));
            assert!(pkg.is_manifest_binary);
            assert!(!pkg.dex_entries.is_empty());
            assert!(pkg.native_libraries.contains_key("arm64-v8a"));

            let minfo = pkg.manifest_info().expect("parse manifest").expect("manifest present");
            assert_eq!(minfo.package_name, "eu.jgamba.myapplication");
        }

        let unpacked_dir = Path::new("tests/fixtures/sample_unpacked_dir");
        if unpacked_dir.exists() {
            let pkg = ApkPackage::open(unpacked_dir).expect("open sample_unpacked_dir");
            assert!(matches!(pkg.source, ApkSource::Directory(_)));
            assert!(!pkg.is_manifest_binary); // text XML
            assert!(!pkg.dex_entries.is_empty());

            let minfo = pkg.manifest_info().expect("parse manifest").expect("manifest present");
            assert_eq!(minfo.package_name, "com.example.unpacked");
        }

        let unpacked_axml_dir = Path::new("tests/fixtures/sample_unpacked_axml_dir");
        if unpacked_axml_dir.exists() {
            let pkg = ApkPackage::open(unpacked_axml_dir).expect("open sample_unpacked_axml_dir");
            assert!(matches!(pkg.source, ApkSource::Directory(_)));
            assert!(pkg.is_manifest_binary); // binary AXML
            assert!(!pkg.dex_entries.is_empty());

            let minfo = pkg.manifest_info().expect("parse manifest").expect("manifest present");
            assert_eq!(minfo.package_name, "eu.jgamba.myapplication");
        }

        let classes_dex = Path::new("tests/fixtures/sample_classes.dex");
        if classes_dex.exists() {
            let pkg = ApkPackage::open(classes_dex).expect("open sample_classes.dex");
            assert!(matches!(pkg.source, ApkSource::Standalone(_)));
            assert_eq!(pkg.dex_entries.len(), 1);
            let bytes = pkg.read_entry("sample_classes.dex").expect("read standalone dex");
            assert!(&bytes[..4] == b"dex\n");
        }

        let aarch64_so = Path::new("tests/fixtures/sample_aarch64_lib.so");
        if aarch64_so.exists() {
            let pkg = ApkPackage::open(aarch64_so).expect("open sample_aarch64_lib.so");
            assert!(matches!(pkg.source, ApkSource::Standalone(_)));
            assert_eq!(pkg.abis(), vec!["arm64-v8a"]);
            let bytes = pkg.read_entry("sample_aarch64_lib.so").expect("read standalone so");
            assert!(&bytes[..4] == b"\x7fELF");
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_collect_files_recursive_circular_symlinks() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        std::fs::write(
            base.join("AndroidManifest.xml"),
            b"<manifest package=\"com.symlink.cycle\" />",
        )
        .unwrap();
        std::fs::write(base.join("classes.dex"), b"dex\n035\0sample_dex").unwrap();

        // Create cyclical and branching symlinks pointing to ancestor / self
        std::os::unix::fs::symlink(base, base.join("l1")).unwrap();
        std::os::unix::fs::symlink(base, base.join("l2")).unwrap();

        let mut files = Vec::new();
        let res = collect_files_recursive(base, &mut files);
        assert!(res.is_ok(), "collect_files_recursive must succeed without hang");

        // Verify that open_directory terminates promptly and correctly
        let pkg = ApkPackage::open(base).expect("open unpacked dir with circular symlinks");
        assert_eq!(pkg.dex_entries.len(), 1);
        assert!(pkg.manifest_data.is_some());
    }

    #[test]
    fn test_detect_elf_abi_header_bytes() {
        let aarch64_so = Path::new("tests/fixtures/sample_aarch64_lib.so");
        if aarch64_so.exists() {
            let bytes = std::fs::read(aarch64_so).unwrap();
            assert_eq!(detect_elf_abi(&bytes), Some("arm64-v8a".to_string()));
            assert_eq!(detect_elf_abi(&bytes[..64]), Some("arm64-v8a".to_string()));
        }
    }

    #[test]
    fn test_detect_languages_java_only() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("java_only.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.java\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0javabytes").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        let langs = pkg.detect_languages();
        assert_eq!(langs.len(), 1);
        assert_eq!(langs[0].language, "Java");
        assert_eq!(langs[0].confidence, "High");
        assert!(langs[0].evidence.iter().any(|e| e.contains("Dalvik DEX")));
        assert!(langs[0].evidence.iter().any(|e| e.contains("AndroidManifest.xml")));
    }

    #[test]
    fn test_detect_languages_c_cpp() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("cpp_app.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.cpp\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0dex").unwrap();
            zip.start_file("lib/arm64-v8a/libnative.so", opt).unwrap();
            zip.write_all(b"\x7fELFdummy_arm64_so").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        let langs = pkg.detect_languages();
        assert_eq!(langs.len(), 2);
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"C/C++"));

        let cpp = langs.iter().find(|l| l.language == "C/C++").unwrap();
        assert_eq!(cpp.confidence, "High");
        assert!(cpp.evidence.iter().any(|e| e.contains("libnative.so") || e.contains("Native shared libraries")));
    }

    #[test]
    fn test_detect_languages_react_native_bundle_and_so() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("rn_app.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.reactnative\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0dex").unwrap();
            zip.start_file("lib/arm64-v8a/libreactnativejni.so", opt).unwrap();
            zip.write_all(b"\x7fELFdummy_rn_so").unwrap();
            zip.start_file("lib/arm64-v8a/libhermes.so", opt).unwrap();
            zip.write_all(b"\x7fELFdummy_hermes_so").unwrap();
            zip.start_file("assets/index.android.bundle", opt).unwrap();
            zip.write_all(b"var __BUNDLE_START__ = true;").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        assert_eq!(pkg.asset_entries.len(), 1);
        assert_eq!(pkg.asset_entries[0].name, "assets/index.android.bundle");

        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"C/C++"));
        assert!(names.contains(&"React Native"));

        let rn = langs.iter().find(|l| l.language == "React Native").unwrap();
        assert_eq!(rn.confidence, "High");
        assert!(rn.evidence.iter().any(|e| e.contains("libreactnativejni.so")));
        assert!(rn.evidence.iter().any(|e| e.contains("libhermes.so")));
        assert!(rn.evidence.iter().any(|e| e.contains("index.android.bundle")));
    }

    #[test]
    fn test_detect_languages_react_native_dex_marker() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("rn_dex_app.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.rn\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0com.facebook.react.ReactActivity").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"React Native"));
    }

    #[test]
    fn test_detect_languages_flutter_dart_snapshot_and_assets() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("flutter_app.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.flutter\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0dex").unwrap();
            zip.start_file("lib/arm64-v8a/libflutter.so", opt).unwrap();
            zip.write_all(b"\x7fELFdummy_flutter_so").unwrap();
            zip.start_file("lib/arm64-v8a/libapp.so", opt).unwrap();
            zip.write_all(b"\x7fELFdummy_app_so").unwrap();
            zip.start_file("assets/flutter_assets/kernel_blob.bin", opt).unwrap();
            zip.write_all(b"flutter_kernel_snapshot").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        assert_eq!(pkg.asset_entries.len(), 1);
        assert_eq!(pkg.asset_entries[0].name, "assets/flutter_assets/kernel_blob.bin");

        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"C/C++"));
        assert!(names.contains(&"Flutter / Dart"));

        let fl = langs.iter().find(|l| l.language == "Flutter / Dart").unwrap();
        assert_eq!(fl.confidence, "High");
        assert!(fl.evidence.iter().any(|e| e.contains("libflutter.so")));
        assert!(fl.evidence.iter().any(|e| e.contains("libapp.so")));
        assert!(fl.evidence.iter().any(|e| e.contains("flutter_assets")));
    }

    #[test]
    fn test_detect_languages_flutter_dex_marker() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("flutter_dex_app.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.flutter\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0io.flutter.embedding.android.FlutterActivity").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open apk");
        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"Flutter / Dart"));
    }

    #[test]
    fn test_detect_languages_unpacked_directory() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        std::fs::write(
            base.join("AndroidManifest.xml"),
            b"<manifest package=\"com.test.unpacked\" />",
        )
        .unwrap();
        std::fs::write(base.join("classes.dex"), b"dex\n035\0dex").unwrap();

        let asset_dir = base.join("assets");
        std::fs::create_dir_all(&asset_dir).unwrap();
        std::fs::write(asset_dir.join("index.android.bundle"), b"bundle").unwrap();

        let lib_dir = base.join("lib").join("arm64-v8a");
        std::fs::create_dir_all(&lib_dir).unwrap();
        std::fs::write(lib_dir.join("libreactnativejni.so"), b"\x7fELF_rn").unwrap();

        let pkg = ApkPackage::open(base).expect("open unpacked directory");
        assert_eq!(pkg.asset_entries.len(), 1);

        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(names.contains(&"C/C++"));
        assert!(names.contains(&"React Native"));
    }

    #[test]
    fn test_detect_languages_real_fixtures() {
        let raw_apk = Path::new("tests/fixtures/sample_raw.apk");
        if raw_apk.exists() {
            let pkg = ApkPackage::open(raw_apk).expect("open sample_raw.apk");
            let langs = pkg.detect_languages();
            let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
            assert!(names.contains(&"Java"));
            assert!(names.contains(&"C/C++"));
        }

        let no_so = Path::new("tests/fixtures/sample_no_so.apk");
        if no_so.exists() {
            let pkg = ApkPackage::open(no_so).expect("open sample_no_so.apk");
            let langs = pkg.detect_languages();
            let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
            assert!(names.contains(&"Java"));
            assert!(!names.contains(&"C/C++"));
        }
    }

    #[test]
    fn test_detect_languages_zero_dex_native_apk_no_java() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("zero_dex_native.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.nativeonly\" />").unwrap();
            zip.start_file("lib/arm64-v8a/libnative.so", opt).unwrap();
            zip.write_all(b"\x7fELF_native_blob").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open zero dex apk");
        assert!(pkg.dex_entries.is_empty());
        assert!(!pkg.native_libraries.is_empty());

        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(!names.contains(&"Java"), "Zero-DEX APK must not report Java even if manifest exists");
        assert!(names.contains(&"C/C++"), "Native libraries must report C/C++");
    }

    #[test]
    fn test_detect_languages_fake_flutter_asset_does_not_trigger() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("fake_flutter.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.fakeflutter\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0dummy_dex").unwrap();
            zip.start_file("assets/flutter_assets_fake.txt", opt).unwrap();
            zip.write_all(b"this is not flutter assets directory").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open fake flutter apk");
        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(!names.contains(&"Flutter / Dart"), "Fake flutter asset filename must not trigger Flutter detection");
    }

    #[test]
    fn test_detect_languages_generic_bundle_does_not_trigger_react_native() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("generic_bundle.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.bundle\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0dummy_dex").unwrap();
            zip.start_file("assets/data.bundle", opt).unwrap();
            zip.write_all(b"raw binary data bundle not react native").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open generic bundle apk");
        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(!names.contains(&"React Native"), "Generic .bundle asset must not trigger React Native detection");
    }

    #[test]
    fn test_detect_languages_undelimited_package_does_not_trigger() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("undelimited.apk");
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.delim\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0https://api.example.com/facebook/reactions and io.fluttershy.mylittlepony").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open undelimited apk");
        let langs = pkg.detect_languages();
        let names: Vec<&str> = langs.iter().map(|l| l.language.as_str()).collect();
        assert!(names.contains(&"Java"));
        assert!(!names.contains(&"React Native"), "Undelimited package name must not trigger React Native");
        assert!(!names.contains(&"Flutter / Dart"), "Undelimited package name must not trigger Flutter / Dart");
    }

    // =========================================================================
    // Milestone 2 Container & ZIP Differential Resilience Unit Tests
    // =========================================================================

    #[test]
    fn test_normalize_fake_encryption_lfh_bit0() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("fake_lfh.apk");
        let content = b"uncompressed_content_inside_lfh_encrypted";
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(content).unwrap();
            zip.finish().unwrap();
        }
        let mut raw = std::fs::read(&apk_path).unwrap();
        // Set bit 0 in LFH only
        let mut i = 0;
        while i + 30 <= raw.len() {
            if &raw[i..i + 4] == b"PK\x03\x04" {
                raw[i + 6] |= 0x01;
                break;
            }
            i += 1;
        }
        std::fs::write(&apk_path, &raw).unwrap();

        let normalized = normalize_zip_encryption_flags(&raw);
        // Verify bit 0 is cleared
        let mut i = 0;
        while i + 30 <= normalized.len() {
            if &normalized[i..i + 4] == b"PK\x03\x04" {
                assert_eq!(normalized[i + 6] & 0x01, 0, "LFH bit 0 must be cleared");
                break;
            }
            i += 1;
        }

        let pkg = ApkPackage::open(&apk_path).expect("open fake lfh apk");
        let read = pkg.read_entry("classes.dex").expect("read classes.dex");
        assert_eq!(read, content);
    }

    #[test]
    fn test_normalize_fake_encryption_cd_bit0() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("fake_cd.apk");
        let content = b"uncompressed_content_inside_cd_encrypted";
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(content).unwrap();
            zip.finish().unwrap();
        }
        let mut raw = std::fs::read(&apk_path).unwrap();
        // Set bit 0 in CD only
        let mut i = 0;
        while i + 46 <= raw.len() {
            if &raw[i..i + 4] == b"PK\x01\x02" {
                raw[i + 8] |= 0x01;
                break;
            }
            i += 1;
        }
        std::fs::write(&apk_path, &raw).unwrap();

        let normalized = normalize_zip_encryption_flags(&raw);
        // Verify bit 0 is cleared
        let mut i = 0;
        while i + 46 <= normalized.len() {
            if &normalized[i..i + 4] == b"PK\x01\x02" {
                assert_eq!(normalized[i + 8] & 0x01, 0, "CD bit 0 must be cleared");
                break;
            }
            i += 1;
        }

        let pkg = ApkPackage::open(&apk_path).expect("open fake cd apk");
        assert!(pkg.normalized_archive_data.is_some());
        let read = pkg.read_entry("classes.dex").expect("read classes.dex");
        assert_eq!(read, content);
    }

    #[test]
    fn test_normalize_fake_encryption_both_lfh_and_cd() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("fake_both.apk");
        let content = b"payload_both_encrypted";
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.fake.both\" />").unwrap();
            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(content).unwrap();
            zip.finish().unwrap();
        }
        let mut raw = std::fs::read(&apk_path).unwrap();
        let mut i = 0;
        while i + 30 <= raw.len() {
            if &raw[i..i + 4] == b"PK\x03\x04" {
                raw[i + 6] |= 0x01;
            }
            i += 1;
        }
        let mut j = 0;
        while j + 46 <= raw.len() {
            if &raw[j..j + 4] == b"PK\x01\x02" {
                raw[j + 8] |= 0x01;
            }
            j += 1;
        }
        std::fs::write(&apk_path, &raw).unwrap();

        let pkg = ApkPackage::open(&apk_path).expect("open fake both apk");
        assert!(pkg.normalized_archive_data.is_some());
        assert_eq!(pkg.dex_entries.len(), 1);
        let read = pkg.read_entry("classes.dex").expect("read classes.dex");
        assert_eq!(read, content);
    }

    #[test]
    fn test_normalizer_preserves_uncompressed_stored_entries_with_magic_bytes() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("magic_payload.apk");
        // Payload contains raw bytes of PK\x03\x04 with fake flags
        let payload = b"HEADER_DATA_PK\x03\x04\x01\x00_TRAILER_DATA";
        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("assets/magic.bin", opt).unwrap();
            zip.write_all(payload).unwrap();
            zip.finish().unwrap();
        }
        let raw = std::fs::read(&apk_path).unwrap();
        let normalized = normalize_zip_encryption_flags(&raw);

        // Decompress normalized archive and assert payload CRC and content are 100% intact
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(normalized)).expect("open normalized archive");
        let mut entry = archive.by_name("assets/magic.bin").expect("find entry");
        let mut decompressed = Vec::new();
        entry.read_to_end(&mut decompressed).expect("decompress entry");
        assert_eq!(decompressed, payload, "Payload containing PK0304 must not be corrupted");
    }

    #[test]
    fn test_path_traversal_zip_slip_prevention() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("slip.apk");
        let extract_dir = dir.path().join("extracted");
        let outside_canary = dir.path().join("canary_slip.txt");

        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("valid.txt", opt).unwrap();
            zip.write_all(b"valid").unwrap();
            zip.start_file("../../canary_slip.txt", opt).unwrap();
            zip.write_all(b"escaped_payload").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open slip apk");
        // read_entry with .. should be rejected
        assert!(pkg.read_entry("../../canary_slip.txt").is_err());
        assert!(pkg.read_entry("/etc/passwd").is_err());

        // extract_to should safely extract without writing outside destination
        pkg.extract_to(&extract_dir).expect("extract_to must succeed");
        assert!(extract_dir.join("valid.txt").is_file());
        assert!(!outside_canary.exists(), "Zip slip entry must never escape extract directory");
    }

    #[test]
    fn test_windows_reserved_device_names_neutralization() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("reserved.apk");
        let extract_dir = dir.path().join("extracted_res");

        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("assets/CON.txt", opt).unwrap();
            zip.write_all(b"con_data").unwrap();
            zip.start_file("assets/PRN.xml", opt).unwrap();
            zip.write_all(b"prn_data").unwrap();
            zip.start_file("assets/AUX.json", opt).unwrap();
            zip.write_all(b"aux_data").unwrap();
            zip.start_file("assets/NUL.bin", opt).unwrap();
            zip.write_all(b"nul_data").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open reserved apk");
        assert!(pkg.asset_entries.iter().any(|e| e.name == "assets/_CON.txt" || e.name == "assets/CON.txt"));
        assert_eq!(pkg.read_entry("assets/CON.txt").unwrap(), b"con_data");
        assert_eq!(pkg.read_entry("assets/_CON.txt").unwrap(), b"con_data");

        pkg.extract_to(&extract_dir).expect("extract_to reserved");
        let con_exists = extract_dir.join("assets/_CON.txt").is_file() || extract_dir.join("assets/CON.txt").is_file();
        assert!(con_exists, "Reserved device name CON must be safely extracted");
    }

    #[test]
    fn test_andresguard_r_directory_resource_discovery_and_extraction() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("andres.apk");
        let extract_dir = dir.path().join("extracted_andres");

        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("r/d/a.png", opt).unwrap();
            zip.write_all(b"png_icon_data").unwrap();
            zip.start_file("r/l/b.xml", opt).unwrap();
            zip.write_all(b"<layout/>").unwrap();
            zip.start_file("res/values/strings.xml", opt).unwrap();
            zip.write_all(b"<resources/>").unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open andres apk");
        let res_entries = pkg.resource_entries();
        assert!(res_entries.iter().any(|e| e.name == "r/d/a.png"), "r/d/a.png must be discovered");
        assert!(res_entries.iter().any(|e| e.name == "r/l/b.xml"), "r/l/b.xml must be discovered");
        assert!(res_entries.iter().any(|e| e.name == "res/values/strings.xml"), "whitelisted res/ entry must be discovered");

        let png = pkg.read_entry("r/d/a.png").expect("read r/d/a.png");
        assert_eq!(png, b"png_icon_data");

        pkg.extract_to(&extract_dir).expect("extract_to");
        assert!(extract_dir.join("r/d/a.png").is_file());
        assert!(extract_dir.join("r/l/b.xml").is_file());
        assert!(extract_dir.join("res/values/strings.xml").is_file());
    }

    #[test]
    fn test_seven_zip_max_deflate_compatibility() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("sevenzip.apk");
        let payload = vec![0x42u8; 10000]; // repetitive data compresses well with max deflate

        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("assets/large.bin", opt).unwrap();
            zip.write_all(&payload).unwrap();
            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open sevenzip apk");
        let read = pkg.read_entry("assets/large.bin").expect("read large.bin");
        assert_eq!(read, payload);
    }

    #[test]
    fn test_path_traversal_categorization_and_suffix_matching() {
        let dir = tempdir().unwrap();
        let apk_path = dir.path().join("traversal_categorization.apk");

        {
            let file = std::fs::File::create(&apk_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opt = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

            zip.start_file("AndroidManifest.xml", opt).unwrap();
            zip.write_all(b"<manifest package=\"com.test.traversal\" />").unwrap();

            zip.start_file("classes.dex", opt).unwrap();
            zip.write_all(b"dex\n035\0valid_dex").unwrap();

            zip.start_file("res/values/strings.xml", opt).unwrap();
            zip.write_all(b"<resources><string name=\"app\">Safe</string></resources>").unwrap();

            // Adversarial traversal entries that attempt to mimic category prefixes
            zip.start_file("res/../../../tmp/canary_res.txt", opt).unwrap();
            zip.write_all(b"evil_res").unwrap();

            zip.start_file("assets/../../../tmp/canary_asset.txt", opt).unwrap();
            zip.write_all(b"evil_asset").unwrap();

            zip.start_file("lib/../../../tmp/canary_lib.so", opt).unwrap();
            zip.write_all(b"evil_lib").unwrap();

            zip.finish().unwrap();
        }

        let pkg = ApkPackage::open(&apk_path).expect("open synthetic traversal apk");

        // 1. Resource entries must only contain the legitimate resource, not the escaped traversal entry
        let res_entries = pkg.resource_entries();
        assert_eq!(res_entries.len(), 1, "Only legitimate res/values/strings.xml should be in resource_entries");
        assert_eq!(res_entries[0].name, "res/values/strings.xml");

        // 2. Asset entries must be empty because assets/../../../tmp/... sanitized path is outside assets/
        assert!(pkg.asset_entries.is_empty(), "Escaped asset traversal must not be in asset_entries");

        // 3. Native libraries must be empty because lib/../../../tmp/... sanitized path is outside lib/
        assert!(pkg.native_libraries.is_empty(), "Escaped lib traversal must not be in native_libraries");

        // 4. Dex entries must contain only classes.dex
        assert_eq!(pkg.dex_entries.len(), 1);
        assert_eq!(pkg.dex_entries[0].name, "classes.dex");

        // 5. Suffix matching in read_entry must not match traversal paths
        assert!(matches!(pkg.read_entry("canary_res.txt"), Err(AppError::FileNotFound(_))));
        assert!(matches!(pkg.read_entry("canary_asset.txt"), Err(AppError::FileNotFound(_))));
        assert!(matches!(pkg.read_entry("canary_lib.so"), Err(AppError::FileNotFound(_))));
    }

    #[test]
    fn test_pure_rust_unpack_on_raw_apk() {
        let apk_path = Path::new("tests/fixtures/sample_raw.apk");
        if apk_path.is_file() {
            let pkg = ApkPackage::open(apk_path).expect("open sample_raw.apk");
            let dir = tempdir().unwrap();
            let unpack_dir = dir.path().join("unpacked_rust");
            let summary = pkg.unpack(&unpack_dir, false).expect("unpack must succeed");

            assert_eq!(summary.engine, "rust-native");
            assert!(summary.manifest_extracted);
            assert!(summary.resources_extracted);
            assert!(summary.smali_generated);
            assert!(summary.file_count > 0);

            assert!(unpack_dir.join("AndroidManifest.xml").is_file());
            assert!(unpack_dir.join("res/values/strings.xml").is_file());
            assert!(unpack_dir.join("smali").is_dir());
        }
    }

    #[test]
    fn test_smali_directory_ingestion_and_parsing() {
        let dir = tempdir().unwrap();
        let smali_dir = dir.path().join("smali").join("com").join("example");
        std::fs::create_dir_all(&smali_dir).unwrap();

        let smali_content = r#".class public Lcom/example/MyTest;
.super Ljava/lang/Object;

# fields
.field private id:I

# methods
.method public testMethod()V
    .registers 2
    return-void
.end method
"#;
        std::fs::write(smali_dir.join("MyTest.smali"), smali_content).unwrap();

        // Also add a manifest
        std::fs::write(dir.path().join("AndroidManifest.xml"), b"<manifest package=\"com.example\" />").unwrap();

        let pkg = ApkPackage::open(dir.path()).expect("open smali directory");
        assert_eq!(pkg.dex_entries.len(), 1);
        assert_eq!(pkg.dex_entries[0].name, "smali");

        let langs = pkg.detect_languages();
        assert!(langs.iter().any(|l| l.language == "Java" && l.confidence == "High"));

        let dex_res = parse_smali_directory(&dir.path().join("smali")).expect("parse smali directory");
        assert_eq!(dex_res.classes_count, 1);
        assert_eq!(dex_res.classes[0].name, "Lcom/example/MyTest;");
        assert_eq!(dex_res.classes[0].super_class.as_deref(), Some("Ljava/lang/Object;"));
        assert_eq!(dex_res.classes[0].methods.len(), 1);
        assert_eq!(dex_res.classes[0].methods[0].name, "testMethod");
    }
}
