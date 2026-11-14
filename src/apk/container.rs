use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use super::manifest::{is_binary_axml, ManifestInfo};

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

/// Unified representation of an ingested Android APK package or standalone component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkPackage {
    pub source: ApkSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_data: Option<Vec<u8>>,
    pub is_manifest_binary: bool,
    pub dex_entries: Vec<ApkEntry>,
    pub native_libraries: HashMap<String, Vec<ApkEntry>>, // abi -> entries
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
        match &self.source {
            ApkSource::Archive(path) => {
                let file = std::fs::File::open(path)?;
                let mut archive = zip::ZipArchive::new(file).map_err(|e| {
                    AppError::InvalidBinary(format!(
                        "Failed to read APK archive '{}': {}",
                        path.display(),
                        e
                    ))
                })?;

                // 1. Exact match
                if let Ok(mut zip_file) = archive.by_name(entry_name) {
                    let mut buf = Vec::with_capacity(zip_file.size() as usize);
                    zip_file.read_to_end(&mut buf)?;
                    return Ok(buf);
                }

                // 2. Suffix / normalized match
                let normalized = entry_name.replace('\\', "/");
                let target_suffix = format!("/{}", normalized.trim_start_matches('/'));

                for i in 0..archive.len() {
                    if let Ok(mut zip_file) = archive.by_index(i) {
                        let name = zip_file.name();
                        if name == normalized
                            || name.ends_with(&target_suffix)
                            || name.ends_with(entry_name)
                        {
                            let mut buf = Vec::with_capacity(zip_file.size() as usize);
                            zip_file.read_to_end(&mut buf)?;
                            return Ok(buf);
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
                let direct_path = base_dir.join(entry_name);
                if direct_path.is_file() {
                    return Ok(std::fs::read(&direct_path)?);
                }

                // 2. Search in dex_entries
                for entry in &self.dex_entries {
                    if entry.name == entry_name || entry.name.ends_with(entry_name) {
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
                        if entry.name == entry_name || entry.name.ends_with(entry_name) {
                            if let Some(p) = &entry.path {
                                if p.is_file() {
                                    return Ok(std::fs::read(p)?);
                                }
                            }
                        }
                    }
                }

                // 4. Manifest special case
                if entry_name == "AndroidManifest.xml" {
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
                    || entry_name == path.to_string_lossy()
                    || self.dex_entries.iter().any(|e| e.name == entry_name)
                    || self
                        .native_libraries
                        .values()
                        .flatten()
                        .any(|e| e.name == entry_name)
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

    // --- Internal Ingestion Methods ---

    fn open_archive(path: &Path) -> Result<Self, AppError> {
        let file = std::fs::File::open(path)?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| {
            AppError::InvalidBinary(format!(
                "Failed to open APK archive '{}': {}",
                path.display(),
                e
            ))
        })?;

        let mut manifest_data = None;
        let mut is_manifest_binary = false;
        let mut dex_entries = Vec::new();
        let mut native_libraries: HashMap<String, Vec<ApkEntry>> = HashMap::new();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).map_err(|e| {
                AppError::InvalidBinary(format!(
                    "Failed to read archive entry at index {}: {}",
                    i, e
                ))
            })?;

            let name = entry.name().to_string();
            let size = entry.size();

            if name == "AndroidManifest.xml" {
                let mut data = Vec::with_capacity(size as usize);
                entry.read_to_end(&mut data)?;
                is_manifest_binary = is_binary_axml(&data);
                manifest_data = Some(data);
            } else if name.ends_with(".dex") {
                dex_entries.push(ApkEntry {
                    name,
                    size,
                    path: None,
                });
            } else if name.ends_with(".so") {
                let abi = extract_abi_from_path(&name);
                native_libraries
                    .entry(abi)
                    .or_default()
                    .push(ApkEntry {
                        name,
                        size,
                        path: None,
                    });
            }
        }

        dex_entries.sort_by(|a, b| a.name.cmp(&b.name));
        for list in native_libraries.values_mut() {
            list.sort_by(|a, b| a.name.cmp(&b.name));
        }

        Ok(Self {
            source: ApkSource::Archive(path.to_path_buf()),
            manifest_data,
            is_manifest_binary,
            dex_entries,
            native_libraries,
        })
    }

    fn open_directory(path: &Path) -> Result<Self, AppError> {
        let mut all_files = Vec::new();
        collect_files_recursive(path, &mut all_files)?;

        let mut manifest_data = None;
        let mut is_manifest_binary = false;
        let mut dex_entries = Vec::new();
        let mut native_libraries: HashMap<String, Vec<ApkEntry>> = HashMap::new();

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

            let ext = file_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if ext == "dex" {
                dex_entries.push(ApkEntry {
                    name: rel,
                    size,
                    path: Some(file_path.clone()),
                });
            } else if ext == "so" {
                let mut abi = extract_abi_from_path(&rel);
                if abi == "unknown" {
                    if let Some(detected) = detect_elf_abi_from_file(file_path) {
                        abi = detected;
                    }
                }
                native_libraries
                    .entry(abi)
                    .or_default()
                    .push(ApkEntry {
                        name: rel,
                        size,
                        path: Some(file_path.clone()),
                    });
            }
        }

        dex_entries.sort_by(|a, b| a.name.cmp(&b.name));
        for list in native_libraries.values_mut() {
            list.sort_by(|a, b| a.name.cmp(&b.name));
        }

        Ok(Self {
            source: ApkSource::Directory(path.to_path_buf()),
            manifest_data,
            is_manifest_binary,
            dex_entries,
            native_libraries,
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
        })
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
}
