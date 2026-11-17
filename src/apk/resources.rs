//! Android resources, assets, and ARSC resource table analysis.
//!
//! Provides inspection of `res/` and `assets/` entries, parsing of `resources.arsc`
//! binary tables (packages, type specs, string pool), automatic decoding of binary
//! AXML resource files into plain XML, and directory dumping.

use std::path::{Component, Path};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::apk::container::ApkPackage;
use crate::apk::manifest::is_binary_axml;

/// Summary of an ARSC resource type specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscTypeSpecInfo {
    pub type_id: u8,
    pub type_name: String,
    pub entry_count: u32,
}

/// Summary of a parsed package from `resources.arsc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArscPackageInfo {
    pub id: u32,
    pub name: String,
    pub types_count: usize,
    pub string_pool_count: usize,
    pub specs: Vec<ArscTypeSpecInfo>,
}

/// Information about a single resource or asset entry in the package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceEntryInfo {
    pub name: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub entry_type: String,
}

/// Extracted resource or asset file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedResource {
    pub name: String,
    pub size: usize,
    pub is_xml: bool,
    pub content: String,
}

/// Aggregate response data for `rvs apk resources`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkResourcesData {
    pub total_resources: usize,
    pub total_assets: usize,
    pub has_arsc: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arsc_packages: Vec<ArscPackageInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<ResourceEntryInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted: Option<ExtractedResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dump_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dumped_files_count: Option<usize>,
}

/// Parse raw `resources.arsc` bytes into structured package and type spec definitions.
pub fn parse_arsc_table(bytes: &[u8]) -> Result<Vec<ArscPackageInfo>, AppError> {
    if bytes.is_empty() {
        return Err(AppError::ZeroByteFile("resources.arsc is empty (0 bytes)".to_string()));
    }
    if bytes.len() < 12 {
        return Err(AppError::InvalidBinary(format!(
            "resources.arsc is too small ({} bytes)",
            bytes.len()
        )));
    }

    let mut input = bytes;
    let arsc = apk_info::ARSC::new(&mut input).map_err(|e| {
        AppError::InvalidBinary(format!("Failed to parse ARSC table: {:?}", e))
    })?;

    let mut packages = Vec::new();

    for pkg in arsc.packages() {
        let pkg_id = pkg.header.id;
        let pkg_name = pkg.header.name();
        let types_count = pkg.type_strings.len();
        let string_pool_count = pkg.key_strings.len();

        let mut specs = Vec::new();
        for idx in 0..pkg.type_strings.len() {
            let type_id = (idx + 1) as u8;
            let type_name = pkg
                .type_strings
                .get(idx as u32)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("type_{}", type_id));

            let mut entry_count = 0u32;
            for type_map in pkg.resources.values() {
                if let Some(entries) = type_map.get(&type_id) {
                    entry_count = entry_count.max(entries.entries.len() as u32);
                }
            }

            specs.push(ArscTypeSpecInfo {
                type_id,
                type_name,
                entry_count,
            });
        }

        specs.sort_by_key(|s| s.type_id);

        packages.push(ArscPackageInfo {
            id: pkg_id,
            name: pkg_name,
            types_count,
            string_pool_count,
            specs,
        });
    }

    packages.sort_by_key(|p| p.id);
    Ok(packages)
}

/// List all resource entries, assets, and ARSC files with normalized metadata.
pub fn list_resources_and_assets(pkg: &ApkPackage) -> Vec<ResourceEntryInfo> {
    let mut list = Vec::new();

    for entry in &pkg.resource_entries {
        let entry_type = if entry.name == "resources.arsc" {
            "arsc".to_string()
        } else {
            "resource".to_string()
        };
        list.push(ResourceEntryInfo {
            name: entry.name.clone(),
            size: entry.size,
            entry_type,
        });
    }

    for entry in &pkg.asset_entries {
        list.push(ResourceEntryInfo {
            name: entry.name.clone(),
            size: entry.size,
            entry_type: "asset".to_string(),
        });
    }

    list.sort_by(|a, b| a.name.cmp(&b.name));
    list
}

/// Extract and optionally decode a resource or asset entry.
/// Automatically decodes binary AXML (.xml) files into readable XML text.
pub fn extract_resource_or_asset(pkg: &ApkPackage, entry_name: &str) -> Result<ExtractedResource, AppError> {
    let rel = Path::new(entry_name);
    if rel.is_absolute()
        || entry_name.starts_with('/')
        || entry_name.starts_with('\\')
        || rel.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(AppError::InvalidBinary(format!(
            "Invalid entry path '{}'",
            entry_name
        )));
    }

    let bytes = pkg.read_entry(entry_name)?;
    let size = bytes.len();

    // Check if entry is AXML binary or plain text XML
    if is_binary_axml(&bytes) || entry_name.ends_with(".xml") {
        if let Ok(decoded_xml) = asc_axml::decode(&bytes) {
            return Ok(ExtractedResource {
                name: entry_name.to_string(),
                size,
                is_xml: true,
                content: decoded_xml,
            });
        }
    }

    // Try UTF-8 plain text
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let is_xml = text.trim_start().starts_with('<');
        return Ok(ExtractedResource {
            name: entry_name.to_string(),
            size,
            is_xml,
            content: text.to_string(),
        });
    }

    // Binary file representation
    let preview_len = size.min(64);
    let hex_preview = bytes[..preview_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");

    let content = if size > 64 {
        format!("[Binary data: {} bytes, preview: {}...]", size, hex_preview)
    } else {
        format!("[Binary data: {} bytes, hex: {}]", size, hex_preview)
    };

    Ok(ExtractedResource {
        name: entry_name.to_string(),
        size,
        is_xml: false,
        content,
    })
}

/// Dump all resources and assets into `output_dir`.
/// Binary AXML files are decoded to human-readable XML where possible.
pub fn dump_resources_and_assets(pkg: &ApkPackage, output_dir: &Path) -> Result<usize, AppError> {
    std::fs::create_dir_all(output_dir)?;
    let canonical_out = output_dir.canonicalize().unwrap_or_else(|_| output_dir.to_path_buf());

    let mut dumped = 0;
    let all_entries = list_resources_and_assets(pkg);

    for entry in &all_entries {
        // Sanitize entry.name before writing:
        // - Reject if path begins with '/' or '\'
        if entry.name.starts_with('/') || entry.name.starts_with('\\') {
            continue;
        }

        let rel = Path::new(&entry.name);
        // - Reject if absolute or contains ParentDir ('..'), RootDir, or Prefix
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
        {
            continue;
        }

        let target_path = output_dir.join(rel);
        // Verify target_path is strictly contained within output_dir
        if !target_path.starts_with(output_dir) {
            continue;
        }

        if let Ok(bytes) = pkg.read_entry(&entry.name) {
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)?;
                if let Ok(canon_parent) = parent.canonicalize() {
                    if !canon_parent.starts_with(&canonical_out) {
                        continue;
                    }
                }
            }

            // Do not follow existing symlinks
            if let Ok(meta) = std::fs::symlink_metadata(&target_path) {
                if meta.file_type().is_symlink() {
                    continue;
                }
            }

            // Decode AXML if binary XML
            if (is_binary_axml(&bytes) || entry.name.ends_with(".xml")) && !bytes.is_empty() {
                if let Ok(decoded) = asc_axml::decode(&bytes) {
                    if std::fs::write(&target_path, decoded.as_bytes()).is_ok() {
                        dumped += 1;
                        continue;
                    }
                }
            }

            if std::fs::write(&target_path, &bytes).is_ok() {
                dumped += 1;
            }
        }
    }

    Ok(dumped)
}

/// High-level analysis function for `rvs apk resources`.
pub fn analyze_apk_resources(
    pkg: &ApkPackage,
    list_entries: bool,
    extract_target: Option<&str>,
    dump_path: Option<&Path>,
) -> Result<ApkResourcesData, AppError> {
    let total_resources = pkg.resource_entries.len();
    let total_assets = pkg.asset_entries.len();

    let has_arsc = pkg
        .resource_entries
        .iter()
        .any(|e| e.name == "resources.arsc" || e.name.ends_with("/resources.arsc"));

    let arsc_packages = if has_arsc {
        match pkg.read_entry("resources.arsc") {
            Ok(bytes) => parse_arsc_table(&bytes).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let entries = if list_entries {
        Some(list_resources_and_assets(pkg))
    } else {
        None
    };

    let extracted = if let Some(target) = extract_target {
        Some(extract_resource_or_asset(pkg, target)?)
    } else {
        None
    };

    let (dump_dir, dumped_files_count) = if let Some(dir) = dump_path {
        let count = dump_resources_and_assets(pkg, dir)?;
        (Some(dir.display().to_string()), Some(count))
    } else {
        (None, None)
    };

    Ok(ApkResourcesData {
        total_resources,
        total_assets,
        has_arsc,
        arsc_packages,
        entries,
        extracted,
        dump_dir,
        dumped_files_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
    }

    #[test]
    fn test_parse_arsc_empty_fails() {
        assert!(parse_arsc_table(&[]).is_err());
    }

    #[test]
    fn test_parse_arsc_too_small_fails() {
        assert!(parse_arsc_table(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_resources_analysis_on_raw_apk() {
        let apk_path = fixtures_dir().join("sample_raw.apk");
        if apk_path.is_file() {
            let pkg = ApkPackage::open(&apk_path).unwrap();
            let analysis = analyze_apk_resources(&pkg, true, Some("assets/app_config.json"), None).unwrap();
            assert!(analysis.total_resources >= 1);
            assert!(analysis.total_assets >= 1);
            assert!(analysis.has_arsc);
            assert!(analysis.entries.is_some());
            assert!(analysis.extracted.is_some());
            let ext = analysis.extracted.unwrap();
            assert_eq!(ext.name, "assets/app_config.json");
            assert!(ext.content.contains("environment"));
        }
    }
}
