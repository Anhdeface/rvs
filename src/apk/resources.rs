//! Android resources, assets, and ARSC resource table analysis.
//!
//! Provides inspection of `res/` and `assets/` entries, parsing of `resources.arsc`
//! binary tables (packages, type specs, string pool), automatic decoding of binary
//! AXML resource files into plain XML, and directory dumping.

use std::path::{Component, Path};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::apk::container::ApkPackage;
use crate::apk::manifest::{decode_raw_manifest, is_binary_axml, normalize_string_pool_chunk};
use crate::apk::sanitize::sanitize_identifier;

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

/// Normalizes an Android binary resource table (`resources.arsc`) buffer:
/// 1. Strips padding bytes between offset 12 and `header_size` when `header_size > 12`, rewriting `header_size = 12`.
/// 2. Safely skips unknown or fake chunk types (`0x0000`, `0xFFFF`, or malformed chunk headers).
/// 3. Clamps string pool `stringCount` to available chunk bounds and sanitizes OOB string offsets.
/// 4. Adjusts total table size to reflect the normalized stream.
pub fn normalize_arsc_table(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 12 {
        return bytes.to_vec();
    }
    let chunk_type = u16::from_le_bytes([bytes[0], bytes[1]]);
    if chunk_type != 0x0002 {
        return bytes.to_vec();
    }
    let header_size = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    let declared_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let total_size = if declared_size >= header_size && declared_size <= bytes.len() {
        declared_size
    } else {
        bytes.len()
    };
    let pkg_count = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

    if header_size < 12 || header_size > total_size {
        return bytes.to_vec();
    }

    let mut valid_chunks = Vec::new();
    let mut offset = header_size;

    while offset + 8 <= total_size {
        let c_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let c_header_size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let c_size = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;

        if c_size < 8 || c_header_size < 8 || offset + c_size > bytes.len() {
            break;
        }

        // Malformed headerSize exceeding chunk_size
        if c_header_size > c_size {
            offset += c_size;
            continue;
        }

        let chunk_slice = &bytes[offset..offset + c_size];

        match c_type {
            0x0001 => {
                // RES_STRING_POOL_TYPE: normalize string pool chunk
                valid_chunks.extend_from_slice(&normalize_string_pool_chunk(chunk_slice, c_header_size));
            }
            0x0200 => {
                // RES_TABLE_PACKAGE_TYPE: keep valid package chunk
                valid_chunks.extend_from_slice(chunk_slice);
            }
            0x0203..=0x0206 => {
                // Other standard AOSP table chunks
                valid_chunks.extend_from_slice(chunk_slice);
            }
            _ => {
                // Skip ALL unknown, foreign, or dummy chunk types (0x0000, 0xFFFF, 0x1234, 0xABCD, etc.)
            }
        }

        offset += c_size;
    }

    let mut normalized = Vec::with_capacity(12 + valid_chunks.len());
    normalized.extend_from_slice(&0x0002u16.to_le_bytes()); // RES_TABLE_TYPE
    normalized.extend_from_slice(&12u16.to_le_bytes());     // standard header_size = 12
    let new_total = (12 + valid_chunks.len()) as u32;
    normalized.extend_from_slice(&new_total.to_le_bytes());
    normalized.extend_from_slice(&pkg_count.to_le_bytes());
    normalized.extend_from_slice(&valid_chunks);
    normalized
}

/// Helper to read variable-length UTF-8 character/byte count in ARSC string pools
fn read_var_len_u8(data: &[u8], mut idx: usize) -> (usize, usize) {
    if idx >= data.len() {
        return (0, idx);
    }
    let b0 = data[idx] as usize;
    idx += 1;
    if (b0 & 0x80) != 0 {
        if idx < data.len() {
            let b1 = data[idx] as usize;
            idx += 1;
            (((b0 & 0x7F) << 8) | b1, idx)
        } else {
            (b0 & 0x7F, idx)
        }
    } else {
        (b0, idx)
    }
}

/// Helper to read variable-length UTF-16 character count in ARSC string pools
fn read_var_len_u16(data: &[u8], mut idx: usize) -> (usize, usize) {
    if idx + 2 > data.len() {
        return (0, idx);
    }
    let u0 = u16::from_le_bytes([data[idx], data[idx + 1]]) as usize;
    idx += 2;
    if (u0 & 0x8000) != 0 {
        if idx + 2 <= data.len() {
            let u1 = u16::from_le_bytes([data[idx], data[idx + 1]]) as usize;
            idx += 2;
            (((u0 & 0x7FFF) << 16) | u1, idx)
        } else {
            (u0 & 0x7FFF, idx)
        }
    } else {
        (u0, idx)
    }
}

/// Zero-panic extraction of strings from a `RES_STRING_POOL_TYPE` buffer
fn parse_string_pool(pool_bytes: &[u8]) -> Vec<String> {
    if pool_bytes.len() < 28 {
        return Vec::new();
    }
    let chunk_type = u16::from_le_bytes([pool_bytes[0], pool_bytes[1]]);
    if chunk_type != 0x0001 {
        return Vec::new();
    }
    let header_size = u16::from_le_bytes([pool_bytes[2], pool_bytes[3]]) as usize;
    let chunk_size = (u32::from_le_bytes([pool_bytes[4], pool_bytes[5], pool_bytes[6], pool_bytes[7]]) as usize)
        .min(pool_bytes.len());
    if header_size < 28 || header_size > chunk_size {
        return Vec::new();
    }
    let raw_string_count = u32::from_le_bytes([
        pool_bytes[8],
        pool_bytes[9],
        pool_bytes[10],
        pool_bytes[11],
    ]) as usize;
    let flags = u32::from_le_bytes([
        pool_bytes[16],
        pool_bytes[17],
        pool_bytes[18],
        pool_bytes[19],
    ]);
    let strings_start = u32::from_le_bytes([
        pool_bytes[20],
        pool_bytes[21],
        pool_bytes[22],
        pool_bytes[23],
    ]) as usize;

    let is_utf8 = (flags & 0x0100) != 0;
    let offsets_limit = if strings_start >= header_size && strings_start <= chunk_size {
        strings_start
    } else {
        chunk_size
    };
    let available_offsets = (offsets_limit.saturating_sub(header_size)) / 4;
    let string_count = raw_string_count.min(available_offsets);

    let mut strings = Vec::with_capacity(string_count);
    for i in 0..string_count {
        let off_idx = header_size + i * 4;
        if off_idx + 4 > offsets_limit {
            strings.push(String::new());
            continue;
        }
        let rel_off = u32::from_le_bytes([
            pool_bytes[off_idx],
            pool_bytes[off_idx + 1],
            pool_bytes[off_idx + 2],
            pool_bytes[off_idx + 3],
        ]) as usize;
        let abs_off = strings_start.saturating_add(rel_off);
        if abs_off >= chunk_size {
            strings.push(String::new());
            continue;
        }
        let str_data = &pool_bytes[abs_off..chunk_size];
        let decoded = if is_utf8 {
            let (_char_len, idx) = read_var_len_u8(str_data, 0);
            let (byte_len, str_start) = read_var_len_u8(str_data, idx);
            let str_bytes = &str_data[str_start..(str_start + byte_len).min(str_data.len())];
            crate::apk::sanitize::decode_mutf8_lossy(str_bytes)
        } else {
            let (char_count, str_start) = read_var_len_u16(str_data, 0);
            let byte_count = char_count * 2;
            let str_bytes = &str_data[str_start..(str_start + byte_count).min(str_data.len())];
            crate::apk::sanitize::decode_utf16le_lossy(str_bytes)
        };
        strings.push(sanitize_identifier(&decoded));
    }
    strings
}

/// Resilient ARSC parser providing zero-panic direct package parsing
/// conforming to `PROJECT.md`.
pub struct ResilientArscParser<'a> {
    data: &'a [u8],
}

impl<'a> ResilientArscParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Alias conforming to PROJECT.md interface contract
    pub fn parse_table(&self) -> Result<Vec<ArscPackageInfo>, AppError> {
        self.parse_packages()
    }

    pub fn parse_packages(&self) -> Result<Vec<ArscPackageInfo>, AppError> {
        let data = self.data;
        if data.len() < 12 {
            return Err(AppError::InvalidBinary("ARSC buffer too small".to_string()));
        }
        let chunk_type = u16::from_le_bytes([data[0], data[1]]);
        if chunk_type != 0x0002 {
            return Err(AppError::InvalidBinary(format!(
                "Invalid ARSC root chunk type: 0x{:04X}",
                chunk_type
            )));
        }
        let header_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        let declared_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let total_size = if declared_size >= header_size && declared_size <= data.len() {
            declared_size
        } else {
            data.len()
        };

        if header_size < 12 || header_size > total_size {
            return Err(AppError::InvalidBinary(format!(
                "Invalid ARSC header_size: {}",
                header_size
            )));
        }

        let mut packages = Vec::new();
        let mut offset = header_size;

        while offset + 8 <= total_size {
            let c_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let c_header_size = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let c_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if c_size < 8 || c_header_size < 8 || offset + c_size > data.len() {
                break;
            }

            if c_type == 0x0200 {
                // RES_TABLE_PACKAGE_TYPE
                if let Some(pkg) = Self::parse_package_chunk(&data[offset..offset + c_size], c_header_size) {
                    packages.push(pkg);
                }
            }

            offset += c_size;
        }

        packages.sort_by_key(|p| p.id);
        Ok(packages)
    }

    fn parse_package_chunk(chunk: &[u8], pkg_h_size: usize) -> Option<ArscPackageInfo> {
        if chunk.len() < 284 || pkg_h_size < 284 || pkg_h_size > chunk.len() {
            return None;
        }

        let pkg_id = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);

        // Package name: 256 bytes UTF-16LE at chunk[12..268]
        let name_bytes = &chunk[12..268.min(chunk.len())];
        let decoded_name = crate::apk::sanitize::decode_utf16le_lossy(name_bytes);
        let pkg_name = sanitize_identifier(decoded_name.split('\0').next().unwrap_or(""));

        let type_strings_off = u32::from_le_bytes([chunk[268], chunk[269], chunk[270], chunk[271]]) as usize;
        let key_strings_off = u32::from_le_bytes([chunk[276], chunk[277], chunk[278], chunk[279]]) as usize;

        let type_strings = if type_strings_off > 0 && type_strings_off < chunk.len() {
            parse_string_pool(&chunk[type_strings_off..])
        } else {
            Vec::new()
        };

        let key_strings = if key_strings_off > 0 && key_strings_off < chunk.len() {
            parse_string_pool(&chunk[key_strings_off..])
        } else {
            Vec::new()
        };

        // Scan child chunks in package chunk for 0x0201 (TableType) and 0x0202 (TableTypeSpec)
        let mut type_entries = std::collections::HashMap::new();
        let mut inner_offset = pkg_h_size;
        while inner_offset + 8 <= chunk.len() {
            let inner_type = u16::from_le_bytes([chunk[inner_offset], chunk[inner_offset + 1]]);
            let inner_h_size = u16::from_le_bytes([chunk[inner_offset + 2], chunk[inner_offset + 3]]) as usize;
            let inner_size = u32::from_le_bytes([
                chunk[inner_offset + 4],
                chunk[inner_offset + 5],
                chunk[inner_offset + 6],
                chunk[inner_offset + 7],
            ]) as usize;

            if inner_size < 8 || inner_h_size < 8 || inner_size < inner_h_size || inner_offset + inner_size > chunk.len() {
                break;
            }

            match inner_type {
                0x0201 | 0x0202 if inner_size >= 16 => {
                    let type_id = chunk[inner_offset + 8];
                    let count = u32::from_le_bytes([
                        chunk[inner_offset + 12],
                        chunk[inner_offset + 13],
                        chunk[inner_offset + 14],
                        chunk[inner_offset + 15],
                    ]);
                    let cur = type_entries.entry(type_id).or_insert(0u32);
                    *cur = (*cur).max(count);
                }
                _ => {}
            }

            inner_offset += inner_size;
        }

        let mut specs = Vec::new();
        for (idx, type_name) in type_strings.iter().enumerate() {
            let type_id = (idx + 1) as u8;
            let entry_count = type_entries.get(&type_id).copied().unwrap_or(0);
            specs.push(ArscTypeSpecInfo {
                type_id,
                type_name: type_name.clone(),
                entry_count,
            });
        }
        specs.sort_by_key(|s| s.type_id);

        Some(ArscPackageInfo {
            id: pkg_id,
            name: pkg_name,
            types_count: type_strings.len(),
            string_pool_count: key_strings.len(),
            specs,
        })
    }
}

/// Parse raw `resources.arsc` bytes into structured package and type spec definitions.
///
/// Implements a two-layer defense against anti-analysis obfuscations:
/// - Layer 1: In-memory normalization (stripping ResTableHeader padding, skipping unknown chunks,
///   clamping string count) and parsing via `apk_info::ARSC`.
/// - Layer 2: Resilient zero-panic fallback via native `ResilientArscParser`.
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

    // Layer 1: In-memory normalization + apk_info::ARSC
    let normalized = normalize_arsc_table(bytes);
    let mut input = normalized.as_slice();
    if let Ok(arsc) = apk_info::ARSC::new(&mut input) {
        let mut packages = Vec::new();
        for pkg in arsc.packages() {
            let pkg_id = pkg.header.id;
            let pkg_name = sanitize_identifier(&pkg.header.name());
            let types_count = pkg.type_strings.len();
            let string_pool_count = pkg.key_strings.len();

            let mut specs = Vec::new();
            for idx in 0..pkg.type_strings.len() {
                let type_id = (idx + 1) as u8;
                let type_name = pkg
                    .type_strings
                    .get(idx as u32)
                    .map(|s| sanitize_identifier(&s))
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

        if !packages.is_empty() {
            packages.sort_by_key(|p| p.id);
            return Ok(packages);
        }
    }

    // Layer 2: Resilient direct fallback parser
    let parser = ResilientArscParser::new(bytes);
    if let Ok(packages) = parser.parse_packages() {
        if !packages.is_empty() {
            return Ok(packages);
        }
    }

    if normalized != bytes {
        let norm_parser = ResilientArscParser::new(&normalized);
        if let Ok(norm_pkgs) = norm_parser.parse_packages() {
            if !norm_pkgs.is_empty() {
                return Ok(norm_pkgs);
            }
        }
    }

    Err(AppError::InvalidBinary("No packages found in ARSC table".to_string()))
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
            name: sanitize_identifier(&entry.name),
            size: entry.size,
            entry_type,
        });
    }

    for entry in &pkg.asset_entries {
        list.push(ResourceEntryInfo {
            name: sanitize_identifier(&entry.name),
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
        if let Ok(decoded_xml) = decode_raw_manifest(&bytes) {
            return Ok(ExtractedResource {
                name: sanitize_identifier(entry_name),
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
            name: sanitize_identifier(entry_name),
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
        name: sanitize_identifier(entry_name),
        size,
        is_xml: false,
        content,
    })
}

/// Helper to escape XML special characters in string values
fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Generate a valid, indented `res/values/strings.xml` XML document from key-value pairs.
pub fn generate_strings_xml(strings: &[(String, String)]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
    for (key, val) in strings {
        let escaped_key = escape_xml_text(key);
        let escaped_val = escape_xml_text(val);
        out.push_str(&format!(
            "    <string name=\"{}\">{}</string>\n",
            escaped_key, escaped_val
        ));
    }
    out.push_str("</resources>\n");
    out
}

/// Extract string resource key-value pairs from `resources.arsc` binary data.
///
/// Supports multi-layer extraction:
/// 1. `apk_info::ARSC` resolution for typed string table entries and resource name lookups.
/// 2. Package key string pool and global string pool correlation fallback.
pub fn extract_arsc_strings(bytes: &[u8]) -> Vec<(String, String)> {
    if bytes.len() < 12 {
        return Vec::new();
    }

    let mut results: Vec<(String, String)> = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    // Layer 1: apk_info::ARSC
    let normalized = normalize_arsc_table(bytes);
    let mut input = normalized.as_slice();
    if let Ok(arsc) = apk_info::ARSC::new(&mut input) {
        for pkg in arsc.packages() {
            for k in 0..pkg.key_strings.len() {
                if let Some(key) = pkg.key_strings.get(k as u32) {
                    let sanitized_key = sanitize_identifier(&key);
                    if sanitized_key.is_empty() || seen_keys.contains(&sanitized_key) {
                        continue;
                    }
                    if let Some(val) = arsc.get_resource_value_by_name(&key) {
                        if !val.is_empty() {
                            seen_keys.insert(sanitized_key.clone());
                            results.push((sanitized_key, val));
                        }
                    }
                }
            }
        }
    }

    // Layer 2: Direct chunk analysis fallback if Layer 1 found nothing or incomplete
    if results.is_empty() {
        let mut offset = 12;
        let mut global_strings = Vec::new();
        let total_size = bytes.len();
        while offset + 8 <= total_size {
            let c_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            let c_size = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize;
            if c_size < 8 || offset + c_size > bytes.len() {
                break;
            }
            if c_type == 0x0001 && global_strings.is_empty() {
                global_strings = parse_string_pool(&bytes[offset..offset + c_size]);
            } else if c_type == 0x0200 && c_size >= 284 {
                // Package chunk: key strings offset is at chunk offset 276
                let key_off = u32::from_le_bytes([
                    bytes[offset + 276],
                    bytes[offset + 277],
                    bytes[offset + 278],
                    bytes[offset + 279],
                ]) as usize;
                if key_off > 0 && offset + key_off < offset + c_size {
                    let key_strings = parse_string_pool(&bytes[offset + key_off..offset + c_size]);
                    for (i, key) in key_strings.iter().enumerate() {
                        let sanitized_key = sanitize_identifier(key);
                        if sanitized_key.is_empty() || seen_keys.contains(&sanitized_key) {
                            continue;
                        }
                        let val = if i < global_strings.len() && !global_strings[i].is_empty() {
                            global_strings[i].clone()
                        } else {
                            key.clone()
                        };
                        seen_keys.insert(sanitized_key.clone());
                        results.push((sanitized_key, val));
                    }
                }
            }
            offset += c_size;
        }
    }

    results
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
                if let Ok(decoded) = decode_raw_manifest(&bytes) {
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
    fn test_normalize_arsc_table_padded_and_unknown_chunks() {
        // Table header with padded header_size (28 = 0x1C) and 16 padding bytes
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0002u16.to_le_bytes()); // RES_TABLE_TYPE
        raw.extend_from_slice(&28u16.to_le_bytes());     // header_size = 28
        // Unknown chunk 0x0000 of size 16
        let total = 28 + 16;
        raw.extend_from_slice(&(total as u32).to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // package_count = 0
        raw.extend_from_slice(&[0xCCu8; 16]);       // padding

        // Unknown chunk 0x0000
        raw.extend_from_slice(&0x0000u16.to_le_bytes());
        raw.extend_from_slice(&8u16.to_le_bytes());
        raw.extend_from_slice(&16u32.to_le_bytes());
        raw.extend_from_slice(&[0u8; 8]);

        let normalized = normalize_arsc_table(&raw);
        assert_eq!(&normalized[0..2], &0x0002u16.to_le_bytes());
        assert_eq!(&normalized[2..4], &12u16.to_le_bytes()); // normalized to 12
        assert_eq!(&normalized[4..8], &12u32.to_le_bytes()); // total size is 12 (0x0000 was stripped)
        assert_eq!(normalized.len(), 12);
    }

    #[test]
    fn test_normalize_arsc_table_arbitrary_unknown_chunks() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0002u16.to_le_bytes()); // RES_TABLE_TYPE
        raw.extend_from_slice(&12u16.to_le_bytes());     // header_size = 12
        let total = 12 + 16 + 16;
        raw.extend_from_slice(&(total as u32).to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());

        // Arbitrary unknown chunk 0x1234
        raw.extend_from_slice(&0x1234u16.to_le_bytes());
        raw.extend_from_slice(&8u16.to_le_bytes());
        raw.extend_from_slice(&16u32.to_le_bytes());
        raw.extend_from_slice(&[0x11u8; 8]);

        // Arbitrary unknown chunk 0xABCD
        raw.extend_from_slice(&0xABCDu16.to_le_bytes());
        raw.extend_from_slice(&8u16.to_le_bytes());
        raw.extend_from_slice(&16u32.to_le_bytes());
        raw.extend_from_slice(&[0x22u8; 8]);

        let normalized = normalize_arsc_table(&raw);
        assert_eq!(&normalized[0..2], &0x0002u16.to_le_bytes());
        assert_eq!(&normalized[2..4], &12u16.to_le_bytes());
        assert_eq!(&normalized[4..8], &12u32.to_le_bytes()); // both unknown chunks skipped
        assert_eq!(normalized.len(), 12);
    }

    #[test]
    fn test_resilient_arsc_parser_empty_packages() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0002u16.to_le_bytes());
        raw.extend_from_slice(&12u16.to_le_bytes());
        raw.extend_from_slice(&12u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());

        let parser = ResilientArscParser::new(&raw);
        let pkgs = parser.parse_packages().unwrap();
        assert!(pkgs.is_empty());
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

    #[test]
    fn test_extract_arsc_strings_and_generate_xml() {
        let apk_path = fixtures_dir().join("sample_raw.apk");
        if apk_path.is_file() {
            let pkg = ApkPackage::open(&apk_path).unwrap();
            if let Ok(bytes) = pkg.read_entry("resources.arsc") {
                let strings = extract_arsc_strings(&bytes);
                assert!(!strings.is_empty(), "Extracted ARSC strings should not be empty");
                let xml = generate_strings_xml(&strings);
                assert!(xml.contains("<resources>"));
                assert!(xml.contains("</resources>"));
                assert!(xml.contains("<string name="));
            }
        }
    }
}
