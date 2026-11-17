//! Dalvik DEX bytecode parsing and method disassembly subsystem.
//!
//! Provides in-memory Dalvik DEX parsing using `dex = "0.5.0"`, extracting class
//! summaries, method prototypes and signatures, field lists, and string pools.
//! Integrates with radare2 for method-level Dalvik bytecode disassembly.

use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::apk::container::{ApkPackage, ApkSource};

/// Summary representation of a Dalvik method inside a DEX class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexMethodSummary {
    pub name: String,
    pub signature: String,
    pub access_flags: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers_size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insns_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<Vec<DalvikInstruction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smali: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompiled: Option<String>,
}

/// Summary representation of a Dalvik class definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexClassSummary {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub super_class: Option<String>,
    pub access_flags: u32,
    pub methods: Vec<DexMethodSummary>,
    pub fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smali: Option<String>,
}

/// Aggregate result of DEX file analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexAnalysisResult {
    pub file_name: String,
    pub classes_count: usize,
    pub methods_count: usize,
    pub strings_count: usize,
    pub classes: Vec<DexClassSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<Vec<DalvikInstruction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smali: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompiled: Option<String>,
}

/// Disassembled Dalvik instruction representation from radare2 `pdj`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DalvikInstruction {
    pub addr: u64,
    #[serde(default)]
    pub opcode: String,
    #[serde(default)]
    pub disasm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub ins_type: Option<String>,
}

/// Helper to read an unsigned LEB128 integer from a byte slice.
fn read_uleb128(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    while *offset < bytes.len() {
        let byte = bytes[*offset];
        *offset += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
        if shift > 64 {
            return None;
        }
    }
    None
}

/// Extracts direct and virtual method code offsets from `ClassDataItem` raw bytes.
/// Returns (direct_offsets, virtual_offsets).
fn extract_method_code_offsets(bytes: &[u8], class_data_off: usize) -> (Vec<Option<u64>>, Vec<Option<u64>>) {
    let mut direct_offsets = Vec::new();
    let mut virtual_offsets = Vec::new();

    if class_data_off == 0 || class_data_off >= bytes.len() {
        return (direct_offsets, virtual_offsets);
    }

    let mut off = class_data_off;
    let static_fields_len = match read_uleb128(bytes, &mut off) {
        Some(v) => v as usize,
        None => return (direct_offsets, virtual_offsets),
    };
    let instance_fields_len = match read_uleb128(bytes, &mut off) {
        Some(v) => v as usize,
        None => return (direct_offsets, virtual_offsets),
    };
    let direct_methods_len = match read_uleb128(bytes, &mut off) {
        Some(v) => v as usize,
        None => return (direct_offsets, virtual_offsets),
    };
    let virtual_methods_len = match read_uleb128(bytes, &mut off) {
        Some(v) => v as usize,
        None => return (direct_offsets, virtual_offsets),
    };

    // Skip static fields: field_idx_diff (uleb128), access_flags (uleb128)
    for _ in 0..static_fields_len {
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
    }

    // Skip instance fields: field_idx_diff (uleb128), access_flags (uleb128)
    for _ in 0..instance_fields_len {
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
    }

    // Direct methods: method_idx_diff (uleb128), access_flags (uleb128), code_off (uleb128)
    for _ in 0..direct_methods_len {
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
        let code_off = read_uleb128(bytes, &mut off).unwrap_or(0);
        direct_offsets.push(if code_off > 0 { Some(code_off) } else { None });
    }

    // Virtual methods: method_idx_diff (uleb128), access_flags (uleb128), code_off (uleb128)
    for _ in 0..virtual_methods_len {
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
        let code_off = read_uleb128(bytes, &mut off).unwrap_or(0);
        virtual_offsets.push(if code_off > 0 { Some(code_off) } else { None });
    }

    (direct_offsets, virtual_offsets)
}

/// Parse raw Dalvik DEX binary bytes and return structured analysis result.
pub fn parse_dex_bytes(bytes: &[u8], file_name: &str) -> Result<DexAnalysisResult, AppError> {
    if bytes.is_empty() {
        return Err(AppError::ZeroByteFile(file_name.to_string()));
    }
    if bytes.len() < 40 {
        return Err(AppError::InvalidBinary(format!(
            "DEX file '{}' is too small ({} bytes)",
            file_name,
            bytes.len()
        )));
    }
    if !bytes.starts_with(b"dex\n") {
        return Err(AppError::InvalidBinary(format!(
            "Invalid DEX magic header in '{}'",
            file_name
        )));
    }

    let dex = dex::DexReader::from_vec(bytes.to_vec()).map_err(|e| {
        AppError::InvalidBinary(format!("Failed to parse DEX '{}': {}", file_name, e))
    })?;

    // Collect string pool
    let strings: Vec<String> = dex
        .strings()
        .filter_map(|s| s.ok().map(|ds| ds.to_string()))
        .collect();
    let strings_count = strings.len();

    // Map class definitions with code offsets
    let mut classes = Vec::new();
    let mut total_methods_count = 0;

    for (class_def_res, class_res) in dex.class_defs().zip(dex.classes()) {
        let class_def = class_def_res.map_err(|e| {
            AppError::InvalidBinary(format!(
                "Failed to read ClassDefItem in '{}': {}",
                file_name, e
            ))
        })?;

        let class = class_res.map_err(|e| {
            AppError::InvalidBinary(format!(
                "Failed to parse Class in '{}': {}",
                file_name, e
            ))
        })?;

        let class_name = class.jtype().type_descriptor().to_string();

        let super_class = class.super_class().and_then(|id| {
            dex.get_type(id)
                .ok()
                .map(|t| t.type_descriptor().to_string())
        });

        let access_flags = class.access_flags().bits();

        // Extract code offsets for direct and virtual methods from class_data
        let (direct_offsets, virtual_offsets) = if class_def.class_data_off() != 0 {
            extract_method_code_offsets(bytes, class_def.class_data_off() as usize)
        } else {
            (Vec::new(), Vec::new())
        };

        let mut class_fields = Vec::new();
        let mut class_methods = Vec::new();

        // Collect fields
        for f in class.static_fields() {
            class_fields.push(f.name().to_string());
        }
        for f in class.instance_fields() {
            class_fields.push(f.name().to_string());
        }

        // Direct methods
        for (idx, m) in class.direct_methods().iter().enumerate() {
            let name = m.name().to_string();
            let params_str: String = m
                .params()
                .iter()
                .map(|p| p.type_descriptor().to_string())
                .collect();
            let signature = format!("({}){}", params_str, m.return_type().type_descriptor());
            let m_access = m.access_flags().bits() as u32;
            let code_offset = direct_offsets.get(idx).copied().flatten();

            let (registers_size, insns_size) = if let Some(off) = code_offset {
                let off_usize = off as usize;
                if off_usize + 16 <= bytes.len() {
                    let reg_sz = u16::from_le_bytes([bytes[off_usize], bytes[off_usize + 1]]);
                    let ins_sz = u32::from_le_bytes([
                        bytes[off_usize + 12],
                        bytes[off_usize + 13],
                        bytes[off_usize + 14],
                        bytes[off_usize + 15],
                    ]);
                    (Some(reg_sz), Some(ins_sz))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            class_methods.push(DexMethodSummary {
                name,
                signature,
                access_flags: m_access,
                code_offset,
                registers_size,
                insns_size,
                disassembly: None,
                smali: None,
                decompiled: None,
            });
        }

        // Virtual methods
        for (idx, m) in class.virtual_methods().iter().enumerate() {
            let name = m.name().to_string();
            let params_str: String = m
                .params()
                .iter()
                .map(|p| p.type_descriptor().to_string())
                .collect();
            let signature = format!("({}){}", params_str, m.return_type().type_descriptor());
            let m_access = m.access_flags().bits() as u32;
            let code_offset = virtual_offsets.get(idx).copied().flatten();

            let (registers_size, insns_size) = if let Some(off) = code_offset {
                let off_usize = off as usize;
                if off_usize + 16 <= bytes.len() {
                    let reg_sz = u16::from_le_bytes([bytes[off_usize], bytes[off_usize + 1]]);
                    let ins_sz = u32::from_le_bytes([
                        bytes[off_usize + 12],
                        bytes[off_usize + 13],
                        bytes[off_usize + 14],
                        bytes[off_usize + 15],
                    ]);
                    (Some(reg_sz), Some(ins_sz))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            class_methods.push(DexMethodSummary {
                name,
                signature,
                access_flags: m_access,
                code_offset,
                registers_size,
                insns_size,
                disassembly: None,
                smali: None,
                decompiled: None,
            });
        }

        total_methods_count += class_methods.len();

        classes.push(DexClassSummary {
            name: class_name,
            super_class,
            access_flags,
            methods: class_methods,
            fields: class_fields,
            smali: None,
        });
    }

    let classes_count = classes.len();

    Ok(DexAnalysisResult {
        file_name: file_name.to_string(),
        classes_count,
        methods_count: total_methods_count,
        strings_count,
        classes,
        strings: Some(strings),
        disassembly: None,
        smali: None,
        decompiled: None,
    })
}

/// Disassembles Dalvik bytecode at a specific instruction address or method offset.
pub fn disassemble_dalvik_at(
    dex_path: &Path,
    offset: u64,
    instruction_count: usize,
) -> Result<Vec<DalvikInstruction>, AppError> {
    if !dex_path.exists() {
        return Err(AppError::FileNotFound(dex_path.display().to_string()));
    }

    let count = if instruction_count == 0 { 20 } else { instruction_count };
    let cmd = format!("pdj {} @ {}", count, offset);

    let output = std::process::Command::new("radare2")
        .arg("-N")
        .arg("-q")
        .arg("-e")
        .arg("scr.color=0")
        .arg("-a")
        .arg("dalvik")
        .arg("-c")
        .arg(&cmd)
        .arg(dex_path)
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .output()
        .map_err(|e| AppError::R2ExecutionError(format!("Failed to spawn radare2: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::R2ExecutionError(format!(
            "radare2 Dalvik disassembly failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();

    if trimmed.is_empty() || trimmed == "[]" {
        return Ok(Vec::new());
    }

    serde_json::from_str::<Vec<DalvikInstruction>>(trimmed).map_err(|e| {
        AppError::R2ExecutionError(format!(
            "Failed to parse radare2 Dalvik disassembly JSON: {}. Output was: {}",
            e, trimmed
        ))
    })
}

/// Disassembles a specific Dalvik method in a DEX file identified by class and method names.
pub fn disassemble_dalvik_method(
    dex_path: &Path,
    class_query: &str,
    method_query: &str,
) -> Result<Vec<DalvikInstruction>, AppError> {
    let bytes = std::fs::read(dex_path)?;
    let analysis = parse_dex_bytes(&bytes, &dex_path.to_string_lossy())?;

    // Find class
    let class = analysis
        .classes
        .iter()
        .find(|c| c.name == class_query || c.name.contains(class_query))
        .ok_or_else(|| {
            AppError::SymbolNotFound(format!(
                "Class '{}' not found in DEX '{}'",
                class_query,
                dex_path.display()
            ))
        })?;

    // Find method
    let method = class
        .methods
        .iter()
        .find(|m| m.name == method_query || m.name.contains(method_query))
        .ok_or_else(|| {
            AppError::SymbolNotFound(format!(
                "Method '{}' not found in class '{}'",
                method_query, class.name
            ))
        })?;

    let code_offset = method.code_offset.ok_or_else(|| {
        AppError::DecompilationFailed {
            function: format!("{}->{}", class.name, method.name),
            reason: "Method has no bytecode (abstract or native)".to_string(),
        }
    })?;

    // In Dalvik DEX code_item: 16-byte header precedes the bytecode instructions
    let instruction_addr = code_offset + 16;
    if let Some(insns_size) = method.insns_size {
        disassemble_dalvik_bounded(dex_path, instruction_addr, insns_size)
    } else {
        disassemble_dalvik_at(dex_path, instruction_addr, 50)
    }
}

/// Disassembles Dalvik bytecode strictly bounded to `insns_size * 2` bytes,
/// preventing instruction spillover across method boundaries.
pub fn disassemble_dalvik_bounded(
    dex_path: &Path,
    instruction_addr: u64,
    insns_size: u32,
) -> Result<Vec<DalvikInstruction>, AppError> {
    let count = (insns_size as usize).max(1);
    let raw = disassemble_dalvik_at(dex_path, instruction_addr, count)?;
    let max_addr = instruction_addr + (insns_size as u64) * 2;
    Ok(raw.into_iter().filter(|i| i.addr >= instruction_addr && i.addr < max_addr).collect())
}

/// Formats class access flags into Smali syntax keywords.
pub fn format_access_flags_class(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x0001 != 0 { parts.push("public"); }
    if flags & 0x0002 != 0 { parts.push("private"); }
    if flags & 0x0004 != 0 { parts.push("protected"); }
    if flags & 0x0008 != 0 { parts.push("static"); }
    if flags & 0x0010 != 0 { parts.push("final"); }
    if flags & 0x0200 != 0 { parts.push("interface"); }
    if flags & 0x0400 != 0 { parts.push("abstract"); }
    if flags & 0x1000 != 0 { parts.push("synthetic"); }
    if flags & 0x2000 != 0 { parts.push("annotation"); }
    if flags & 0x4000 != 0 { parts.push("enum"); }
    parts.join(" ")
}

/// Formats method access flags into Smali syntax keywords.
pub fn format_access_flags_method(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x0001 != 0 { parts.push("public"); }
    if flags & 0x0002 != 0 { parts.push("private"); }
    if flags & 0x0004 != 0 { parts.push("protected"); }
    if flags & 0x0008 != 0 { parts.push("static"); }
    if flags & 0x0010 != 0 { parts.push("final"); }
    if flags & 0x0020 != 0 { parts.push("synchronized"); }
    if flags & 0x0040 != 0 { parts.push("bridge"); }
    if flags & 0x0080 != 0 { parts.push("varargs"); }
    if flags & 0x0100 != 0 { parts.push("native"); }
    if flags & 0x0400 != 0 { parts.push("abstract"); }
    if flags & 0x0800 != 0 { parts.push("strictfp"); }
    if flags & 0x1000 != 0 { parts.push("synthetic"); }
    if flags & 0x8000 != 0 { parts.push("constructor"); }
    if flags & 0x10000 != 0 { parts.push("declared-synchronized"); }
    parts.join(" ")
}

/// Formats a single method into canonical Smali assembly representation.
pub fn format_method_smali(m: &DexMethodSummary) -> String {
    let access = format_access_flags_method(m.access_flags);
    let access_str = if access.is_empty() { String::new() } else { format!("{} ", access) };
    let mut out = format!(".method {}{}{}\n", access_str, m.name, m.signature);

    if let Some(regs) = m.registers_size {
        out.push_str(&format!("    .registers {}\n", regs));
    }

    if let Some(instructions) = &m.disassembly {
        for inst in instructions {
            let line = if !inst.disasm.is_empty() {
                &inst.disasm
            } else {
                &inst.opcode
            };
            out.push_str(&format!("    {}\n", line));
        }
    }

    out.push_str(".end method");
    out
}

/// Formats a complete class into canonical Smali assembly representation.
pub fn format_class_smali(c: &DexClassSummary) -> String {
    let access = format_access_flags_class(c.access_flags);
    let access_str = if access.is_empty() { String::new() } else { format!("{} ", access) };
    let mut out = format!(".class {}{}\n", access_str, c.name);

    if let Some(super_cls) = &c.super_class {
        out.push_str(&format!(".super {}\n", super_cls));
    }
    out.push('\n');

    if !c.fields.is_empty() {
        out.push_str("# fields\n");
        for f in &c.fields {
            out.push_str(&format!(".field {}\n", f));
        }
        out.push('\n');
    }

    if !c.methods.is_empty() {
        out.push_str("# methods\n");
        for m in &c.methods {
            out.push_str(&format_method_smali(m));
            out.push_str("\n\n");
        }
    }

    out.trim_end().to_string()
}

/// Decompiles Dalvik bytecode at a specific instruction address into pseudo-code using radare2 (`af; pdc`).
pub fn decompile_dalvik_method(
    dex_path: &Path,
    instruction_addr: u64,
) -> Result<String, AppError> {
    if !dex_path.exists() {
        return Err(AppError::FileNotFound(dex_path.display().to_string()));
    }

    let cmd = format!("af @ {}; pdc @ {}", instruction_addr, instruction_addr);

    let output = std::process::Command::new("radare2")
        .arg("-N")
        .arg("-q")
        .arg("-e")
        .arg("scr.color=0")
        .arg("-a")
        .arg("dalvik")
        .arg("-c")
        .arg(&cmd)
        .arg(dex_path)
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .output()
        .map_err(|e| AppError::R2ExecutionError(format!("Failed to spawn radare2: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::R2ExecutionError(format!(
            "radare2 Dalvik decompilation failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

// -----------------------------------------------------------------------------
// ApkPackage Extension Methods for DEX
// -----------------------------------------------------------------------------

impl ApkPackage {
    /// Analyze Dalvik DEX files contained in this Android artifact.
    ///
    /// If `dex_name` is Some, analyzes only the matching DEX entry;
    /// otherwise analyzes all DEX entries present in the package.
    pub fn analyze_dex(&self, dex_name: Option<&str>) -> Result<Vec<DexAnalysisResult>, AppError> {
        if let Some(target) = dex_name {
            let entry = self
                .dex_entries
                .iter()
                .find(|e| e.name == target || e.name.ends_with(target))
                .ok_or_else(|| {
                    AppError::FileNotFound(format!(
                        "DEX entry '{}' not found in package",
                        target
                    ))
                })?;
            let bytes = self.read_entry(&entry.name)?;
            let analysis = parse_dex_bytes(&bytes, &entry.name)?;
            Ok(vec![analysis])
        } else {
            if self.dex_entries.is_empty() {
                if let ApkSource::Standalone(p) = &self.source {
                    if p.extension().is_some_and(|e| e == "dex") {
                        let bytes = std::fs::read(p)?;
                        let fname = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                        let analysis = parse_dex_bytes(&bytes, &fname)?;
                        return Ok(vec![analysis]);
                    }
                }
                return Ok(Vec::new());
            }

            let mut results = Vec::with_capacity(self.dex_entries.len());
            for entry in &self.dex_entries {
                let bytes = self.read_entry(&entry.name)?;
                let analysis = parse_dex_bytes(&bytes, &entry.name)?;
                results.push(analysis);
            }
            Ok(results)
        }
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_classes_dex() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_classes.dex")
    }

    #[test]
    fn test_parse_dex_sample_classes() {
        let dex_path = fixture_classes_dex();
        assert!(dex_path.exists(), "sample_classes.dex fixture missing");
        let bytes = std::fs::read(&dex_path).unwrap();

        let result = parse_dex_bytes(&bytes, "sample_classes.dex").unwrap();
        assert!(result.classes_count >= 3);
        assert!(result.methods_count >= 10);
        assert!(result.strings_count >= 20);

        // Verify class lookup
        let quick_action = result.classes.iter().find(|c| c.name.contains("QuickActionItem"));
        assert!(quick_action.is_some(), "Class QuickActionItem must exist");
        let qa = quick_action.unwrap();
        assert!(qa.super_class.as_deref().unwrap_or("").contains("LinearLayout"));

        // Verify methods
        assert!(qa.methods.iter().any(|m| m.name == "isChecked"));
        assert!(qa.methods.iter().any(|m| m.name == "setChecked"));
        assert!(qa.methods.iter().any(|m| m.name == "setText"));

        // Verify string pool
        let strings = result.strings.expect("string pool must be present");
        assert!(strings.iter().any(|s| s.contains("QuickAction")));
    }

    #[test]
    fn test_parse_dex_corrupt_header() {
        let bad_bytes = b"dex\n035\0\x00corrupted_bytes_here_which_should_fail_checksum";
        let res = parse_dex_bytes(bad_bytes, "corrupt.dex");
        assert!(res.is_err(), "Corrupt DEX header must fail");
    }

    #[test]
    fn test_parse_dex_empty_file() {
        let res = parse_dex_bytes(&[], "empty.dex");
        assert!(res.is_err());
    }

    #[test]
    fn test_disassemble_dalvik_method() {
        let dex_path = fixture_classes_dex();
        let insns = disassemble_dalvik_method(&dex_path, "QuickActionItem", "isChecked");
        assert!(insns.is_ok(), "Dalvik disassembly for isChecked should succeed");
        let list = insns.unwrap();
        assert!(!list.is_empty(), "Instructions list should not be empty");
        assert!(list.iter().any(|i| i.opcode.contains("iget") || i.disasm.contains("iget")));
    }

    #[test]
    fn test_disassemble_dalvik_at() {
        let dex_path = fixture_classes_dex();
        let insns = disassemble_dalvik_at(&dex_path, 108012, 3);
        assert!(insns.is_ok());
        let list = insns.unwrap();
        assert!(!list.is_empty());
        assert_eq!(list[0].addr, 108012);
    }

    #[test]
    fn test_disassemble_dalvik_method_not_found() {
        let dex_path = fixture_classes_dex();
        let res_class = disassemble_dalvik_method(&dex_path, "NonExistentClass", "foo");
        assert!(res_class.is_err());

        let res_method = disassemble_dalvik_method(&dex_path, "QuickActionItem", "nonExistentMethod");
        assert!(res_method.is_err());
    }

    #[test]
    fn test_apk_package_analyze_dex() {
        let raw_apk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_raw.apk");
        if raw_apk.exists() {
            let pkg = ApkPackage::open(&raw_apk).expect("open raw apk");
            let analyses = pkg.analyze_dex(None).expect("analyze dex");
            assert!(!analyses.is_empty(), "Should find DEX analyses in raw APK");
            assert!(analyses[0].classes_count >= 3);
            assert!(analyses[0].methods_count >= 10);

            // Specific entry
            let single = pkg.analyze_dex(Some("classes.dex")).expect("analyze classes.dex");
            assert_eq!(single.len(), 1);

            // Nonexistent entry
            let missing = pkg.analyze_dex(Some("definitely_not_existing.dex"));
            assert!(missing.is_err());
        }
    }

    #[test]
    fn test_apk_package_multi_dex() {
        let multi_apk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_multi_dex.apk");
        if multi_apk.exists() {
            let pkg = ApkPackage::open(&multi_apk).expect("open multi dex apk");
            let analyses = pkg.analyze_dex(None).expect("analyze multi dex");
            assert!(analyses.len() >= 2, "Multi-dex must return at least 2 DEX analyses");
        }
    }

    #[test]
    fn test_format_access_flags() {
        assert_eq!(format_access_flags_class(0x0001), "public");
        assert_eq!(format_access_flags_class(0x0011), "public final");
        assert_eq!(format_access_flags_method(0x0009), "public static");
    }

    #[test]
    fn test_format_method_smali_basic() {
        let m = DexMethodSummary {
            name: "testMethod".to_string(),
            signature: "(I)V".to_string(),
            access_flags: 1,
            code_offset: Some(100),
            registers_size: Some(2),
            insns_size: Some(1),
            disassembly: Some(vec![DalvikInstruction {
                addr: 116,
                opcode: "return-void".to_string(),
                disasm: "return-void".to_string(),
                bytes: Some("0e00".to_string()),
                ins_type: Some("ret".to_string()),
            }]),
            smali: None,
            decompiled: None,
        };
        let smali = format_method_smali(&m);
        assert!(smali.contains(".method public testMethod(I)V"));
        assert!(smali.contains(".registers 2"));
        assert!(smali.contains("return-void"));
        assert!(smali.contains(".end method"));
    }

    #[test]
    fn test_disassemble_dalvik_bounded_strict() {
        let dex_path = fixture_classes_dex();
        // isChecked has 3 code units = 6 bytes (starts at 108012)
        let insns = disassemble_dalvik_bounded(&dex_path, 108012, 3).unwrap();
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].addr, 108012);
        assert_eq!(insns[1].addr, 108016);
    }
}
