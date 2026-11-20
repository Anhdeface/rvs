//! Dalvik DEX bytecode parsing and method disassembly subsystem.
//!
//! Provides in-memory Dalvik DEX parsing using `dex = "0.5.0"`, extracting class
//! summaries, method prototypes and signatures, field lists, and string pools.
//! Integrates with radare2 for method-level Dalvik bytecode disassembly.

use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::apk::container::{ApkPackage, ApkSource};
use crate::apk::sanitize::{decode_mutf8_lossy, sanitize_identifier};

/// Source position record from Dalvik debug_info_item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexSourcePosition {
    pub address: u32,
    pub line: u32,
}

/// Local variable record from Dalvik debug_info_item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexLocalVariable {
    pub register: u32,
    pub name: Option<String>,
    pub type_descriptor: Option<String>,
    pub signature: Option<String>,
    pub start_addr: u32,
    pub end_addr: Option<u32>,
}

/// Autonomous parsed debug information for a Dalvik method.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexDebugInfo {
    pub line_start: u32,
    pub parameter_names: Vec<Option<String>>,
    pub positions: Vec<DexSourcePosition>,
    pub locals: Vec<DexLocalVariable>,
    pub source_file: Option<String>,
}

/// Detailed representation of a Dalvik class field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexFieldSummary {
    pub name: String,
    pub type_descriptor: String,
    pub access_flags: u32,
    pub is_static: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<DexAnnotationSummary>,
}

/// Annotation metadata associated with a class, method, or field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexAnnotationSummary {
    pub visibility: String, // "build", "runtime", "system"
    pub type_descriptor: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub elements: Vec<(String, String)>, // (key, value preview)
}

/// Basic block in Dalvik control flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexBasicBlock {
    pub id: usize,
    pub start_addr: u64,
    pub end_addr: u64,
    pub instructions: Vec<DalvikInstruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_target: Option<u64>,
}

/// Complete Control Flow Graph representation for a Dalvik method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexMethodCfg {
    pub method_name: String,
    pub total_blocks: usize,
    pub blocks: Vec<DexBasicBlock>,
    pub decision_gates: Vec<crate::agent::flow::BranchGateNode>,
    pub loop_count: usize,
}

/// Cross-reference summary for a method, field, or string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexXrefSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings_referenced: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_read: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields_written: Vec<String>,
}

/// High-level summary of DEX classes and methods for `--summary` CLI output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexSummary {
    pub total_classes: usize,
    pub total_methods: usize,
    pub total_fields: usize,
    pub total_strings: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_classes: Vec<String>,
}

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
    pub debug_info: Option<DexDebugInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<Vec<DalvikInstruction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smali: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompiled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg: Option<DexMethodCfg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<DexXrefSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<DexAnnotationSummary>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detailed_fields: Vec<DexFieldSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<DexAnnotationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smali: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dex_source: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<DexSummary>,
}

/// Disassembled Dalvik instruction representation.
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

/// Helper to read a signed LEB128 integer from a byte slice.
fn read_sleb128(bytes: &[u8], offset: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0;
    let mut byte;
    loop {
        if *offset >= bytes.len() {
            return None;
        }
        byte = bytes[*offset];
        *offset += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    if (shift < 64) && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Some(result)
}

/// Pure-Rust Adler-32 implementation (RFC 1950) for Dalvik DEX checksum recalculation.
pub fn adler32(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for chunk in data.chunks(5552) {
        for &b in chunk {
            s1 += b as u32;
            s2 += s1;
        }
        s1 %= 65521;
        s2 %= 65521;
    }
    (s2 << 16) | s1
}

/// Pure-Rust SHA-1 implementation (RFC 3174) for Dalvik DEX signature recalculation.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, &w_val) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w_val);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Validates whether a debug_info_item header can be read cleanly.
fn is_debug_info_header_valid(bytes: &[u8], debug_info_off: usize, string_ids_size: usize) -> bool {
    let mut off = debug_info_off;
    if read_uleb128(bytes, &mut off).is_none() {
        return false;
    }
    let params_size = match read_uleb128(bytes, &mut off) {
        Some(v) => v as usize,
        None => return false,
    };
    if params_size > bytes.len().saturating_sub(off) || params_size > 65535 {
        return false;
    }
    for _ in 0..params_size {
        let sid = match read_uleb128(bytes, &mut off) {
            Some(v) => v,
            None => return false,
        };
        if sid > 0 && (sid - 1) as usize >= string_ids_size {
            return false;
        }
    }
    true
}

/// Inspects method code items in raw DEX bytes and sanitizes corrupted debug info offsets.
/// If `debug_info_off` points outside the data section or beyond the buffer, zeroes it out
/// and recomputes the SHA-1 and Adler32 checksums in the DEX header.
pub fn normalize_dex_debug_info_offsets(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") {
        return bytes.to_vec();
    }

    let string_ids_size = u32::from_le_bytes([bytes[0x38], bytes[0x39], bytes[0x3A], bytes[0x3B]]) as usize;
    let class_defs_size = u32::from_le_bytes([bytes[0x60], bytes[0x61], bytes[0x62], bytes[0x63]]) as usize;
    let class_defs_off = u32::from_le_bytes([bytes[0x64], bytes[0x65], bytes[0x66], bytes[0x67]]) as usize;
    let data_size = u32::from_le_bytes([bytes[0x68], bytes[0x69], bytes[0x6A], bytes[0x6B]]) as usize;
    let data_off = u32::from_le_bytes([bytes[0x6C], bytes[0x6D], bytes[0x6E], bytes[0x6F]]) as usize;

    let mut normalized = bytes.to_vec();
    let mut modified = false;
    let data_end = data_off.saturating_add(data_size).min(normalized.len());

    let max_class_defs = (normalized.len().saturating_sub(class_defs_off)) / 32;
    let defs_count = class_defs_size.min(max_class_defs);

    for i in 0..defs_count {
        let def_off = class_defs_off + i * 32;
        if def_off + 28 > normalized.len() {
            break;
        }
        let class_data_off = u32::from_le_bytes([
            normalized[def_off + 24],
            normalized[def_off + 25],
            normalized[def_off + 26],
            normalized[def_off + 27],
        ]) as usize;
        if class_data_off == 0 || class_data_off >= normalized.len() {
            continue;
        }

        let (direct, virt) = extract_method_code_offsets(&normalized, class_data_off);
        for code_off in direct.into_iter().chain(virt).flatten() {
            let c_off = code_off as usize;
            if c_off + 12 <= normalized.len() {
                let dbg_off = u32::from_le_bytes([
                    normalized[c_off + 8],
                    normalized[c_off + 9],
                    normalized[c_off + 10],
                    normalized[c_off + 11],
                ]) as usize;
                if dbg_off != 0
                    && (dbg_off < data_off
                        || dbg_off >= data_end
                        || dbg_off >= normalized.len()
                        || !is_debug_info_header_valid(&normalized, dbg_off, string_ids_size))
                {
                    normalized[c_off + 8..c_off + 12].copy_from_slice(&[0, 0, 0, 0]);
                    modified = true;
                }
            }
        }
    }

    if modified && normalized.len() >= 32 {
        let sha1_digest = sha1(&normalized[32..]);
        normalized[12..32].copy_from_slice(&sha1_digest);
        let adler = adler32(&normalized[12..]);
        normalized[8..12].copy_from_slice(&adler.to_le_bytes());
    }

    normalized
}

/// Autonomous, resilient Dalvik debug_info_item bytecode state machine parser.
///
/// Tolerates truncated streams, missing DBG_END_SEQUENCE, out-of-bounds register indices,
/// out-of-bounds string IDs, and negative line transitions without panicking.
pub fn parse_debug_info_resilient(
    bytes: &[u8],
    debug_info_off: usize,
    strings: &[String],
    registers_size: u16,
) -> Option<DexDebugInfo> {
    if debug_info_off >= bytes.len() || (debug_info_off == 0 && bytes.starts_with(b"dex\n")) {
        return None;
    }

    let mut off = debug_info_off;
    let line_start = read_uleb128(bytes, &mut off)? as u32;
    let parameters_size = read_uleb128(bytes, &mut off)? as usize;

    let max_params = (bytes.len().saturating_sub(off)).min(65535).min(registers_size as usize + 256);
    let count = parameters_size.min(max_params);

    let mut parameter_names = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        match read_uleb128(bytes, &mut off) {
            Some(0) => parameter_names.push(None),
            Some(val) => {
                let idx = (val - 1) as usize;
                parameter_names.push(strings.get(idx).cloned());
            }
            None => break,
        }
    }

    let mut address: u32 = 0;
    let mut line: u32 = line_start;
    let mut source_file: Option<String> = None;
    let mut positions: Vec<DexSourcePosition> = Vec::new();
    let mut locals: Vec<DexLocalVariable> = Vec::new();

    let max_regs = (registers_size as usize).clamp(32, 1024);
    let mut active_locals: Vec<Option<DexLocalVariable>> = vec![None; max_regs];

    const MAX_DEBUG_OPS: usize = 100_000;
    let mut ops_count = 0;

    while off < bytes.len() && ops_count < MAX_DEBUG_OPS {
        ops_count += 1;
        let opcode = bytes[off];
        off += 1;

        match opcode {
            0x00 => break, // DBG_END_SEQUENCE
            0x01 => {
                let addr_diff = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as u32,
                    None => break,
                };
                address = address.saturating_add(addr_diff);
            }
            0x02 => {
                let line_diff = match read_sleb128(bytes, &mut off) {
                    Some(v) => v,
                    None => break,
                };
                line = (line as i64)
                    .saturating_add(line_diff)
                    .clamp(1, u32::MAX as i64) as u32;
            }
            0x03 => {
                let reg = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let name_idx = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let type_idx = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let name = if name_idx > 0 { strings.get(name_idx - 1).cloned() } else { None };
                let type_desc = if type_idx > 0 { strings.get(type_idx - 1).cloned() } else { None };

                if reg < active_locals.len() {
                    active_locals[reg] = Some(DexLocalVariable {
                        register: reg as u32,
                        name,
                        type_descriptor: type_desc,
                        signature: None,
                        start_addr: address,
                        end_addr: None,
                    });
                }
            }
            0x04 => {
                let reg = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let name_idx = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let type_idx = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let sig_idx = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                let name = if name_idx > 0 { strings.get(name_idx - 1).cloned() } else { None };
                let type_desc = if type_idx > 0 { strings.get(type_idx - 1).cloned() } else { None };
                let sig = if sig_idx > 0 { strings.get(sig_idx - 1).cloned() } else { None };

                if reg < active_locals.len() {
                    active_locals[reg] = Some(DexLocalVariable {
                        register: reg as u32,
                        name,
                        type_descriptor: type_desc,
                        signature: sig,
                        start_addr: address,
                        end_addr: None,
                    });
                }
            }
            0x05 => {
                let reg = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                if reg < active_locals.len() {
                    if let Some(mut loc) = active_locals[reg].take() {
                        loc.end_addr = Some(address);
                        locals.push(loc);
                    }
                }
            }
            0x06 => {
                let reg = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                if reg < active_locals.len() {
                    if let Some(loc) = &mut active_locals[reg] {
                        loc.start_addr = address;
                    }
                }
            }
            0x07 => {} // DBG_SET_PROLOGUE_END
            0x08 => {} // DBG_SET_EPILOGUE_BEGIN
            0x09 => {
                let name_idx = match read_uleb128(bytes, &mut off) {
                    Some(v) => v as usize,
                    None => break,
                };
                source_file = if name_idx > 0 { strings.get(name_idx - 1).cloned() } else { None };
            }
            0x0a..=0xff => {
                let adjusted = (opcode - 0x0a) as u32;
                let line_diff = ((adjusted % 15) as i32) - 4;
                let addr_diff = adjusted / 15;
                address = address.saturating_add(addr_diff);
                line = (line as i64)
                    .saturating_add(line_diff as i64)
                    .clamp(1, u32::MAX as i64) as u32;
                positions.push(DexSourcePosition { address, line });
            }
        }
    }

    for loc in active_locals.into_iter().flatten() {
        let mut closed = loc;
        if closed.end_addr.is_none() {
            closed.end_addr = Some(address);
        }
        locals.push(closed);
    }

    Some(DexDebugInfo {
        line_start,
        parameter_names,
        positions,
        locals,
        source_file,
    })
}

/// Resiliently extracts the entire string pool from raw DEX binary bytes.
///
/// Bypasses `dex-0.5.0`'s strict `cesu8` validator, ensuring that malformed strings,
/// 2-byte nulls, and unpaired surrogates are decoded without panicking or dropping items.
pub fn extract_dex_strings_resilient(bytes: &[u8]) -> Vec<String> {
    if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") {
        return Vec::new();
    }

    let string_ids_size = u32::from_le_bytes([bytes[0x38], bytes[0x39], bytes[0x3A], bytes[0x3B]]) as usize;
    let string_ids_off = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;

    if string_ids_off >= bytes.len() {
        return Vec::new();
    }

    // Guard against integer overflow / memory exhaustion on adversarial stringCount
    let max_possible = (bytes.len().saturating_sub(string_ids_off)) / 4;
    let count = string_ids_size.min(max_possible).min(500_000);

    let mut strings = Vec::with_capacity(count);

    for i in 0..count {
        let entry_off = string_ids_off + i * 4;
        if entry_off + 4 > bytes.len() {
            strings.push(String::new());
            continue;
        }

        let data_off = u32::from_le_bytes([
            bytes[entry_off],
            bytes[entry_off + 1],
            bytes[entry_off + 2],
            bytes[entry_off + 3],
        ]) as usize;

        if data_off >= bytes.len() {
            strings.push(String::new());
            continue;
        }

        let mut off = data_off;
        // Skip ULEB128 utf16_size
        if read_uleb128(bytes, &mut off).is_none() {
            strings.push(String::new());
            continue;
        }

        // Scan for null terminator 0x00
        let start = off;
        let mut end = start;
        while end < bytes.len() && bytes[end] != 0 {
            end += 1;
        }

        let raw = &bytes[start..end];
        strings.push(decode_mutf8_lossy(raw));
    }

    strings
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

    let max_items = bytes.len().saturating_sub(off);
    let s_len = static_fields_len.min(max_items);
    let i_len = instance_fields_len.min(max_items);
    let d_len = direct_methods_len.min(max_items);
    let v_len = virtual_methods_len.min(max_items);

    // Skip static fields: field_idx_diff (uleb128), access_flags (uleb128)
    for _ in 0..s_len {
        if off >= bytes.len() { break; }
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
    }

    // Skip instance fields: field_idx_diff (uleb128), access_flags (uleb128)
    for _ in 0..i_len {
        if off >= bytes.len() { break; }
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
    }

    // Direct methods: method_idx_diff (uleb128), access_flags (uleb128), code_off (uleb128)
    for _ in 0..d_len {
        if off >= bytes.len() { break; }
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
        let code_off = read_uleb128(bytes, &mut off).unwrap_or(0);
        direct_offsets.push(if code_off > 0 { Some(code_off) } else { None });
    }

    // Virtual methods: method_idx_diff (uleb128), access_flags (uleb128), code_off (uleb128)
    for _ in 0..v_len {
        if off >= bytes.len() { break; }
        read_uleb128(bytes, &mut off);
        read_uleb128(bytes, &mut off);
        let code_off = read_uleb128(bytes, &mut off).unwrap_or(0);
        virtual_offsets.push(if code_off > 0 { Some(code_off) } else { None });
    }

    (direct_offsets, virtual_offsets)
}

/// Formats an encoded value into a human-readable string preview.
fn format_encoded_value(val: &dex::encoded_value::EncodedValue) -> String {
    use dex::encoded_value::EncodedValue;
    match val {
        EncodedValue::Byte(b) => b.to_string(),
        EncodedValue::Short(s) => s.to_string(),
        EncodedValue::Char(c) => format!("{:?}", char::from_u32(*c as u32).unwrap_or('?')),
        EncodedValue::Int(i) => i.to_string(),
        EncodedValue::Long(l) => l.to_string(),
        EncodedValue::Float(f) => f.to_string(),
        EncodedValue::Double(d) => d.to_string(),
        EncodedValue::String(s) => format!("\"{}\"", s),
        EncodedValue::Type(t) => t.type_descriptor().to_string(),
        EncodedValue::Array(arr) => {
            let inner = arr.iter().take(5).map(format_encoded_value).collect::<Vec<_>>().join(", ");
            if arr.len() > 5 {
                format!("[{}, ...]", inner)
            } else {
                format!("[{}]", inner)
            }
        }
        EncodedValue::Annotation(a) => format!("@{}", a.jtype().type_descriptor()),
        EncodedValue::Null => "null".to_string(),
        EncodedValue::Boolean(b) => b.to_string(),
        _ => format!("{:?}", val),
    }
}

/// Extracts annotation summaries from a DEX AnnotationSetItem.
fn extract_annotations(set: &dex::annotation::AnnotationSetItem) -> Vec<DexAnnotationSummary> {
    set.annotations()
        .iter()
        .map(|item| {
            let vis = match item.visibility() {
                dex::annotation::Visibility::Build => "build",
                dex::annotation::Visibility::Runtime => "runtime",
                dex::annotation::Visibility::System => "system",
            };
            let type_desc = sanitize_identifier(item.annotation().jtype().type_descriptor());
            let elements = item
                .annotation()
                .elements()
                .iter()
                .map(|e| (e.name().to_string(), format_encoded_value(e.value())))
                .collect();
            DexAnnotationSummary {
                visibility: vis.to_string(),
                type_descriptor: type_desc,
                elements,
            }
        })
        .collect()
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

    let normalized_bytes = normalize_dex_debug_info_offsets(bytes);

    let dex = dex::DexReader::from_vec(normalized_bytes.clone()).map_err(|e| {
        AppError::InvalidBinary(format!("Failed to parse DEX '{}': {}", file_name, e))
    })?;

    // Collect string pool using resilient MUTF-8 decoder
    let strings = extract_dex_strings_resilient(&normalized_bytes);
    let strings_count = strings.len();

    // Map class definitions with code offsets
    let mut classes = Vec::new();
    let mut total_methods_count = 0;

    for (class_def_res, class_res) in dex.class_defs().zip(dex.classes()) {
        let class_def = match class_def_res {
            Ok(cd) => cd,
            Err(_) => continue,
        };

        let class = match class_res {
            Ok(c) => c,
            Err(_) => continue,
        };

        let class_name = sanitize_identifier(class.jtype().type_descriptor());

        let super_class = class.super_class().and_then(|id| {
            dex.get_type(id)
                .ok()
                .map(|t| sanitize_identifier(t.type_descriptor()))
        });

        let access_flags = class.access_flags().bits();

        let interfaces: Vec<String> = class
            .interfaces()
            .iter()
            .map(|t| sanitize_identifier(t.type_descriptor()))
            .collect();

        let source_file = class.source_file().map(|s| s.to_string());
        let class_annotations = extract_annotations(class.annotations());

        // Extract code offsets for direct and virtual methods from class_data
        let (direct_offsets, virtual_offsets) = if class_def.class_data_off() != 0 {
            extract_method_code_offsets(&normalized_bytes, class_def.class_data_off() as usize)
        } else {
            (Vec::new(), Vec::new())
        };

        let mut class_fields = Vec::new();
        let mut detailed_fields = Vec::new();
        let mut class_methods = Vec::new();

        // Collect static fields
        for f in class.static_fields() {
            let name = sanitize_identifier(f.name());
            let type_desc = sanitize_identifier(f.jtype().type_descriptor());
            let f_access = f.access_flags().bits() as u32;
            let initial_value = f.initial_value().map(format_encoded_value);
            let f_annots = extract_annotations(f.annotations());
            detailed_fields.push(DexFieldSummary {
                name: name.clone(),
                type_descriptor: type_desc,
                access_flags: f_access,
                is_static: true,
                initial_value,
                annotations: f_annots,
            });
            class_fields.push(name);
        }

        // Collect instance fields
        for f in class.instance_fields() {
            let name = sanitize_identifier(f.name());
            let type_desc = sanitize_identifier(f.jtype().type_descriptor());
            let f_access = f.access_flags().bits() as u32;
            let f_annots = extract_annotations(f.annotations());
            detailed_fields.push(DexFieldSummary {
                name: name.clone(),
                type_descriptor: type_desc,
                access_flags: f_access,
                is_static: false,
                initial_value: None,
                annotations: f_annots,
            });
            class_fields.push(name);
        }

        // Direct methods
        for (idx, m) in class.direct_methods().iter().enumerate() {
            let name = sanitize_identifier(m.name());
            let params_str: String = m
                .params()
                .iter()
                .map(|p| sanitize_identifier(p.type_descriptor()))
                .collect();
            let signature = format!("({}){}", params_str, sanitize_identifier(m.return_type().type_descriptor()));
            let m_access = m.access_flags().bits() as u32;
            let code_offset = direct_offsets.get(idx).copied().flatten();
            let m_annotations = extract_annotations(m.annotations());

            let (registers_size, insns_size, debug_info) = if let Some(off) = code_offset {
                let off_usize = off as usize;
                if off_usize + 16 <= normalized_bytes.len() {
                    let reg_sz = u16::from_le_bytes([normalized_bytes[off_usize], normalized_bytes[off_usize + 1]]);
                    let dbg_off = u32::from_le_bytes([
                        normalized_bytes[off_usize + 8],
                        normalized_bytes[off_usize + 9],
                        normalized_bytes[off_usize + 10],
                        normalized_bytes[off_usize + 11],
                    ]) as usize;
                    let ins_sz = u32::from_le_bytes([
                        normalized_bytes[off_usize + 12],
                        normalized_bytes[off_usize + 13],
                        normalized_bytes[off_usize + 14],
                        normalized_bytes[off_usize + 15],
                    ]);
                    let dbg = if dbg_off > 0 {
                        parse_debug_info_resilient(&normalized_bytes, dbg_off, &strings, reg_sz)
                    } else {
                        None
                    };
                    (Some(reg_sz), Some(ins_sz), dbg)
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

            class_methods.push(DexMethodSummary {
                name,
                signature,
                access_flags: m_access,
                code_offset,
                registers_size,
                insns_size,
                debug_info,
                disassembly: None,
                smali: None,
                decompiled: None,
                cfg: None,
                xrefs: None,
                annotations: m_annotations,
            });
        }

        // Virtual methods
        for (idx, m) in class.virtual_methods().iter().enumerate() {
            let name = sanitize_identifier(m.name());
            let params_str: String = m
                .params()
                .iter()
                .map(|p| sanitize_identifier(p.type_descriptor()))
                .collect();
            let signature = format!("({}){}", params_str, sanitize_identifier(m.return_type().type_descriptor()));
            let m_access = m.access_flags().bits() as u32;
            let code_offset = virtual_offsets.get(idx).copied().flatten();
            let m_annotations = extract_annotations(m.annotations());

            let (registers_size, insns_size, debug_info) = if let Some(off) = code_offset {
                let off_usize = off as usize;
                if off_usize + 16 <= normalized_bytes.len() {
                    let reg_sz = u16::from_le_bytes([normalized_bytes[off_usize], normalized_bytes[off_usize + 1]]);
                    let dbg_off = u32::from_le_bytes([
                        normalized_bytes[off_usize + 8],
                        normalized_bytes[off_usize + 9],
                        normalized_bytes[off_usize + 10],
                        normalized_bytes[off_usize + 11],
                    ]) as usize;
                    let ins_sz = u32::from_le_bytes([
                        normalized_bytes[off_usize + 12],
                        normalized_bytes[off_usize + 13],
                        normalized_bytes[off_usize + 14],
                        normalized_bytes[off_usize + 15],
                    ]);
                    let dbg = if dbg_off > 0 {
                        parse_debug_info_resilient(&normalized_bytes, dbg_off, &strings, reg_sz)
                    } else {
                        None
                    };
                    (Some(reg_sz), Some(ins_sz), dbg)
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

            class_methods.push(DexMethodSummary {
                name,
                signature,
                access_flags: m_access,
                code_offset,
                registers_size,
                insns_size,
                debug_info,
                disassembly: None,
                smali: None,
                decompiled: None,
                cfg: None,
                xrefs: None,
                annotations: m_annotations,
            });
        }

        total_methods_count += class_methods.len();

        classes.push(DexClassSummary {
            name: class_name,
            super_class,
            access_flags,
            methods: class_methods,
            fields: class_fields,
            detailed_fields,
            interfaces,
            source_file,
            annotations: class_annotations,
            smali: None,
            dex_source: Some(file_name.to_string()),
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
        summary: None,
    })
}

/// Disassembles Dalvik bytecode at a specific instruction address or method offset using pure-Rust decoder.
pub fn disassemble_dalvik_at(
    dex_path: &Path,
    offset: u64,
    instruction_count: usize,
) -> Result<Vec<DalvikInstruction>, AppError> {
    if !dex_path.exists() {
        return Err(AppError::FileNotFound(dex_path.display().to_string()));
    }

    let bytes = std::fs::read(dex_path)?;
    let count = if instruction_count == 0 { 20 } else { instruction_count };
    let resolver = crate::apk::dalvik::DexResolver::new(&bytes);
    let insts = crate::apk::dalvik::disassemble_dalvik_instructions(
        &bytes,
        offset,
        count as u32,
        resolver.as_ref(),
    );
    Ok(insts)
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

/// Returns true if the Dalvik instruction represents an unconditional terminal or jump
/// where sequential control flow never falls through.
pub fn is_unconditional_control_flow(inst: &DalvikInstruction) -> bool {
    let op = inst.opcode.trim();
    if op == "return-void"
        || op.starts_with("return ")
        || op.starts_with("return-wide ")
        || op.starts_with("return-object ")
        || op == "throw"
        || op.starts_with("throw ")
        || op == "goto"
        || op.starts_with("goto ")
        || op.starts_with("goto/16 ")
        || op.starts_with("goto/32 ")
    {
        return true;
    }
    inst.ins_type.as_deref() == Some("ret")
}

/// Returns true if radare2 marked the Dalvik instruction as invalid/null/illegal opcode.
pub fn is_invalid_instruction(inst: &DalvikInstruction) -> bool {
    let op = inst.opcode.trim();
    let dis = inst.disasm.trim();
    op == "invalid"
        || dis == "invalid"
        || dis.starts_with("invalid")
        || inst.ins_type.as_deref() == Some("null")
        || inst.ins_type.as_deref() == Some("ill")
}

/// Disassembles Dalvik bytecode strictly bounded to `insns_size * 2` bytes using pure-Rust decoder,
/// preventing instruction spillover across method boundaries.
pub fn disassemble_dalvik_bounded(
    dex_path: &Path,
    instruction_addr: u64,
    insns_size: u32,
) -> Result<Vec<DalvikInstruction>, AppError> {
    if !dex_path.exists() {
        return Err(AppError::FileNotFound(dex_path.display().to_string()));
    }
    if insns_size == 0 {
        return Ok(Vec::new());
    }

    let bytes = std::fs::read(dex_path)?;
    let resolver = crate::apk::dalvik::DexResolver::new(&bytes);
    let insts = crate::apk::dalvik::disassemble_dalvik_instructions(
        &bytes,
        instruction_addr,
        insns_size,
        resolver.as_ref(),
    );
    Ok(insts)
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
            if inst.opcode == ".byte" || inst.disasm.starts_with(".byte") {
                let line = if !inst.disasm.is_empty() { &inst.disasm } else { &inst.opcode };
                out.push_str(&format!("    {}\n", line));
            } else if is_invalid_instruction(inst) {
                if let Some(hex) = &inst.bytes {
                    for chunk in hex.as_bytes().chunks(2) {
                        if let Ok(s) = std::str::from_utf8(chunk) {
                            if let Ok(b) = u8::from_str_radix(s, 16) {
                                out.push_str(&format!("    .byte {:#04x}\n", b));
                            }
                        }
                    }
                } else {
                    out.push_str("    .byte 0x00\n");
                }
            } else {
                let line = if !inst.disasm.is_empty() {
                    &inst.disasm
                } else {
                    &inst.opcode
                };
                out.push_str(&format!("    {}\n", line));
            }
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

/// Decompiles Dalvik bytecode at a specific instruction address into structured pseudo-Java using pure-Rust decompiler.
pub fn decompile_dalvik_method(
    dex_path: &Path,
    instruction_addr: u64,
) -> Result<String, AppError> {
    if !dex_path.exists() {
        return Err(AppError::FileNotFound(dex_path.display().to_string()));
    }

    let bytes = std::fs::read(dex_path)?;
    let analysis = parse_dex_bytes(&bytes, &dex_path.to_string_lossy()).ok();
    let resolver = crate::apk::dalvik::DexResolver::new(&bytes);

    let (class_name, method_summary) = if let Some(an) = &analysis {
        let mut found = None;
        'search: for c in &an.classes {
            for m in &c.methods {
                if let Some(off) = m.code_offset {
                    if off + 16 == instruction_addr {
                        found = Some((c.name.clone(), m.clone()));
                        break 'search;
                    }
                }
            }
        }
        found.unwrap_or_else(|| {
            ("UnknownClass".to_string(), DexMethodSummary {
                name: "unknownMethod".to_string(),
                signature: "()V".to_string(),
                access_flags: 1,
                code_offset: Some(instruction_addr.saturating_sub(16)),
                registers_size: None,
                insns_size: Some(100),
                debug_info: None,
                disassembly: None,
                smali: None,
                decompiled: None,
                cfg: None,
                xrefs: None,
                annotations: Vec::new(),
            })
        })
    } else {
        ("UnknownClass".to_string(), DexMethodSummary {
            name: "unknownMethod".to_string(),
            signature: "()V".to_string(),
            access_flags: 1,
            code_offset: Some(instruction_addr.saturating_sub(16)),
            registers_size: None,
            insns_size: Some(100),
            debug_info: None,
            disassembly: None,
            smali: None,
            decompiled: None,
            cfg: None,
            xrefs: None,
            annotations: Vec::new(),
        })
    };

    let insns_sz = method_summary.insns_size.unwrap_or(100);
    let insts = crate::apk::dalvik::disassemble_dalvik_instructions(
        &bytes,
        instruction_addr,
        insns_sz,
        resolver.as_ref(),
    );
    let cfg = crate::apk::dalvik::build_dalvik_cfg(&method_summary.name, &insts);
    Ok(crate::apk::dalvik::decompile_dalvik_method_pure_rust(&class_name, &method_summary, &cfg))
}

/// Extracts a field reference from a Dalvik instruction disassembly string.
/// Handles resolved references (e.g. `Lcom/.../Class;->field type`) as well as unresolved (`field@123`).
fn extract_field_ref(dis: &str) -> Option<String> {
    // In Dalvik instructions (iget/iput/sget/sput), registers precede the field operand:
    // e.g. "iget-boolean v0, v1, Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z"
    // or "sget-object v0, Ljava/lang/System;->out Ljava/io/PrintStream;"
    // or unresolved: "sget v0, field@123"
    if let Some(comma_pos) = dis.rfind(',') {
        let field_part = dis[comma_pos + 1..].trim();
        if (field_part.contains("->") || field_part.starts_with("field@")) && !field_part.contains('(') {
            return Some(field_part.to_string());
        }
    }

    // Fallback: scan all whitespace-separated tokens
    for token in dis.split_whitespace() {
        let clean = token.trim_matches(',');
        if (clean.contains("->") || clean.starts_with("field@")) && !clean.contains('(') {
            return Some(clean.to_string());
        }
    }

    None
}

/// Populates cross-references (callers, callees, strings, fields read/written) across all classes.
pub fn populate_multidex_xrefs(
    classes: &mut [DexClassSummary],
    dex_bytes_map: &std::collections::HashMap<String, Vec<u8>>,
) {
    use std::collections::BTreeSet;

    let mut caller_map: std::collections::HashMap<String, BTreeSet<String>> = std::collections::HashMap::new();
    let mut callee_map: std::collections::HashMap<String, BTreeSet<String>> = std::collections::HashMap::new();
    let mut strings_map: std::collections::HashMap<String, BTreeSet<String>> = std::collections::HashMap::new();
    let mut fields_read_map: std::collections::HashMap<String, BTreeSet<String>> = std::collections::HashMap::new();
    let mut fields_written_map: std::collections::HashMap<String, BTreeSet<String>> = std::collections::HashMap::new();

    // Cache resolvers per DEX name
    let resolvers: std::collections::HashMap<&str, crate::apk::dalvik::DexResolver> = dex_bytes_map
        .iter()
        .filter_map(|(name, bytes)| {
            crate::apk::dalvik::DexResolver::new(bytes).map(|r| (name.as_str(), r))
        })
        .collect();

    for class in classes.iter_mut() {
        let dex_name = class.dex_source.as_deref().unwrap_or("classes.dex");
        let dex_bytes = dex_bytes_map.get(dex_name).or_else(|| dex_bytes_map.values().next());
        let resolver = resolvers.get(dex_name).or_else(|| resolvers.values().next());

        for method in &mut class.methods {
            let method_key = format!("{}->{}{}", class.name, method.name, method.signature);

            // Get or decode instructions
            let insts: Vec<DalvikInstruction> = if let Some(existing) = &method.disassembly {
                existing.clone()
            } else if let (Some(off), Some(insns_sz), Some(bytes)) = (method.code_offset, method.insns_size, dex_bytes) {
                let inst_addr = off + 16;
                crate::apk::dalvik::disassemble_dalvik_instructions(bytes, inst_addr, insns_sz, resolver)
            } else {
                Vec::new()
            };

            for inst in &insts {
                let op = inst.opcode.trim();
                let dis = inst.disasm.trim();

                if op.starts_with("invoke-") {
                    if let Some(brace_end) = dis.find('}') {
                        let target = dis[brace_end + 1..].trim().trim_start_matches(',').trim();
                        if !target.is_empty() {
                            callee_map.entry(method_key.clone()).or_default().insert(target.to_string());
                            caller_map.entry(target.to_string()).or_default().insert(method_key.clone());
                        }
                    }
                } else if op.starts_with("sget") || op.starts_with("iget") {
                    if let Some(field_ref) = extract_field_ref(dis) {
                        fields_read_map.entry(method_key.clone()).or_default().insert(field_ref);
                    }
                } else if op.starts_with("sput") || op.starts_with("iput") {
                    if let Some(field_ref) = extract_field_ref(dis) {
                        fields_written_map.entry(method_key.clone()).or_default().insert(field_ref);
                    }
                } else if op.starts_with("const-string") {
                    if let Some(first_quote) = dis.find('"') {
                        if let Some(last_quote) = dis.rfind('"') {
                            if last_quote > first_quote {
                                let s = &dis[first_quote + 1..last_quote];
                                strings_map.entry(method_key.clone()).or_default().insert(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Second pass: attach XREFs to each method
    for class in classes.iter_mut() {
        for method in &mut class.methods {
            let method_key = format!("{}->{}{}", class.name, method.name, method.signature);

            let callers = caller_map.remove(&method_key).map(|s| s.into_iter().collect()).unwrap_or_default();
            let callees = callee_map.remove(&method_key).map(|s| s.into_iter().collect()).unwrap_or_default();
            let strings_referenced = strings_map.remove(&method_key).map(|s| s.into_iter().collect()).unwrap_or_default();
            let fields_read = fields_read_map.remove(&method_key).map(|s| s.into_iter().collect()).unwrap_or_default();
            let fields_written = fields_written_map.remove(&method_key).map(|s| s.into_iter().collect()).unwrap_or_default();

            method.xrefs = Some(DexXrefSummary {
                callers,
                callees,
                strings_referenced,
                fields_read,
                fields_written,
            });
        }
    }
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
        let analyze_single_entry = |entry: &crate::apk::container::ApkEntry| -> Result<DexAnalysisResult, AppError> {
            if entry.name == "smali"
                || entry.name.starts_with("smali_classes")
                || entry.path.as_ref().map(|p| p.is_dir()).unwrap_or(false)
            {
                if let Some(p) = &entry.path {
                    if p.is_dir() {
                        return crate::apk::container::parse_smali_directory(p);
                    }
                }
                if let ApkSource::Directory(base) = &self.source {
                    let dir_path = base.join(&entry.name);
                    if dir_path.is_dir() {
                        return crate::apk::container::parse_smali_directory(&dir_path);
                    }
                }
            }
            let bytes = self.read_entry(&entry.name)?;
            parse_dex_bytes(&bytes, &entry.name)
        };

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
            let analysis = analyze_single_entry(entry)?;
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
                let analysis = analyze_single_entry(entry)?;
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
            debug_info: None,
            disassembly: Some(vec![DalvikInstruction {
                addr: 116,
                opcode: "return-void".to_string(),
                disasm: "return-void".to_string(),
                bytes: Some("0e00".to_string()),
                ins_type: Some("ret".to_string()),
            }]),
            smali: None,
            decompiled: None,
            cfg: None,
            xrefs: None,
            annotations: Vec::new(),
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

    #[test]
    fn test_adler32_and_sha1() {
        let data = b"Dalvik DEX Checksum Test";
        let adler = adler32(data);
        assert!(adler > 0);
        let digest = sha1(data);
        assert_eq!(digest.len(), 20);
    }

    #[test]
    fn test_parse_debug_info_resilient_truncated() {
        // Truncated header
        assert!(parse_debug_info_resilient(&[], 0, &[], 2).is_none());
        assert!(parse_debug_info_resilient(&[0x01], 10, &[], 2).is_none());

        // line_start = 1 (0x01), parameters_size = 1 (0x01), parameter name = 1 (0x01, idx 0)
        // Missing DBG_END_SEQUENCE (0x00)
        let bytes = vec![0x01, 0x01, 0x01, 0x0a]; // 0x0a is special opcode
        let strings = vec!["param0".to_string()];
        let debug = parse_debug_info_resilient(&bytes, 0, &strings, 4);
        assert!(debug.is_some());
        let info = debug.unwrap();
        assert_eq!(info.line_start, 1);
        assert_eq!(info.parameter_names.len(), 1);
        assert_eq!(info.parameter_names[0], Some("param0".to_string()));
        assert!(!info.positions.is_empty());
    }

    #[test]
    fn test_parse_debug_info_resilient_advance_line_and_locals() {
        // line_start = 10, params_size = 0
        // 0x02 (DBG_ADVANCE_LINE) + sleb128(-5) -> line = 5
        // 0x03 (DBG_START_LOCAL) + reg 0 + name_idx 1 (idx 0) + type_idx 2 (idx 1)
        // 0x01 (DBG_ADVANCE_PC) + uleb128(4) -> addr = 4
        // 0x05 (DBG_END_LOCAL) + reg 0
        // 0x00 (DBG_END_SEQUENCE)
        let bytes = vec![
            10, 0, // header
            0x02, 0x7b, // line_diff = -5
            0x03, 0x00, 0x01, 0x02, // start local
            0x01, 0x04, // advance PC by 4
            0x05, 0x00, // end local reg 0
            0x00, // end sequence
        ];
        let strings = vec!["myVar".to_string(), "I".to_string()];
        let debug = parse_debug_info_resilient(&bytes, 0, &strings, 2).unwrap();
        assert_eq!(debug.line_start, 10);
        assert_eq!(debug.locals.len(), 1);
        assert_eq!(debug.locals[0].name.as_deref(), Some("myVar"));
        assert_eq!(debug.locals[0].type_descriptor.as_deref(), Some("I"));
        assert_eq!(debug.locals[0].start_addr, 0);
        assert_eq!(debug.locals[0].end_addr, Some(4));
    }

    #[test]
    fn test_is_unconditional_control_flow() {
        let ret = DalvikInstruction {
            addr: 0,
            opcode: "return-void".to_string(),
            disasm: "return-void".to_string(),
            bytes: None,
            ins_type: Some("ret".to_string()),
        };
        assert!(is_unconditional_control_flow(&ret));

        let goto = DalvikInstruction {
            addr: 0,
            opcode: "goto +4".to_string(),
            disasm: "goto +4".to_string(),
            bytes: None,
            ins_type: Some("jmp".to_string()),
        };
        assert!(is_unconditional_control_flow(&goto));

        let if_eq = DalvikInstruction {
            addr: 0,
            opcode: "if-eqz v0, +4".to_string(),
            disasm: "if-eqz v0, +4".to_string(),
            bytes: None,
            ins_type: Some("cjmp".to_string()),
        };
        assert!(!is_unconditional_control_flow(&if_eq));
    }

    #[test]
    fn test_parse_debug_info_extreme_line_arithmetic() {
        let strings = vec!["test.java".to_string()];

        // 1. DBG_ADVANCE_LINE with i64::MAX saturates without panic
        let mut stream1 = vec![0x01, 0x00, 0x02];
        let mut val = i64::MAX;
        let mut more = true;
        while more {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            let sign_bit = (byte & 0x40) != 0;
            if (val == 0 && !sign_bit) || (val == -1 && sign_bit) {
                more = false;
            } else {
                byte |= 0x80;
            }
            stream1.push(byte);
        }
        stream1.push(0x00);
        let res1 = parse_debug_info_resilient(&stream1, 0, &strings, 4);
        assert!(res1.is_some());
        let info1 = res1.unwrap();
        assert_eq!(info1.line_start, 1);

        // 2. Special opcode with line_start = 0x7FFFFFFF (i32::MAX) saturating without panic
        let stream2 = vec![0xff, 0xff, 0xff, 0xff, 0x07, 0x00, 0x12, 0x00];
        let res2 = parse_debug_info_resilient(&stream2, 0, &strings, 4);
        assert!(res2.is_some());
        let info2 = res2.unwrap();
        assert_eq!(info2.line_start, 0x7fffffff);
        assert_eq!(info2.positions.len(), 1);
        assert_eq!(info2.positions[0].line, 0x7fffffff + 4);

        // 3. Special opcode with line_start = 0x80000000 clamping without panic
        let stream3 = vec![0x80, 0x80, 0x80, 0x80, 0x08, 0x00, 0x0a, 0x00];
        let res3 = parse_debug_info_resilient(&stream3, 0, &strings, 4);
        assert!(res3.is_some());
        let info3 = res3.unwrap();
        assert_eq!(info3.line_start, 0x80000000);
        assert_eq!(info3.positions.len(), 1);
        assert_eq!(info3.positions[0].line, 0x80000000 - 4);
    }

    #[test]
    fn test_extract_field_ref_various_formats() {
        // Resolved instance field
        let dis1 = "iget-boolean v0, v1, Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z";
        assert_eq!(
            extract_field_ref(dis1),
            Some("Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z".to_string())
        );

        // Resolved static field
        let dis2 = "sget-object v0, Ljava/lang/System;->out Ljava/io/PrintStream;";
        assert_eq!(
            extract_field_ref(dis2),
            Some("Ljava/lang/System;->out Ljava/io/PrintStream;".to_string())
        );

        // Resolved store field
        let dis3 = "iput-boolean v2, v1, Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z";
        assert_eq!(
            extract_field_ref(dis3),
            Some("Lcom/devoteam/quickaction/QuickActionItem;->mChecked Z".to_string())
        );

        // Unresolved field
        let dis4 = "iget v0, v1, field@123";
        assert_eq!(extract_field_ref(dis4), Some("field@123".to_string()));

        // Unresolved static put
        let dis5 = "sput v0, field@456";
        assert_eq!(extract_field_ref(dis5), Some("field@456".to_string()));

        // Fallback token match without comma
        let dis6 = "sget field@789";
        assert_eq!(extract_field_ref(dis6), Some("field@789".to_string()));

        // Non-field instructions
        let dis7 = "return-void";
        assert_eq!(extract_field_ref(dis7), None);

        let dis8 = "invoke-virtual {v1}, Lcom/foo/Bar;->baz()V";
        assert_eq!(extract_field_ref(dis8), None);
    }
}
