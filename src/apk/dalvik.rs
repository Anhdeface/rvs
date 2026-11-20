//! Pure-Rust Dalvik instruction decoder, Control Flow Graph (CFG) analysis,
//! and method pseudo-Java decompilation subsystem.
//!
//! Provides zero-subprocess Dalvik bytecode disassembly, basic block CFG partitioning,
//! branch gate classification, cross-reference extraction, and pseudo-decompilation.

use std::collections::{BTreeSet, HashMap};

use crate::agent::flow::{classify_gate_type, BranchGateNode};
use crate::apk::sanitize::decode_mutf8_lossy;
use crate::apk::dex::{
    DalvikInstruction, DexBasicBlock, DexMethodCfg, DexMethodSummary,
};

/// Zero-copy DEX table resolver for strings, types, fields, and methods.
#[derive(Debug, Clone, Copy)]
pub struct DexResolver<'a> {
    bytes: &'a [u8],
    string_ids_off: usize,
    string_ids_size: usize,
    type_ids_off: usize,
    type_ids_size: usize,
    proto_ids_off: usize,
    proto_ids_size: usize,
    field_ids_off: usize,
    field_ids_size: usize,
    method_ids_off: usize,
    method_ids_size: usize,
}

impl<'a> DexResolver<'a> {
    /// Constructs a new resolver from raw DEX bytes.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 0x70 || !bytes.starts_with(b"dex\n") {
            return None;
        }

        let read_u32 = |off: usize| -> usize {
            if off + 4 <= bytes.len() {
                u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as usize
            } else {
                0
            }
        };

        let string_ids_size = read_u32(0x38);
        let string_ids_off = read_u32(0x3c);
        let type_ids_size = read_u32(0x40);
        let type_ids_off = read_u32(0x44);
        let proto_ids_size = read_u32(0x48);
        let proto_ids_off = read_u32(0x4c);
        let field_ids_size = read_u32(0x50);
        let field_ids_off = read_u32(0x54);
        let method_ids_size = read_u32(0x58);
        let method_ids_off = read_u32(0x5c);

        Some(Self {
            bytes,
            string_ids_off,
            string_ids_size,
            type_ids_off,
            type_ids_size,
            proto_ids_off,
            proto_ids_size,
            field_ids_off,
            field_ids_size,
            method_ids_off,
            method_ids_size,
        })
    }

    /// Resolves a string by its string_id index.
    pub fn resolve_string(&self, idx: u32) -> Option<String> {
        let i = idx as usize;
        if i >= self.string_ids_size {
            return None;
        }
        let off = self.string_ids_off.checked_add(i.checked_mul(4)?)?;
        if off + 4 > self.bytes.len() {
            return None;
        }
        let str_off = u32::from_le_bytes([
            self.bytes[off],
            self.bytes[off + 1],
            self.bytes[off + 2],
            self.bytes[off + 3],
        ]) as usize;

        if str_off >= self.bytes.len() {
            return None;
        }

        // Skip ULEB128 utf16_size
        let mut curr = str_off;
        let mut shift = 0;
        while curr < self.bytes.len() {
            let b = self.bytes[curr];
            curr += 1;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                return None;
            }
        }

        let start = curr;
        let mut end = start;
        while end < self.bytes.len() && self.bytes[end] != 0 {
            end += 1;
        }

        Some(decode_mutf8_lossy(&self.bytes[start..end]))
    }

    /// Resolves a type descriptor by its type_id index.
    pub fn resolve_type(&self, idx: u32) -> Option<String> {
        let i = idx as usize;
        if i >= self.type_ids_size {
            return None;
        }
        let off = self.type_ids_off.checked_add(i.checked_mul(4)?)?;
        if off + 4 > self.bytes.len() {
            return None;
        }
        let desc_idx = u32::from_le_bytes([
            self.bytes[off],
            self.bytes[off + 1],
            self.bytes[off + 2],
            self.bytes[off + 3],
        ]);
        self.resolve_string(desc_idx)
    }

    /// Resolves a field reference by its field_id index.
    /// Returns (class_descriptor, field_name, type_descriptor).
    pub fn resolve_field(&self, idx: u32) -> Option<(String, String, String)> {
        let i = idx as usize;
        if i >= self.field_ids_size {
            return None;
        }
        let off = self.field_ids_off.checked_add(i.checked_mul(8)?)?;
        if off + 8 > self.bytes.len() {
            return None;
        }
        let class_idx = u16::from_le_bytes([self.bytes[off], self.bytes[off + 1]]) as u32;
        let type_idx = u16::from_le_bytes([self.bytes[off + 2], self.bytes[off + 3]]) as u32;
        let name_idx = u32::from_le_bytes([
            self.bytes[off + 4],
            self.bytes[off + 5],
            self.bytes[off + 6],
            self.bytes[off + 7],
        ]);

        let class_desc = self.resolve_type(class_idx).unwrap_or_else(|| format!("type@{}", class_idx));
        let type_desc = self.resolve_type(type_idx).unwrap_or_else(|| format!("type@{}", type_idx));
        let name = self.resolve_string(name_idx).unwrap_or_else(|| format!("string@{}", name_idx));

        Some((class_desc, name, type_desc))
    }

    /// Resolves a method reference by its method_id index.
    /// Returns (class_descriptor, method_name, method_signature).
    pub fn resolve_method(&self, idx: u32) -> Option<(String, String, String)> {
        let i = idx as usize;
        if i >= self.method_ids_size {
            return None;
        }
        let off = self.method_ids_off.checked_add(i.checked_mul(8)?)?;
        if off + 8 > self.bytes.len() {
            return None;
        }
        let class_idx = u16::from_le_bytes([self.bytes[off], self.bytes[off + 1]]) as u32;
        let proto_idx = u16::from_le_bytes([self.bytes[off + 2], self.bytes[off + 3]]) as usize;
        let name_idx = u32::from_le_bytes([
            self.bytes[off + 4],
            self.bytes[off + 5],
            self.bytes[off + 6],
            self.bytes[off + 7],
        ]);

        let class_desc = self.resolve_type(class_idx).unwrap_or_else(|| format!("type@{}", class_idx));
        let name = self.resolve_string(name_idx).unwrap_or_else(|| format!("string@{}", name_idx));

        // Resolve prototype
        let signature = if proto_idx < self.proto_ids_size {
            let p_off = self.proto_ids_off + proto_idx * 12;
            if p_off + 12 <= self.bytes.len() {
                let ret_type_idx = u32::from_le_bytes([
                    self.bytes[p_off + 4],
                    self.bytes[p_off + 5],
                    self.bytes[p_off + 6],
                    self.bytes[p_off + 7],
                ]);
                let ret_desc = self.resolve_type(ret_type_idx).unwrap_or_else(|| "V".to_string());
                let params_off = u32::from_le_bytes([
                    self.bytes[p_off + 8],
                    self.bytes[p_off + 9],
                    self.bytes[p_off + 10],
                    self.bytes[p_off + 11],
                ]) as usize;

                let mut params_str = String::new();
                if params_off > 0 && params_off + 4 <= self.bytes.len() {
                    let param_count = u32::from_le_bytes([
                        self.bytes[params_off],
                        self.bytes[params_off + 1],
                        self.bytes[params_off + 2],
                        self.bytes[params_off + 3],
                    ]) as usize;
                    let list_start = params_off + 4;
                    for p in 0..param_count {
                        let item_off = list_start + p * 2;
                        if item_off + 2 <= self.bytes.len() {
                            let p_idx = u16::from_le_bytes([self.bytes[item_off], self.bytes[item_off + 1]]) as u32;
                            if let Some(td) = self.resolve_type(p_idx) {
                                params_str.push_str(&td);
                            }
                        }
                    }
                }
                format!("({}){}", params_str, ret_desc)
            } else {
                "()V".to_string()
            }
        } else {
            "()V".to_string()
        };

        Some((class_desc, name, signature))
    }
}

/// Decodes instructions strictly bounded to `insns_size * 2` bytes.
pub fn disassemble_dalvik_instructions(
    bytes: &[u8],
    instruction_addr: u64,
    insns_size: u32,
    resolver: Option<&DexResolver>,
) -> Vec<DalvikInstruction> {
    if insns_size == 0 {
        return Vec::new();
    }

    let start_offset = instruction_addr as usize;
    let byte_len = (insns_size as usize) * 2;
    let end_offset = (start_offset + byte_len).min(bytes.len());

    if start_offset >= bytes.len() {
        return Vec::new();
    }

    let mut instructions = Vec::new();
    let mut offset = start_offset;

    while offset < end_offset {
        let addr = offset as u64;
        let remaining_words = (end_offset - offset) / 2;
        if remaining_words == 0 {
            // Trailing odd byte
            instructions.push(DalvikInstruction {
                addr,
                opcode: ".byte".to_string(),
                disasm: format!(".byte {:#04x}", bytes[offset]),
                bytes: Some(format!("{:02x}", bytes[offset])),
                ins_type: Some("data".to_string()),
            });
            break;
        }

        let word0 = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let opcode = (word0 & 0xff) as u8;

        // Check for payload directives (packed-switch-payload: 0x0100, sparse-switch: 0x0200, fill-array: 0x0300)
        if opcode == 0x00 && (word0 >> 8) != 0 {
            let ident = word0;
            let (payload_words, disasm_str) = match ident {
                0x0100 => {
                    // packed-switch-payload
                    if offset + 4 <= end_offset {
                        let size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
                        let total_w = 4 + size * 2;
                        (total_w, format!("packed-switch-payload ({})", size))
                    } else {
                        (1, "packed-switch-payload (truncated)".to_string())
                    }
                }
                0x0200 => {
                    // sparse-switch-payload
                    if offset + 4 <= end_offset {
                        let size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
                        let total_w = 2 + size * 4;
                        (total_w, format!("sparse-switch-payload ({})", size))
                    } else {
                        (1, "sparse-switch-payload (truncated)".to_string())
                    }
                }
                0x0300 => {
                    // fill-array-data-payload
                    if offset + 8 <= end_offset {
                        let elem_w = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
                        let size = u32::from_le_bytes([
                            bytes[offset + 4],
                            bytes[offset + 5],
                            bytes[offset + 6],
                            bytes[offset + 7],
                        ]) as usize;
                        let data_bytes = (size * elem_w).div_ceil(2) * 2;
                        let total_w = 4 + (data_bytes / 2);
                        (total_w, format!("fill-array-data-payload (sz: {}, width: {})", size, elem_w))
                    } else {
                        (1, "fill-array-data-payload (truncated)".to_string())
                    }
                }
                _ => (1, format!(".word {:#06x}", word0)),
            };

            let actual_w = payload_words.min(remaining_words);
            let b_len = actual_w * 2;
            let hex_bytes = bytes[offset..offset + b_len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();

            instructions.push(DalvikInstruction {
                addr,
                opcode: disasm_str.clone(),
                disasm: disasm_str,
                bytes: Some(hex_bytes),
                ins_type: Some("data".to_string()),
            });
            offset += b_len;
            continue;
        }

        // Standard opcode decode
        let (words_consumed, disasm, ins_type) = decode_single_instruction(
            bytes,
            offset,
            end_offset,
            addr,
            resolver,
        );

        let actual_words = words_consumed.min(remaining_words).max(1);
        let b_len = actual_words * 2;
        let hex_bytes = bytes[offset..offset + b_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        instructions.push(DalvikInstruction {
            addr,
            opcode: disasm.clone(),
            disasm,
            bytes: Some(hex_bytes),
            ins_type: Some(ins_type),
        });

        offset += b_len;
    }

    instructions
}

/// Decodes a single instruction word at `offset`.
/// Returns (instruction_words, formatted_disassembly, instruction_type).
fn decode_single_instruction(
    bytes: &[u8],
    offset: usize,
    _end_offset: usize,
    addr: u64,
    resolver: Option<&DexResolver>,
) -> (usize, String, String) {
    let word0 = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let op = (word0 & 0xff) as u8;
    let hi8 = ((word0 >> 8) & 0xff) as u8;
    let nib_a = ((word0 >> 8) & 0x0f) as u8;
    let nib_b = ((word0 >> 12) & 0x0f) as u8;

    let read_w = |idx: usize| -> u16 {
        let o = offset + idx * 2;
        if o + 2 <= bytes.len() {
            u16::from_le_bytes([bytes[o], bytes[o + 1]])
        } else {
            0
        }
    };

    match op {
        // 0x00: nop
        0x00 => (1, "nop".to_string(), "nop".to_string()),

        // 0x01..0x09: move instructions
        0x01 => (1, format!("move v{}, v{}", nib_a, nib_b), "mov".to_string()),
        0x02 => {
            let w1 = read_w(1);
            (2, format!("move/from16 v{}, v{}", hi8, w1), "mov".to_string())
        }
        0x03 => {
            let w1 = read_w(1);
            let w2 = read_w(2);
            (3, format!("move/16 v{}, v{}", w1, w2), "mov".to_string())
        }
        0x04 => (1, format!("move-wide v{}, v{}", nib_a, nib_b), "mov".to_string()),
        0x05 => {
            let w1 = read_w(1);
            (2, format!("move-wide/from16 v{}, v{}", hi8, w1), "mov".to_string())
        }
        0x06 => {
            let w1 = read_w(1);
            let w2 = read_w(2);
            (3, format!("move-wide/16 v{}, v{}", w1, w2), "mov".to_string())
        }
        0x07 => (1, format!("move-object v{}, v{}", nib_a, nib_b), "mov".to_string()),
        0x08 => {
            let w1 = read_w(1);
            (2, format!("move-object/from16 v{}, v{}", hi8, w1), "mov".to_string())
        }
        0x09 => {
            let w1 = read_w(1);
            let w2 = read_w(2);
            (3, format!("move-object/16 v{}, v{}", w1, w2), "mov".to_string())
        }

        // 0x0a..0x0d: move-result / move-exception
        0x0a => (1, format!("move-result v{}", hi8), "mov".to_string()),
        0x0b => (1, format!("move-result-wide v{}", hi8), "mov".to_string()),
        0x0c => (1, format!("move-result-object v{}", hi8), "mov".to_string()),
        0x0d => (1, format!("move-exception v{}", hi8), "mov".to_string()),

        // 0x0e..0x11: return instructions
        0x0e => (1, "return-void".to_string(), "ret".to_string()),
        0x0f => (1, format!("return v{}", hi8), "ret".to_string()),
        0x10 => (1, format!("return-wide v{}", hi8), "ret".to_string()),
        0x11 => (1, format!("return-object v{}", hi8), "ret".to_string()),

        // 0x12..0x19: const instructions
        0x12 => {
            // const/4 vA, #+B (B is signed 4-bit)
            let lit = ((nib_b as i8) << 4) >> 4;
            (1, format!("const/4 v{}, #{}", nib_a, lit), "load".to_string())
        }
        0x13 => {
            let w1 = read_w(1) as i16;
            (2, format!("const/16 v{}, #{}", hi8, w1), "load".to_string())
        }
        0x14 => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let val = ((w2 << 16) | w1) as i32;
            (3, format!("const v{}, #{}", hi8, val), "load".to_string())
        }
        0x15 => {
            let w1 = read_w(1) as u32;
            let val = (w1 << 16) as i32;
            (2, format!("const-high16 v{}, #{}", hi8, val), "load".to_string())
        }
        0x16 => {
            let w1 = read_w(1) as i16;
            (2, format!("const-wide/16 v{}, #{}", hi8, w1), "load".to_string())
        }
        0x17 => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let val = ((w2 << 16) | w1) as i32 as i64;
            (3, format!("const-wide/32 v{}, #{}", hi8, val), "load".to_string())
        }
        0x18 => {
            let w1 = read_w(1) as u64;
            let w2 = read_w(2) as u64;
            let w3 = read_w(3) as u64;
            let w4 = read_w(4) as u64;
            let val = (w4 << 48) | (w3 << 32) | (w2 << 16) | w1;
            (5, format!("const-wide v{}, #{}", hi8, val as i64), "load".to_string())
        }
        0x19 => {
            let w1 = read_w(1) as u64;
            let val = (w1 << 48) as i64;
            (2, format!("const-wide-high16 v{}, #{}", hi8, val), "load".to_string())
        }

        // 0x1a: const-string vAA, string@BBBB
        0x1a => {
            let s_idx = read_w(1) as u32;
            let s_text = resolver
                .and_then(|r| r.resolve_string(s_idx))
                .map(|s| format!("\"{}\"", s.escape_default()))
                .unwrap_or_else(|| format!("string@{}", s_idx));
            (2, format!("const-string v{}, {}", hi8, s_text), "load".to_string())
        }
        // 0x1b: const-string/jumbo vAA, string@BBBBBBBB
        0x1b => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let s_idx = (w2 << 16) | w1;
            let s_text = resolver
                .and_then(|r| r.resolve_string(s_idx))
                .map(|s| format!("\"{}\"", s.escape_default()))
                .unwrap_or_else(|| format!("string@{}", s_idx));
            (3, format!("const-string/jumbo v{}, {}", hi8, s_text), "load".to_string())
        }
        // 0x1c: const-class vAA, type@BBBB
        0x1c => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            (2, format!("const-class v{}, {}", hi8, t_desc), "load".to_string())
        }

        // 0x1d..0x1e: monitor
        0x1d => (1, format!("monitor-enter v{}", hi8), "sync".to_string()),
        0x1e => (1, format!("monitor-exit v{}", hi8), "sync".to_string()),

        // 0x1f: check-cast
        0x1f => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            (2, format!("check-cast v{}, {}", hi8, t_desc), "cmp".to_string())
        }
        // 0x20: instance-of vA, vB, type@CCCC
        0x20 => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            (2, format!("instance-of v{}, v{}, {}", nib_a, nib_b, t_desc), "cmp".to_string())
        }
        // 0x21: array-length
        0x21 => (1, format!("array-length v{}, v{}", nib_a, nib_b), "load".to_string()),
        // 0x22: new-instance vAA, type@BBBB
        0x22 => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            (2, format!("new-instance v{}, {}", hi8, t_desc), "load".to_string())
        }
        // 0x23: new-array vA, vB, type@CCCC
        0x23 => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            (2, format!("new-array v{}, v{}, {}", nib_a, nib_b, t_desc), "load".to_string())
        }
        // 0x24: filled-new-array {vC, ...}, type@BBBB
        0x24 => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            let w2 = read_w(2);
            let args = format_35c_args(nib_b as usize, nib_a, w2);
            (3, format!("filled-new-array {{{}}}, {}", args, t_desc), "load".to_string())
        }
        // 0x25: filled-new-array/range {vCCCC .. vNNNN}, type@BBBB
        0x25 => {
            let t_idx = read_w(1) as u32;
            let t_desc = resolver
                .and_then(|r| r.resolve_type(t_idx))
                .unwrap_or_else(|| format!("type@{}", t_idx));
            let start_reg = read_w(2);
            let count = hi8 as u16;
            let end_reg = start_reg + count.saturating_sub(1);
            (3, format!("filled-new-array/range {{v{} .. v{}}}, {}", start_reg, end_reg, t_desc), "load".to_string())
        }
        // 0x26: fill-array-data vAA, +BBBBBBBB
        0x26 => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let rel_offset = ((w2 << 16) | w1) as i32;
            let target_addr = (addr as i64 + (rel_offset as i64) * 2) as u64;
            (3, format!("fill-array-data v{}, 0x{:x}", hi8, target_addr), "store".to_string())
        }
        // 0x27: throw
        0x27 => (1, format!("throw v{}", hi8), "jmp".to_string()),

        // 0x28..0x2a: goto
        0x28 => {
            let off = (hi8 as i8) as i64;
            let target = (addr as i64 + off * 2) as u64;
            (1, format!("goto 0x{:x}", target), "jmp".to_string())
        }
        0x29 => {
            let off = (read_w(1) as i16) as i64;
            let target = (addr as i64 + off * 2) as u64;
            (2, format!("goto/16 0x{:x}", target), "jmp".to_string())
        }
        0x2a => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let off = ((w2 << 16) | w1) as i32 as i64;
            let target = (addr as i64 + off * 2) as u64;
            (3, format!("goto/32 0x{:x}", target), "jmp".to_string())
        }

        // 0x2b..0x2c: switch
        0x2b => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let off = ((w2 << 16) | w1) as i32 as i64;
            let target = (addr as i64 + off * 2) as u64;
            (3, format!("packed-switch v{}, 0x{:x}", hi8, target), "cjmp".to_string())
        }
        0x2c => {
            let w1 = read_w(1) as u32;
            let w2 = read_w(2) as u32;
            let off = ((w2 << 16) | w1) as i32 as i64;
            let target = (addr as i64 + off * 2) as u64;
            (3, format!("sparse-switch v{}, 0x{:x}", hi8, target), "cjmp".to_string())
        }

        // 0x2d..0x31: cmp
        0x2d => (2, format_23x("cmpl-float", hi8, read_w(1)), "cmp".to_string()),
        0x2e => (2, format_23x("cmpg-float", hi8, read_w(1)), "cmp".to_string()),
        0x2f => (2, format_23x("cmpl-double", hi8, read_w(1)), "cmp".to_string()),
        0x30 => (2, format_23x("cmpg-double", hi8, read_w(1)), "cmp".to_string()),
        0x31 => (2, format_23x("cmp-long", hi8, read_w(1)), "cmp".to_string()),

        // 0x32..0x37: if-test vA, vB, +CCCC
        0x32..=0x37 => {
            let mnem = match op {
                0x32 => "if-eq",
                0x33 => "if-ne",
                0x34 => "if-lt",
                0x35 => "if-ge",
                0x36 => "if-gt",
                0x37 => "if-le",
                _ => unreachable!(),
            };
            let off = (read_w(1) as i16) as i64;
            let target = (addr as i64 + off * 2) as u64;
            (2, format!("{} v{}, v{}, 0x{:x}", mnem, nib_a, nib_b, target), "cjmp".to_string())
        }

        // 0x38..0x3d: if-testz vAA, +BBBB
        0x38..=0x3d => {
            let mnem = match op {
                0x38 => "if-eqz",
                0x39 => "if-nez",
                0x3a => "if-ltz",
                0x3b => "if-gez",
                0x3c => "if-gtz",
                0x3d => "if-lez",
                _ => unreachable!(),
            };
            let off = (read_w(1) as i16) as i64;
            let target = (addr as i64 + off * 2) as u64;
            (2, format!("{} v{}, 0x{:x}", mnem, hi8, target), "cjmp".to_string())
        }

        // 0x44..0x4a: aget
        0x44..=0x4a => {
            let mnem = match op {
                0x44 => "aget",
                0x45 => "aget-wide",
                0x46 => "aget-object",
                0x47 => "aget-boolean",
                0x48 => "aget-byte",
                0x49 => "aget-char",
                0x4a => "aget-short",
                _ => unreachable!(),
            };
            (2, format_23x(mnem, hi8, read_w(1)), "load".to_string())
        }

        // 0x4b..0x51: aput
        0x4b..=0x51 => {
            let mnem = match op {
                0x4b => "aput",
                0x4c => "aput-wide",
                0x4d => "aput-object",
                0x4e => "aput-boolean",
                0x4f => "aput-byte",
                0x50 => "aput-char",
                0x51 => "aput-short",
                _ => unreachable!(),
            };
            (2, format_23x(mnem, hi8, read_w(1)), "store".to_string())
        }

        // 0x52..0x58: iget
        0x52..=0x58 => {
            let mnem = match op {
                0x52 => "iget",
                0x53 => "iget-wide",
                0x54 => "iget-object",
                0x55 => "iget-boolean",
                0x56 => "iget-byte",
                0x57 => "iget-char",
                0x58 => "iget-short",
                _ => unreachable!(),
            };
            let f_idx = read_w(1) as u32;
            let field_str = format_field_ref(f_idx, resolver);
            (2, format!("{} v{}, v{}, {}", mnem, nib_a, nib_b, field_str), "load".to_string())
        }

        // 0x59..0x5f: iput
        0x59..=0x5f => {
            let mnem = match op {
                0x59 => "iput",
                0x5a => "iput-wide",
                0x5b => "iput-object",
                0x5c => "iput-boolean",
                0x5d => "iput-byte",
                0x5e => "iput-char",
                0x5f => "iput-short",
                _ => unreachable!(),
            };
            let f_idx = read_w(1) as u32;
            let field_str = format_field_ref(f_idx, resolver);
            (2, format!("{} v{}, v{}, {}", mnem, nib_a, nib_b, field_str), "store".to_string())
        }

        // 0x60..0x66: sget
        0x60..=0x66 => {
            let mnem = match op {
                0x60 => "sget",
                0x61 => "sget-wide",
                0x62 => "sget-object",
                0x63 => "sget-boolean",
                0x64 => "sget-byte",
                0x65 => "sget-char",
                0x66 => "sget-short",
                _ => unreachable!(),
            };
            let f_idx = read_w(1) as u32;
            let field_str = format_field_ref(f_idx, resolver);
            (2, format!("{} v{}, {}", mnem, hi8, field_str), "load".to_string())
        }

        // 0x67..0x6d: sput
        0x67..=0x6d => {
            let mnem = match op {
                0x67 => "sput",
                0x68 => "sput-wide",
                0x69 => "sput-object",
                0x6a => "sput-boolean",
                0x6b => "sput-byte",
                0x6c => "sput-char",
                0x6d => "sput-short",
                _ => unreachable!(),
            };
            let f_idx = read_w(1) as u32;
            let field_str = format_field_ref(f_idx, resolver);
            (2, format!("{} v{}, {}", mnem, hi8, field_str), "store".to_string())
        }

        // 0x6e..0x72: invoke-kind {vC, ...}, meth@BBBB
        0x6e..=0x72 => {
            let mnem = match op {
                0x6e => "invoke-virtual",
                0x6f => "invoke-super",
                0x70 => "invoke-direct",
                0x71 => "invoke-static",
                0x72 => "invoke-interface",
                _ => unreachable!(),
            };
            let m_idx = read_w(1) as u32;
            let meth_str = format_method_ref(m_idx, resolver);
            let w2 = read_w(2);
            let args = format_35c_args(nib_b as usize, nib_a, w2);
            (3, format!("{} {{{}}}, {}", mnem, args, meth_str), "call".to_string())
        }

        // 0x74..0x78: invoke-kind/range {vCCCC .. vNNNN}, meth@BBBB
        0x74..=0x78 => {
            let mnem = match op {
                0x74 => "invoke-virtual/range",
                0x75 => "invoke-super/range",
                0x76 => "invoke-direct/range",
                0x77 => "invoke-static/range",
                0x78 => "invoke-interface/range",
                _ => unreachable!(),
            };
            let m_idx = read_w(1) as u32;
            let meth_str = format_method_ref(m_idx, resolver);
            let start_reg = read_w(2);
            let count = hi8 as u16;
            let end_reg = start_reg + count.saturating_sub(1);
            let range_str = if count == 0 {
                "".to_string()
            } else if count == 1 {
                format!("v{}", start_reg)
            } else {
                format!("v{} .. v{}", start_reg, end_reg)
            };
            (3, format!("{} {{{}}}, {}", mnem, range_str, meth_str), "call".to_string())
        }

        // 0x7b..0x8f: unops
        0x7b..=0x8f => {
            let mnem = match op {
                0x7b => "neg-int",
                0x7c => "not-int",
                0x7d => "neg-long",
                0x7e => "not-long",
                0x7f => "neg-float",
                0x80 => "neg-double",
                0x81 => "int-to-long",
                0x82 => "int-to-float",
                0x83 => "int-to-double",
                0x84 => "long-to-int",
                0x85 => "long-to-float",
                0x86 => "long-to-double",
                0x87 => "float-to-int",
                0x88 => "float-to-long",
                0x89 => "float-to-double",
                0x8a => "double-to-int",
                0x8b => "double-to-long",
                0x8c => "double-to-float",
                0x8d => "int-to-byte",
                0x8e => "int-to-char",
                0x8f => "int-to-short",
                _ => unreachable!(),
            };
            (1, format!("{} v{}, v{}", mnem, nib_a, nib_b), "arith".to_string())
        }

        // 0x90..0xaf: binops (23x)
        0x90..=0xaf => {
            let mnem = match op {
                0x90 => "add-int", 0x91 => "sub-int", 0x92 => "mul-int", 0x93 => "div-int", 0x94 => "rem-int",
                0x95 => "and-int", 0x96 => "or-int", 0x97 => "xor-int", 0x98 => "shl-int", 0x99 => "shr-int",
                0x9a => "ushr-int", 0x9b => "add-long", 0x9c => "sub-long", 0x9d => "mul-long", 0x9e => "div-long",
                0x9f => "rem-long", 0xa0 => "and-long", 0xa1 => "or-long", 0xa2 => "xor-long", 0xa3 => "shl-long",
                0xa4 => "shr-long", 0xa5 => "ushr-long", 0xa6 => "add-float", 0xa7 => "sub-float", 0xa8 => "mul-float",
                0xa9 => "div-float", 0xaa => "rem-float", 0xab => "add-double", 0xac => "sub-double", 0xad => "mul-double",
                0xae => "div-double", 0xaf => "rem-double",
                _ => unreachable!(),
            };
            (2, format_23x(mnem, hi8, read_w(1)), "arith".to_string())
        }

        // 0xb0..0xcf: binops/2addr (12x)
        0xb0..=0xcf => {
            let mnem = match op {
                0xb0 => "add-int/2addr", 0xb1 => "sub-int/2addr", 0xb2 => "mul-int/2addr", 0xb3 => "div-int/2addr",
                0xb4 => "rem-int/2addr", 0xb5 => "and-int/2addr", 0xb6 => "or-int/2addr", 0xb7 => "xor-int/2addr",
                0xb8 => "shl-int/2addr", 0xb9 => "shr-int/2addr", 0xba => "ushr-int/2addr",
                0xbb => "add-long/2addr", 0xbc => "sub-long/2addr", 0xbd => "mul-long/2addr", 0xbe => "div-long/2addr",
                0xbf => "rem-long/2addr", 0xc0 => "and-long/2addr", 0xc1 => "or-long/2addr", 0xc2 => "xor-long/2addr",
                0xc3 => "shl-long/2addr", 0xc4 => "shr-long/2addr", 0xc5 => "ushr-long/2addr",
                0xc6 => "add-float/2addr", 0xc7 => "sub-float/2addr", 0xc8 => "mul-float/2addr", 0xc9 => "div-float/2addr",
                0xca => "rem-float/2addr", 0xcb => "add-double/2addr", 0xcc => "sub-double/2addr", 0xcd => "mul-double/2addr",
                0xce => "div-double/2addr", 0xcf => "rem-double/2addr",
                _ => unreachable!(),
            };
            (1, format!("{} v{}, v{}", mnem, nib_a, nib_b), "arith".to_string())
        }

        // 0xd0..0xd7: binop/lit16 (22s)
        0xd0..=0xd7 => {
            let mnem = match op {
                0xd0 => "add-int/lit16", 0xd1 => "rsub-int", 0xd2 => "mul-int/lit16", 0xd3 => "div-int/lit16",
                0xd4 => "rem-int/lit16", 0xd5 => "and-int/lit16", 0xd6 => "or-int/lit16", 0xd7 => "xor-int/lit16",
                _ => unreachable!(),
            };
            let lit = read_w(1) as i16;
            (2, format!("{} v{}, v{}, #{}", mnem, nib_a, nib_b, lit), "arith".to_string())
        }

        // 0xd8..0xe2: binop/lit8 (22b)
        0xd8..=0xe2 => {
            let mnem = match op {
                0xd8 => "add-int/lit8", 0xd9 => "rsub-int/lit8", 0xda => "mul-int/lit8", 0xdb => "div-int/lit8",
                0xdc => "rem-int/lit8", 0xdd => "and-int/lit8", 0xde => "or-int/lit8", 0xdf => "xor-int/lit8",
                0xe0 => "shl-int/lit8", 0xe1 => "shr-int/lit8", 0xe2 => "ushr-int/lit8",
                _ => unreachable!(),
            };
            let w1 = read_w(1);
            let v_b = (w1 & 0xff) as u8;
            let lit = ((w1 >> 8) as i8) as i32;
            (2, format!("{} v{}, v{}, #{}", mnem, hi8, v_b, lit), "arith".to_string())
        }

        // 0xfa..0xfd: invoke-polymorphic / invoke-custom
        0xfa => (4, format!("invoke-polymorphic v{}", hi8), "call".to_string()),
        0xfb => (4, format!("invoke-polymorphic/range v{}", hi8), "call".to_string()),
        0xfc => (3, format!("invoke-custom v{}", hi8), "call".to_string()),
        0xfd => (3, format!("invoke-custom/range v{}", hi8), "call".to_string()),

        // Fallback for unknown / illegal / data bytes
        _ => {
            (1, format!(".byte {:#04x}", op), "data".to_string())
        }
    }
}

fn format_35c_args(count: usize, g: u8, w2: u16) -> String {
    let c = (w2 & 0x0f) as u8;
    let d = ((w2 >> 4) & 0x0f) as u8;
    let e = ((w2 >> 8) & 0x0f) as u8;
    let f = ((w2 >> 12) & 0x0f) as u8;

    match count {
        0 => "".to_string(),
        1 => format!("v{}", c),
        2 => format!("v{}, v{}", c, d),
        3 => format!("v{}, v{}, v{}", c, d, e),
        4 => format!("v{}, v{}, v{}, v{}", c, d, e, f),
        5 => format!("v{}, v{}, v{}, v{}, v{}", c, d, e, f, g),
        _ => format!("v{}, v{}, v{}, v{}, v{}", c, d, e, f, g),
    }
}

fn format_23x(mnem: &str, v_a: u8, w1: u16) -> String {
    let v_b = (w1 & 0xff) as u8;
    let v_c = ((w1 >> 8) & 0xff) as u8;
    format!("{} v{}, v{}, v{}", mnem, v_a, v_b, v_c)
}

fn format_field_ref(idx: u32, resolver: Option<&DexResolver>) -> String {
    if let Some(r) = resolver {
        if let Some((cls, name, ty)) = r.resolve_field(idx) {
            return format!("{}->{} {}", cls, name, ty);
        }
    }
    format!("field@{}", idx)
}

fn format_method_ref(idx: u32, resolver: Option<&DexResolver>) -> String {
    if let Some(r) = resolver {
        if let Some((cls, name, sig)) = r.resolve_method(idx) {
            return format!("{}->{}{}", cls, name, sig);
        }
    }
    format!("meth@{}", idx)
}

// -----------------------------------------------------------------------------
// Control Flow Graph (CFG) Analysis
// -----------------------------------------------------------------------------

/// Builds a complete Control Flow Graph (CFG) for a method's disassembled instructions.
pub fn build_dalvik_cfg(method_name: &str, instructions: &[DalvikInstruction]) -> DexMethodCfg {
    if instructions.is_empty() {
        return DexMethodCfg {
            method_name: method_name.to_string(),
            total_blocks: 0,
            blocks: Vec::new(),
            decision_gates: Vec::new(),
            loop_count: 0,
        };
    }

    // 1. Identify basic block leaders
    let mut leaders = BTreeSet::new();
    leaders.insert(instructions[0].addr);

    for (idx, inst) in instructions.iter().enumerate() {
        let is_term = is_branch_or_terminal(inst);
        if let Some(target) = extract_branch_target(inst) {
            leaders.insert(target);
        }
        if is_term && idx + 1 < instructions.len() {
            leaders.insert(instructions[idx + 1].addr);
        }
    }

    // 2. Partition instructions into basic blocks
    let mut raw_blocks = Vec::new();
    let mut curr_insts: Vec<DalvikInstruction> = Vec::new();
    let mut curr_start = instructions[0].addr;

    for inst in instructions {
        if leaders.contains(&inst.addr) && !curr_insts.is_empty() {
            let last_inst = curr_insts.last().unwrap();
            let end_addr = last_inst.addr + instruction_byte_size(last_inst);
            raw_blocks.push((curr_start, end_addr, curr_insts));
            curr_insts = Vec::new();
            curr_start = inst.addr;
        }
        curr_insts.push(inst.clone());
    }

    if !curr_insts.is_empty() {
        let last_inst = curr_insts.last().unwrap();
        let end_addr = last_inst.addr + instruction_byte_size(last_inst);
        raw_blocks.push((curr_start, end_addr, curr_insts));
    }

    // Map start_addr to block ID
    let addr_to_id: HashMap<u64, usize> = raw_blocks
        .iter()
        .enumerate()
        .map(|(id, (start, _, _))| (*start, id))
        .collect();

    let mut blocks = Vec::new();
    let mut decision_gates = Vec::new();
    let mut loop_count = 0;

    for (id, (start_addr, end_addr, insts)) in raw_blocks.into_iter().enumerate() {
        let last_inst = insts.last().unwrap();
        let mut successors = Vec::new();
        let mut jump_target = None;
        let mut fail_target = None;

        let last_op = &last_inst.opcode;
        let is_ret_or_throw = last_inst.ins_type.as_deref() == Some("ret")
            || last_op.starts_with("return")
            || last_op.starts_with("throw");

        if is_conditional_branch(last_inst) {
            jump_target = extract_branch_target(last_inst);
            fail_target = Some(end_addr);

            if let Some(jt) = jump_target {
                if let Some(&succ_id) = addr_to_id.get(&jt) {
                    successors.push(succ_id);
                }
                if jt <= start_addr {
                    loop_count += 1;
                }
            }
            if let Some(ft) = fail_target {
                if let Some(&succ_id) = addr_to_id.get(&ft) {
                    successors.push(succ_id);
                }
                if ft <= start_addr {
                    loop_count += 1;
                }
            }

            // Create Decision Gate
            if let (Some(jt), Some(ft)) = (jump_target, fail_target) {
                let condition_inst = if insts.len() >= 2 {
                    insts[insts.len() - 2].disasm.clone()
                } else {
                    "implicit".to_string()
                };

                let gate_type = classify_gate_type(&last_inst.disasm);

                decision_gates.push(BranchGateNode {
                    addr: last_inst.addr,
                    addr_hex: format!("0x{:x}", last_inst.addr),
                    condition_instruction: condition_inst,
                    branch_instruction: last_inst.disasm.clone(),
                    jump_target: jt,
                    jump_target_hex: format!("0x{:x}", jt),
                    fail_target: ft,
                    fail_target_hex: format!("0x{:x}", ft),
                    gate_type,
                });
            }
        } else if is_unconditional_jump(last_inst) {
            jump_target = extract_branch_target(last_inst);
            if let Some(jt) = jump_target {
                if let Some(&succ_id) = addr_to_id.get(&jt) {
                    successors.push(succ_id);
                }
                if jt <= start_addr {
                    loop_count += 1;
                }
            }
        } else if !is_ret_or_throw {
            // Fallthrough to next block
            fail_target = Some(end_addr);
            if let Some(&succ_id) = addr_to_id.get(&end_addr) {
                successors.push(succ_id);
            }
        }

        blocks.push(DexBasicBlock {
            id,
            start_addr,
            end_addr,
            instructions: insts,
            successors,
            predecessors: Vec::new(),
            jump_target,
            fail_target,
        });
    }

    // Populate predecessors
    for src_id in 0..blocks.len() {
        let succs = blocks[src_id].successors.clone();
        for succ_id in succs {
            if succ_id < blocks.len() && !blocks[succ_id].predecessors.contains(&src_id) {
                blocks[succ_id].predecessors.push(src_id);
            }
        }
    }

    let total_blocks = blocks.len();
    DexMethodCfg {
        method_name: method_name.to_string(),
        total_blocks,
        blocks,
        decision_gates,
        loop_count,
    }
}

fn is_conditional_branch(inst: &DalvikInstruction) -> bool {
    let op = inst.opcode.trim();
    op.starts_with("if-")
}

fn is_unconditional_jump(inst: &DalvikInstruction) -> bool {
    let op = inst.opcode.trim();
    op.starts_with("goto")
}

fn is_branch_or_terminal(inst: &DalvikInstruction) -> bool {
    let op = inst.opcode.trim();
    op.starts_with("if-")
        || op.starts_with("goto")
        || op.starts_with("return")
        || op.starts_with("throw")
        || op.starts_with("packed-switch")
        || op.starts_with("sparse-switch")
        || inst.ins_type.as_deref() == Some("ret")
        || inst.ins_type.as_deref() == Some("jmp")
        || inst.ins_type.as_deref() == Some("cjmp")
}

fn extract_branch_target(inst: &DalvikInstruction) -> Option<u64> {
    let text = &inst.disasm;
    // Look for trailing 0x hex address
    for part in text.split_whitespace().rev() {
        let cleaned = part.trim_matches(|c: char| c == ',' || c == '{' || c == '}');
        if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
            if let Ok(v) = u64::from_str_radix(&cleaned[2..], 16) {
                return Some(v);
            }
        }
    }
    None
}

fn instruction_byte_size(inst: &DalvikInstruction) -> u64 {
    if let Some(b) = &inst.bytes {
        (b.len() / 2) as u64
    } else {
        2
    }
}

// -----------------------------------------------------------------------------
// Method Pseudo-Java Decompilation
// -----------------------------------------------------------------------------

/// Decompiles a Dalvik method into structured, readable pseudo-Java directly from its CFG blocks.
pub fn decompile_dalvik_method_pure_rust(
    class_name: &str,
    method: &DexMethodSummary,
    cfg: &DexMethodCfg,
) -> String {
    let mut out = String::new();

    // Reconstruct method signature header
    let access = crate::apk::dex::format_access_flags_method(method.access_flags);
    let access_prefix = if access.is_empty() { String::new() } else { format!("{} ", access) };

    // Format return type and parameters from signature
    let (params_java, ret_java) = parse_dalvik_signature(&method.signature);

    out.push_str(&format!("{}{} {}({}) {{\n", access_prefix, ret_java, method.name, params_java));

    if cfg.blocks.is_empty() {
        out.push_str("    // <no bytecode: abstract or native>\n");
        out.push_str("}\n");
        return out;
    }

    out.push_str(&format!("    // Method {} (blocks: {}, loops: {})\n", method.name, cfg.total_blocks, cfg.loop_count));

    for block in &cfg.blocks {
        out.push_str(&format!("  block_{}:\n", block.id));

        for inst in &block.instructions {
            let line = decompile_single_instruction(inst, class_name);
            if !line.is_empty() {
                out.push_str(&format!("    {}\n", line));
            }
        }
    }

    out.push_str("}\n");
    out
}

fn parse_dalvik_signature(sig: &str) -> (String, String) {
    if !sig.starts_with('(') {
        return ("".to_string(), "void".to_string());
    }
    let close = match sig.find(')') {
        Some(idx) => idx,
        None => return ("".to_string(), "void".to_string()),
    };
    let params_part = &sig[1..close];
    let ret_part = &sig[close + 1..];

    let ret_type = descriptor_to_java(ret_part);
    let param_types = split_descriptors(params_part);
    let params_str = param_types
        .into_iter()
        .enumerate()
        .map(|(i, t)| format!("{} p{}", descriptor_to_java(&t), i))
        .collect::<Vec<_>>()
        .join(", ");

    (params_str, ret_type)
}

fn descriptor_to_java(desc: &str) -> String {
    if desc.is_empty() { return "void".to_string(); }
    if let Some(stripped) = desc.strip_prefix('[') {
        return format!("{}[]", descriptor_to_java(stripped));
    }
    match desc {
        "V" => "void".to_string(),
        "Z" => "boolean".to_string(),
        "B" => "byte".to_string(),
        "S" => "short".to_string(),
        "C" => "char".to_string(),
        "I" => "int".to_string(),
        "J" => "long".to_string(),
        "F" => "float".to_string(),
        "D" => "double".to_string(),
        _ => {
            if desc.starts_with('L') && desc.ends_with(';') {
                let inner = &desc[1..desc.len() - 1];
                let simple = inner.rsplit('/').next().unwrap_or(inner);
                simple.replace('$', ".").to_string()
            } else {
                desc.to_string()
            }
        }
    }
}

fn split_descriptors(params: &str) -> Vec<String> {
    let mut list = Vec::new();
    let chars: Vec<char> = params.chars().collect();
    let mut idx = 0;
    while idx < chars.len() {
        let mut prefix = String::new();
        while idx < chars.len() && chars[idx] == '[' {
            prefix.push('[');
            idx += 1;
        }
        if idx >= chars.len() { break; }
        if chars[idx] == 'L' {
            let start = idx;
            while idx < chars.len() && chars[idx] != ';' {
                idx += 1;
            }
            if idx < chars.len() && chars[idx] == ';' {
                idx += 1;
            }
            let s: String = chars[start..idx].iter().collect();
            list.push(format!("{}{}", prefix, s));
        } else {
            let s: String = chars[idx..=idx].iter().collect();
            idx += 1;
            list.push(format!("{}{}", prefix, s));
        }
    }
    list
}

fn decompile_single_instruction(inst: &DalvikInstruction, _class_name: &str) -> String {
    let op = inst.opcode.trim();
    let dis = inst.disasm.trim();

    if op == "nop" {
        return "// nop".to_string();
    }
    if op == "return-void" {
        return "return;".to_string();
    }
    if op.starts_with("return ") || op.starts_with("return-wide ") || op.starts_with("return-object ") {
        let reg = op.split_whitespace().nth(1).unwrap_or("v0");
        return format!("return {};", reg);
    }
    if op.starts_with("throw ") {
        let reg = op.split_whitespace().nth(1).unwrap_or("v0");
        return format!("throw {};", reg);
    }
    if op.starts_with("const-string ") || op.starts_with("const-string/jumbo ") {
        let parts: Vec<&str> = dis.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            let reg = parts[1].trim_matches(',');
            let str_val = parts[2];
            return format!("{} = {};", reg, str_val);
        }
    }
    if op.starts_with("const ") || op.starts_with("const/4 ") || op.starts_with("const/16 ") || op.starts_with("const-wide ") {
        let parts: Vec<&str> = dis.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            let reg = parts[1].trim_matches(',');
            let val = parts[2].trim_start_matches('#');
            return format!("{} = {};", reg, val);
        }
    }
    if op.starts_with("iget") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 4 {
            let dst = parts[1].trim_matches(',');
            let obj = parts[2].trim_matches(',');
            let field_info = parts[3];
            let field_name = field_info.split("->").nth(1).unwrap_or(field_info);
            return format!("{} = {}.{};", dst, obj, field_name);
        }
    }
    if op.starts_with("iput") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 4 {
            let src = parts[1].trim_matches(',');
            let obj = parts[2].trim_matches(',');
            let field_info = parts[3];
            let field_name = field_info.split("->").nth(1).unwrap_or(field_info);
            return format!("{}.{} = {};", obj, field_name, src);
        }
    }
    if op.starts_with("sget") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 3 {
            let dst = parts[1].trim_matches(',');
            let field_info = parts[2];
            let field_name = field_info.split("->").nth(1).unwrap_or(field_info);
            return format!("{} = {};", dst, field_name);
        }
    }
    if op.starts_with("sput") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 3 {
            let src = parts[1].trim_matches(',');
            let field_info = parts[2];
            let field_name = field_info.split("->").nth(1).unwrap_or(field_info);
            return format!("{} = {};", field_name, src);
        }
    }
    if op.starts_with("invoke-") {
        if let Some(brace_start) = dis.find('{') {
            if let Some(brace_end) = dis.find('}') {
                let args = &dis[brace_start + 1..brace_end];
                let meth = dis[brace_end + 1..].trim().trim_start_matches(',').trim();
                let meth_name = meth.split("->").nth(1).unwrap_or(meth);
                return format!("{}({});", meth_name, args);
            }
        }
    }
    if op.starts_with("if-") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 4 {
            let mnem = parts[0];
            let v1 = parts[1].trim_matches(',');
            let v2 = parts[2].trim_matches(',');
            let target = parts[3];
            let sym = match mnem {
                "if-eq" => "==", "if-ne" => "!=", "if-lt" => "<", "if-ge" => ">=", "if-gt" => ">", "if-le" => "<=", _ => "==",
            };
            return format!("if ({} {} {}) goto {};", v1, sym, v2, target);
        } else if parts.len() >= 3 {
            let mnem = parts[0];
            let v1 = parts[1].trim_matches(',');
            let target = parts[2];
            let sym = match mnem {
                "if-eqz" => "==", "if-nez" => "!=", "if-ltz" => "<", "if-gez" => ">=", "if-gtz" => ">", "if-lez" => "<=", _ => "==",
            };
            return format!("if ({} {} 0) goto {};", v1, sym, target);
        }
    }
    if op.starts_with("goto") {
        let target = dis.split_whitespace().nth(1).unwrap_or("");
        return format!("goto {};", target);
    }
    if op.starts_with("move") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 3 {
            let dst = parts[1].trim_matches(',');
            let src = parts[2];
            return format!("{} = {};", dst, src);
        }
    }
    if op.starts_with("check-cast") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 3 {
            let reg = parts[1].trim_matches(',');
            let ty = parts[2];
            return format!("{} = ({}) {};", reg, descriptor_to_java(ty), reg);
        }
    }
    if op.starts_with("new-instance") {
        let parts: Vec<&str> = dis.split_whitespace().collect();
        if parts.len() >= 3 {
            let reg = parts[1].trim_matches(',');
            let ty = parts[2];
            return format!("{} = new {}();", reg, descriptor_to_java(ty));
        }
    }

    // Default statement format
    format!("{};", dis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dalvik_decode_canonical_instructions() {
        // Construct synthetic bytecode exercising various canonical formats:
        // 0: nop (10x) -> 0x00, 0x00
        // 2: move v0, v1 (12x) -> 0x01, 0x10 (A=0, B=1)
        // 4: const/4 v2, #5 (11n) -> 0x12, 0x52 (A=2, B=5)
        // 6: move-result v3 (11x) -> 0x0a, 0x03 (AA=3)
        // 8: goto +2 (10t) -> 0x28, 0x02 (+2 16-bit words => addr 8 + 4 = 12)
        // 10: return-void (10x) -> 0x0e, 0x00
        // 12: if-eq v0, v1, +2 (22t) -> 0x32, 0x10, 0x02, 0x00 (+2 words => addr 12 + 4 = 16)
        // 16: if-eqz v2, +2 (21t) -> 0x38, 0x02, 0x02, 0x00 (+2 words => addr 16 + 4 = 20)
        // 20: const-string v0, string@1 (21c) -> 0x1a, 0x00, 0x01, 0x00
        // 24: iget v1, v0, field@2 (22c) -> 0x52, 0x01, 0x02, 0x00
        // 28: invoke-virtual {v0, v1}, method@3 (35c) -> 0x6e, 0x20, 0x03, 0x00, 0x10, 0x00
        // 34: invoke-virtual/range {v0 .. v3}, method@3 (3rc) -> 0x74, 0x04, 0x03, 0x00, 0x00, 0x00
        // 40: return v0 (11x) -> 0x0f, 0x00
        let bytecode = vec![
            0x00, 0x00,             // 0: nop
            0x01, 0x10,             // 2: move v0, v1
            0x12, 0x52,             // 4: const/4 v2, #5
            0x0a, 0x03,             // 6: move-result v3
            0x28, 0x02,             // 8: goto +2
            0x0e, 0x00,             // 10: return-void
            0x32, 0x10, 0x02, 0x00, // 12: if-eq v0, v1, +2
            0x38, 0x02, 0x02, 0x00, // 16: if-eqz v2, +2
            0x1a, 0x00, 0x01, 0x00, // 20: const-string v0, string@1
            0x52, 0x01, 0x02, 0x00, // 24: iget v1, v0, field@2
            0x6e, 0x20, 0x03, 0x00, 0x10, 0x00, // 28: invoke-virtual {v0, v1}, method@3
            0x74, 0x04, 0x03, 0x00, 0x00, 0x00, // 34: invoke-virtual/range {v0 .. v3}, method@3
            0x0f, 0x00,             // 40: return v0
        ];

        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        assert_eq!(instructions.len(), 13);

        assert_eq!(instructions[0].disasm, "nop");
        assert_eq!(instructions[0].addr, 0);

        assert_eq!(instructions[1].disasm, "move v0, v1");
        assert_eq!(instructions[1].addr, 2);

        assert_eq!(instructions[2].disasm, "const/4 v2, #5");
        assert_eq!(instructions[2].addr, 4);

        assert_eq!(instructions[3].disasm, "move-result v3");

        assert_eq!(instructions[4].disasm, "goto 0xc");

        assert_eq!(instructions[5].disasm, "return-void");

        assert_eq!(instructions[6].disasm, "if-eq v0, v1, 0x10");

        assert_eq!(instructions[7].disasm, "if-eqz v2, 0x14");

        assert!(instructions[8].disasm.starts_with("const-string"));
        assert!(instructions[8].disasm.contains("string@1"));

        assert!(instructions[9].disasm.starts_with("iget"));
        assert!(instructions[9].disasm.contains("field@2"));

        assert!(instructions[10].disasm.starts_with("invoke-virtual"));
        assert!(instructions[10].disasm.contains("{v0, v1}"));
        assert!(instructions[10].disasm.contains("meth@3"));

        assert!(instructions[11].disasm.starts_with("invoke-virtual/range"));
        assert!(instructions[11].disasm.contains("{v0 .. v3}"));
        assert!(instructions[11].disasm.contains("meth@3"));

        assert_eq!(instructions[12].disasm, "return v0");
    }

    #[test]
    fn test_dalvik_decode_payloads() {
        // Test packed-switch payload
        let mut bytecode = vec![
            0x2b, 0x00, 0x04, 0x00, 0x00, 0x00, // 0: packed-switch v0, +4 (target at word offset 4 => byte offset 8)
            0x0e, 0x00,                         // 6: return-void
            0x00, 0x01,                         // 8: ident 0x0100
            0x02, 0x00,                         // 10: size = 2
            0x0a, 0x00, 0x00, 0x00,             // 12: first_key = 10
            0x05, 0x00, 0x00, 0x00,             // 16: target 0 = +5 words
            0x08, 0x00, 0x00, 0x00,             // 20: target 1 = +8 words
        ];

        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        assert!(instructions.len() >= 3);
        assert!(instructions[0].disasm.starts_with("packed-switch"));
        assert_eq!(instructions[1].disasm, "return-void");
        assert!(instructions[2].disasm.starts_with("packed-switch-payload"));
        assert!(instructions[2].disasm.contains("(2)"));

        // Test fill-array-data payload
        bytecode = vec![
            0x26, 0x00, 0x04, 0x00, 0x00, 0x00, // 0: fill-array-data v0, +4 words (byte 8)
            0x0e, 0x00,                         // 6: return-void
            0x00, 0x03,                         // 8: ident 0x0300
            0x01, 0x00,                         // 10: element_width = 1
            0x04, 0x00, 0x00, 0x00,             // 12: size = 4
            0x11, 0x22, 0x33, 0x44,             // 16: data = 4 bytes
        ];
        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        assert_eq!(instructions.len(), 3);
        assert!(instructions[0].disasm.starts_with("fill-array-data"));
        assert!(instructions[2].disasm.starts_with("fill-array-data-payload"));
        assert!(instructions[2].disasm.contains("sz: 4"));
        assert!(instructions[2].disasm.contains("width: 1"));
    }

    #[test]
    fn test_dalvik_cfg_leaders_and_partitioning() {
        // Construct bytecode:
        // Block 0:
        // 0: const/4 v0, #0 (0x12, 0x00)
        // 2: if-eqz v0, +3 (0x38, 0x00, 0x03, 0x00) -> jumps to addr 2 + 6 = 8
        // Block 1 (fallthrough from if-eqz):
        // 6: const/4 v1, #1 (0x12, 0x11)
        // Block 2 (target of if-eqz):
        // 8: return-void (0x0e, 0x00)
        let bytecode = vec![
            0x12, 0x00,             // 0: const/4 v0, #0
            0x38, 0x00, 0x03, 0x00, // 2: if-eqz v0, +3 (target = 8)
            0x12, 0x11,             // 6: const/4 v1, #1
            0x0e, 0x00,             // 8: return-void
        ];

        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        let cfg = build_dalvik_cfg("testMethod", &instructions);

        assert_eq!(cfg.total_blocks, 3);
        // Block 0: 0..6
        assert_eq!(cfg.blocks[0].start_addr, 0);
        assert_eq!(cfg.blocks[0].end_addr, 6);
        assert_eq!(cfg.blocks[0].instructions.len(), 2);
        assert!(cfg.blocks[0].successors.contains(&1)); // fallthrough block id 1
        assert!(cfg.blocks[0].successors.contains(&2)); // jump target block id 2
        assert_eq!(cfg.blocks[0].jump_target, Some(8));
        assert_eq!(cfg.blocks[0].fail_target, Some(6));

        // Block 1: 6..8
        assert_eq!(cfg.blocks[1].start_addr, 6);
        assert_eq!(cfg.blocks[1].end_addr, 8);
        assert!(cfg.blocks[1].successors.contains(&2)); // fallthrough to return block id 2

        // Block 2: 8..10
        assert_eq!(cfg.blocks[2].start_addr, 8);
        assert_eq!(cfg.blocks[2].end_addr, 10);
        assert!(cfg.blocks[2].successors.is_empty()); // return-void has no successors

        // Decision gate on block 0
        assert_eq!(cfg.decision_gates.len(), 1);
        let gate = &cfg.decision_gates[0];
        assert_eq!(gate.addr, 2);
        assert_eq!(gate.branch_instruction, "if-eqz v0, 0x8");
        assert_eq!(gate.jump_target, 8);
        assert_eq!(gate.fail_target, 6);
        assert_eq!(gate.gate_type.as_deref(), Some("equality_zero_check"));
    }

    #[test]
    fn test_dalvik_cfg_loop_counting_back_edges() {
        // Construct a loop:
        // Block 0:
        // 0: const/4 v0, #0 (0x12, 0x00)
        // Block 1 (loop header):
        // 2: add-int/lit8 v0, v0, #1 (0xd8, 0x00, 0x00, 0x01)
        // 6: const/4 v1, #5 (0x12, 0x51)
        // 8: if-ge v0, v1, -3 (0x35, 0x10, 0xfd, 0xff) -> jumps to 8 + (-3 * 2) = 2
        // Block 2 (exit):
        // 12: return v0 (0x0f, 0x00)
        let bytecode = vec![
            0x12, 0x00,                         // 0: const/4 v0, #0
            0xd8, 0x00, 0x00, 0x01,             // 2: add-int/lit8 v0, v0, #1
            0x12, 0x51,                         // 6: const/4 v1, #5
            0x35, 0x10, 0xfd, 0xff,             // 8: if-ge v0, v1, -3 (target = 2)
            0x0f, 0x00,                         // 12: return v0
        ];

        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        let cfg = build_dalvik_cfg("loopMethod", &instructions);

        assert!(cfg.total_blocks >= 2);
        assert_eq!(cfg.loop_count, 1, "Back-edge to address 2 must be detected as a loop");
        assert_eq!(cfg.decision_gates.len(), 1);
        assert_eq!(cfg.decision_gates[0].gate_type.as_deref(), Some("greater_check"));
    }

    #[test]
    fn test_dalvik_pseudo_decompilation_statements() {
        let bytecode = vec![
            0x12, 0x00,                         // 0: const/4 v0, #0
            0x1a, 0x01, 0x05, 0x00,             // 2: const-string v1, string@5
            0x38, 0x00, 0x03, 0x00,             // 6: if-eqz v0, +3 (target = 12)
            0x0e, 0x00,                         // 10: return-void
            0x0f, 0x01,                         // 12: return v1
        ];

        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        let cfg = build_dalvik_cfg("testMethod", &instructions);
        let method = DexMethodSummary {
            name: "testMethod".to_string(),
            signature: "()V".to_string(),
            access_flags: 1,
            code_offset: Some(0),
            registers_size: Some(2),
            insns_size: Some(7),
            disassembly: None,
            cfg: None,
            xrefs: None,
            annotations: Vec::new(),
            debug_info: None,
            smali: None,
            decompiled: None,
        };
        let decompiled = decompile_dalvik_method_pure_rust("com.example.Test", &method, &cfg);

        assert!(decompiled.contains("public void testMethod()"));
        assert!(decompiled.contains("return;"));
        assert!(decompiled.contains("return v1;"));
        assert!(decompiled.contains("if (v0 == 0) goto 0xc;"));
    }

    #[test]
    fn test_dalvik_pseudo_decompilation_unconditional_goto_single_emission() {
        // Method with conditional branch and unconditional goto:
        // 0: const/4 v0, #0 (0x12, 0x00)
        // 2: if-nez v0, +3 (0x39, 0x00, 0x03, 0x00) -> target = 8 (0x8)
        // 6: goto +2 (0x28, 0x02) -> target = 10 (0xa)
        // 8: const/4 v0, #1 (0x12, 0x10)
        // 10: return v0 (0x0f, 0x00)
        let bytecode = vec![
            0x12, 0x00,
            0x39, 0x00, 0x03, 0x00,
            0x28, 0x02,
            0x12, 0x10,
            0x0f, 0x00,
        ];

        let instructions = disassemble_dalvik_instructions(&bytecode, 0, (bytecode.len() / 2) as u32, None);
        let cfg = build_dalvik_cfg("testGoto", &instructions);
        let method = DexMethodSummary {
            name: "testGoto".to_string(),
            signature: "()I".to_string(),
            access_flags: 1,
            code_offset: Some(0),
            registers_size: Some(1),
            insns_size: Some(6),
            disassembly: None,
            cfg: None,
            xrefs: None,
            annotations: Vec::new(),
            debug_info: None,
            smali: None,
            decompiled: None,
        };
        let decompiled = decompile_dalvik_method_pure_rust("com.example.Test", &method, &cfg);

        assert!(decompiled.contains("public int testGoto()"));
        assert!(decompiled.contains("goto 0xa;"));
        assert_eq!(
            decompiled.matches("goto 0xa;").count(),
            1,
            "Expected exactly 1 goto statement per jump, got duplicates:\n{}",
            decompiled
        );
    }
}

