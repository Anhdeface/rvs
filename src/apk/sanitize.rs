//! Android APK string sanitization and resilient decoding engine.
//!
//! Provides defense-in-depth sanitization against terminal injection (ANSI CSI, OSC, DCS),
//! bidirectional spoofing (BiDi controls), Zalgo vertical overflows (combining marks clamping),
//! CRLF log injection, and ZIP path traversal. Also provides lossy decoders for Dalvik MUTF-8
//! and UTF-16LE string pools.

/// Windows OS-reserved device names (DOS devices) that must not be used as file or directory names.
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Checks if a path component matches an OS-reserved device name on Windows.
///
/// On Windows, reserved names are matched case-insensitively against the component's stem
/// (the portion before the first dot or colon). For example, `CON`, `con.txt`, `aux.xml`,
/// and `COM1:stream` are all reserved device names.
fn is_windows_reserved_component(component: &str) -> bool {
    let clean = component.trim_end_matches([' ', '.']);
    let stem = clean.split(['.', ':']).next().unwrap_or(clean);
    let stem_upper = stem.to_ascii_uppercase();
    WINDOWS_RESERVED_NAMES.contains(&stem_upper.as_str())
}

/// Sanitizes a single path component:
/// If it matches a Windows reserved device name, it is prefixed with an underscore `_`.
fn sanitize_component(component: &str) -> String {
    if is_windows_reserved_component(component) {
        format!("_{component}")
    } else {
        component.to_string()
    }
}

/// Returns true if character is a Unicode Bidirectional Format Control.
#[inline]
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
        | '\u{200E}'
        | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
    )
}

/// Returns true if character is within standard Unicode combining diacritical blocks.
#[inline]
pub fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}'
        | '\u{FE20}'..='\u{FE2F}'
    )
}

/// Sanitizes user-facing and external identifiers (package names, resource names, error messages).
///
/// 1. Strips ANSI escape sequences: CSI (`\x1b[...]`), OSC (`\x1b]...`), DCS (`\x1bP...`, `\x1b P...`),
///    single escapes (e.g. `\x1b(B`, `\x1b=`), and incomplete escapes.
/// 2. Neutralizes BiDi controls: RLO (`U+202E`), LRO (`U+202D`), LRE/RLE/PDF (`U+202A`..=`U+202C`),
///    isolates (`U+2066`..=`U+2069`), and directional marks (`U+200E`, `U+200F`, `U+061C`).
/// 3. Clamps Zalgo combining marks: Unicode blocks `U+0300..=U+036F`, `U+1AB0..=U+1AFF`, `U+1DC0..=U+1DFF`,
///    `U+20D0..=U+20FF`, `U+FE20..=U+FE2F`. Enforces a threshold of max 2 combining marks per base glyph.
///    Drops marks exceeding the threshold and drops leading/orphan combining marks.
/// 4. Replaces carriage returns (`\r\n` or `\r`), newlines (`\n`), and tabs (`\t`) with a single space `' '`
///    to eliminate CRLF log injection, while stripping all other C0 controls and C1 controls (`U+0080`..=`U+009F`).
pub fn sanitize_identifier(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut has_base = false;
    let mut combining_count = 0usize;

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some(&'[') => {
                    chars.next(); // consume '['
                    // CSI sequence: \x1b[ ... (until final byte 0x40..=0x7E)
                    while let Some(&ch) = chars.peek() {
                        chars.next();
                        if (ch as u32) >= 0x40 && (ch as u32) <= 0x7e {
                            break;
                        }
                    }
                }
                Some(&']') => {
                    chars.next(); // consume ']'
                    // OSC sequence: \x1b] ... (until \x07 or \x1b\)
                    while let Some(ch) = chars.next() {
                        if ch == '\x07' {
                            break;
                        }
                        if ch == '\x1b' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(&'P') => {
                    chars.next(); // consume 'P'
                    // DCS sequence: \x1bP ... (until \x07 or \x1b\)
                    while let Some(ch) = chars.next() {
                        if ch == '\x07' {
                            break;
                        }
                        if ch == '\x1b' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(&' ') => {
                    chars.next(); // consume ' '
                    if chars.peek() == Some(&'P') {
                        chars.next(); // consume 'P'
                        while let Some(ch) = chars.next() {
                            if ch == '\x07' {
                                break;
                            }
                            if ch == '\x1b' {
                                if chars.peek() == Some(&'\\') {
                                    chars.next();
                                }
                                break;
                            }
                        }
                    }
                }
                Some(&'(') | Some(&')') | Some(&'*') | Some(&'+') => {
                    chars.next(); // consume prefix
                    chars.next(); // consume charset designator
                }
                Some(&ch) if (ch as u32) >= 0x20 && (ch as u32) <= 0x7e => {
                    chars.next(); // 2-character escape
                }
                _ => {}
            }
            continue;
        }

        // BiDi controls check
        if is_bidi_control(c) {
            continue;
        }

        // Combining mark check
        if is_combining_mark(c) {
            if has_base && combining_count < 2 {
                combining_count += 1;
                out.push(c);
            }
            continue;
        }

        // Carriage return and newline handling
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push(' ');
            has_base = false;
            combining_count = 0;
            continue;
        }

        if c == '\n' || c == '\t' {
            out.push(' ');
            has_base = false;
            combining_count = 0;
            continue;
        }

        // Other C0 controls and DEL
        if (c as u32) < 0x20 || c == '\x7f' {
            continue;
        }

        // C1 controls
        if (c as u32) >= 0x80 && (c as u32) <= 0x9f {
            continue;
        }

        // Normal whitespace does not act as base glyph for diacritics
        if c == ' ' {
            out.push(' ');
            has_base = false;
            combining_count = 0;
            continue;
        }

        // Valid base glyph
        has_base = true;
        combining_count = 0;
        out.push(c);
    }

    out
}

/// Resiliently decodes Dalvik Modified UTF-8 (MUTF-8) bytes into a String.
///
/// Features:
/// - Dalvik 2-byte null (`0xC0, 0x80`) is decoded as `'\0'`.
/// - 6-byte surrogate pairs (`0xED 0xA0..0xAF 0x80..0xBF` + `0xED 0xB0..0xBF 0x80..0xBF`)
///   are recombined into Unicode supplementary characters (U+10000..U+10FFFF).
/// - Unpaired / lone surrogates (U+D800..U+DFFF) are replaced with `U+FFFD`.
/// - Standard 1-byte, 2-byte, 3-byte, and permissive 4-byte UTF-8 sequences are supported.
/// - Malformed continuation bytes, truncated sequences, and invalid bytes are safely replaced
///   with `U+FFFD` without throwing unhandled exceptions or halting execution.
pub fn decode_mutf8_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    let len = bytes.len();

    while i < len {
        let b0 = bytes[i];

        // 1. ASCII (0x01..=0x7F) and raw null (0x00)
        if b0 <= 0x7F {
            out.push(b0 as char);
            i += 1;
            continue;
        }

        // 2. Dalvik MUTF-8 two-byte null (0xC0, 0x80) -> '\0'
        if b0 == 0xC0 && i + 1 < len && bytes[i + 1] == 0x80 {
            out.push('\0');
            i += 2;
            continue;
        }

        // 3. Two-byte sequence (0xC0..=0xDF)
        if (0xC0..=0xDF).contains(&b0) {
            if i + 1 < len {
                let b1 = bytes[i + 1];
                if (b1 & 0xC0) == 0x80 {
                    let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
                    // Check for overlong 2-byte sequences (cp < 0x80 is overlong, except 0xC0 0x80 handled above)
                    if cp >= 0x80 {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                            i += 2;
                            continue;
                        }
                    }
                    out.push(char::REPLACEMENT_CHARACTER);
                    i += 2;
                    continue;
                }
            }
            // Incomplete or invalid continuation byte
            out.push(char::REPLACEMENT_CHARACTER);
            i += 1;
            continue;
        }

        // 4. Three-byte sequence (0xE0..=0xEF)
        if (0xE0..=0xEF).contains(&b0) {
            // Check for MUTF-8 6-byte surrogate pair:
            // High surrogate: 0xED, 0xA0..=0xAF, 0x80..=0xBF
            // Low surrogate:  0xED, 0xB0..=0xBF, 0x80..=0xBF
            if b0 == 0xED && i + 2 < len && (0xA0..=0xAF).contains(&bytes[i + 1]) && (bytes[i + 2] & 0xC0) == 0x80 {
                // High surrogate found
                if i + 5 < len
                    && bytes[i + 3] == 0xED
                    && (0xB0..=0xBF).contains(&bytes[i + 4])
                    && (bytes[i + 5] & 0xC0) == 0x80
                {
                    // Valid surrogate pair -> recombine into supplementary codepoint
                    let high = ((0xEDu32 & 0x0F) << 12)
                        | (((bytes[i + 1] & 0x3F) as u32) << 6)
                        | ((bytes[i + 2] & 0x3F) as u32);
                    let low = ((0xEDu32 & 0x0F) << 12)
                        | (((bytes[i + 4] & 0x3F) as u32) << 6)
                        | ((bytes[i + 5] & 0x3F) as u32);
                    let cp = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                    } else {
                        out.push(char::REPLACEMENT_CHARACTER);
                    }
                    i += 6;
                    continue;
                } else {
                    // Unpaired / lone high surrogate: replace with U+FFFD
                    out.push(char::REPLACEMENT_CHARACTER);
                    i += 3;
                    continue;
                }
            }

            // Check for lone low surrogate: 0xED, 0xB0..=0xBF, 0x80..=0xBF
            if b0 == 0xED && i + 2 < len && (0xB0..=0xBF).contains(&bytes[i + 1]) && (bytes[i + 2] & 0xC0) == 0x80 {
                out.push(char::REPLACEMENT_CHARACTER);
                i += 3;
                continue;
            }

            // Standard 3-byte sequence
            if i + 2 < len {
                let b1 = bytes[i + 1];
                let b2 = bytes[i + 2];
                if (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 {
                    let cp = (((b0 & 0x0F) as u32) << 12)
                        | (((b1 & 0x3F) as u32) << 6)
                        | ((b2 & 0x3F) as u32);
                    // Check overlong (cp < 0x800) or surrogate range (0xD800..=0xDFFF)
                    if cp >= 0x800 && !(0xD800..=0xDFFF).contains(&cp) {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                            i += 3;
                            continue;
                        }
                    }
                    out.push(char::REPLACEMENT_CHARACTER);
                    i += 3;
                    continue;
                }
            }

            // Incomplete or invalid continuation for 3-byte
            if i + 1 < len && (bytes[i + 1] & 0xC0) == 0x80 {
                out.push(char::REPLACEMENT_CHARACTER);
                i += 2;
            } else {
                out.push(char::REPLACEMENT_CHARACTER);
                i += 1;
            }
            continue;
        }

        // 5. Four-byte UTF-8 sequence (0xF0..=0xF4)
        if (0xF0..=0xF4).contains(&b0) {
            if i + 3 < len {
                let b1 = bytes[i + 1];
                let b2 = bytes[i + 2];
                let b3 = bytes[i + 3];
                if (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 {
                    let cp = (((b0 & 0x07) as u32) << 18)
                        | (((b1 & 0x3F) as u32) << 12)
                        | (((b2 & 0x3F) as u32) << 6)
                        | ((b3 & 0x3F) as u32);
                    if (0x10000..=0x10FFFF).contains(&cp) {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                            i += 4;
                            continue;
                        }
                    }
                    out.push(char::REPLACEMENT_CHARACTER);
                    i += 4;
                    continue;
                }
            }
            let mut adv = 1;
            if i + 1 < len && (bytes[i + 1] & 0xC0) == 0x80 {
                adv = 2;
                if i + 2 < len && (bytes[i + 2] & 0xC0) == 0x80 {
                    adv = 3;
                }
            }
            out.push(char::REPLACEMENT_CHARACTER);
            i += adv;
            continue;
        }

        // 6. Stray continuation byte (0x80..=0xBF) or out-of-spec byte (0xF5..=0xFF)
        out.push(char::REPLACEMENT_CHARACTER);
        i += 1;
    }

    out
}

/// Resiliently decodes UTF-16LE bytes, replacing unpaired surrogates and odd trailing bytes with U+FFFD.
pub fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    let u16_iter = chunks.iter().map(|c| u16::from_le_bytes(*c));

    let mut out: String = std::char::decode_utf16(u16_iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();

    if !remainder.is_empty() {
        out.push(char::REPLACEMENT_CHARACTER);
    }

    out
}

/// Sanitizes relative archive entry paths to prevent directory traversal and OS reserved device names.
///
/// 1. Strips Windows drive prefixes (e.g. `C:`).
/// 2. Normalizes all backslashes (`\`) to forward slashes (`/`).
/// 3. Normalizes and validates path segments:
///    - Skips empty segments and single dots (`.`).
///    - Handles `..` using stack-based resolution, dropping segments that attempt to escape the root.
/// 4. Neutralizes Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`)
///    in any directory or file component by prefixing with `_`.
/// 5. Preserves trailing slash for directory entries if non-empty.
pub fn sanitize_archive_entry_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // Strip Windows drive letter (e.g. "C:" or "c:")
    let path_no_drive = if path.len() >= 2
        && path.as_bytes()[0].is_ascii_alphabetic()
        && path.as_bytes()[1] == b':'
    {
        &path[2..]
    } else {
        path
    };

    let is_dir = path_no_drive.ends_with('/') || path_no_drive.ends_with('\\');

    let mut stack: Vec<String> = Vec::new();

    for segment in path_no_drive.split(['/', '\\']) {
        let trimmed = segment.trim();
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            // Drop traversal that attempts to escape root; otherwise pop parent
            stack.pop();
        } else {
            stack.push(sanitize_component(trimmed));
        }
    }

    if stack.is_empty() {
        return String::new();
    }

    let mut result = stack.join("/");
    if is_dir {
        result.push('/');
    }
    result
}

// =============================================================================
// Unit Tests (40 Exhaustive Unit Tests)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // 1. sanitize_identifier Unit Tests (13 tests)
    // =========================================================================

    #[test]
    fn test_sanitize_identifier_plain_ascii() {
        assert_eq!(sanitize_identifier("com.example.app"), "com.example.app");
        assert_eq!(sanitize_identifier("MainActivity_v2"), "MainActivity_v2");
        assert_eq!(sanitize_identifier("android.permission.INTERNET"), "android.permission.INTERNET");
        assert_eq!(sanitize_identifier("simple-name-123"), "simple-name-123");
        assert_eq!(sanitize_identifier(""), "");
    }

    #[test]
    fn test_sanitize_identifier_ansi_csi_colors() {
        // Red foreground
        assert_eq!(sanitize_identifier("\x1b[31mcom.example.app\x1b[0m"), "com.example.app");
        // Bold green with background
        assert_eq!(sanitize_identifier("\x1b[1;32;40mMyActivity\x1b[0m"), "MyActivity");
        // 256-color and 24-bit RGB
        assert_eq!(sanitize_identifier("\x1b[38;5;196mColor256\x1b[0m"), "Color256");
        assert_eq!(sanitize_identifier("\x1b[38;2;255;0;0mTrueColor\x1b[0m"), "TrueColor");
    }

    #[test]
    fn test_sanitize_identifier_ansi_csi_cursor_and_screen() {
        // Cursor movement
        assert_eq!(sanitize_identifier("\x1b[2AUp\x1b[5BDown\x1b[10;20HAtPos"), "UpDownAtPos");
        // Clear screen and line
        assert_eq!(sanitize_identifier("\x1b[2JEraseScreen\x1b[KClearLine"), "EraseScreenClearLine");
        // Cursor visibility and bracketed paste
        assert_eq!(sanitize_identifier("\x1b[?25lHidden\x1b[?25hVisible"), "HiddenVisible");
        assert_eq!(sanitize_identifier("\x1b[?2004hPaste\x1b[?2004l"), "Paste");
    }

    #[test]
    fn test_sanitize_identifier_ansi_osc_titles_and_links() {
        // Window title injection with BEL (\x07)
        assert_eq!(sanitize_identifier("\x1b]0;PwnedTitle\x07NormalPackage"), "NormalPackage");
        // Window title injection with ST (\x1b\)
        assert_eq!(sanitize_identifier("\x1b]2;EvilTitle\x1b\\SafeActivity"), "SafeActivity");
        // Hyperlink injection (OSC 8)
        assert_eq!(
            sanitize_identifier("\x1b]8;;http://evil.com\x07ClickMe\x1b]8;;\x07"),
            "ClickMe"
        );
        // Unterminated OSC at EOF
        assert_eq!(sanitize_identifier("\x1b]0;Unterminated"), "");
    }

    #[test]
    fn test_sanitize_identifier_single_escapes_and_dcs() {
        // Character set designation
        assert_eq!(sanitize_identifier("\x1b(Bcom.example\x1b)0"), "com.example");
        // Reverse index and save/restore cursor
        assert_eq!(sanitize_identifier("\x1bM\x1b7Text\x1b8"), "Text");
        // Dangling single escape
        assert_eq!(sanitize_identifier("prefix\x1b"), "prefix");
        assert_eq!(sanitize_identifier("\x1b"), "");
        // Device Control String (DCS)
        assert_eq!(sanitize_identifier("\x1bP+q54657374\x1b\\Content"), "Content");
        assert_eq!(sanitize_identifier("\x1b Pcommand\x1b\\SafeName"), "SafeName");
    }

    #[test]
    fn test_sanitize_identifier_bidi_overrides() {
        // U+202E Right-to-Left Override (RLO)
        assert_eq!(sanitize_identifier("com.example.\u{202E}cod.evil"), "com.example.cod.evil");
        // U+202D Left-to-Right Override (LRO)
        assert_eq!(sanitize_identifier("\u{202D}com.safe.package\u{202C}"), "com.safe.package");
        // U+202C Pop Directional Formatting (PDF)
        assert_eq!(sanitize_identifier("test\u{202C}end"), "testend");
    }

    #[test]
    fn test_sanitize_identifier_bidi_embeddings_isolates_marks() {
        // Embeddings: U+202A (LRE), U+202B (RLE)
        assert_eq!(sanitize_identifier("\u{202A}embed\u{202B}text\u{202C}"), "embedtext");
        // Isolates: U+2066 (LRI), U+2067 (RLI), U+2068 (FSI), U+2069 (PDI)
        assert_eq!(
            sanitize_identifier("\u{2066}isolate1\u{2067}isolate2\u{2068}isolate3\u{2069}"),
            "isolate1isolate2isolate3"
        );
        // Directional marks: U+200E (LRM), U+200F (RLM), U+061C (ALM)
        assert_eq!(sanitize_identifier("start\u{200E}mid\u{200F}end\u{061C}"), "startmidend");
    }

    #[test]
    fn test_sanitize_identifier_zalgo_normal_and_vietnamese() {
        // Standard ASCII: 0 combining marks
        assert_eq!(sanitize_identifier("Android"), "Android");
        // Single combining mark (French accented 'e' decomposed: 'e' + U+0301)
        let french = "e\u{0301}cole";
        assert_eq!(sanitize_identifier(french), french);
        // Vietnamese characters with 2 combining marks preserved
        // 'e' + circumflex (U+0302) + acute (U+0301) = 'ế'
        let vn_tieng = "tie\u{0302}\u{0301}ng";
        assert_eq!(sanitize_identifier(vn_tieng), vn_tieng);
        // 'e' + circumflex (U+0302) + dot below (U+0323) = 'ệ'
        let vn_viet = "Vie\u{0302}\u{0323}t";
        assert_eq!(sanitize_identifier(vn_viet), vn_viet);
        // Precomposed Vietnamese
        assert_eq!(sanitize_identifier("tiếng Việt"), "tiếng Việt");
    }

    #[test]
    fn test_sanitize_identifier_zalgo_clamping_excessive() {
        // 5 combining marks on single base glyph clamped to 2
        let excessive = "a\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}";
        assert_eq!(sanitize_identifier(excessive), "a\u{0300}\u{0301}");

        // 10 combining marks from different Unicode blocks clamped to 2
        let multi_block = "Z\u{0300}\u{1AB0}\u{1DC0}\u{20D0}\u{FE20}\u{0301}\u{0302}\u{0303}\u{0304}\u{0305}";
        assert_eq!(sanitize_identifier(multi_block), "Z\u{0300}\u{1AB0}");

        // Consecutive base glyphs each with excessive marks
        let multiple_bases = "a\u{0300}\u{0301}\u{0302}b\u{0303}\u{0304}\u{0305}";
        assert_eq!(sanitize_identifier(multiple_bases), "a\u{0300}\u{0301}b\u{0303}\u{0304}");
    }

    #[test]
    fn test_sanitize_identifier_zalgo_leading_dropped() {
        // Leading combining marks without preceding base character dropped
        let leading = "\u{0300}\u{0301}ValidBase";
        assert_eq!(sanitize_identifier(leading), "ValidBase");

        // String consisting purely of combining marks produces empty string
        let all_marks = "\u{0300}\u{0301}\u{0302}\u{0303}";
        assert_eq!(sanitize_identifier(all_marks), "");
    }

    #[test]
    fn test_sanitize_identifier_log_injection_newlines_cr() {
        // Standalone newline replaced with space
        assert_eq!(sanitize_identifier("com.app\nInjectedLine"), "com.app InjectedLine");
        // Carriage return replaced with space
        assert_eq!(sanitize_identifier("com.app\rCRInjection"), "com.app CRInjection");
        // CRLF replaced with single space
        assert_eq!(sanitize_identifier("com.app\r\nCRLFInjection"), "com.app CRLFInjection");
        // Multiple consecutive newlines
        assert_eq!(sanitize_identifier("line1\n\n\nline2"), "line1   line2");
        // Tab replaced with space
        assert_eq!(sanitize_identifier("col1\tcol2"), "col1 col2");
    }

    #[test]
    fn test_sanitize_identifier_c0_c1_controls() {
        // Null byte, Bell, Backspace, FormFeed, DEL
        assert_eq!(sanitize_identifier("test\x00null"), "testnull");
        assert_eq!(sanitize_identifier("bell\x07sound"), "bellsound");
        assert_eq!(sanitize_identifier("back\x08space"), "backspace");
        assert_eq!(sanitize_identifier("form\x0cfeed"), "formfeed");
        assert_eq!(sanitize_identifier("del\x7fchar"), "delchar");
        // C1 control characters (0x80..0x9F)
        assert_eq!(sanitize_identifier("c1\u{0080}\u{009F}test"), "c1test");
    }

    #[test]
    fn test_sanitize_identifier_adversarial_composite() {
        // Composite attack: ANSI CSI + BiDi RLO + 5x Zalgo + Log injection + C0 Bell
        let composite = "\x1b[31mcom.evil.\u{202E}bank\u{0300}\u{0301}\u{0302}\u{0303}\n\x1b[0m\x07Injected";
        assert_eq!(sanitize_identifier(composite), "com.evil.bank\u{0300}\u{0301} Injected");
    }

    // =========================================================================
    // 2. decode_mutf8_lossy Unit Tests (11 tests)
    // =========================================================================

    #[test]
    fn test_decode_mutf8_lossy_pure_ascii() {
        assert_eq!(decode_mutf8_lossy(b""), "");
        assert_eq!(decode_mutf8_lossy(b"classes.dex"), "classes.dex");
        assert_eq!(decode_mutf8_lossy(b"Lcom/example/MyClass;"), "Lcom/example/MyClass;");
    }

    #[test]
    fn test_decode_mutf8_lossy_two_byte_null() {
        // Dalvik MUTF-8 0xC0 0x80 -> '\0'
        assert_eq!(decode_mutf8_lossy(&[0xC0, 0x80]), "\0");
        // Embedded null
        assert_eq!(decode_mutf8_lossy(&[b'a', 0xC0, 0x80, b'b']), "a\0b");
        // Consecutive nulls
        assert_eq!(decode_mutf8_lossy(&[0xC0, 0x80, 0xC0, 0x80]), "\0\0");
    }

    #[test]
    fn test_decode_mutf8_lossy_standard_multibyte() {
        // 2-byte Greek: αβγ (0xCE 0xB1, 0xCE 0xB2, 0xCE 0xB3)
        assert_eq!(decode_mutf8_lossy(&[0xCE, 0xB1, 0xCE, 0xB2, 0xCE, 0xB3]), "αβγ");
        // 2-byte Latin extended: é (0xC3 0xA9)
        assert_eq!(decode_mutf8_lossy(&[0xC3, 0xA9]), "é");
        // 3-byte CJK: 中文 (0xE4 0xB8 0xAD, 0xE6, 0x96, 0x87)
        assert_eq!(decode_mutf8_lossy(&[0xE4, 0xB8, 0xAD, 0xE6, 0x96, 0x87]), "中文");
        // 3-byte Euro symbol: € (0xE2 0x82 0xAC)
        assert_eq!(decode_mutf8_lossy(&[0xE2, 0x82, 0xAC]), "€");
    }

    #[test]
    fn test_decode_mutf8_lossy_supplementary_surrogate_pairs() {
        // U+1F600 Grinning Face 😀: High 0xD83D (0xED 0xA0 0xBD), Low 0xDE00 (0xED 0xB8 0x80)
        let emoji = &[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_mutf8_lossy(emoji), "😀");

        // Min supplementary code point U+10000: High 0xD800 (0xED 0xA0 0x80), Low 0xDC00 (0xED 0xB0 0x80)
        let min_supp = &[0xED, 0xA0, 0x80, 0xED, 0xB0, 0x80];
        assert_eq!(decode_mutf8_lossy(min_supp), "\u{10000}");

        // Max supplementary code point U+10FFFF: High 0xDBFF (0xED 0xAF 0xBF), Low 0xDFFF (0xED 0xBF 0xBF)
        let max_supp = &[0xED, 0xAF, 0xBF, 0xED, 0xBF, 0xBF];
        assert_eq!(decode_mutf8_lossy(max_supp), "\u{10FFFF}");

        // Musical symbol G clef U+1D11E 𝄞: High 0xD834 (0xED 0xA0 0xB4), Low 0xDD1E (0xED 0xB4 0x9E)
        let g_clef = &[0xED, 0xA0, 0xB4, 0xED, 0xB4, 0x9E];
        assert_eq!(decode_mutf8_lossy(g_clef), "𝄞");

        // Flanked by ASCII
        let flanked = &[b'A', 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80, b'Z'];
        assert_eq!(decode_mutf8_lossy(flanked), "A😀Z");
    }

    #[test]
    fn test_decode_mutf8_lossy_lone_high_surrogate() {
        // Lone high surrogate 0xD800 (0xED 0xA0 0x80) without low surrogate -> U+FFFD
        assert_eq!(decode_mutf8_lossy(&[0xED, 0xA0, 0x80]), "\u{FFFD}");
        // Followed by ASCII
        assert_eq!(decode_mutf8_lossy(&[0xED, 0xA0, 0xBD, b'A']), "\u{FFFD}A");
    }

    #[test]
    fn test_decode_mutf8_lossy_lone_low_surrogate() {
        // Lone low surrogate 0xDC00 (0xED 0xB0 0x80) without preceding high surrogate -> U+FFFD
        assert_eq!(decode_mutf8_lossy(&[0xED, 0xB0, 0x80]), "\u{FFFD}");
        // Preceded by ASCII
        assert_eq!(decode_mutf8_lossy(&[b'B', 0xED, 0xB0, 0x80]), "B\u{FFFD}");
    }

    #[test]
    fn test_decode_mutf8_lossy_double_surrogates() {
        // Two consecutive high surrogates: both replaced by U+FFFD
        let two_high = &[0xED, 0xA0, 0x80, 0xED, 0xA0, 0x80];
        assert_eq!(decode_mutf8_lossy(two_high), "\u{FFFD}\u{FFFD}");
        // Two consecutive low surrogates: both replaced by U+FFFD
        let two_low = &[0xED, 0xB0, 0x80, 0xED, 0xB0, 0x80];
        assert_eq!(decode_mutf8_lossy(two_low), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn test_decode_mutf8_lossy_truncated_at_eof() {
        // Lone 0xED at EOF
        assert_eq!(decode_mutf8_lossy(&[0xED]), "\u{FFFD}");
        // Incomplete 2-byte surrogate header at EOF
        assert_eq!(decode_mutf8_lossy(&[0xED, 0xA0]), "\u{FFFD}");
        // Complete high surrogate followed by truncated low surrogate lead
        assert_eq!(decode_mutf8_lossy(&[0xED, 0xA0, 0xBD, 0xED]), "\u{FFFD}\u{FFFD}");
        // Truncated standard 2-byte sequence
        assert_eq!(decode_mutf8_lossy(&[0xC3]), "\u{FFFD}");
        // Truncated standard 3-byte sequence
        assert_eq!(decode_mutf8_lossy(&[0xE4, 0xBD]), "\u{FFFD}");
    }

    #[test]
    fn test_decode_mutf8_lossy_invalid_continuations() {
        // Invalid continuation in 2-byte sequence (ASCII space instead of 0x80..0xBF)
        assert_eq!(decode_mutf8_lossy(&[0xC3, 0x20]), "\u{FFFD} ");
        // Invalid continuation in 3-byte sequence
        assert_eq!(decode_mutf8_lossy(&[0xE4, 0x20, 0x80]), "\u{FFFD} \u{FFFD}");
    }

    #[test]
    fn test_decode_mutf8_lossy_orphaned_and_invalid_lead_bytes() {
        // Orphaned continuation byte
        assert_eq!(decode_mutf8_lossy(&[0x80]), "\u{FFFD}");
        assert_eq!(decode_mutf8_lossy(&[0xBF]), "\u{FFFD}");
        // Illegal UTF-8 lead byte (0xFF, 0xFE)
        assert_eq!(decode_mutf8_lossy(&[0xFF]), "\u{FFFD}");
        assert_eq!(decode_mutf8_lossy(&[0xFE]), "\u{FFFD}");
    }

    #[test]
    fn test_decode_mutf8_lossy_permissive_4byte() {
        // Permissive 4-byte UTF-8 sequence 😀
        assert_eq!(decode_mutf8_lossy(&[0xF0, 0x9F, 0x98, 0x80]), "😀");
    }

    // =========================================================================
    // 3. decode_utf16le_lossy Unit Tests (7 tests)
    // =========================================================================

    #[test]
    fn test_decode_utf16le_lossy_pure_ascii() {
        assert_eq!(decode_utf16le_lossy(&[]), "");
        // "Hello" in UTF-16LE
        let hello = &[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0];
        assert_eq!(decode_utf16le_lossy(hello), "Hello");
    }

    #[test]
    fn test_decode_utf16le_lossy_bmp_characters() {
        // "中文": U+4E2D (0x2D, 0x4E), U+6587 (0x87, 0x65)
        let cjk = &[0x2D, 0x4E, 0x87, 0x65];
        assert_eq!(decode_utf16le_lossy(cjk), "中文");
    }

    #[test]
    fn test_decode_utf16le_lossy_supplementary_surrogate_pairs() {
        // 😀 U+1F600: High 0xD83D (0x3D, 0xD8), Low 0xDE00 (0x00, 0xDE)
        let emoji = &[0x3D, 0xD8, 0x00, 0xDE];
        assert_eq!(decode_utf16le_lossy(emoji), "😀");

        // Min supplementary code point U+10000: High 0xD800 (0x00, 0xD8), Low 0xDC00 (0x00, 0xDC)
        let min_supp = &[0x00, 0xD8, 0x00, 0xDC];
        assert_eq!(decode_utf16le_lossy(min_supp), "\u{10000}");

        // Max supplementary code point U+10FFFF: High 0xDBFF (0xFF, 0xDB), Low 0xDFFF (0xFF, 0xDF)
        let max_supp = &[0xFF, 0xDB, 0xFF, 0xDF];
        assert_eq!(decode_utf16le_lossy(max_supp), "\u{10FFFF}");
    }

    #[test]
    fn test_decode_utf16le_lossy_unpaired_high_surrogate() {
        // High surrogate 0xD800 (0x00, 0xD8) alone
        assert_eq!(decode_utf16le_lossy(&[0x00, 0xD8]), "\u{FFFD}");
        // Followed by valid ASCII 'A'
        assert_eq!(decode_utf16le_lossy(&[0x00, 0xD8, b'A', 0]), "\u{FFFD}A");
    }

    #[test]
    fn test_decode_utf16le_lossy_unpaired_low_surrogate() {
        // Low surrogate 0xDC00 (0x00, 0xDC) alone
        assert_eq!(decode_utf16le_lossy(&[0x00, 0xDC]), "\u{FFFD}");
        // Preceded by valid ASCII 'B'
        assert_eq!(decode_utf16le_lossy(&[b'B', 0, 0x00, 0xDC]), "B\u{FFFD}");
    }

    #[test]
    fn test_decode_utf16le_lossy_inverted_surrogates() {
        // Low surrogate followed by High surrogate
        let inverted = &[0x00, 0xDC, 0x00, 0xD8];
        assert_eq!(decode_utf16le_lossy(inverted), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn test_decode_utf16le_lossy_odd_byte_count() {
        // 1 byte: incomplete trailing byte replaced with U+FFFD
        assert_eq!(decode_utf16le_lossy(b"A"), "\u{FFFD}");
        // 3 bytes: 'A' (2 bytes) + 1 odd byte
        assert_eq!(decode_utf16le_lossy(&[b'A', 0, b'X']), "A\u{FFFD}");
        // 5 bytes: 'A', 'B' (4 bytes) + 1 odd byte
        assert_eq!(decode_utf16le_lossy(&[b'A', 0, b'B', 0, 0xFF]), "AB\u{FFFD}");
    }

    // =========================================================================
    // 4. sanitize_archive_entry_path Unit Tests (9 tests)
    // =========================================================================

    #[test]
    fn test_sanitize_archive_entry_path_safe_paths() {
        assert_eq!(sanitize_archive_entry_path("classes.dex"), "classes.dex");
        assert_eq!(sanitize_archive_entry_path("AndroidManifest.xml"), "AndroidManifest.xml");
        assert_eq!(sanitize_archive_entry_path("res/drawable/icon.png"), "res/drawable/icon.png");
        assert_eq!(sanitize_archive_entry_path("r/a/a.xml"), "r/a/a.xml");
        assert_eq!(sanitize_archive_entry_path("assets/sub/data.json"), "assets/sub/data.json");
        assert_eq!(sanitize_archive_entry_path("lib/arm64-v8a/libnative.so"), "lib/arm64-v8a/libnative.so");
        assert_eq!(sanitize_archive_entry_path("res/layout/"), "res/layout/");
    }

    #[test]
    fn test_sanitize_archive_entry_path_traversal_stripping() {
        // Traversal escaping root
        assert_eq!(sanitize_archive_entry_path("../../etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_archive_entry_path("../../../shadow"), "shadow");
        // Internal traversal resolved correctly
        assert_eq!(sanitize_archive_entry_path("foo/../../bar"), "bar");
        assert_eq!(sanitize_archive_entry_path("foo/bar/../../baz"), "baz");
        assert_eq!(sanitize_archive_entry_path("a/b/c/../../../d"), "d");
        // Pure traversal returns empty string
        assert_eq!(sanitize_archive_entry_path("../../../"), "");
        assert_eq!(sanitize_archive_entry_path(".."), "");
    }

    #[test]
    fn test_sanitize_archive_entry_path_current_dir_and_empty_segments() {
        // Current directory '.' ignored
        assert_eq!(sanitize_archive_entry_path("./classes.dex"), "classes.dex");
        assert_eq!(sanitize_archive_entry_path("res/./drawable/./icon.png"), "res/drawable/icon.png");
        // Redundant consecutive slashes ignored
        assert_eq!(sanitize_archive_entry_path("foo//bar///baz.dex"), "foo/bar/baz.dex");
        assert_eq!(sanitize_archive_entry_path("."), "");
    }

    #[test]
    fn test_sanitize_archive_entry_path_leading_slashes() {
        assert_eq!(sanitize_archive_entry_path("/classes.dex"), "classes.dex");
        assert_eq!(sanitize_archive_entry_path("//classes.dex"), "classes.dex");
        assert_eq!(sanitize_archive_entry_path(r"\res\layout\main.xml"), "res/layout/main.xml");
        assert_eq!(sanitize_archive_entry_path(r"\\res\\layout\\main.xml"), "res/layout/main.xml");
        assert_eq!(sanitize_archive_entry_path("/../classes.dex"), "classes.dex");
    }

    #[test]
    fn test_sanitize_archive_entry_path_backslash_normalization() {
        assert_eq!(sanitize_archive_entry_path(r"res\drawable\icon.png"), "res/drawable/icon.png");
        assert_eq!(sanitize_archive_entry_path(r"assets\sub\config.json"), "assets/sub/config.json");
        assert_eq!(sanitize_archive_entry_path(r"res\layout\"), "res/layout/");
    }

    #[test]
    fn test_sanitize_archive_entry_path_windows_reserved_names() {
        // Direct reserved devices
        assert_eq!(sanitize_archive_entry_path("CON"), "_CON");
        assert_eq!(sanitize_archive_entry_path("PRN"), "_PRN");
        assert_eq!(sanitize_archive_entry_path("AUX"), "_AUX");
        assert_eq!(sanitize_archive_entry_path("NUL"), "_NUL");
        assert_eq!(sanitize_archive_entry_path("COM1"), "_COM1");
        assert_eq!(sanitize_archive_entry_path("LPT9"), "_LPT9");

        // Reserved devices with file extensions
        assert_eq!(sanitize_archive_entry_path("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_archive_entry_path("aux.xml"), "_aux.xml");
        assert_eq!(sanitize_archive_entry_path("NUL.dat"), "_NUL.dat");
        assert_eq!(sanitize_archive_entry_path("PRN.log"), "_PRN.log");
        assert_eq!(sanitize_archive_entry_path("com1.dex"), "_com1.dex");
        assert_eq!(sanitize_archive_entry_path("lpt1.bin"), "_lpt1.bin");

        // Case insensitivity
        assert_eq!(sanitize_archive_entry_path("CoN.TxT"), "_CoN.TxT");
        assert_eq!(sanitize_archive_entry_path("aUx.XmL"), "_aUx.XmL");
    }

    #[test]
    fn test_sanitize_archive_entry_path_reserved_in_subdirectories() {
        // Directory component is reserved
        assert_eq!(sanitize_archive_entry_path("com1/test.dex"), "_com1/test.dex");
        assert_eq!(sanitize_archive_entry_path("res/con/icon.png"), "res/_con/icon.png");
        assert_eq!(sanitize_archive_entry_path("assets/AUX/data.bin"), "assets/_AUX/data.bin");
        // Multiple reserved components
        assert_eq!(sanitize_archive_entry_path("aux/con.xml"), "_aux/_con.xml");
    }

    #[test]
    fn test_sanitize_archive_entry_path_windows_drive_letters() {
        assert_eq!(sanitize_archive_entry_path("C:/classes.dex"), "classes.dex");
        assert_eq!(sanitize_archive_entry_path(r"D:\res\drawable\icon.png"), "res/drawable/icon.png");
        assert_eq!(sanitize_archive_entry_path("c:AndroidManifest.xml"), "AndroidManifest.xml");
    }

    #[test]
    fn test_sanitize_archive_entry_path_complex_adversarial() {
        // Traversal + Windows drive + Reserved name
        assert_eq!(
            sanitize_archive_entry_path(r"C:\..\..\Windows\System32\CON.dll"),
            "Windows/System32/_CON.dll"
        );
        // Traversal + leading slashes + Reserved directory and file
        assert_eq!(
            sanitize_archive_entry_path("/../../com2/aux.xml"),
            "_com2/_aux.xml"
        );
    }
}
