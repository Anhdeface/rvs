use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use serde::de::DeserializeOwned;
use crate::response::AppError;

/// High-performance driver wrapping radare2 subprocess invocations.
#[derive(Debug, Clone)]
pub struct R2Driver {
    pub binary_path: PathBuf,
    pub arch: Option<String>,
    pub bits: Option<u32>,
    pub quiet: bool,
    pub timeout: Duration,
}

pub const BATCH_DELIMITER: &str = "===RVS_CMD_BATCH_BOUNDARY_DELIM===";

impl R2Driver {
    /// Creates a new `R2Driver` instance after validating the target binary exists.
    pub fn new(
        binary_path: impl AsRef<Path>,
        arch: Option<String>,
        bits: Option<u32>,
        quiet: bool,
    ) -> Result<Self, AppError> {
        let path = binary_path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(AppError::FileNotFound(path.display().to_string()));
        }
        if path.is_dir() {
            return Err(AppError::FileNotFound(format!(
                "Target path is a directory, not a binary file: {}",
                path.display()
            )));
        }
        if let Ok(metadata) = std::fs::metadata(&path) {
            if metadata.len() == 0 {
                return Err(AppError::ZeroByteFile(path.display().to_string()));
            }
        }
        Ok(Self {
            binary_path: path,
            arch,
            bits,
            quiet,
            timeout: Duration::from_secs(30),
        })
    }

    /// Customizes the subprocess execution timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Builds base Command with strict terminal & environment isolation.
    fn build_base_command(&self, write_mode: bool) -> Command {
        let mut cmd = Command::new("radare2");
        if write_mode {
            cmd.arg("-w");
        }
        cmd.arg("-N")
            .arg("-q")
            .arg("-e").arg("scr.color=0")
            .arg("-e").arg("scr.interactive=0")
            .arg("-e").arg("scr.prompt=0")
            .arg("-e").arg("scr.utf8=0")
            .arg("-e").arg("cfg.fortunes=0")
            .arg("-e").arg("cfg.plugins=false")
            .arg("-e").arg("log.level=0")
            .arg("-e").arg("bin.relocs.apply=false")
            .arg("-e").arg("anal.hasnext=false")
            .arg("-e").arg("anal.vars=false");

        if let Some(ref a) = self.arch {
            cmd.arg("-a").arg(a);
        }
        if let Some(b) = self.bits {
            cmd.arg("-b").arg(b.to_string());
        }

        cmd.env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("R2_NOPLUGINS", "1")
            .env("RADARE2_RCFILE", "/dev/null")
            .env("R2_RCFILE", "/dev/null")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        cmd
    }

    /// Executes a read-only radare2 command batch and returns raw stdout string.
    pub fn cmd(&self, r2_cmd: &str) -> Result<String, AppError> {
        let mut cmd = self.build_base_command(false);
        cmd.arg("-c").arg(r2_cmd);
        cmd.arg(&self.binary_path);

        let (status, stdout_bytes, stderr_bytes) = execute_command_with_timeout(cmd, self.timeout)?;
        let stdout = sanitize_terminal_output(&String::from_utf8_lossy(&stdout_bytes));
        let stderr = sanitize_terminal_output(&String::from_utf8_lossy(&stderr_bytes));

        if !status.success() {
            if stderr.contains("Permission denied") {
                return Err(AppError::PermissionDenied(self.binary_path.display().to_string()));
            }
            return Err(AppError::R2ExecutionError(format!(
                "radare2 exited with status {}: {}",
                status, stderr.trim()
            )));
        }

        Ok(stdout)
    }

    /// Executes a read-only radare2 command batch and deserializes JSON output.
    pub fn cmdj<T: DeserializeOwned>(&self, r2_cmd: &str) -> Result<T, AppError> {
        let raw = self.cmd(r2_cmd)?;
        Self::parse_json(&raw)
    }

    /// Executes multiple radare2 commands in a single subprocess invocation,
    /// returning the isolated stdout strings in corresponding order.
    pub fn cmd_batch(&self, commands: &[&str]) -> Result<Vec<String>, AppError> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        if commands.len() == 1 {
            return self.cmd(commands[0]).map(|out| vec![out]);
        }

        // Join commands separated by echo delimiter
        let mut batched_cmd = String::new();
        for (i, cmd) in commands.iter().enumerate() {
            if i > 0 {
                batched_cmd.push_str(&format!("; ?e {}; ", BATCH_DELIMITER));
            }
            batched_cmd.push_str(cmd.trim());
        }

        let raw = self.cmd(&batched_cmd)?;
        let parts: Vec<&str> = raw.split(BATCH_DELIMITER).collect();

        let mut results = Vec::with_capacity(commands.len());
        for (i, part) in parts.iter().enumerate() {
            if i < commands.len() {
                results.push(part.trim().to_string());
            }
        }

        // If radare2 stopped early, fill remaining outputs with empty strings
        while results.len() < commands.len() {
            results.push(String::new());
        }

        Ok(results)
    }

    /// Executes a write-mode radare2 command batch on the target binary.
    pub fn cmd_write(&self, r2_cmd: &str) -> Result<String, AppError> {
        let mut cmd = self.build_base_command(true);
        cmd.arg("-c").arg(r2_cmd);
        cmd.arg(&self.binary_path);

        let (status, stdout_bytes, stderr_bytes) = execute_command_with_timeout(cmd, self.timeout)?;
        let stdout = sanitize_terminal_output(&String::from_utf8_lossy(&stdout_bytes));
        let stderr = sanitize_terminal_output(&String::from_utf8_lossy(&stderr_bytes));

        if stderr.contains("Cannot assemble") || stderr.contains("ERROR") {
            return Err(AppError::AssemblyFailed {
                instruction: r2_cmd.to_string(),
                details: stderr.trim().to_string(),
            });
        }

        if !status.success() {
            if stderr.contains("Permission denied") {
                return Err(AppError::PermissionDenied(self.binary_path.display().to_string()));
            }
            return Err(AppError::R2ExecutionError(format!(
                "Write operation failed (status {}): {}",
                status, stderr.trim()
            )));
        }

        Ok(stdout)
    }

    /// Reads `len` bytes from target memory address in hex representation.
    pub fn read_bytes_hex(&self, addr: &str, len: usize) -> Result<String, AppError> {
        let cmd = format!("s {}; p8 {}", addr, len);
        let out = self.cmd(&cmd)?;
        Ok(out.trim().to_string())
    }

    /// Reads null-terminated string at specified address.
    pub fn read_string_at(&self, addr: &str) -> Result<String, AppError> {
        let cmd = format!("s {}; ps", addr);
        let out = self.cmd(&cmd)?;
        Ok(out.trim().to_string())
    }

    /// Robustly extracts and parses JSON from potentially noisy radare2 output.
    pub fn parse_json<T: DeserializeOwned>(raw: &str) -> Result<T, AppError> {
        let sanitized = sanitize_terminal_output(raw);
        let trimmed = sanitized.trim();
        if trimmed.is_empty() {
            return serde_json::from_str::<T>("[]")
                .or_else(|_| serde_json::from_str::<T>("{}"))
                .map_err(|e| AppError::R2ExecutionError(format!("Empty output from radare2: {e}")));
        }

        // Try direct parse first
        if let Ok(val) = serde_json::from_str::<T>(trimmed) {
            return Ok(val);
        }

        // Search for JSON boundaries `[...]` or `{...}`
        let array_start = trimmed.find('[');
        let array_end = trimmed.rfind(']');
        if let (Some(s), Some(e)) = (array_start, array_end) {
            if e >= s {
                let slice = &trimmed[s..=e];
                if let Ok(val) = serde_json::from_str::<T>(slice) {
                    return Ok(val);
                }
            }
        }

        let obj_start = trimmed.find('{');
        let obj_end = trimmed.rfind('}');
        if let (Some(s), Some(e)) = (obj_start, obj_end) {
            if e >= s {
                let slice = &trimmed[s..=e];
                if let Ok(val) = serde_json::from_str::<T>(slice) {
                    return Ok(val);
                }
            }
        }

        let preview: String = trimmed.chars().take(200).collect();
        Err(AppError::R2ExecutionError(format!(
            "Failed to parse JSON from radare2 output: {}",
            preview
        )))
    }

    /// Resolves target string (hex, decimal, symbol or expression) to virtual address.
    pub fn resolve_address(&self, target: &str) -> Result<u64, AppError> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidArgument("Target address or symbol cannot be empty".to_string()));
        }
        const FORBIDDEN_CHARS: &[char] = &[
            ';', '\n', '\r', '`', '|', '&', '$', '>', '<', '~', '!', '\\', '"', '\'', '#',
        ];
        if trimmed.chars().any(|c| FORBIDDEN_CHARS.contains(&c) || c.is_control()) {
            return Err(AppError::InvalidArgument(format!(
                "Invalid characters in target address or symbol: {}",
                trimmed
            )));
        }
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            if let Ok(addr) = u64::from_str_radix(&trimmed[2..], 16) {
                return Ok(addr);
            }
        }
        if let Ok(addr) = trimmed.parse::<u64>() {
            return Ok(addr);
        }

        // Check functions or symbols via radare2 evaluation: "?v <expr>"
        let eval_out = self.cmd(&format!("?v {}", trimmed))?;
        let eval_str = eval_out.trim();
        if let Ok(addr) = eval_str.parse::<u64>() {
            if addr != 0 || trimmed == "0" || trimmed == "0x0" {
                return Ok(addr);
            }
        }
        if eval_str.starts_with("0x") || eval_str.starts_with("0X") {
            if let Ok(addr) = u64::from_str_radix(&eval_str[2..], 16) {
                if addr != 0 || trimmed == "0" || trimmed == "0x0" {
                    return Ok(addr);
                }
            }
        }

        // Check if symbol exists in AFL
        let funcs: Vec<serde_json::Value> = self.cmdj("aa; aflj").unwrap_or_default();

        for f in funcs {
            if let Some(name) = f.get("name").and_then(|n| n.as_str()) {
                if name == trimmed || name.trim_start_matches("sym.") == trimmed {
                    if let Some(addr) = f.get("offset").or_else(|| f.get("addr")).and_then(|a| a.as_u64()) {
                        return Ok(addr);
                    }
                }
            }
        }

        // Check if symbol exists in symbol table (isj)
        let symbols: Vec<serde_json::Value> = self.cmdj("isj").unwrap_or_default();
        for s in symbols {
            if let Some(name) = s.get("name").or_else(|| s.get("flagname")).or_else(|| s.get("realname")).and_then(|n| n.as_str()) {
                if name == trimmed || name.trim_start_matches("sym.") == trimmed {
                    if let Some(addr) = s.get("vaddr").or_else(|| s.get("paddr")).or_else(|| s.get("offset")).and_then(|a| a.as_u64()) {
                        return Ok(addr);
                    }
                }
            }
        }

        Err(AppError::SymbolNotFound(target.to_string()))
    }
}

/// Executes a subprocess with concurrent pipe reading and execution timeout.
fn execute_command_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), AppError> {
    let mut child = cmd.spawn().map_err(|e| {
        AppError::R2ExecutionError(format!("Failed to spawn radare2 process: {e}"))
    })?;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe.take() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe.take() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    });

    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(AppError::Timeout(format!(
                        "radare2 process timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(AppError::R2ExecutionError(format!(
                    "Failed to wait on radare2 process: {e}"
                )));
            }
        }
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();

    Ok((status, stdout, stderr))
}

/// Strips ANSI escape sequences and non-printable control characters from text.
pub fn sanitize_terminal_output(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ANSI Escape sequence
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: \x1b[ ... (until final byte 0x40..=0x7E)
                    chars.next(); // consume '['
                    while let Some(&seq_c) = chars.peek() {
                        chars.next();
                        if (seq_c as u32) >= 0x40 && (seq_c as u32) <= 0x7E {
                            break;
                        }
                    }
                } else if next == ']' {
                    // OSC sequence: \x1b] ... (until \x07 or \x1b\)
                    chars.next(); // consume ']'
                    while let Some(&seq_c) = chars.peek() {
                        chars.next();
                        if seq_c == '\x07' {
                            break;
                        }
                        if seq_c == '\x1b' {
                            if let Some(&after_esc) = chars.peek() {
                                if after_esc == '\\' {
                                    chars.next();
                                }
                            }
                            break;
                        }
                    }
                } else if next == '(' || next == ')' || next == '*' || next == '+' {
                    chars.next();
                    chars.next();
                } else {
                    chars.next();
                }
            }
        } else if c == '\n' || c == '\r' || c == '\t' || (c >= ' ' && c != '\x7f') {
            out.push(c);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_terminal_output_ansi_colors() {
        let input = "\x1b[31mRed Text\x1b[0m and \x1b[1;32mGreen Bold\x1b[0m";
        let cleaned = sanitize_terminal_output(input);
        assert_eq!(cleaned, "Red Text and Green Bold");
    }

    #[test]
    fn test_sanitize_terminal_output_control_chars() {
        let input = "Hello\x0eWorld\x07!\x08 Tab:\tNewline:\nCR:\rEnd";
        let cleaned = sanitize_terminal_output(input);
        assert_eq!(cleaned, "HelloWorld! Tab:\tNewline:\nCR:\rEnd");
    }

    #[test]
    fn test_sanitize_terminal_output_osc_and_complex_sequences() {
        let input = "\x1b]0;Window Title\x07Clean Output\x1b[2J\x1b[HDone";
        let cleaned = sanitize_terminal_output(input);
        assert_eq!(cleaned, "Clean OutputDone");
    }

    #[test]
    fn test_parse_json_with_ansi_and_noise() {
        let noisy = "\x1b[33mWARN: something\x1b[0m\n[{\"name\":\"main\",\"addr\":4096}]\n";
        let parsed: Vec<serde_json::Value> = R2Driver::parse_json(noisy).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], "main");
    }

    #[test]
    fn test_driver_new_validation() {
        assert!(R2Driver::new("/nonexistent/file/path", None, None, false).is_err());
        assert!(R2Driver::new("/tmp", None, None, false).is_err());
    }
}
