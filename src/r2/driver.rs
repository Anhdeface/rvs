use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::de::DeserializeOwned;
use crate::response::AppError;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
#[repr(C)]
struct pollfd {
    fd: std::os::raw::c_int,
    events: std::os::raw::c_short,
    revents: std::os::raw::c_short,
}

#[cfg(unix)]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn poll(fds: *mut pollfd, nfds: usize, timeout: std::os::raw::c_int) -> std::os::raw::c_int;
}

struct R2Session {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    buffer: Vec<u8>,
    buf_pos: usize,
    buf_len: usize,
    terminated: bool,
}

impl R2Session {
    fn terminate(&mut self) {
        if !self.terminated {
            self.terminated = true;
            #[cfg(unix)]
            unsafe {
                kill(-(self.child.id() as i32), 9);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn read_response(&mut self, timeout: Duration) -> Result<Vec<u8>, AppError> {
        let start = std::time::Instant::now();
        let mut result = Vec::new();

        #[cfg(unix)]
        let raw_fd = self.stdout.as_raw_fd();

        loop {
            // First check if there is any \0 in the buffered data
            if self.buf_pos < self.buf_len {
                if let Some(nul_idx) = self.buffer[self.buf_pos..self.buf_len]
                    .iter()
                    .position(|&b| b == 0)
                {
                    let actual_idx = self.buf_pos + nul_idx;
                    result.extend_from_slice(&self.buffer[self.buf_pos..actual_idx]);
                    self.buf_pos = actual_idx + 1;
                    return Ok(result);
                } else {
                    result.extend_from_slice(&self.buffer[self.buf_pos..self.buf_len]);
                    self.buf_pos = 0;
                    self.buf_len = 0;
                }
            }

            // Buffer is empty, check timeout before waiting for fd
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                self.terminate();
                return Err(AppError::Timeout(format!(
                    "radare2 process timed out after {}s",
                    timeout.as_secs()
                )));
            }
            let remaining = timeout - elapsed;
            let remaining_ms = (remaining.as_millis() as std::os::raw::c_int).max(1);

            #[cfg(unix)]
            {
                let mut pfd = pollfd {
                    fd: raw_fd,
                    events: 0x0001, // POLLIN
                    revents: 0,
                };
                let ret = unsafe { poll(&mut pfd, 1, remaining_ms) };
                if ret < 0 {
                    self.terminate();
                    return Err(AppError::R2ExecutionError("poll() error on radare2 stdout".to_string()));
                }
                if ret == 0 {
                    self.terminate();
                    return Err(AppError::Timeout(format!(
                        "radare2 process timed out after {}s",
                        timeout.as_secs()
                    )));
                }
            }

            self.buf_pos = 0;
            match self.stdout.read(&mut self.buffer) {
                Ok(0) => {
                    self.terminate();
                    return Err(AppError::R2ExecutionError(
                        "radare2 persistent process closed unexpectedly (EOF)".to_string(),
                    ));
                }
                Ok(n) => {
                    self.buf_len = n;
                }
                Err(e) => {
                    self.terminate();
                    return Err(AppError::R2ExecutionError(format!(
                        "Failed to read from radare2 stdout: {e}"
                    )));
                }
            }
        }
    }

    fn send_command(&mut self, cmd: &str, timeout: Duration) -> Result<String, AppError> {
        let trimmed = cmd.trim();
        self.stdin
            .write_all(trimmed.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| {
                self.terminate();
                AppError::R2ExecutionError(format!("Failed to write to radare2 stdin: {e}"))
            })?;

        let bytes = self.read_response(timeout)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

impl Drop for R2Session {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// High-performance driver wrapping radare2 subprocess invocations.
pub struct R2Driver {
    pub binary_path: PathBuf,
    pub arch: Option<String>,
    pub bits: Option<u32>,
    pub quiet: bool,
    pub timeout: Duration,
    session: Arc<Mutex<Option<R2Session>>>,
    address_cache: Arc<Mutex<HashMap<String, u64>>>,
}

impl Clone for R2Driver {
    fn clone(&self) -> Self {
        Self {
            binary_path: self.binary_path.clone(),
            arch: self.arch.clone(),
            bits: self.bits,
            quiet: self.quiet,
            timeout: self.timeout,
            session: Arc::clone(&self.session),
            address_cache: Arc::clone(&self.address_cache),
        }
    }
}

impl std::fmt::Debug for R2Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Driver")
            .field("binary_path", &self.binary_path)
            .field("arch", &self.arch)
            .field("bits", &self.bits)
            .field("quiet", &self.quiet)
            .field("timeout", &self.timeout)
            .finish()
    }
}

pub const BATCH_DELIMITER: &str = "===RVS_CMD_BATCH_BOUNDARY_DELIM===";

/// Checks if an ELF binary has machine type EM_AARCH64 (183).
pub fn is_aarch64_elf(path: &Path) -> bool {
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut header = [0u8; 20];
        if let Ok(n) = f.read(&mut header) {
            if n >= 20 && &header[0..4] == b"\x7fELF" {
                let e_machine = if header[5] == 2 {
                    u16::from_be_bytes([header[18], header[19]])
                } else {
                    u16::from_le_bytes([header[18], header[19]])
                };
                return e_machine == 183;
            }
        }
    }
    false
}

/// Normalizes architecture and bits for radare2 invocations.
/// Converts "aarch64" / "arm64" to arch="arm", bits=64.
/// Also auto-detects AArch64 ELF binaries when architecture is unspecified.
pub fn normalize_arch_bits(
    binary_path: &Path,
    arch: Option<String>,
    bits: Option<u32>,
) -> (Option<String>, Option<u32>) {
    if let Some(ref a) = arch {
        let a_lower = a.to_lowercase();
        if a_lower == "aarch64" || a_lower == "arm64" {
            return (Some("arm".to_string()), Some(64));
        }
        if a_lower == "arm" && bits == Some(64) {
            return (Some("arm".to_string()), Some(64));
        }
    } else if is_aarch64_elf(binary_path) {
        return (Some("arm".to_string()), Some(64));
    }
    (arch, bits)
}

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
        let (norm_arch, norm_bits) = normalize_arch_bits(&path, arch, bits);
        Ok(Self {
            binary_path: path,
            arch: norm_arch,
            bits: norm_bits,
            quiet,
            timeout: Duration::from_secs(30),
            session: Arc::new(Mutex::new(None)),
            address_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Returns true if this driver targets an AArch64 / ARM64 architecture.
    pub fn is_aarch64(&self) -> bool {
        if let Some(ref a) = self.arch {
            let a_lower = a.to_lowercase();
            if a_lower == "aarch64" || a_lower == "arm64" {
                return true;
            }
            if a_lower == "arm" && self.bits == Some(64) {
                return true;
            }
        }
        is_aarch64_elf(&self.binary_path)
    }

    /// Spawns a persistent bidirectional radare2 process using -N -0 -2.
    fn spawn_session(&self) -> Result<R2Session, AppError> {
        let is_arm64 = self.is_aarch64();
        let mut cmd = Command::new("radare2");
        cmd.arg("-N")
            .arg("-0")
            .arg("-2")
            .arg("-e").arg("scr.color=0")
            .arg("-e").arg("scr.interactive=0")
            .arg("-e").arg("scr.prompt=0")
            .arg("-e").arg("scr.utf8=0")
            .arg("-e").arg("cfg.fortunes=0")
            .arg("-e").arg("cfg.plugins=false")
            .arg("-e").arg("log.level=0");

        if is_arm64 {
            cmd.arg("-e").arg("bin.relocs.apply=true");
        } else {
            cmd.arg("-e").arg("bin.relocs.apply=false");
        }

        cmd.arg("-e").arg("anal.hasnext=false")
            .arg("-e").arg("anal.vars=false");

        if let Some(ref a) = self.arch {
            cmd.arg("-a").arg(a);
        }
        if let Some(b) = self.bits {
            cmd.arg("-b").arg(b.to_string());
        }
        if is_arm64 {
            cmd.arg("-e").arg("asm.cpu=v8");
        }

        cmd.arg(&self.binary_path);

        cmd.env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("R2_NOPLUGINS", "1")
            .env("RADARE2_RCFILE", "/dev/null")
            .env("R2_RCFILE", "/dev/null")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());

        #[cfg(unix)]
        cmd.process_group(0);

        let mut child = cmd.spawn().map_err(|e| {
            AppError::R2ExecutionError(format!("Failed to spawn radare2 process: {e}"))
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            AppError::R2ExecutionError("Failed to open stdin for radare2".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            AppError::R2ExecutionError("Failed to open stdout for radare2".to_string())
        })?;

        let mut session = R2Session {
            child,
            stdin,
            stdout,
            buffer: vec![0u8; 16384],
            buf_pos: 0,
            buf_len: 0,
            terminated: false,
        };

        // Read initial \0 emitted by radare2 on startup
        if let Err(e) = session.read_response(self.timeout) {
            session.terminate();
            return Err(e);
        }

        Ok(session)
    }

    /// Customizes the subprocess execution timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Builds base Command with strict terminal & environment isolation.
    fn build_base_command(&self, write_mode: bool) -> Command {
        let is_arm64 = self.is_aarch64();
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
            .arg("-e").arg("log.level=0");

        if is_arm64 {
            cmd.arg("-e").arg("bin.relocs.apply=true");
        } else {
            cmd.arg("-e").arg("bin.relocs.apply=false");
        }

        cmd.arg("-e").arg("anal.hasnext=false")
            .arg("-e").arg("anal.vars=false");

        if let Some(ref a) = self.arch {
            cmd.arg("-a").arg(a);
        }
        if let Some(b) = self.bits {
            cmd.arg("-b").arg(b.to_string());
        }
        if is_arm64 {
            cmd.arg("-e").arg("asm.cpu=v8");
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
        let mut session_guard = self.session.lock().unwrap();
        if session_guard.is_none() {
            *session_guard = Some(self.spawn_session()?);
        }

        let raw = match session_guard.as_mut().unwrap().send_command(r2_cmd, self.timeout) {
            Ok(out) => out,
            Err(e) => {
                *session_guard = None;
                return Err(e);
            }
        };

        Ok(sanitize_terminal_output(&raw))
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

        const CHUNK_SIZE: usize = 30;
        let mut results = Vec::with_capacity(commands.len());

        for chunk in commands.chunks(CHUNK_SIZE) {
            let mut batched_cmd = String::new();
            for (i, cmd) in chunk.iter().enumerate() {
                if i > 0 {
                    batched_cmd.push_str(&format!("; ?e {}; ", BATCH_DELIMITER));
                }
                batched_cmd.push_str(cmd.trim());
            }

            let raw = self.cmd(&batched_cmd)?;
            let parts: Vec<&str> = raw.split(BATCH_DELIMITER).collect();

            for (i, part) in parts.iter().enumerate() {
                if i < chunk.len() {
                    results.push(part.trim().to_string());
                }
            }

            while results.len() < results.capacity().min(results.len() + chunk.len().saturating_sub(parts.len())) {
                results.push(String::new());
            }
        }

        while results.len() < commands.len() {
            results.push(String::new());
        }

        Ok(results)
    }

    /// Executes a write-mode radare2 command batch on the target binary.
    pub fn cmd_write(&self, r2_cmd: &str) -> Result<String, AppError> {
        // Reset persistent session and invalidate address cache upon write
        {
            let mut session_guard = self.session.lock().unwrap();
            *session_guard = None;
            let mut cache = self.address_cache.lock().unwrap();
            cache.clear();
        }

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

        // Check in-memory cache
        {
            let cache = self.address_cache.lock().unwrap();
            if let Some(&addr) = cache.get(trimmed) {
                return Ok(addr);
            }
        }

        // Check functions or symbols via radare2 evaluation: "?v <expr>"
        if let Ok(eval_out) = self.cmd(&format!("?v {}", trimmed)) {
            let eval_str = eval_out.trim();
            let mut resolved: Option<u64> = None;
            if let Ok(addr) = eval_str.parse::<u64>() {
                if addr != 0 || trimmed == "0" || trimmed == "0x0" {
                    resolved = Some(addr);
                }
            } else if eval_str.starts_with("0x") || eval_str.starts_with("0X") {
                if let Ok(addr) = u64::from_str_radix(&eval_str[2..], 16) {
                    if addr != 0 || trimmed == "0" || trimmed == "0x0" {
                        resolved = Some(addr);
                    }
                }
            }
            if let Some(addr) = resolved {
                let mut cache = self.address_cache.lock().unwrap();
                cache.insert(trimmed.to_string(), addr);
                return Ok(addr);
            }
        }

        // Check if symbol exists in symbol table (isj) first (faster than aa; aflj)
        let symbols: Vec<serde_json::Value> = self.cmdj("isj").unwrap_or_default();
        let mut found_addr = None;
        {
            let mut cache = self.address_cache.lock().unwrap();
            for s in symbols {
                if let Some(name) = s.get("name").or_else(|| s.get("flagname")).or_else(|| s.get("realname")).and_then(|n| n.as_str()) {
                    if let Some(addr) = s.get("vaddr").or_else(|| s.get("paddr")).or_else(|| s.get("offset")).and_then(|a| a.as_u64()) {
                        cache.insert(name.to_string(), addr);
                        let clean = name.trim_start_matches("sym.");
                        if clean != name {
                            cache.insert(clean.to_string(), addr);
                        }
                        if found_addr.is_none() && (name == trimmed || clean == trimmed) {
                            found_addr = Some(addr);
                        }
                    }
                }
            }
        }
        if let Some(addr) = found_addr {
            return Ok(addr);
        }

        // Check if symbol exists in AFL
        let afl_cmd = if self.is_aarch64() { "aaa; aflj" } else { "aa; aflj" };
        let funcs: Vec<serde_json::Value> = self.cmdj(afl_cmd).unwrap_or_default();
        {
            let mut cache = self.address_cache.lock().unwrap();
            for f in funcs {
                if let Some(name) = f.get("name").and_then(|n| n.as_str()) {
                    if let Some(addr) = f.get("offset").or_else(|| f.get("addr")).and_then(|a| a.as_u64()) {
                        cache.insert(name.to_string(), addr);
                        let clean = name.trim_start_matches("sym.");
                        if clean != name {
                            cache.insert(clean.to_string(), addr);
                        }
                        if found_addr.is_none() && (name == trimmed || clean == trimmed) {
                            found_addr = Some(addr);
                        }
                    }
                }
            }
        }
        if let Some(addr) = found_addr {
            return Ok(addr);
        }

        Err(AppError::SymbolNotFound(target.to_string()))
    }
}

/// Executes a subprocess with concurrent pipe reading and execution timeout.
fn execute_command_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), AppError> {
    #[cfg(unix)]
    cmd.process_group(0);

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
    let mut sleep_dur = Duration::from_micros(100);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    #[cfg(unix)]
                    unsafe {
                        kill(-(child.id() as i32), 9);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(AppError::Timeout(format!(
                        "radare2 process timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(sleep_dur);
                if sleep_dur < Duration::from_millis(2) {
                    sleep_dur = (sleep_dur * 2).min(Duration::from_millis(2));
                }
            }
            Err(e) => {
                #[cfg(unix)]
                unsafe {
                    kill(-(child.id() as i32), 9);
                }
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

    #[test]
    fn test_normalize_arch_bits_aarch64_and_arm64() {
        let dummy = Path::new("/dummy/path");
        let (a1, b1) = normalize_arch_bits(dummy, Some("aarch64".to_string()), None);
        assert_eq!(a1.as_deref(), Some("arm"));
        assert_eq!(b1, Some(64));

        let (a2, b2) = normalize_arch_bits(dummy, Some("arm64".to_string()), None);
        assert_eq!(a2.as_deref(), Some("arm"));
        assert_eq!(b2, Some(64));

        let (a3, b3) = normalize_arch_bits(dummy, Some("AARCH64".to_string()), Some(32));
        assert_eq!(a3.as_deref(), Some("arm"));
        assert_eq!(b3, Some(64));

        let (a4, b4) = normalize_arch_bits(dummy, Some("x86".to_string()), Some(32));
        assert_eq!(a4.as_deref(), Some("x86"));
        assert_eq!(b4, Some(32));
    }

    #[test]
    fn test_aarch64_fixture_detection() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sample_aarch64_lib.so");
        if fixture.exists() {
            assert!(is_aarch64_elf(&fixture));
            let driver = R2Driver::new(&fixture, None, None, true).expect("Failed to create driver");
            assert!(driver.is_aarch64());
            assert_eq!(driver.arch.as_deref(), Some("arm"));
            assert_eq!(driver.bits, Some(64));
        }
    }
}
