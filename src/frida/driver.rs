use std::io::Read;
use std::process::Command;
use std::time::Duration;
use serde::de::DeserializeOwned;
use crate::error::AppError;
use crate::frida::detect::is_r2frida_available;
use crate::r2::driver::sanitize_terminal_output;
use crate::r2::R2Driver;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// Stateless subprocess driver for radare2 with r2frida dynamic instrumentation.
#[derive(Debug, Clone)]
pub struct FridaDriver {
    pub target_uri: String,
    pub quiet: bool,
    pub timeout: Duration,
}

impl FridaDriver {
    /// Creates a new FridaDriver for the target URI.
    /// Returns R2FridaNotInstalled if the r2frida plugin is missing.
    pub fn new(target_uri: impl Into<String>, quiet: bool) -> Result<Self, AppError> {
        let uri = target_uri.into();
        if uri.trim().is_empty() {
            return Err(AppError::InvalidArgument("Target URI or PID cannot be empty".to_string()));
        }

        if !is_r2frida_available() {
            return Err(AppError::R2FridaNotInstalled(
                "io_frida plugin not found via Loj or plugin search paths".to_string(),
            ));
        }

        Ok(Self {
            target_uri: uri,
            quiet,
            timeout: Duration::from_secs(30),
        })
    }

    /// Sets the timeout for Frida driver operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Builds the base radare2 command configured for r2frida plugin loading.
    fn build_base_command(&self) -> Command {
        let mut cmd = Command::new("radare2");
        cmd.arg("-N")
            .arg("-q")
            .arg("-e").arg("scr.color=0")
            .arg("-e").arg("scr.interactive=0")
            .arg("-e").arg("scr.prompt=0")
            .arg("-e").arg("scr.utf8=0")
            .arg("-e").arg("cfg.fortunes=0")
            .arg("-e").arg("cfg.plugins=true") // CRITICAL: Plugin loading enabled!
            .arg("-e").arg("log.level=0");

        cmd.env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env_remove("R2_NOPLUGINS") // CRITICAL: Omit R2_NOPLUGINS!
            .env("RADARE2_RCFILE", "/dev/null")
            .env("R2_RCFILE", "/dev/null")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        cmd
    }

    /// Executes a Frida command via radare2 subprocess and returns stdout string.
    pub fn cmd(&self, frida_cmd: &str) -> Result<String, AppError> {
        let trimmed = frida_cmd.trim();
        let formatted = if trimmed.starts_with(':') || trimmed.starts_with('=') {
            trimmed.to_string()
        } else {
            format!(":{}", trimmed)
        };

        let mut cmd = self.build_base_command();
        cmd.arg("-c").arg(&formatted);
        cmd.arg(&self.target_uri);

        let (status, stdout_bytes, stderr_bytes) = execute_subprocess_with_timeout(cmd, self.timeout)?;

        let stdout = sanitize_terminal_output(&String::from_utf8_lossy(&stdout_bytes));
        let stderr = sanitize_terminal_output(&String::from_utf8_lossy(&stderr_bytes));
        let combined = format!("{}\n{}", stdout, stderr);

        if combined.contains("Cannot open 'frida://") || combined.contains("io_frida") {
            return Err(AppError::R2FridaNotInstalled(
                "Cannot open frida URI. Ensure io_frida plugin is installed.".to_string(),
            ));
        }

        if combined.contains("Permission denied")
            || combined.contains("Operation not permitted")
            || combined.contains("requires root")
            || combined.contains("CAP_SYS_PTRACE")
        {
            let reason = if !stderr.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            return Err(AppError::PermissionDenied(format!(
                "Permission denied attaching to target '{}': {}",
                self.target_uri, reason
            )));
        }

        if !status.success() {
            let reason = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            return Err(AppError::FridaAttachFailed {
                target: self.target_uri.clone(),
                reason,
            });
        }

        Ok(stdout)
    }

    /// Executes a Frida command and deserializes the JSON output.
    pub fn cmdj<T: DeserializeOwned>(&self, frida_cmd: &str) -> Result<T, AppError> {
        let raw = self.cmd(frida_cmd)?;
        R2Driver::parse_json(&raw)
    }
}

/// Executes a subprocess with concurrent stdout/stderr reading and a timeout watchdog.
fn execute_subprocess_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), AppError> {
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd.spawn().map_err(|e| {
        AppError::R2ExecutionError(format!("Failed to spawn radare2 frida subprocess: {e}"))
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
                    #[cfg(unix)]
                    unsafe {
                        kill(-(child.id() as i32), 9);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(AppError::Timeout(format!(
                        "Frida subprocess timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
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
                    "Error waiting for frida subprocess: {e}"
                )));
            }
        }
    };

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    Ok((status, stdout_bytes, stderr_bytes))
}
