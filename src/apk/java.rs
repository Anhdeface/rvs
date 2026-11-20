//! Java runtime and Apktool toolchain discovery and execution bridge.
//!
//! Provides dynamic detection of host Java runtime (OpenJDK >= 8) and Apktool runner
//! (binary or standalone JAR) to facilitate Tier 1 accelerated APK extraction.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::AppError;

/// Apktool runner representation: either a native/wrapper binary or a standalone `.jar` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApktoolRunner {
    /// Executable binary (e.g., `apktool` in PATH or `~/.local/bin/apktool`)
    Executable(PathBuf),
    /// Standalone JAR requiring `java -jar <jar_path>`
    Jar {
        java_bin: PathBuf,
        jar_path: PathBuf,
    },
}

impl ApktoolRunner {
    /// Returns the main executable path (either apktool or java).
    pub fn executable_path(&self) -> &Path {
        match self {
            Self::Executable(p) => p.as_path(),
            Self::Jar { java_bin, .. } => java_bin.as_path(),
        }
    }
}

/// Java Environment discovery and verification service.
pub struct JavaEnvironment;

impl JavaEnvironment {
    /// Locate a Java executable on the host system.
    ///
    /// Priority order:
    /// 1. `JAVA_HOME` environment variable (`$JAVA_HOME/bin/java`)
    /// 2. `PATH` environment variable lookup
    /// 3. Standard fallback locations (`~/.local/opt/jdk/bin/java`, `/usr/bin/java`, etc.)
    pub fn find_java() -> Option<PathBuf> {
        // 1. JAVA_HOME
        if let Ok(java_home) = std::env::var("JAVA_HOME") {
            let candidate = PathBuf::from(java_home).join("bin").join("java");
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // 2. PATH
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("java");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }

        // 3. Standard user and system fallback locations
        let mut fallbacks = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            fallbacks.push(PathBuf::from(&home).join(".local/opt/jdk/bin/java"));
            fallbacks.push(PathBuf::from(&home).join(".jdks").join("openjdk-21").join("bin/java"));
            fallbacks.push(PathBuf::from(&home).join(".jdks").join("openjdk-17").join("bin/java"));
        }
        fallbacks.push(PathBuf::from("/usr/bin/java"));
        fallbacks.push(PathBuf::from("/usr/local/bin/java"));
        fallbacks.push(PathBuf::from("/usr/lib/jvm/default-java/bin/java"));
        fallbacks.push(PathBuf::from("/usr/lib/jvm/default/bin/java"));

        fallbacks.into_iter().find(|candidate| candidate.is_file())
    }

    /// Query the Java version by executing `<java> -version`.
    ///
    /// Parses version strings such as `21.0.13` from `openjdk version "21.0.13"`.
    pub fn get_java_version(java_path: Option<&Path>) -> Option<String> {
        let java_bin = match java_path {
            Some(p) => p.to_path_buf(),
            None => Self::find_java()?,
        };

        let output = Command::new(&java_bin)
            .arg("-version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .ok()?;

        let mut combined = String::from_utf8_lossy(&output.stderr).to_string();
        combined.push_str(&String::from_utf8_lossy(&output.stdout));

        Self::parse_java_version_output(&combined)
    }

    /// Parse version string from `java -version` command output.
    pub fn parse_java_version_output(output: &str) -> Option<String> {
        for line in output.lines() {
            if let Some(idx) = line.find("version \"") {
                let rest = &line[idx + 9..];
                if let Some(end) = rest.find('"') {
                    return Some(rest[..end].to_string());
                }
            }
        }
        None
    }

    /// Validate that a Java version string corresponds to OpenJDK / Oracle JDK >= 8.
    pub fn check_java_version_supported(version_str: &str) -> bool {
        let trimmed = version_str.trim();
        let cleaned = trimmed.strip_prefix('v').unwrap_or(trimmed);
        if let Some(rest) = cleaned.strip_prefix("1.") {
            // Legacy version scheme: 1.8, 1.7, 1.8.0_312, etc.
            let minor_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(minor) = minor_str.parse::<u32>() {
                minor >= 8
            } else {
                false
            }
        } else {
            // Modern scheme or non-1 prefix: 9, 11, 17, 21, 21+35, 17+35-2724, 8u382-b05, etc.
            let first_token = cleaned
                .split(&['.', '-', '_', '+', 'u', 'U'][..])
                .next()
                .unwrap_or("");
            let major_digits: String = first_token
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(major) = major_digits.parse::<u32>() {
                major >= 8
            } else {
                false
            }
        }
    }

    /// Check if a supported Java runtime (>= 8) is available.
    pub fn is_java_supported() -> bool {
        if let Some(java_bin) = Self::find_java() {
            if let Some(ver) = Self::get_java_version(Some(&java_bin)) {
                return Self::check_java_version_supported(&ver);
            }
        }
        false
    }

    /// Find an Apktool runner (executable wrapper or `.jar`).
    pub fn find_apktool() -> Option<ApktoolRunner> {
        // 1. Look for `apktool` executable in PATH
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("apktool");
                if candidate.is_file() {
                    return Some(ApktoolRunner::Executable(candidate));
                }
            }
        }

        // 2. Look for executable in standard user/system directories
        let mut exe_candidates = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            exe_candidates.push(PathBuf::from(&home).join(".local/bin/apktool"));
        }
        exe_candidates.push(PathBuf::from("/usr/local/bin/apktool"));
        exe_candidates.push(PathBuf::from("/usr/bin/apktool"));

        if let Some(exe) = exe_candidates.into_iter().find(|candidate| candidate.is_file()) {
            return Some(ApktoolRunner::Executable(exe));
        }

        // 3. Look for `apktool.jar` standalone
        let mut jar_candidates = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            jar_candidates.push(PathBuf::from(&home).join(".local/opt/apktool/apktool.jar"));
        }
        jar_candidates.push(PathBuf::from("/usr/local/share/apktool/apktool.jar"));
        jar_candidates.push(PathBuf::from("/usr/share/java/apktool.jar"));
        jar_candidates.push(PathBuf::from("/opt/apktool/apktool.jar"));

        if let Some(java_bin) = Self::find_java() {
            if let Some(jar_path) = jar_candidates.into_iter().find(|p| p.is_file()) {
                return Some(ApktoolRunner::Jar { java_bin, jar_path });
            }
        }

        None
    }
}

/// Execute Apktool decode (`apktool d <apk> -o <out_dir> [-f]`) with a specified timeout.
pub fn run_apktool_decode(
    apk: &Path,
    out_dir: &Path,
    force: bool,
    timeout: Option<Duration>,
) -> Result<(), AppError> {
    run_apktool_decode_options(apk, out_dir, force, false, false, timeout)
}

/// Execute Apktool decode with full control over flags (including `-r` no-res and `-s` no-src).
pub fn run_apktool_decode_options(
    apk: &Path,
    out_dir: &Path,
    force: bool,
    no_resources: bool,
    no_sources: bool,
    timeout: Option<Duration>,
) -> Result<(), AppError> {
    if !apk.exists() {
        return Err(AppError::FileNotFound(apk.display().to_string()));
    }

    let runner = JavaEnvironment::find_apktool().ok_or_else(|| {
        AppError::Internal(
            "Apktool runner not found on host (neither 'apktool' executable nor 'apktool.jar')"
                .to_string(),
        )
    })?;

    let timeout = timeout.unwrap_or_else(|| Duration::from_secs(120));

    let mut cmd = match &runner {
        ApktoolRunner::Executable(bin) => {
            let mut c = Command::new(bin);
            c.arg("d");
            c.arg(apk);
            c.arg("-o");
            c.arg(out_dir);
            if force {
                c.arg("-f");
            }
            if no_resources {
                c.arg("-r");
            }
            if no_sources {
                c.arg("-s");
            }
            c
        }
        ApktoolRunner::Jar { java_bin, jar_path } => {
            let mut c = Command::new(java_bin);
            c.arg("-jar");
            c.arg(jar_path);
            c.arg("d");
            c.arg(apk);
            c.arg("-o");
            c.arg(out_dir);
            if force {
                c.arg("-f");
            }
            if no_resources {
                c.arg("-r");
            }
            if no_sources {
                c.arg("-s");
            }
            c
        }
    };

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        AppError::Internal(format!("Failed to spawn Apktool runner: {}", e))
    })?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut stream) = stdout.take() {
            let _ = stream.read_to_end(&mut buf);
        }
        buf
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut stream) = stderr.take() {
            let _ = stream.read_to_end(&mut buf);
        }
        buf
    });

    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout_bytes = stdout_handle.join().unwrap_or_default();
                let stderr_bytes = stderr_handle.join().unwrap_or_default();

                if status.success() {
                    return Ok(());
                } else {
                    let stderr = String::from_utf8_lossy(&stderr_bytes);
                    let stdout = String::from_utf8_lossy(&stdout_bytes);
                    return Err(AppError::Internal(format!(
                        "Apktool decode failed (exit status: {}):\nStdout: {}\nStderr: {}",
                        status, stdout, stderr
                    )));
                }
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_handle.join();
                    let _ = stderr_handle.join();
                    return Err(AppError::Timeout(format!(
                        "Apktool decode timed out after {} seconds",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(AppError::Internal(format!(
                    "Error monitoring Apktool child process: {}",
                    e
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_java_version_output() {
        let output1 = "openjdk version \"21.0.13\" 2026-10-20 LTS\nOpenJDK Runtime Environment";
        assert_eq!(
            JavaEnvironment::parse_java_version_output(output1),
            Some("21.0.13".to_string())
        );

        let output2 = "java version \"1.8.0_312\"\nJava(TM) SE Runtime Environment";
        assert_eq!(
            JavaEnvironment::parse_java_version_output(output2),
            Some("1.8.0_312".to_string())
        );

        let output3 = "invalid version output";
        assert_eq!(JavaEnvironment::parse_java_version_output(output3), None);
    }

    #[test]
    fn test_check_java_version_supported() {
        assert!(JavaEnvironment::check_java_version_supported("21.0.13"));
        assert!(JavaEnvironment::check_java_version_supported("17.0.2"));
        assert!(JavaEnvironment::check_java_version_supported("11.0.11"));
        assert!(JavaEnvironment::check_java_version_supported("1.8.0_312"));
        assert!(JavaEnvironment::check_java_version_supported("1.8"));

        // Modern GA versions with '+' build indicator
        assert!(JavaEnvironment::check_java_version_supported("21+35"));
        assert!(JavaEnvironment::check_java_version_supported("17+35-2724"));
        assert!(JavaEnvironment::check_java_version_supported("11+28"));

        // Versions with update indicator 'u' / 'U'
        assert!(JavaEnvironment::check_java_version_supported("8u382-b05"));
        assert!(JavaEnvironment::check_java_version_supported("8U123"));

        // Prefixed with 'v'
        assert!(JavaEnvironment::check_java_version_supported("v21+35"));
        assert!(JavaEnvironment::check_java_version_supported("v17.0.2"));

        // Unsupported / older versions
        assert!(!JavaEnvironment::check_java_version_supported("1.7.0_80"));
        assert!(!JavaEnvironment::check_java_version_supported("1.6.0_45"));
        assert!(!JavaEnvironment::check_java_version_supported("7u80"));
        assert!(!JavaEnvironment::check_java_version_supported("invalid"));
        assert!(!JavaEnvironment::check_java_version_supported(""));
    }

    #[test]
    fn test_dynamic_host_java_discovery() {
        if let Some(java_bin) = JavaEnvironment::find_java() {
            assert!(java_bin.is_file(), "Java binary must exist if found");
            let ver = JavaEnvironment::get_java_version(Some(&java_bin));
            assert!(ver.is_some(), "Should be able to parse java -version");
            let ver_str = ver.unwrap();
            assert!(
                JavaEnvironment::check_java_version_supported(&ver_str),
                "Java version {} must be supported (>= 8)",
                ver_str
            );
        }
    }

    #[test]
    fn test_dynamic_host_apktool_discovery() {
        if let Some(runner) = JavaEnvironment::find_apktool() {
            match runner {
                ApktoolRunner::Executable(p) => assert!(p.is_file()),
                ApktoolRunner::Jar { java_bin, jar_path } => {
                    assert!(java_bin.is_file());
                    assert!(jar_path.is_file());
                }
            }
        }
    }
}
