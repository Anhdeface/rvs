use std::path::PathBuf;
use crate::error::AppError;

/// Resolved target for Frida attachment or spawning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FridaTarget {
    Pid(u32),
    ProcessName(String),
    Spawn {
        path: PathBuf,
        args: Vec<String>,
    },
    Uri(String),
}

impl FridaTarget {
    /// Parses an attach target string into a FridaTarget.
    /// Handles numeric PIDs, negative numbers, URIs, and process names.
    pub fn parse_attach(target: &str) -> Result<Self, AppError> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidArgument("Target cannot be empty".to_string()));
        }

        // Scheme validation
        if trimmed.contains("://") {
            if !trimmed.starts_with("frida://") {
                return Err(AppError::InvalidArgument(format!(
                    "Invalid URI scheme in '{trimmed}'. Only 'frida://' URIs are supported."
                )));
            }
            return Ok(FridaTarget::Uri(trimmed.to_string()));
        }

        // Check for negative number (e.g. -1)
        if trimmed.starts_with('-') {
            return Err(AppError::InvalidArgument(format!(
                "Invalid PID '{trimmed}': Process ID cannot be negative"
            )));
        }

        // Check for purely numeric string
        let num_str = trimmed.strip_prefix('+').unwrap_or(trimmed);
        if !num_str.is_empty() && num_str.chars().all(|c| c.is_ascii_digit()) {
            match trimmed.parse::<u32>() {
                Ok(pid) => return Ok(FridaTarget::Pid(pid)),
                Err(_) => {
                    return Err(AppError::InvalidArgument(format!(
                        "Invalid PID '{trimmed}': exceeds maximum allowable PID value"
                    )));
                }
            }
        }

        // Otherwise process name
        Ok(FridaTarget::ProcessName(trimmed.to_string()))
    }

    /// Parses a spawn target path and arguments into a FridaTarget.
    /// Performs strict pre-flight validation on the binary target:
    /// 1. Verifies the path exists (returns FileNotFound).
    /// 2. Verifies the path is not a directory (returns FileNotFound).
    /// 3. Retrieves metadata and verifies the file is non-empty (returns ZeroByteFile).
    /// 4. On Unix, verifies executable permissions (returns PermissionDenied).
    pub fn parse_spawn(path: PathBuf, args: Vec<String>) -> Result<Self, AppError> {
        if !path.exists() {
            return Err(AppError::FileNotFound(path.display().to_string()));
        }

        if path.is_dir() {
            return Err(AppError::FileNotFound(format!(
                "Target path is a directory, not an executable binary: {}",
                path.display()
            )));
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                return match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        Err(AppError::FileNotFound(path.display().to_string()))
                    }
                    std::io::ErrorKind::PermissionDenied => {
                        Err(AppError::PermissionDenied(format!(
                            "Permission denied accessing target binary '{}'",
                            path.display()
                        )))
                    }
                    _ => Err(AppError::IoError(e)),
                };
            }
        };

        if metadata.len() == 0 {
            return Err(AppError::ZeroByteFile(path.display().to_string()));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(AppError::PermissionDenied(format!(
                    "Target binary '{}' is not executable",
                    path.display()
                )));
            }
        }

        let abs_path = std::fs::canonicalize(&path).unwrap_or(path);
        Ok(FridaTarget::Spawn {
            path: abs_path,
            args,
        })
    }

    /// Constructs the radare2 frida:// URI for the target.
    pub fn to_uri(&self) -> String {
        match self {
            FridaTarget::Pid(pid) => format!("frida://{pid}"),
            FridaTarget::ProcessName(name) => format!("frida://attach/local//{name}"),
            FridaTarget::Spawn { path, args } => {
                let path_str = path.display().to_string();
                if args.is_empty() {
                    format!("frida://spawn/local///{path_str}")
                } else {
                    let joined_args = args.join(" ");
                    format!("frida://spawn/local///{path_str} {joined_args}")
                }
            }
            FridaTarget::Uri(uri) => uri.clone(),
        }
    }

    /// Human-readable target name or identifier for API envelopes.
    pub fn display_target(&self) -> String {
        match self {
            FridaTarget::Pid(pid) => pid.to_string(),
            FridaTarget::ProcessName(name) => name.clone(),
            FridaTarget::Spawn { path, .. } => path.display().to_string(),
            FridaTarget::Uri(uri) => uri.clone(),
        }
    }

    pub fn pid(&self) -> Option<u32> {
        match self {
            FridaTarget::Pid(pid) => Some(*pid),
            _ => None,
        }
    }

    pub fn process_name(&self) -> Option<String> {
        match self {
            FridaTarget::ProcessName(name) => Some(name.clone()),
            FridaTarget::Spawn { path, .. } => path
                .file_name()
                .map(|f| f.to_string_lossy().to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_attach_numeric_pid() {
        let target = FridaTarget::parse_attach("12345").unwrap();
        assert_eq!(target, FridaTarget::Pid(12345));
        assert_eq!(target.to_uri(), "frida://12345");
        assert_eq!(target.pid(), Some(12345));
    }

    #[test]
    fn test_parse_attach_negative_pid_fails() {
        let err = FridaTarget::parse_attach("-1").unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_parse_attach_process_name() {
        let target = FridaTarget::parse_attach("firefox").unwrap();
        assert_eq!(target, FridaTarget::ProcessName("firefox".to_string()));
        assert_eq!(target.to_uri(), "frida://attach/local//firefox");
        assert_eq!(target.process_name(), Some("firefox".to_string()));
    }

    #[test]
    fn test_parse_attach_valid_frida_uri() {
        let target = FridaTarget::parse_attach("frida://1234").unwrap();
        assert_eq!(target, FridaTarget::Uri("frida://1234".to_string()));
    }

    #[test]
    fn test_parse_attach_invalid_scheme() {
        let err = FridaTarget::parse_attach("invalid_scheme://test").unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_parse_spawn_nonexistent_binary() {
        let err = FridaTarget::parse_spawn(PathBuf::from("/nonexistent/binary/xyz"), vec![]).unwrap_err();
        assert!(matches!(err, AppError::FileNotFound(_)));
    }

    #[test]
    fn test_parse_attach_overflow_pid_fails() {
        let err = FridaTarget::parse_attach("9999999999999999999999999999999999999999").unwrap_err();
        assert!(matches!(err, AppError::InvalidArgument(_)));
    }

    #[test]
    fn test_parse_spawn_directory_fails() {
        let temp_dir = std::env::temp_dir();
        let err = FridaTarget::parse_spawn(temp_dir, vec![]).unwrap_err();
        assert!(matches!(err, AppError::FileNotFound(_)));
    }

    #[test]
    fn test_parse_spawn_zero_byte_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let empty_file = dir.path().join("empty.bin");
        std::fs::File::create(&empty_file).unwrap();
        let err = FridaTarget::parse_spawn(empty_file, vec![]).unwrap_err();
        assert!(matches!(err, AppError::ZeroByteFile(_)));
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_spawn_non_executable_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let noexec_file = dir.path().join("noexec.bin");
        std::fs::write(&noexec_file, b"#!/bin/sh\necho test\n").unwrap();
        std::fs::set_permissions(&noexec_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = FridaTarget::parse_spawn(noexec_file, vec![]).unwrap_err();
        assert!(matches!(err, AppError::PermissionDenied(_)));
    }

    #[test]
    fn test_parse_spawn_valid_executable() {
        let current_exe = std::env::current_exe().unwrap();
        let target = FridaTarget::parse_spawn(current_exe.clone(), vec!["--help".to_string()]).unwrap();
        match target {
            FridaTarget::Spawn { path, args } => {
                assert!(path.is_absolute());
                assert_eq!(args, vec!["--help".to_string()]);
            }
            _ => panic!("Expected FridaTarget::Spawn"),
        }
    }
}
