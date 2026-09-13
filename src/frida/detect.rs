use std::path::Path;
use std::process::Command;
use serde::Deserialize;
use crate::error::AppError;
use crate::frida::types::FridaEnvStatus;
use crate::r2::driver::sanitize_terminal_output;

#[derive(Debug, Deserialize)]
struct IoPluginInfo {
    name: Option<String>,
    #[serde(default)]
    uris: Vec<String>,
    #[allow(dead_code)]
    desc: Option<String>,
    #[allow(dead_code)]
    permissions: Option<String>,
}

/// Probes the host system and radare2 configuration for r2frida availability.
pub fn probe_r2frida_env() -> FridaEnvStatus {
    let mut search_paths = Vec::new();
    let mut r2_version = "unknown".to_string();

    // Query radare2 paths via radare2 -H
    if let Ok(output) = Command::new("radare2").arg("-H").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(val) = line.strip_prefix("R2_USER_PLUGINS=") {
                let p = val.trim().to_string();
                if !p.is_empty() && !search_paths.contains(&p) {
                    search_paths.push(p);
                }
            } else if let Some(val) = line.strip_prefix("R2_LIBR_PLUGINS=") {
                let p = val.trim().to_string();
                if !p.is_empty() && !search_paths.contains(&p) {
                    search_paths.push(p);
                }
            } else if let Some(val) = line.strip_prefix("R2_VERSION=") {
                r2_version = val.trim().to_string();
            }
        }
    }

    // 1. Filesystem probe in radare2 plugin directories
    let plugin_filename = if cfg!(target_os = "macos") {
        "io_frida.dylib"
    } else if cfg!(target_os = "windows") {
        "io_frida.dll"
    } else {
        "io_frida.so"
    };

    let mut found_path: Option<String> = None;
    for sp in &search_paths {
        let candidate = Path::new(sp).join(plugin_filename);
        if candidate.exists() {
            found_path = Some(candidate.display().to_string());
            break;
        }
    }

    // 2. IO Plugin probe via `radare2 -qc "Loj" -`
    let mut installed = found_path.is_some();
    let mut cmd = Command::new("radare2");
    cmd.arg("-N")
        .arg("-q")
        .arg("-e").arg("scr.color=0")
        .arg("-e").arg("scr.interactive=0")
        .arg("-e").arg("scr.prompt=0")
        .arg("-e").arg("scr.utf8=0")
        .arg("-e").arg("cfg.fortunes=0")
        .arg("-e").arg("cfg.plugins=true")
        .arg("-qc").arg("Loj")
        .arg("-");

    cmd.env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env_remove("R2_NOPLUGINS")
        .env("RADARE2_RCFILE", "/dev/null")
        .env("R2_RCFILE", "/dev/null");

    if let Ok(output) = cmd.output() {
        let raw = sanitize_terminal_output(&String::from_utf8_lossy(&output.stdout));
        if let (Some(s), Some(e)) = (raw.find('['), raw.rfind(']')) {
            if e >= s {
                let json_slice = &raw[s..=e];
                if let Ok(plugins) = serde_json::from_str::<Vec<IoPluginInfo>>(json_slice) {
                    for p in plugins {
                        if p.name.as_deref() == Some("frida")
                            || p.uris.iter().any(|u| u.starts_with("frida://"))
                        {
                            installed = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    FridaEnvStatus {
        installed,
        radare2_version: r2_version,
        plugin_version: None,
        plugin_path: found_path,
        supported_uris: vec!["frida://".to_string()],
        search_paths,
        suggestion: if !installed {
            Some("Install r2frida via r2pm -ci r2frida or ensure io_frida.so is in plugin search path".to_string())
        } else {
            None
        },
    }
}

/// Checks whether r2frida is installed and returns environment details or R2FridaNotInstalled error.
pub fn detect_r2frida() -> Result<FridaEnvStatus, AppError> {
    let status = probe_r2frida_env();
    if !status.installed {
        return Err(AppError::R2FridaNotInstalled(
            "r2frida plugin (io_frida.so) not found in radare2 plugin search paths or Loj IO plugin list".to_string(),
        ));
    }
    Ok(status)
}

/// Returns true if r2frida plugin is detected on the host system.
pub fn is_r2frida_available() -> bool {
    probe_r2frida_env().installed
}
