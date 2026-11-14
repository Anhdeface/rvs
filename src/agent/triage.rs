use serde::{Deserialize, Serialize};
use crate::analysis::{self, info::SecurityMitigations};
use crate::error::AppError;
use crate::r2::R2Driver;

/// Payload for `agent triage` command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentTriageData {
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub endian: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityInfo>,
    pub total_functions: usize,
    pub total_strings: usize,
    pub top_functions: Vec<TriageFunctionSummary>,
    pub interesting_strings: Vec<String>,
    pub recommendations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_languages: Option<Vec<crate::apk::container::LanguageDetection>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nx: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relro: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripped: Option<bool>,
}

impl From<SecurityMitigations> for SecurityInfo {
    fn from(s: SecurityMitigations) -> Self {
        Self {
            canary: Some(s.canary),
            nx: Some(s.nx),
            pic: Some(s.pic),
            relro: Some(s.relro),
            stripped: Some(s.stripped),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TriageFunctionSummary {
    pub name: String,
    pub addr: u64,
    pub addr_hex: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_blocks: Option<usize>,
}

pub fn run_triage(driver: &R2Driver) -> Result<AgentTriageData, AppError> {
    let info = analysis::get_binary_info(driver)?;
    let funcs_resp = analysis::analyze_functions(driver, None, true)?;
    let strings_resp = analysis::list_strings(driver, 4)?;

    let total_functions = funcs_resp.functions.len();
    let total_strings = strings_resp.strings.len();

    // Select top functions
    let mut sorted_funcs = funcs_resp.functions.clone();
    sorted_funcs.sort_by(|a, b| {
        let comp_cmp = b.cyclomatic_complexity.unwrap_or(0).cmp(&a.cyclomatic_complexity.unwrap_or(0));
        if comp_cmp == std::cmp::Ordering::Equal {
            b.size.cmp(&a.size)
        } else {
            comp_cmp
        }
    });

    let mut top_functions: Vec<TriageFunctionSummary> = Vec::new();
    let mut included_names = std::collections::HashSet::new();

    // Always include main / entry function if it exists
    for f in &funcs_resp.functions {
        if (f.name == "main" || f.name.ends_with(".main") || f.name.contains("main"))
            && included_names.insert(f.name.clone())
        {
            top_functions.push(TriageFunctionSummary {
                name: f.name.clone(),
                addr: f.offset,
                addr_hex: format!("0x{:x}", f.offset),
                size: f.size,
                complexity: f.cyclomatic_complexity,
                num_blocks: f.num_basic_blocks.map(|n| n as usize),
            });
            break;
        }
    }

    for f in sorted_funcs {
        if top_functions.len() >= 15 {
            break;
        }
        if included_names.insert(f.name.clone()) {
            top_functions.push(TriageFunctionSummary {
                name: f.name.clone(),
                addr: f.offset,
                addr_hex: format!("0x{:x}", f.offset),
                size: f.size,
                complexity: f.cyclomatic_complexity,
                num_blocks: f.num_basic_blocks.map(|n| n as usize),
            });
        }
    }

    // Filter interesting strings
    let keywords = [
        "pass", "key", "secret", "auth", "token", "flag", "status", "lock", "serial", "valid",
        "invalid", "reaper", "soul", "http", "admin", "root", "error", "fail", "banner", "system",
        "debug", "correct", "wrong", "welcome", "license",
    ];

    let mut interesting_strings: Vec<String> = Vec::new();
    let mut seen_strings = std::collections::HashSet::new();

    for s in &strings_resp.strings {
        let text = s.string.trim();
        if text.is_empty() || seen_strings.contains(text) {
            continue;
        }

        let is_interesting = text.len() >= 8 || keywords.iter().any(|&k| {
            if text.len() < k.len() {
                false
            } else {
                text.as_bytes().windows(k.len()).any(|w| w.eq_ignore_ascii_case(k.as_bytes()))
            }
        });

        if is_interesting {
            seen_strings.insert(text.to_string());
            interesting_strings.push(text.to_string());
            if interesting_strings.len() >= 30 {
                break;
            }
        }
    }

    // Check if the target is an Android APK package or container
    let mut detected_languages = None;
    let mut apk_format_override = None;
    let mut apk_arch_override = None;
    let mut is_apk = false;
    let mut apk_recommendations = Vec::new();

    if let Ok(pkg) = crate::apk::container::ApkPackage::open(&driver.binary_path) {
        let is_archive_or_dir = matches!(
            pkg.source,
            crate::apk::container::ApkSource::Archive(_)
                | crate::apk::container::ApkSource::Directory(_)
        );
        is_apk = is_archive_or_dir
            && (pkg.manifest_data.is_some()
                || !pkg.dex_entries.is_empty()
                || !pkg.native_libraries.is_empty()
                || !pkg.asset_entries.is_empty());
        if is_apk {
            let langs = pkg.detect_languages();
            for lang in &langs {
                match lang.language.as_str() {
                    "Java" => {
                        apk_recommendations.push("Dalvik DEX bytecode detected: analyze classes, methods, and strings via 'rvs apk dex'.".to_string());
                    }
                    "C/C++" => {
                        apk_recommendations.push("Native C/C++ libraries detected: analyze JNI exports and symbol tables via 'rvs apk so'.".to_string());
                    }
                    "React Native" => {
                        apk_recommendations.push("React Native framework detected: analyze JavaScript bundle in assets/ or Hermes bytecode via 'rvs apk inspect'.".to_string());
                    }
                    "Flutter / Dart" => {
                        apk_recommendations.push("Flutter / Dart framework detected: inspect libapp.so AOT snapshot and flutter_assets via 'rvs apk so'.".to_string());
                    }
                    _ => {}
                }
            }
            if !langs.is_empty() {
                detected_languages = Some(langs);
            }
            apk_format_override = Some("APK".to_string());
            if !pkg.native_libraries.is_empty() {
                let abis = pkg.abis();
                apk_arch_override = Some(abis.join("/"));
            }
        }
    }

    // Generate recommendations: prioritize APK framework recommendations for APK targets
    let mut recommendations = Vec::new();
    recommendations.extend(apk_recommendations);

    if !is_apk {
        if info.security.stripped {
            recommendations.push("Binary is stripped: use string cross-references and entrypoint tracing to locate verification functions.".to_string());
        }
        if info.security.pic {
            recommendations.push("Position Independent Executable (PIE) enabled: use relative offsets for static patch calculations.".to_string());
        }
        if !info.security.nx {
            recommendations.push("NX bit disabled: stack/heap pages may be executable.".to_string());
        }

        if let Some(first_func) = top_functions.first() {
            recommendations.push(format!(
                "Inspect control flow for primary function '{}' via 'rvs agent flow {}'.",
                first_func.name, first_func.name
            ));
        }

        if !interesting_strings.is_empty() {
            recommendations.push("Trace cross-references to key strings using 'rvs analyze xrefs <string_addr>' to locate validation logic.".to_string());
        }
    } else if recommendations.is_empty() {
        recommendations.push("APK container package: inspect manifest and package layout via 'rvs apk inspect'.".to_string());
    }

    let format = if let Some(fmt) = apk_format_override {
        if info.format.is_empty() || info.format == "raw" || info.format == "zip" {
            fmt
        } else {
            info.format
        }
    } else {
        info.format
    };

    let arch = if let Some(a) = apk_arch_override {
        if info.arch.is_empty() {
            a
        } else {
            info.arch
        }
    } else {
        info.arch
    };

    Ok(AgentTriageData {
        format,
        arch,
        bits: info.bits,
        endian: info.endian,
        entry_point: Some(info.entry_point),
        entry_point_hex: Some(info.entry_point_hex),
        security: Some(info.security.into()),
        total_functions,
        total_strings,
        top_functions,
        interesting_strings,
        recommendations,
        detected_languages,
    })
}
