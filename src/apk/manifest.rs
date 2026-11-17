use serde::{Deserialize, Serialize};
use crate::error::AppError;

/// Structured summary of an AndroidManifest.xml file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestInfo {
    pub package_name: String,
    pub version_code: Option<u32>,
    pub version_name: Option<String>,
    pub min_sdk_version: Option<u32>,
    pub target_sdk_version: Option<u32>,
    pub debuggable: bool,
    pub permissions: Vec<String>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
    pub receivers: Vec<String>,
    pub providers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
}

/// Decode AndroidManifest raw bytes (binary AXML or plain text XML) into readable XML text.
pub fn decode_raw_manifest(bytes: &[u8]) -> Result<String, AppError> {
    if bytes.is_empty() {
        return Err(AppError::ZeroByteFile("Manifest data is empty (0 bytes)".to_string()));
    }
    if is_binary_axml(bytes) {
        if let Ok(xml) = asc_axml::decode(bytes) {
            return Ok(xml);
        }
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if text.trim_start().starts_with('<') {
            return Ok(text.to_string());
        }
    }
    // Fallback attempt with asc_axml
    if let Ok(xml) = asc_axml::decode(bytes) {
        return Ok(xml);
    }
    Err(AppError::InvalidBinary(
        "Failed to decode Android binary XML (AXML) manifest".to_string(),
    ))
}

/// Checks whether the raw byte buffer begins with Android binary XML (AXML) magic.
///
/// In Android AXML, the document begins with a `ResXMLTree_header`:
/// - Chunk type: `RES_XML_TYPE = 0x0003` (2 bytes, little-endian: `0x03, 0x00`)
/// - Header size: 8 bytes (2 bytes, little-endian: `0x08, 0x00`)
///
/// Combined 32-bit little-endian value: `0x00080003`.
pub fn is_binary_axml(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0x03 && bytes[1] == 0x00 && bytes[2] == 0x08 && bytes[3] == 0x00
}

impl ManifestInfo {
    /// Parse an `AndroidManifest.xml` from raw bytes.
    ///
    /// Automatically detects whether the bytes are binary AXML or plain text XML,
    /// while honoring `is_binary` as an initial hint.
    pub fn parse(bytes: &[u8], is_binary: bool) -> Result<Self, AppError> {
        if bytes.is_empty() {
            return Err(AppError::ZeroByteFile("Manifest data is empty (0 bytes)".to_string()));
        }

        let is_axml = is_binary || is_binary_axml(bytes);

        if is_axml {
            // 1. Try parsing binary AXML element tree directly
            if let Ok(tree) = asc_axml::parse_tree(bytes, None) {
                if let Ok(info) = Self::from_axml_element(&tree) {
                    return Ok(info);
                }
            }

            // 2. Try decoding AXML to string with asc_axml, then parse XML
            if let Ok(decoded_xml) = asc_axml::decode(bytes) {
                if let Ok(info) = Self::from_xml_str(&decoded_xml) {
                    return Ok(info);
                }
            }

            // 3. Fallback: if bytes were actually plain text XML
            if let Ok(text) = std::str::from_utf8(bytes) {
                if text.trim_start().starts_with('<') {
                    if let Ok(info) = Self::from_xml_str(text) {
                        return Ok(info);
                    }
                }
            }

            Err(AppError::InvalidBinary(
                "Failed to decode Android binary XML (AXML) manifest".to_string(),
            ))
        } else {
            // Text XML mode
            if is_binary_axml(bytes) {
                return Self::parse(bytes, true);
            }

            let text = std::str::from_utf8(bytes)
                .map_err(|e| AppError::InvalidBinary(format!("Invalid UTF-8 in manifest: {}", e)))?;

            // If it starts with '<', parse as XML text
            if text.trim_start().starts_with('<') {
                Self::from_xml_str(text)
            } else {
                // Last ditch attempt as binary AXML
                Self::parse(bytes, true)
            }
        }
    }

    /// Parse directly from binary AXML bytes.
    pub fn from_axml(bytes: &[u8]) -> Result<Self, AppError> {
        Self::parse(bytes, true)
    }

    /// Parse directly from a plain text XML string.
    pub fn from_xml_str(xml_str: &str) -> Result<Self, AppError> {
        let mut reader = quick_xml::reader::Reader::from_str(xml_str);
        reader.config_mut().trim_text(true);

        let mut package_name = String::new();
        let mut version_code = None;
        let mut version_name = None;
        let mut min_sdk_version = None;
        let mut target_sdk_version = None;
        let mut debuggable = false;
        let mut permissions = Vec::new();
        let mut activities = Vec::new();
        let mut services = Vec::new();
        let mut receivers = Vec::new();
        let mut providers = Vec::new();

        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Start(e)) | Ok(quick_xml::events::Event::Empty(e)) => {
                    let local_tag = e.name().local_name();
                    let tag_bytes = local_tag.as_ref();

                    let get_attr = |target: &str| -> Option<String> {
                        for attr in e.attributes().flatten() {
                            let key_local = attr.key.local_name();
                            if key_local.as_ref().eq_ignore_ascii_case(target.as_bytes()) {
                                if let Ok(val) = attr.unescape_value() {
                                    return Some(val.trim().to_string());
                                }
                            }
                        }
                        None
                    };

                    match tag_bytes {
                        b"manifest" => {
                            if let Some(pkg) = get_attr("package") {
                                package_name = pkg;
                            }
                            if let Some(vc) = get_attr("versionCode").and_then(|s| parse_int(&s)) {
                                version_code = Some(vc);
                            }
                            if let Some(vn) = get_attr("versionName") {
                                version_name = Some(vn);
                            }
                        }
                        b"uses-sdk" => {
                            if let Some(min) = get_attr("minSdkVersion").and_then(|s| parse_int(&s)) {
                                min_sdk_version = Some(min);
                            }
                            if let Some(target) = get_attr("targetSdkVersion").and_then(|s| parse_int(&s)) {
                                target_sdk_version = Some(target);
                            }
                        }
                        b"uses-permission" | b"permission" => {
                            if let Some(name) = get_attr("name") {
                                if !name.is_empty() && !permissions.contains(&name) {
                                    permissions.push(name);
                                }
                            }
                        }
                        b"application" => {
                            if let Some(dbg) = get_attr("debuggable") {
                                debuggable = dbg.eq_ignore_ascii_case("true") || dbg == "1";
                            }
                        }
                        b"activity" | b"activity-alias" => {
                            if let Some(name) = get_attr("name") {
                                if !name.is_empty() && !activities.contains(&name) {
                                    activities.push(name);
                                }
                            }
                        }
                        b"service" => {
                            if let Some(name) = get_attr("name") {
                                if !name.is_empty() && !services.contains(&name) {
                                    services.push(name);
                                }
                            }
                        }
                        b"receiver" => {
                            if let Some(name) = get_attr("name") {
                                if !name.is_empty() && !receivers.contains(&name) {
                                    receivers.push(name);
                                }
                            }
                        }
                        b"provider" => {
                            if let Some(name) = get_attr("name") {
                                if !name.is_empty() && !providers.contains(&name) {
                                    providers.push(name);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(e) => {
                    return Err(AppError::InvalidBinary(format!("XML parsing error: {}", e)));
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(ManifestInfo {
            package_name,
            version_code,
            version_name,
            min_sdk_version,
            target_sdk_version,
            debuggable,
            permissions,
            activities,
            services,
            receivers,
            providers,
            raw_xml: None,
        })
    }

    /// Extract `ManifestInfo` from an `asc_axml::Element` tree.
    fn from_axml_element(root: &asc_axml::Element) -> Result<Self, AppError> {
        let package_name = find_attr(root, "package")
            .map(|a| a.value.trim().to_string())
            .unwrap_or_default();

        let version_code = find_attr(root, "versionCode")
            .and_then(|a| a.as_int().map(|v| v as u32).or_else(|| parse_int(&a.value)));

        let version_name = find_attr(root, "versionName")
            .map(|a| a.value.trim().to_string());

        let mut min_sdk_version = None;
        let mut target_sdk_version = None;
        let mut debuggable = false;
        let mut permissions = Vec::new();
        let mut activities = Vec::new();
        let mut services = Vec::new();
        let mut receivers = Vec::new();
        let mut providers = Vec::new();

        // Traverse elements
        for child in &root.children {
            match child.name.as_str() {
                "uses-sdk" => {
                    if let Some(min) = find_attr(child, "minSdkVersion")
                        .and_then(|a| a.as_int().map(|v| v as u32).or_else(|| parse_int(&a.value)))
                    {
                        min_sdk_version = Some(min);
                    }
                    if let Some(target) = find_attr(child, "targetSdkVersion")
                        .and_then(|a| a.as_int().map(|v| v as u32).or_else(|| parse_int(&a.value)))
                    {
                        target_sdk_version = Some(target);
                    }
                }
                "uses-permission" | "permission" => {
                    if let Some(name) = find_attr(child, "name").map(|a| a.value.trim().to_string()) {
                        if !name.is_empty() && !permissions.contains(&name) {
                            permissions.push(name);
                        }
                    }
                }
                "application" => {
                    if let Some(dbg) = find_attr(child, "debuggable")
                        .and_then(|a| a.as_bool().or_else(|| a.value.trim().parse::<bool>().ok()))
                    {
                        debuggable = dbg;
                    }

                    for app_child in &child.children {
                        match app_child.name.as_str() {
                            "activity" | "activity-alias" => {
                                if let Some(name) = find_attr(app_child, "name").map(|a| a.value.trim().to_string()) {
                                    if !name.is_empty() && !activities.contains(&name) {
                                        activities.push(name);
                                    }
                                }
                            }
                            "service" => {
                                if let Some(name) = find_attr(app_child, "name").map(|a| a.value.trim().to_string()) {
                                    if !name.is_empty() && !services.contains(&name) {
                                        services.push(name);
                                    }
                                }
                            }
                            "receiver" => {
                                if let Some(name) = find_attr(app_child, "name").map(|a| a.value.trim().to_string()) {
                                    if !name.is_empty() && !receivers.contains(&name) {
                                        receivers.push(name);
                                    }
                                }
                            }
                            "provider" => {
                                if let Some(name) = find_attr(app_child, "name").map(|a| a.value.trim().to_string()) {
                                    if !name.is_empty() && !providers.contains(&name) {
                                        providers.push(name);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(ManifestInfo {
            package_name,
            version_code,
            version_name,
            min_sdk_version,
            target_sdk_version,
            debuggable,
            permissions,
            activities,
            services,
            receivers,
            providers,
            raw_xml: None,
        })
    }
}

/// Helper to parse decimal or hex u32 strings.
fn parse_int(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

/// Helper to look up an attribute by name in an `asc_axml::Element`
/// across android namespace, plain namespace, and local attribute name.
fn find_attr<'a>(element: &'a asc_axml::Element, name: &str) -> Option<&'a asc_axml::Attribute> {
    element
        .android(name)
        .or_else(|| element.plain(name))
        .or_else(|| element.attrs.iter().find(|a| a.name.eq_ignore_ascii_case(name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TEXT_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.reversetarget"
    android:versionCode="42"
    android:versionName="2.1.0">

    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:label="ReverseTarget"
        android:debuggable="true">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name="com.example.reversetarget.SettingsActivity" />
        <service android:name=".BackgroundWorkerService" />
        <receiver android:name=".BootReceiver" />
        <provider android:name=".DataProvider" android:authorities="com.example.provider" />
    </application>
</manifest>
"#;

    #[test]
    fn test_parse_text_manifest_full() {
        let info = ManifestInfo::from_xml_str(SAMPLE_TEXT_XML).expect("Failed to parse text manifest");
        assert_eq!(info.package_name, "com.example.reversetarget");
        assert_eq!(info.version_code, Some(42));
        assert_eq!(info.version_name.as_deref(), Some("2.1.0"));
        assert_eq!(info.min_sdk_version, Some(24));
        assert_eq!(info.target_sdk_version, Some(34));
        assert!(info.debuggable);

        assert_eq!(
            info.permissions,
            vec![
                "android.permission.INTERNET".to_string(),
                "android.permission.ACCESS_NETWORK_STATE".to_string(),
            ]
        );

        assert_eq!(
            info.activities,
            vec![
                ".MainActivity".to_string(),
                "com.example.reversetarget.SettingsActivity".to_string(),
            ]
        );

        assert_eq!(info.services, vec![".BackgroundWorkerService".to_string()]);
        assert_eq!(info.receivers, vec![".BootReceiver".to_string()]);
        assert_eq!(info.providers, vec![".DataProvider".to_string()]);
    }

    #[test]
    fn test_parse_text_manifest_minimal() {
        let minimal_xml = r#"<manifest package="com.minimal.app" />"#;
        let info = ManifestInfo::from_xml_str(minimal_xml).expect("parse minimal");
        assert_eq!(info.package_name, "com.minimal.app");
        assert_eq!(info.version_code, None);
        assert_eq!(info.version_name, None);
        assert_eq!(info.min_sdk_version, None);
        assert_eq!(info.target_sdk_version, None);
        assert!(!info.debuggable);
        assert!(info.permissions.is_empty());
        assert!(info.activities.is_empty());
    }

    #[test]
    fn test_parse_empty_manifest_fails() {
        let res = ManifestInfo::parse(&[], false);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_binary_axml_detector() {
        assert!(!is_binary_axml(b"<?xml"));
        assert!(!is_binary_axml(b"<manifest"));
        assert!(is_binary_axml(&[0x03, 0x00, 0x08, 0x00, 0x50, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_parse_real_binary_axml_asset() {
        let sample_path = "/home/quanh/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rusty-axml-0.2.1/tests/assets/AndroidManifest.xml";
        if let Ok(bytes) = std::fs::read(sample_path) {
            let info = ManifestInfo::parse(&bytes, true).expect("Failed to parse real binary AXML asset");
            assert!(!info.package_name.is_empty(), "Package name should not be empty");
            println!("Decoded real AXML package: {}", info.package_name);
        }
    }

    #[test]
    fn test_decode_raw_manifest_empty() {
        assert!(decode_raw_manifest(&[]).is_err());
    }

    #[test]
    fn test_decode_raw_manifest_text() {
        let xml = "<manifest package=\"com.test\"><application/></manifest>";
        let res = decode_raw_manifest(xml.as_bytes()).unwrap();
        assert!(res.contains("com.test"));
    }
}
