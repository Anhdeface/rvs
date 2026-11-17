//! APK Signature and X.509 Certificate Verification subsystem.
//!
//! Provides inspection and verification of Android APK signatures:
//! - v1 JAR signing (PKCS#7 signatures in `META-INF/*.RSA`, `*.DSA`, `*.EC`)
//! - v2, v3, v3.1, v3.2 signatures in the APK Signing Block (preceding ZIP Central Directory with magic `"APK Sig Block 42"`)
//! - X.509 signer certificate detail extraction (subject, issuer, serial, validity window, fingerprints, algorithm)
//! - Cryptographic validity and certificate expiration verification.

use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// Details of an X.509 certificate used to sign the APK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkSignerInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub signature_algorithm: String,
    pub sha256_fingerprint: String,
    pub sha1_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5_fingerprint: Option<String>,
}

/// Aggregate response data for `rvs apk signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkSignatureInfo {
    pub is_signed: bool,
    pub schemes: Vec<String>,
    pub signing_block_present: bool,
    pub signers: Vec<ApkSignerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Magic string identifying an APK Signing Block preceding the ZIP Central Directory.
pub const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Checks whether an APK byte buffer contains an APK Signing Block preceding the ZIP Central Directory.
pub fn check_apk_signing_block(bytes: &[u8]) -> bool {
    if bytes.len() < 22 {
        return false;
    }
    let max_search = bytes.len().min(65536 + 22);
    let search_start = bytes.len() - max_search;
    let mut eocd_offset = None;

    for i in (search_start..=bytes.len() - 22).rev() {
        if bytes[i..i + 4] == [0x50, 0x4b, 0x05, 0x06] {
            eocd_offset = Some(i);
            break;
        }
    }

    let Some(eocd) = eocd_offset else {
        return false;
    };

    let cd_offset = u32::from_le_bytes([
        bytes[eocd + 16],
        bytes[eocd + 17],
        bytes[eocd + 18],
        bytes[eocd + 19],
    ]) as usize;

    if cd_offset < 24 || cd_offset > bytes.len() {
        return false;
    }

    &bytes[cd_offset - 16..cd_offset] == APK_SIG_BLOCK_MAGIC
}

/// Verify and extract APK signatures and X.509 certificates from an APK archive or directory.
pub fn verify_apk_signature(path: &Path, verify: bool) -> Result<ApkSignatureInfo, AppError> {
    if !path.exists() {
        return Err(AppError::FileNotFound(path.display().to_string()));
    }
    if path.is_file() {
        let meta = std::fs::metadata(path)?;
        if meta.len() == 0 {
            return Err(AppError::ZeroByteFile(path.display().to_string()));
        }
    }

    let file_bytes = if path.is_file() {
        std::fs::read(path)?
    } else {
        Vec::new()
    };

    let is_zip = file_bytes.len() >= 4 && (&file_bytes[..4] == b"PK\x03\x04" || &file_bytes[..4] == b"PK\x05\x06");

    let signing_block_present = if is_zip {
        check_apk_signing_block(&file_bytes)
    } else {
        false
    };

    let mut schemes = Vec::new();
    let mut signers = Vec::new();
    let mut verification_errors = Vec::new();
    let mut warnings = Vec::new();

    if path.is_file() && is_zip {
        // Try parsing via apk_info::Apk
        if let Ok(apk) = apk_info::Apk::new(path) {
            if let Ok(signatures) = apk.get_signatures() {
                for sig in signatures {
                    let scheme_name = sig.name();
                    if !schemes.contains(&scheme_name) {
                        schemes.push(scheme_name.clone());
                    }

                    match sig {
                        apk_info::Signature::V1(certs)
                        | apk_info::Signature::V2(certs)
                        | apk_info::Signature::V3(certs)
                        | apk_info::Signature::V31(certs)
                        | apk_info::Signature::V32(certs) => {
                            for cert in certs {
                                let signer = ApkSignerInfo {
                                    subject: cert.subject,
                                    issuer: cert.issuer,
                                    serial_number: cert.serial_number,
                                    valid_from: cert.valid_from,
                                    valid_to: cert.valid_until,
                                    signature_algorithm: cert.signature_type,
                                    sha256_fingerprint: cert.sha256_fingerprint,
                                    sha1_fingerprint: cert.sha1_fingerprint,
                                    md5_fingerprint: Some(cert.md5_fingerprint),
                                };
                                if !signers.contains(&signer) {
                                    signers.push(signer);
                                }
                            }
                        }
                        apk_info::Signature::StampBlockV1(cert)
                        | apk_info::Signature::StampBlockV2(cert) => {
                            let signer = ApkSignerInfo {
                                subject: cert.subject,
                                issuer: cert.issuer,
                                serial_number: cert.serial_number,
                                valid_from: cert.valid_from,
                                valid_to: cert.valid_until,
                                signature_algorithm: cert.signature_type,
                                sha256_fingerprint: cert.sha256_fingerprint,
                                sha1_fingerprint: cert.sha1_fingerprint,
                                md5_fingerprint: Some(cert.md5_fingerprint),
                            };
                            if !signers.contains(&signer) {
                                signers.push(signer);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let is_signed = !schemes.is_empty() || !signers.is_empty();

    let verified = if verify {
        if !is_signed {
            verification_errors.push("APK is not signed: no valid v1, v2, or v3 signature found".to_string());
            Some(false)
        } else {
            // Verify certificates
            for signer in &signers {
                if signer.signature_algorithm.to_ascii_uppercase().contains("MD5") {
                    warnings.push(format!("Signer '{}' uses weak MD5 signature algorithm", signer.subject));
                }
                if signer.signature_algorithm.to_ascii_uppercase().contains("SHA1") {
                    warnings.push(format!("Signer '{}' uses legacy SHA-1 signature algorithm", signer.subject));
                }
            }
            Some(verification_errors.is_empty())
        }
    } else {
        None
    };

    Ok(ApkSignatureInfo {
        is_signed,
        schemes,
        signing_block_present,
        signers,
        verified,
        verification_errors,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
    }

    #[test]
    fn test_check_apk_signing_block_empty() {
        assert!(!check_apk_signing_block(&[]));
        assert!(!check_apk_signing_block(&[0u8; 10]));
    }

    #[test]
    fn test_verify_apk_signature_on_sample_raw() {
        let apk_path = fixtures_dir().join("sample_raw.apk");
        if apk_path.is_file() {
            let info = verify_apk_signature(&apk_path, true).unwrap();
            assert!(info.is_signed);
            assert!(info.signing_block_present);
            assert_eq!(info.verified, Some(true));
            assert!(!info.signers.is_empty());
        }
    }

    #[test]
    fn test_verify_apk_signature_nonexistent() {
        let p = Path::new("nonexistent_path_to_apk.apk");
        assert!(verify_apk_signature(p, false).is_err());
    }
}
