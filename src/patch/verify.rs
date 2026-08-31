use std::path::{Path, PathBuf};
use crate::r2::R2Driver;
use crate::response::AppError;

/// Creates a `.bak` backup copy of the target binary file.
pub fn create_backup(binary_path: &Path) -> Result<PathBuf, AppError> {
    let mut backup_path = binary_path.to_path_buf();
    let file_name = backup_path
        .file_name()
        .map(|f| format!("{}.bak", f.to_string_lossy()))
        .unwrap_or_else(|| "backup.bak".to_string());
    backup_path.set_file_name(file_name);

    std::fs::copy(binary_path, &backup_path).map_err(|e| {
        AppError::BackupFailed(format!("{}: {}", backup_path.display(), e))
    })?;

    Ok(backup_path)
}

/// Verifies that the bytes on disk at `addr_hex` match `expected_hex`.
pub fn verify_write(
    driver: &R2Driver,
    addr_hex: &str,
    expected_hex: &str,
) -> Result<(), AppError> {
    let byte_len = expected_hex.len() / 2;
    let actual_hex = driver.read_bytes_hex(addr_hex, byte_len)?;

    if actual_hex.to_lowercase() != expected_hex.to_lowercase() {
        return Err(AppError::VerificationFailed {
            address: addr_hex.to_string(),
            expected: expected_hex.to_lowercase(),
            actual: actual_hex.to_lowercase(),
        });
    }

    Ok(())
}
