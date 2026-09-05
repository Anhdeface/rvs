pub mod verify;
pub mod instruction;
pub mod string;
pub mod bytes;

pub use verify::{create_backup, verify_write};
pub use instruction::{patch_instruction, validate_assembly, FORBIDDEN_ASM_CHARS, PatchResult};
pub use string::patch_string;
pub use bytes::patch_bytes;
