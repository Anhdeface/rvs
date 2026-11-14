#![no_std]
#![allow(non_snake_case)]

use core::arch::asm;

static APP_NAME: &[u8; 14] = b"RvsAArch64Demo";
static SECRET_KEY: &[u8; 20] = b"SECRET_KEY_AARCH64_!";
static AUTH_SUCCESS_MSG: &[u8; 18] = b"AUTH_GRANTED_2026\0";

#[no_mangle]
pub extern "C" fn helper_add(a: i32, b: i32) -> i32 {
    a + b
}

#[no_mangle]
pub extern "C" fn helper_multiply(a: i32, b: i32) -> i32 {
    a * b
}

/// JNI static export: returns pointer to SECRET_KEY using ADRP + LDR / ADRP + ADD
#[no_mangle]
pub extern "C" fn Java_com_example_app_MainActivity_stringFromJNI() -> *const u8 {
    SECRET_KEY.as_ptr()
}

/// JNI static export: returns app name pointer
#[no_mangle]
pub extern "C" fn Java_com_example_app_MainActivity_getAppName() -> *const u8 {
    APP_NAME.as_ptr()
}

/// AArch64 decision gate with `cmp` and `b.ne` suitable for NOP sled or branch inversion patching
#[no_mangle]
pub extern "C" fn auth_gate_check(key: i32) -> i32 {
    let res: i32;
    unsafe {
        asm!(
            "cmp {0:w}, #1337",
            "b.ne 1f",
            "mov {1:w}, #1",
            "b 2f",
            "1:",
            "mov {1:w}, #0",
            "2:",
            in(reg) key,
            out(reg) res,
        );
    }
    res
}

/// Function exercising AArch64 `cbz` and `cbnz` branches plus `bl` calls
#[no_mangle]
pub extern "C" fn check_zero_and_call(val: i32) -> i32 {
    let mut status: i32;
    unsafe {
        asm!(
            "cbz {0:w}, 1f",
            "cbnz {0:w}, 2f",
            "1:",
            "mov w8, #0",
            "b 3f",
            "2:",
            "bl helper_add",
            "mov w8, w0",
            "3:",
            in(reg) val,
            out("w8") status,
            clobber_abi("C"),
        );
    }
    status
}

/// Function exercising AArch64 `tbz` and `tbnz` bit test branches
#[no_mangle]
pub extern "C" fn check_bit_flags(flags: u32) -> i32 {
    let res: i32;
    unsafe {
        asm!(
            "tbz {0:w}, #0, 1f",
            "tbnz {0:w}, #1, 2f",
            "mov {1:w}, #10",
            "b 3f",
            "1:",
            "mov {1:w}, #20",
            "b 3f",
            "2:",
            "mov {1:w}, #30",
            "3:",
            in(reg) flags,
            out(reg) res,
        );
    }
    res
}

/// Function exercising indirect call via `blr` register
#[no_mangle]
pub extern "C" fn dispatch_call_indirect(target_fn: extern "C" fn(i32, i32) -> i32, a: i32, b: i32) -> i32 {
    let res: i32;
    unsafe {
        asm!(
            "blr {0}",
            in(reg) target_fn,
            in("w0") a,
            in("w1") b,
            lateout("w0") res,
            clobber_abi("C"),
        );
    }
    res
}

/// JNI validation function exercising multi-branch decision gates and calls
#[no_mangle]
pub extern "C" fn Java_com_example_app_MainActivity_validateLicense(code: i32) -> i32 {
    let status: i32;
    unsafe {
        asm!(
            "cbz {0:w}, 1f",
            "bl helper_multiply",
            "cmp w0, #100",
            "b.gt 2f",
            "1:",
            "mov w8, #0",
            "b 3f",
            "2:",
            "mov w8, #1",
            "3:",
            in(reg) code,
            out("w8") status,
            clobber_abi("C"),
        );
    }
    status
}

/// Standard JNI initialization hook
#[no_mangle]
pub extern "C" fn JNI_OnLoad(_vm: *const (), _reserved: *const ()) -> i32 {
    0x00010006 // JNI_VERSION_1_6
}

/// Crackme unlocker string pointer for verification
#[no_mangle]
pub extern "C" fn get_success_message() -> *const u8 {
    AUTH_SUCCESS_MSG.as_ptr()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
