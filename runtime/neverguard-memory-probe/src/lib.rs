#![cfg(windows)]

use std::{ffi::c_void, thread, time::Duration};

const JNI_VERSION_1_6: i32 = 0x0001_0006;
const JNI_ERR: i32 = -1;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn VirtualProtect(address: *mut c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32;
    fn FlushInstructionCache(process: *mut c_void, address: *const c_void, size: usize) -> i32;
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn neverguard_memory_probe_target() -> u32 {
    0x4E47_4D49
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    // Delay until NeverGuard has observed and baselined this newly loaded image.
    // The fixture then mutates its own unused exported code byte and restores the
    // original page protection. Memory Integrity must still detect the content
    // drift on its next executable-image hash pass and fail closed.
    let spawned = thread::Builder::new()
        .name("neverguard-memory-tamper-probe".to_string())
        .spawn(|| {
            thread::sleep(Duration::from_millis(3200));
            let target = neverguard_memory_probe_target as *mut c_void;
            let mut old_protect = 0u32;
            if unsafe { VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) } == 0 {
                return;
            }
            unsafe {
                let byte = target.cast::<u8>();
                std::ptr::write_volatile(byte, std::ptr::read_volatile(byte) ^ 0x01);
            }
            let mut ignored = 0u32;
            unsafe {
                let _ = VirtualProtect(target, 1, old_protect, &mut ignored);
                let _ = FlushInstructionCache(GetCurrentProcess(), target as *const c_void, 1);
            }
        });
    if spawned.is_err() {
        return JNI_ERR;
    }
    JNI_VERSION_1_6
}
