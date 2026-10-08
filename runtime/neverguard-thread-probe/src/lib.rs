#![cfg(windows)]

use std::{ffi::c_void, ptr, thread, time::Duration};

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(address: *mut c_void, size: usize, allocation_type: u32, protect: u32) -> *mut c_void;
    fn CreateThread(
        attributes: *const c_void,
        stack_size: usize,
        start_address: *const c_void,
        parameter: *mut c_void,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

unsafe fn create_private_executable_thread() {
    #[cfg(target_arch = "x86_64")]
    const LOOP_CODE: &[u8] = &[0xEB, 0xFE]; // jmp $
    #[cfg(target_arch = "aarch64")]
    const LOOP_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x14]; // b .
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const LOOP_CODE: &[u8] = &[];

    if LOOP_CODE.is_empty() {
        return;
    }
    let code = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if code.is_null() {
        return;
    }
    unsafe {
        ptr::copy_nonoverlapping(LOOP_CODE.as_ptr(), code as *mut u8, LOOP_CODE.len());
    }
    let handle = unsafe {
        CreateThread(
            ptr::null(),
            0,
            code as *const c_void,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    if !handle.is_null() {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    // Delay until Module Guard/Hook Engine have reconciled this newly loaded DLL.
    // The later VirtualAlloc therefore has legitimate Memory Integrity provenance;
    // the violation is specifically the thread start address in MEM_PRIVATE code.
    let _ = thread::Builder::new()
        .name("neverguard-thread-probe".to_string())
        .spawn(|| {
            thread::sleep(Duration::from_secs(3));
            unsafe { create_private_executable_thread() };
            thread::sleep(Duration::from_secs(10));
        });
    0x0001_0008 // JNI_VERSION_1_8
}
