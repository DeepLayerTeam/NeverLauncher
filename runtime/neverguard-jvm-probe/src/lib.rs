#![cfg(windows)]

use std::{ffi::c_void, ptr, thread, time::Duration};

const JNI_VERSION_1_8: i32 = 0x0001_0008;
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation_type: u32,
        protect: u32,
    ) -> *mut c_void;
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
    // Delay до Модуль Защита имеет загружен DLL и Агрессивный Хук Движок имеет
    // согласовывать его IAT. выделение затем originates на этот fixture's собственный
    // нативный поток, так нет JVM.DLL кадр существует в VirtualAlloc вызов цепочка.
    let _ = thread::Builder::new()
        .name("neverguard-jvm-aware-probe".to_string())
        .spawn(|| {
            thread::sleep(Duration::from_millis(3200));
            let memory = unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if !memory.is_null() {
                unsafe {
                    std::ptr::write_volatile(memory.cast::<u8>(), 0xC3);
                }
            }
            thread::sleep(Duration::from_secs(10));
        });
    JNI_VERSION_1_8
}
