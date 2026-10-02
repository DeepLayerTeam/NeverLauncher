#![cfg(windows)]

use std::{env, process, time::{Duration, Instant}};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    WaitForDebugEvent, DEBUG_EVENT, DBG_CONTINUE, EXIT_PROCESS_DEBUG_EVENT,
};

fn main() {
    let pid = env::args()
        .nth(1)
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| process::exit(64));

    if unsafe { DebugActiveProcess(pid) } == 0 {
        process::exit(2);
    }
    unsafe {
        let _ = DebugSetProcessKillOnExit(0);
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_exit = false;
    while Instant::now() < deadline {
        let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        if unsafe { WaitForDebugEvent(&mut event, 250) } == 0 {
            continue;
        }
        let code = event.dwDebugEventCode;
        let event_pid = event.dwProcessId;
        let thread_id = event.dwThreadId;
        unsafe {
            let _ = ContinueDebugEvent(event_pid, thread_id, DBG_CONTINUE);
        }
        if code == EXIT_PROCESS_DEBUG_EVENT {
            saw_exit = true;
            break;
        }
    }

    if !saw_exit {
        unsafe {
            let _ = DebugActiveProcessStop(pid);
        }
    }
}
