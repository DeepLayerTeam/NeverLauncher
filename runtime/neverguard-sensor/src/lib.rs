#![cfg(windows)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    cell::UnsafeCell,
    env,
    ffi::{c_char, c_void},
    fs::{File, OpenOptions},
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const JNI_OK: i32 = 0;
const JNI_ERR: i32 = -1;
const SENSOR_PROTOCOL_VERSION: u32 = 2;
const SENSOR_MAGIC: &[u8; 8] = b"NGSENS03";
const SENSOR_DOMAIN: &[u8] = b"neverguard-sensor-startup-v2";
const SENSOR_PIPE_ENV: &str = "NEVERGUARD_SENSOR_PIPE";
const SENSOR_SECRET_ENV: &str = "NEVERGUARD_SENSOR_SECRET";

const MODULE_GUARD_ARM_MAGIC: &[u8; 8] = b"NGARM003";
const MODULE_GUARD_ARM_DOMAIN: &[u8] = b"neverguard-module-guard-arm-v1";
const MODULE_EVENT_MAGIC: &[u8; 8] = b"NGMOD003";
const MODULE_EVENT_DOMAIN: &[u8] = b"neverguard-module-event-v1";
const MODULE_EVENT_REASON_LOADED: u32 = 1;
const MODULE_EVENT_REASON_UNLOADED: u32 = 2;
const MODULE_EVENT_REASON_HEARTBEAT: u32 = 3;
const MODULE_EVENT_REASON_OVERFLOW: u32 = 4;
const MODULE_EVENT_REASON_SHUTDOWN: u32 = 5;
const MODULE_EVENT_FLAG_PATH_TRUNCATED: u32 = 1;
const MODULE_PATH_WCHARS: usize = 2048;
const MODULE_EVENT_PREFIX_LEN: usize = 48 + MODULE_PATH_WCHARS * 2;
const MODULE_EVENT_PACKET_LEN: usize = MODULE_EVENT_PREFIX_LEN + 32;
const MODULE_RING_CAPACITY: usize = 512;
const MODULE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
const MODULE_WORKER_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct LdrDllNotificationEntry {
    flags: u32,
    full_dll_name: *const UnicodeString,
    base_dll_name: *const UnicodeString,
    dll_base: *mut c_void,
    size_of_image: u32,
}

#[repr(C)]
union LdrDllNotificationData {
    loaded: LdrDllNotificationEntry,
    unloaded: LdrDllNotificationEntry,
}

type LdrDllNotificationFunction = unsafe extern "system" fn(
    notification_reason: u32,
    notification_data: *const LdrDllNotificationData,
    context: *mut c_void,
);

#[link(name = "ntdll")]
extern "system" {
    fn LdrRegisterDllNotification(
        flags: u32,
        notification_function: LdrDllNotificationFunction,
        context: *mut c_void,
        cookie: *mut *mut c_void,
    ) -> i32;
    fn LdrUnregisterDllNotification(cookie: *mut c_void) -> i32;
}

#[derive(Clone, Copy)]
struct RawModuleEvent {
    reason: u32,
    flags: u32,
    base_address: u64,
    size_of_image: u32,
    path_len: u16,
    path: [u16; MODULE_PATH_WCHARS],
}

const EMPTY_MODULE_EVENT: RawModuleEvent = RawModuleEvent {
    reason: 0,
    flags: 0,
    base_address: 0,
    size_of_image: 0,
    path_len: 0,
    path: [0; MODULE_PATH_WCHARS],
};

struct ModuleEventSlot {
    ready: AtomicBool,
    event: UnsafeCell<RawModuleEvent>,
}

impl ModuleEventSlot {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            event: UnsafeCell::new(EMPTY_MODULE_EVENT),
        }
    }
}

// The producer side only writes a slot after reserving a unique ring index and
// publishes it with Release. The worker is the only consumer and clears slots
// after an Acquire load. Loader notifications are therefore allocation-free and
// never take a process-global lock while the Windows loader lock is held.
unsafe impl Sync for ModuleEventSlot {}

static MODULE_RING: [ModuleEventSlot; MODULE_RING_CAPACITY] =
    [const { ModuleEventSlot::new() }; MODULE_RING_CAPACITY];
static MODULE_WRITE_INDEX: AtomicU64 = AtomicU64::new(0);
static MODULE_READ_INDEX: AtomicU64 = AtomicU64::new(0);
static MODULE_DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);
static MODULE_WORKER_STOP: AtomicBool = AtomicBool::new(false);
static MODULE_NOTIFICATION_COOKIE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static MODULE_WORKER_HANDLE: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);

fn unicode_for_entry(entry: &LdrDllNotificationEntry) -> Option<UnicodeString> {
    let source = if !entry.full_dll_name.is_null() {
        entry.full_dll_name
    } else {
        entry.base_dll_name
    };
    if source.is_null() {
        None
    } else {
        // SAFETY: the structure is owned by the loader and documented as valid
        // for the duration of this notification callback.
        Some(unsafe { *source })
    }
}

fn reserve_module_slot() -> Option<u64> {
    loop {
        let write = MODULE_WRITE_INDEX.load(Ordering::Acquire);
        let read = MODULE_READ_INDEX.load(Ordering::Acquire);
        if write.wrapping_sub(read) >= MODULE_RING_CAPACITY as u64 {
            MODULE_DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if MODULE_WRITE_INDEX
            .compare_exchange_weak(write, write + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(write);
        }
    }
}

fn queue_module_event(reason: u32, entry: &LdrDllNotificationEntry) {
    let Some(write_index) = reserve_module_slot() else {
        return;
    };
    let slot = &MODULE_RING[(write_index % MODULE_RING_CAPACITY as u64) as usize];
    let mut event = EMPTY_MODULE_EVENT;
    event.reason = reason;
    event.base_address = entry.dll_base as usize as u64;
    event.size_of_image = entry.size_of_image;

    if let Some(name) = unicode_for_entry(entry) {
        if !name.buffer.is_null() && name.length > 0 {
            let available = (name.length as usize) / std::mem::size_of::<u16>();
            let to_copy = available.min(MODULE_PATH_WCHARS);
            event.path_len = to_copy as u16;
            if available > MODULE_PATH_WCHARS {
                event.flags |= MODULE_EVENT_FLAG_PATH_TRUNCATED;
            }
            // Avoid allocation, filesystem calls, synchronization primitives,
            // and calls into other modules from the loader notification.
            for index in 0..to_copy {
                // SAFETY: UNICODE_STRING.Length bounds the readable UTF-16 data
                // supplied by the Windows loader for this callback.
                event.path[index] = unsafe { *name.buffer.add(index) };
            }
        }
    }

    // SAFETY: the slot is exclusively owned by this reserved write index until
    // ready becomes true. The consumer clears ready before the ring can reuse it.
    unsafe {
        *slot.event.get() = event;
    }
    slot.ready.store(true, Ordering::Release);
}

unsafe extern "system" fn module_notification(
    notification_reason: u32,
    notification_data: *const LdrDllNotificationData,
    _context: *mut c_void,
) {
    if notification_data.is_null() {
        return;
    }
    match notification_reason {
        MODULE_EVENT_REASON_LOADED => {
            // SAFETY: the union member is selected by NotificationReason.
            let entry = unsafe { (*notification_data).loaded };
            queue_module_event(MODULE_EVENT_REASON_LOADED, &entry);
        }
        MODULE_EVENT_REASON_UNLOADED => {
            // SAFETY: the union member is selected by NotificationReason.
            let entry = unsafe { (*notification_data).unloaded };
            queue_module_event(MODULE_EVENT_REASON_UNLOADED, &entry);
        }
        _ => {}
    }
}

fn register_module_notifications() -> Result<(), ()> {
    MODULE_WORKER_STOP.store(false, Ordering::Release);
    MODULE_WRITE_INDEX.store(0, Ordering::Release);
    MODULE_READ_INDEX.store(0, Ordering::Release);
    MODULE_DROPPED_EVENTS.store(0, Ordering::Release);
    let mut cookie = std::ptr::null_mut();
    // SAFETY: callback and cookie pointers remain valid for the lifetime of the
    // loaded Sensor DLL; Flags must be zero per LdrRegisterDllNotification.
    let status = unsafe {
        LdrRegisterDllNotification(0, module_notification, std::ptr::null_mut(), &mut cookie)
    };
    if status < 0 || cookie.is_null() {
        return Err(());
    }
    MODULE_NOTIFICATION_COOKIE.store(cookie, Ordering::Release);
    Ok(())
}

fn unregister_module_notifications() {
    let cookie = MODULE_NOTIFICATION_COOKIE.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !cookie.is_null() {
        // SAFETY: cookie was returned by LdrRegisterDllNotification and is
        // exchanged exactly once before unregistration.
        unsafe {
            let _ = LdrUnregisterDllNotification(cookie);
        }
    }
}

struct SensorChannel {
    stream: File,
    secret: Vec<u8>,
    pid: u32,
}

impl Drop for SensorChannel {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

fn open_sensor_channel() -> Result<SensorChannel, ()> {
    let pipe = env::var(SENSOR_PIPE_ENV).map_err(|_| ())?;
    let mut secret_hex = env::var(SENSOR_SECRET_ENV).map_err(|_| ())?;
    if pipe.is_empty() || secret_hex.len() != 64 {
        secret_hex.zeroize();
        return Err(());
    }
    let mut secret = hex::decode(&secret_hex).map_err(|_| ())?;
    secret_hex.zeroize();
    if secret.len() != 32 {
        secret.zeroize();
        return Err(());
    }

    let result = OpenOptions::new().read(true).write(true).open(&pipe);
    env::remove_var(SENSOR_PIPE_ENV);
    env::remove_var(SENSOR_SECRET_ENV);
    let stream = match result {
        Ok(stream) => stream,
        Err(_) => {
            secret.zeroize();
            return Err(());
        }
    };
    Ok(SensorChannel {
        stream,
        secret,
        pid: std::process::id(),
    })
}

fn startup_handshake(channel: &mut SensorChannel) -> Result<(), ()> {
    let mut mac = HmacSha256::new_from_slice(&channel.secret).map_err(|_| ())?;
    mac.update(SENSOR_DOMAIN);
    mac.update(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
    mac.update(&channel.pid.to_le_bytes());
    let digest = mac.finalize().into_bytes();

    let mut packet = [0u8; 48];
    packet[..8].copy_from_slice(SENSOR_MAGIC);
    packet[8..12].copy_from_slice(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
    packet[12..16].copy_from_slice(&channel.pid.to_le_bytes());
    packet[16..].copy_from_slice(&digest);

    let result = channel
        .stream
        .write_all(&packet)
        .and_then(|_| channel.stream.flush())
        .map_err(|_| ());
    packet.zeroize();
    result
}

fn wait_for_module_guard_arm(channel: &mut SensorChannel) -> Result<(), ()> {
    let mut packet = [0u8; 48];
    channel.stream.read_exact(&mut packet).map_err(|_| ())?;
    if &packet[..8] != MODULE_GUARD_ARM_MAGIC {
        packet.zeroize();
        return Err(());
    }
    let protocol = u32::from_le_bytes(packet[8..12].try_into().map_err(|_| ())?);
    let pid = u32::from_le_bytes(packet[12..16].try_into().map_err(|_| ())?);
    if protocol != SENSOR_PROTOCOL_VERSION || pid != channel.pid {
        packet.zeroize();
        return Err(());
    }
    let mut mac = HmacSha256::new_from_slice(&channel.secret).map_err(|_| ())?;
    mac.update(MODULE_GUARD_ARM_DOMAIN);
    mac.update(&protocol.to_le_bytes());
    mac.update(&pid.to_le_bytes());
    mac.verify_slice(&packet[16..]).map_err(|_| ())?;
    packet.zeroize();
    Ok(())
}

fn encode_module_packet(
    packet: &mut [u8; MODULE_EVENT_PACKET_LEN],
    secret: &[u8],
    pid: u32,
    sequence: u64,
    event: &RawModuleEvent,
) -> Result<(), ()> {
    packet.fill(0);
    packet[..8].copy_from_slice(MODULE_EVENT_MAGIC);
    packet[8..12].copy_from_slice(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
    packet[12..16].copy_from_slice(&pid.to_le_bytes());
    packet[16..24].copy_from_slice(&sequence.to_le_bytes());
    packet[24..28].copy_from_slice(&event.reason.to_le_bytes());
    packet[28..32].copy_from_slice(&event.flags.to_le_bytes());
    packet[32..40].copy_from_slice(&event.base_address.to_le_bytes());
    packet[40..44].copy_from_slice(&event.size_of_image.to_le_bytes());
    packet[44..46].copy_from_slice(&event.path_len.to_le_bytes());
    for (index, value) in event.path[..event.path_len as usize].iter().enumerate() {
        let offset = 48 + index * 2;
        packet[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| ())?;
    mac.update(MODULE_EVENT_DOMAIN);
    mac.update(&packet[..MODULE_EVENT_PREFIX_LEN]);
    let digest = mac.finalize().into_bytes();
    packet[MODULE_EVENT_PREFIX_LEN..].copy_from_slice(&digest);
    Ok(())
}

fn write_module_event(
    stream: &mut File,
    secret: &[u8],
    pid: u32,
    sequence: &mut u64,
    event: &RawModuleEvent,
) -> Result<(), ()> {
    *sequence = sequence.checked_add(1).ok_or(())?;
    let mut packet = [0u8; MODULE_EVENT_PACKET_LEN];
    encode_module_packet(&mut packet, secret, pid, *sequence, event)?;
    let result = stream
        .write_all(&packet)
        .and_then(|_| stream.flush())
        .map_err(|_| ());
    packet.zeroize();
    result
}

fn module_worker(mut channel: SensorChannel) {
    let mut sequence = 0u64;
    let mut heartbeat_at = Instant::now();
    loop {
        let dropped = MODULE_DROPPED_EVENTS.swap(0, Ordering::AcqRel);
        if dropped > 0 {
            let overflow = RawModuleEvent {
                reason: MODULE_EVENT_REASON_OVERFLOW,
                flags: dropped.min(u32::MAX as u64) as u32,
                base_address: dropped,
                ..EMPTY_MODULE_EVENT
            };
            if write_module_event(
                &mut channel.stream,
                &channel.secret,
                channel.pid,
                &mut sequence,
                &overflow,
            )
            .is_err()
            {
                channel.secret.zeroize();
                std::process::abort();
            }
        }

        loop {
            let read = MODULE_READ_INDEX.load(Ordering::Acquire);
            let write = MODULE_WRITE_INDEX.load(Ordering::Acquire);
            if read >= write {
                break;
            }
            let slot = &MODULE_RING[(read % MODULE_RING_CAPACITY as u64) as usize];
            if !slot.ready.load(Ordering::Acquire) {
                break;
            }
            // SAFETY: ready=true publishes a completely initialized Copy value
            // and this worker is the single consumer for the ring.
            let event = unsafe { *slot.event.get() };
            slot.ready.store(false, Ordering::Release);
            MODULE_READ_INDEX.store(read + 1, Ordering::Release);
            if write_module_event(
                &mut channel.stream,
                &channel.secret,
                channel.pid,
                &mut sequence,
                &event,
            )
            .is_err()
            {
                channel.secret.zeroize();
                std::process::abort();
            }
        }

        if MODULE_WORKER_STOP.load(Ordering::Acquire) {
            let shutdown = RawModuleEvent {
                reason: MODULE_EVENT_REASON_SHUTDOWN,
                ..EMPTY_MODULE_EVENT
            };
            if write_module_event(
                &mut channel.stream,
                &channel.secret,
                channel.pid,
                &mut sequence,
                &shutdown,
            )
            .is_err()
            {
                channel.secret.zeroize();
                std::process::abort();
            }
            break;
        }
        if heartbeat_at.elapsed() >= MODULE_HEARTBEAT_INTERVAL {
            let heartbeat = RawModuleEvent {
                reason: MODULE_EVENT_REASON_HEARTBEAT,
                ..EMPTY_MODULE_EVENT
            };
            if write_module_event(
                &mut channel.stream,
                &channel.secret,
                channel.pid,
                &mut sequence,
                &heartbeat,
            )
            .is_err()
            {
                channel.secret.zeroize();
                std::process::abort();
            }
            heartbeat_at = Instant::now();
        }
        thread::sleep(MODULE_WORKER_POLL_INTERVAL);
    }
    channel.secret.zeroize();
}

/// JVM native-agent entry point. Module notification is registered before the
/// startup proof is accepted. The JVM remains inside Agent_OnLoad until the
/// parent authenticates the Sensor, captures a baseline and returns a signed
/// Module Guard arm acknowledgement. Any failure aborts VM startup.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Agent_OnLoad(
    _vm: *mut c_void,
    _options: *mut c_char,
    _reserved: *mut c_void,
) -> i32 {
    let mut channel = match open_sensor_channel() {
        Ok(channel) => channel,
        Err(()) => return JNI_ERR,
    };
    if register_module_notifications().is_err() {
        channel.secret.zeroize();
        return JNI_ERR;
    }
    if startup_handshake(&mut channel).is_err() || wait_for_module_guard_arm(&mut channel).is_err() {
        unregister_module_notifications();
        channel.secret.zeroize();
        return JNI_ERR;
    }
    match thread::Builder::new()
        .name("neverguard-module-guard".to_string())
        .spawn(move || module_worker(channel))
    {
        Ok(handle) => match MODULE_WORKER_HANDLE.lock() {
            Ok(mut slot) => {
                *slot = Some(handle);
                JNI_OK
            }
            Err(_) => {
                MODULE_WORKER_STOP.store(true, Ordering::Release);
                let _ = handle.join();
                unregister_module_notifications();
                JNI_ERR
            }
        },
        Err(_) => {
            unregister_module_notifications();
            JNI_ERR
        }
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Agent_OnUnload(_vm: *mut c_void) {
    MODULE_WORKER_STOP.store(true, Ordering::Release);
    unregister_module_notifications();
    let handle = MODULE_WORKER_HANDLE
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}
