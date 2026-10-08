use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    fs::File,
    io::Read,
    os::windows::io::AsRawHandle,
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

use super::{RawModuleEvent, EMPTY_MODULE_EVENT, MODULE_PATH_WCHARS};

type HmacSha256 = Hmac<Sha256>;

pub const CONTINUOUS_GUARD_VERSION: u32 = 1;
const CONTINUOUS_GUARD_ACK_MAGIC: &[u8; 8] = b"NGCGAK01";
const CONTINUOUS_GUARD_ACK_DOMAIN: &[u8] = b"neverguard-continuous-guard-ack-v1";
const CONTINUOUS_GUARD_ACK_PREFIX_LEN: usize = 64;
const CONTINUOUS_GUARD_ACK_PACKET_LEN: usize = 96;
const GUARD_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const GUARD_ACK_POLL: Duration = Duration::from_millis(10);

static SENSOR_EVENT_CHAIN: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);

#[link(name = "kernel32")]
extern "system" {
    fn PeekNamedPipe(
        named_pipe: *mut c_void,
        buffer: *mut c_void,
        buffer_size: u32,
        bytes_read: *mut u32,
        total_bytes_available: *mut u32,
        bytes_left_this_message: *mut u32,
    ) -> i32;
}

pub fn reset_event_chain() -> Result<(), String> {
    let mut chain = SENSOR_EVENT_CHAIN
        .lock()
        .map_err(|_| "Continuous Guard event-chain lock poisoned".to_string())?;
    chain.fill(0);
    Ok(())
}

pub fn current_event_chain() -> Result<[u8; 32], String> {
    SENSOR_EVENT_CHAIN
        .lock()
        .map(|chain| *chain)
        .map_err(|_| "Continuous Guard event-chain lock poisoned".to_string())
}

pub fn advance_event_chain(packet: &[u8]) -> Result<[u8; 32], String> {
    let mut chain = SENSOR_EVENT_CHAIN
        .lock()
        .map_err(|_| "Continuous Guard event-chain lock poisoned".to_string())?;
    let mut digest = Sha256::new();
    digest.update(b"NeverLauncher Continuous Guard sensor-event-chain v1\0");
    digest.update(*chain);
    digest.update((packet.len() as u32).to_le_bytes());
    digest.update(packet);
    let output = digest.finalize();
    chain.copy_from_slice(&output);
    Ok(*chain)
}

pub fn cross_check_event(reason: u32, last_guard_sequence: u64) -> Result<RawModuleEvent, String> {
    let chain = current_event_chain()?;
    let encoded = hex::encode(chain);
    let wide = encoded.encode_utf16().collect::<Vec<_>>();
    if wide.len() > MODULE_PATH_WCHARS {
        return Err("Continuous Guard digest exceeds event payload capacity".to_string());
    }
    let mut event = RawModuleEvent {
        reason,
        flags: CONTINUOUS_GUARD_VERSION,
        base_address: last_guard_sequence,
        size_of_image: 0,
        ..EMPTY_MODULE_EVENT
    };
    event.path_len = wide.len() as u16;
    event.path[..wide.len()].copy_from_slice(&wide);
    Ok(event)
}

pub fn tamper_event(reason: u32, detail: &str) -> RawModuleEvent {
    let mut event = RawModuleEvent {
        reason,
        ..EMPTY_MODULE_EVENT
    };
    let wide = detail.encode_utf16().collect::<Vec<_>>();
    let to_copy = wide.len().min(MODULE_PATH_WCHARS);
    event.path_len = to_copy as u16;
    event.path[..to_copy].copy_from_slice(&wide[..to_copy]);
    event
}

pub fn wait_for_guard_ack(
    stream: &mut File,
    secret: &[u8],
    pid: u32,
    expected_guard_sequence: u64,
    expected_sensor_sequence: u64,
    expected_chain: [u8; 32],
) -> Result<(), String> {
    let deadline = Instant::now() + GUARD_ACK_TIMEOUT;
    loop {
        let mut available = 0u32;
        // SAFETY: дескриптор comes из открытый duplex именованный pipe Файл. Все
        // необязательный PeekNamedPipe вывод pointers except total availability являются
        // намеренно null потому что нет байты являются использованный через этот probe.
        let ok = unsafe {
            PeekNamedPipe(
                stream.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "Непрерывный Защита Guard-ACK pipe probe ошибка: {}",
                std::io::Error::last_os_error()
            ));
        }
        if available as usize >= CONTINUOUS_GUARD_ACK_PACKET_LEN {
            break;
        }
        if Instant::now() >= deadline {
            return Err("Continuous Guard Guard-ACK heartbeat timeout".to_string());
        }
        thread::sleep(GUARD_ACK_POLL);
    }

    let mut packet = [0u8; CONTINUOUS_GUARD_ACK_PACKET_LEN];
    stream
        .read_exact(&mut packet)
        .map_err(|err| format!("Непрерывный Защита Guard-ACK чтение ошибка: {err}"))?;
    let result = verify_guard_ack_packet(
        &packet,
        secret,
        pid,
        expected_guard_sequence,
        expected_sensor_sequence,
        expected_chain,
    );
    packet.zeroize();
    result
}

fn verify_guard_ack_packet(
    packet: &[u8; CONTINUOUS_GUARD_ACK_PACKET_LEN],
    secret: &[u8],
    pid: u32,
    expected_guard_sequence: u64,
    expected_sensor_sequence: u64,
    expected_chain: [u8; 32],
) -> Result<(), String> {
    if &packet[..8] != CONTINUOUS_GUARD_ACK_MAGIC {
        return Err("Continuous Guard Guard-ACK magic mismatch".to_string());
    }
    let version = u32::from_le_bytes(packet[8..12].try_into().expect("fixed ACK packet"));
    let packet_pid = u32::from_le_bytes(packet[12..16].try_into().expect("fixed ACK packet"));
    let guard_sequence = u64::from_le_bytes(packet[16..24].try_into().expect("fixed ACK packet"));
    let sensor_sequence = u64::from_le_bytes(packet[24..32].try_into().expect("fixed ACK packet"));
    if version != CONTINUOUS_GUARD_VERSION || packet_pid != pid {
        return Err("Continuous Guard Guard-ACK version/PID mismatch".to_string());
    }
    if guard_sequence != expected_guard_sequence {
        return Err(format!(
            "Непрерывный Защита Guard-ACK последовательность несоответствие: ожидаемый {expected_guard_sequence}, получил {guard_sequence}"
        ));
    }
    if sensor_sequence != expected_sensor_sequence {
        return Err(format!(
            "Непрерывный Защита Guard-ACK sensor последовательность несоответствие: ожидаемый {expected_sensor_sequence}, получил {sensor_sequence}"
        ));
    }
    if packet[32..64] != expected_chain[..] {
        return Err("Continuous Guard Guard-ACK event-chain mismatch".to_string());
    }
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| "Continuous Guard Guard-ACK HMAC initialization failed".to_string())?;
    mac.update(CONTINUOUS_GUARD_ACK_DOMAIN);
    mac.update(&packet[..CONTINUOUS_GUARD_ACK_PREFIX_LEN]);
    mac.verify_slice(&packet[CONTINUOUS_GUARD_ACK_PREFIX_LEN..])
        .map_err(|_| "Continuous Guard Guard-ACK HMAC mismatch".to_string())
}
