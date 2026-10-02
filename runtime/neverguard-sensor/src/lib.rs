#![cfg(windows)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    env,
    ffi::{c_char, c_void},
    fs::OpenOptions,
    io::Write,
};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const JNI_OK: i32 = 0;
const JNI_ERR: i32 = -1;
const SENSOR_PROTOCOL_VERSION: u32 = 1;
const SENSOR_MAGIC: &[u8; 8] = b"NGSENS02";
const SENSOR_DOMAIN: &[u8] = b"neverguard-sensor-startup-v1";
const SENSOR_PIPE_ENV: &str = "NEVERGUARD_SENSOR_PIPE";
const SENSOR_SECRET_ENV: &str = "NEVERGUARD_SENSOR_SECRET";

fn startup_handshake() -> Result<(), ()> {
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

    let pid = std::process::id();
    let mut mac = HmacSha256::new_from_slice(&secret).map_err(|_| ())?;
    mac.update(SENSOR_DOMAIN);
    mac.update(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
    mac.update(&pid.to_le_bytes());
    let digest = mac.finalize().into_bytes();

    let mut packet = [0u8; 48];
    packet[..8].copy_from_slice(SENSOR_MAGIC);
    packet[8..12].copy_from_slice(&SENSOR_PROTOCOL_VERSION.to_le_bytes());
    packet[12..16].copy_from_slice(&pid.to_le_bytes());
    packet[16..].copy_from_slice(&digest);

    let result = OpenOptions::new()
        .write(true)
        .open(&pipe)
        .and_then(|mut stream| {
            stream.write_all(&packet)?;
            stream.flush()
        })
        .map_err(|_| ());

    packet.zeroize();
    secret.zeroize();
    result
}

/// JVM native-agent entry point. Returning JNI_ERR aborts VM startup before
/// Minecraft/loader main code executes, making the sensor fail closed.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Agent_OnLoad(
    _vm: *mut c_void,
    _options: *mut c_char,
    _reserved: *mut c_void,
) -> i32 {
    match startup_handshake() {
        Ok(()) => JNI_OK,
        Err(()) => JNI_ERR,
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Agent_OnUnload(_vm: *mut c_void) {}
