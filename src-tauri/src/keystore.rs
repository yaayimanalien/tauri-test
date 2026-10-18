//! Where the data key lives for biometric ("quick") unlock.
//!   * Windows / macOS / Linux / iOS: the OS credential store (via `keyring`)
//!   * Android: a file in the app's private data dir (no keyring backend exists;
//!     protected by Android app sandboxing only)
//!
//! The biometric prompt is enforced by our code (see biometric.rs) before the
//! key is read back; the OS store is what keeps the key off disk in plain form.

use crate::crypto::Key;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::path::Path;
use zeroize::Zeroizing;

const SERVICE: &str = "com.daylight.diary";
const USER: &str = "vault-key";

fn decode(s: &str) -> Result<Key, String> {
    let raw = B64.decode(s.trim()).map_err(|e| e.to_string())?;
    if raw.len() != 32 {
        return Err("stored key is invalid".into());
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&raw);
    Ok(k)
}

#[cfg(not(target_os = "android"))]
mod imp {
    use super::*;
    fn entry() -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, USER).map_err(|e| e.to_string())
    }
    pub fn save(_dir: &Path, key: &Key) -> Result<(), String> {
        entry()?.set_password(&B64.encode(&key[..])).map_err(|e| e.to_string())
    }
    pub fn load(_dir: &Path) -> Result<Key, String> {
        decode(&entry()?.get_password().map_err(|e| e.to_string())?)
    }
    pub fn delete(_dir: &Path) {
        if let Ok(e) = entry() {
            let _ = e.delete_credential();
        }
    }
    pub fn exists(_dir: &Path) -> bool {
        entry().and_then(|e| e.get_password().map_err(|e| e.to_string())).is_ok()
    }
}

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    fn path(dir: &Path) -> std::path::PathBuf {
        dir.join("quick.key")
    }
    pub fn save(dir: &Path, key: &Key) -> Result<(), String> {
        std::fs::write(path(dir), B64.encode(&key[..])).map_err(|e| e.to_string())
    }
    pub fn load(dir: &Path) -> Result<Key, String> {
        decode(&std::fs::read_to_string(path(dir)).map_err(|e| e.to_string())?)
    }
    pub fn delete(dir: &Path) {
        let _ = std::fs::remove_file(path(dir));
    }
    pub fn exists(dir: &Path) -> bool {
        path(dir).exists()
    }
}

pub use imp::{delete, exists, load, save};
