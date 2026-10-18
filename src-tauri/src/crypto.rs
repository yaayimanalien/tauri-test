//! Vault crypto. No Tauri dependencies so it can be tested on its own.
//!
//! * A random 256-bit data key (DEK) encrypts everything (local vault + Drive blobs).
//! * The DEK is wrapped by a key derived from the password with Argon2id.
//!   Changing the password only re-wraps the DEK; nothing else is re-encrypted.
//! * Cipher: XChaCha20-Poly1305 (random 24-byte nonce, prepended to the ciphertext).

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;

const WRAP_AAD: &[u8] = b"daylight-wrap-v1";
pub const VAULT_AAD: &[u8] = b"daylight-vault-v1";

/// Not secret. Stored next to the vault and uploaded to Drive so a new device
/// can restore with just the password.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Header {
    pub v: u8,
    pub salt: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub wrapped_key: String, // base64(nonce || ciphertext) of the DEK
}

pub fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *k);
    k
}

fn kek(password: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Key, String> {
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|e| e.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(out)
}

pub fn open(key: &Key, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 24 + 16 {
        return Err("data is too short".into());
    }
    let (nonce, ct) = blob.split_at(24);
    XChaCha20Poly1305::new(key.as_slice().into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| "wrong key or corrupted data".to_string())
}

/// Make a brand-new DEK protected by `password`.
pub fn create(password: &str) -> Result<(Header, Key), String> {
    let dek = random_key();
    let header = wrap(&dek, password)?;
    Ok((header, dek))
}

/// Wrap an existing DEK with a (new) password. Fresh salt each time.
pub fn wrap(dek: &Key, password: &str) -> Result<Header, String> {
    let (m_kib, t, p) = (64 * 1024, 3, 1);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let k = kek(password, &salt, m_kib, t, p)?;
    let wrapped = seal(&k, &dek[..], WRAP_AAD)?;
    Ok(Header {
        v: 1,
        salt: B64.encode(salt),
        m_kib,
        t,
        p,
        wrapped_key: B64.encode(wrapped),
    })
}

pub fn unwrap(header: &Header, password: &str) -> Result<Key, String> {
    if header.v != 1 {
        return Err("unsupported vault version".into());
    }
    // Refuse absurd parameters from a tampered header (memory-exhaustion guard).
    if header.m_kib > 1024 * 1024 || header.t > 16 || header.p > 16 {
        return Err("unsupported key settings".into());
    }
    let salt = B64.decode(&header.salt).map_err(|e| e.to_string())?;
    let wrapped = B64.decode(&header.wrapped_key).map_err(|e| e.to_string())?;
    let k = kek(password, &salt, header.m_kib, header.t, header.p)?;
    let raw = open(&k, &wrapped, WRAP_AAD).map_err(|_| "Wrong password".to_string())?;
    let mut dek = Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        return Err("corrupted key".into());
    }
    dek.copy_from_slice(&raw);
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let (h, dek) = create("correct horse").unwrap();
        let again = unwrap(&h, "correct horse").unwrap();
        assert_eq!(&dek[..], &again[..]);
        assert_eq!(unwrap(&h, "nope").unwrap_err(), "Wrong password");
    }

    #[test]
    fn password_change_keeps_data_key() {
        let (_, dek) = create("one").unwrap();
        let h2 = wrap(&dek, "two").unwrap();
        assert_eq!(&unwrap(&h2, "two").unwrap()[..], &dek[..]);
        assert!(unwrap(&h2, "one").is_err());
    }

    #[test]
    fn seal_open_and_tamper() {
        let k = random_key();
        let blob = seal(&k, b"dear diary", b"aad").unwrap();
        assert_eq!(open(&k, &blob, b"aad").unwrap(), b"dear diary");
        assert!(open(&k, &blob, b"other-aad").is_err());
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&k, &bad, b"aad").is_err());
    }
}
