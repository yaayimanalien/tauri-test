//! Google Drive backup. No Tauri dependencies.
//!
//! * Uses the `drive.appdata` scope only: the app sees its own hidden folder and
//!   nothing else in the user's Drive.
//! * OAuth 2.0 "installed app" flow with PKCE over a loopback redirect.
//! * Every remote file carries a content stamp (`h`) and a last-changed time (`u`)
//!   in `appProperties`, so a sync can compare without downloading anything.
//!   The merge logic itself lives in `sync.rs`; this file is just Drive I/O.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
const UPLOAD_URL: &str = "https://www.googleapis.com/upload/drive/v3/files";
const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DriveCfg {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
}

#[derive(Debug, Clone)]
pub struct Remote {
    pub id: String,
    pub name: String,
    pub stamp: Option<String>,
    /// Last-changed time (unix seconds) recorded by the device that uploaded it; 0 if unknown.
    pub updated: i64,
}

/// Full error text including the underlying cause (DNS, TLS, timeout...),
/// which reqwest hides behind a generic "error sending request" message.
fn err_chain(e: impl std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        out.push_str(": ");
        out.push_str(&c.to_string());
        src = c.source();
    }
    out
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(err_chain)
}

pub fn stamp_of(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p.as_bytes());
    }
    h.finalize().iter().take(12).map(|b| format!("{b:02x}")).collect()
}

fn rand_url_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    B64URL.encode(b)
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Runs the browser consent flow and returns a refresh token.
/// `open_browser` is given the consent URL.
pub async fn authorize(
    client_id: &str,
    client_secret: &str,
    open_browser: impl FnOnce(&str) -> Result<(), String>,
) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(err_chain)?;
    let port = listener.local_addr().map_err(err_chain)?.port();
    let redirect = format!("http://127.0.0.1:{port}");

    let verifier = rand_url_token(48);
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    let state = rand_url_token(16);

    let url = format!(
        "{AUTH_URL}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent&code_challenge={}&code_challenge_method=S256&state={}",
        enc(client_id), enc(&redirect), enc(SCOPE), challenge, state
    );
    open_browser(&url)?;

    let wait = async {
        loop {
            let (mut sock, _) = listener.accept().await.map_err(err_chain)?;
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.map_err(err_chain)?;
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let line = req.lines().next().unwrap_or("");
            let path = line.split_whitespace().nth(1).unwrap_or("");
            let query = path.split_once('?').map(|x| x.1).unwrap_or("");
            let mut code = None;
            let mut got_state = None;
            let mut error = None;
            for kv in query.split('&') {
                if let Some((k, v)) = kv.split_once('=') {
                    match k {
                        "code" => code = Some(dec(v)),
                        "state" => got_state = Some(dec(v)),
                        "error" => error = Some(dec(v)),
                        _ => {}
                    }
                }
            }
            // Ignore stray requests (favicon etc.) that carry no result.
            if code.is_none() && error.is_none() {
                let _ = sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                continue;
            }
            let ok = error.is_none() && got_state.as_deref() == Some(state.as_str());
            let body = if ok {
                "<html><body style='font-family:-apple-system,Segoe UI,sans-serif;background:#000;color:#fff;text-align:center;padding-top:20vh'><h2>Daylight is connected</h2><p>You can close this tab.</p></body></html>"
            } else {
                "<html><body style='font-family:-apple-system,Segoe UI,sans-serif;background:#000;color:#fff;text-align:center;padding-top:20vh'><h2>Connection failed</h2><p>Go back to Daylight and try again.</p></body></html>"
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            if let Some(e) = error {
                return Err(format!("Google returned: {e}"));
            }
            if !ok {
                return Err("State mismatch, aborting".to_string());
            }
            return Ok::<String, String>(code.unwrap());
        }
    };
    let code = tokio::time::timeout(Duration::from_secs(180), wait)
        .await
        .map_err(|_| "Timed out waiting for Google sign-in".to_string())??;

    #[derive(Deserialize)]
    struct Tok {
        refresh_token: Option<String>,
    }
    let resp = client()?
        .post(TOKEN_URL)
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .map_err(err_chain)?;
    if !resp.status().is_success() {
        return Err(format!("Token exchange failed ({})", resp.status()));
    }
    let tok: Tok = resp.json().await.map_err(err_chain)?;
    tok.refresh_token
        .ok_or_else(|| "Google did not return a refresh token".to_string())
}

pub async fn access_token(cfg: &DriveCfg) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Tok {
        access_token: String,
    }
    let resp = client()?
        .post(TOKEN_URL)
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("refresh_token", cfg.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(err_chain)?;
    if !resp.status().is_success() {
        return Err(format!("Google sign-in expired ({}). Reconnect Drive in Settings.", resp.status()));
    }
    Ok(resp.json::<Tok>().await.map_err(err_chain)?.access_token)
}

pub async fn list_remote(token: &str) -> Result<Vec<Remote>, String> {
    #[derive(Deserialize)]
    struct F {
        id: String,
        name: String,
        #[serde(rename = "appProperties")]
        app_properties: Option<HashMap<String, String>>,
    }
    #[derive(Deserialize)]
    struct L {
        files: Vec<F>,
        #[serde(rename = "nextPageToken")]
        next: Option<String>,
    }
    let c = client()?;
    let mut out = Vec::new();
    let mut page: Option<String> = None;
    loop {
        let mut q = vec![
            ("spaces", "appDataFolder".to_string()),
            ("pageSize", "1000".to_string()),
            ("fields", "nextPageToken,files(id,name,appProperties)".to_string()),
        ];
        if let Some(p) = &page {
            q.push(("pageToken", p.clone()));
        }
        let resp = c.get(FILES_URL).bearer_auth(token).query(&q).send().await.map_err(err_chain)?;
        if !resp.status().is_success() {
            return Err(format!("Drive list failed ({})", resp.status()));
        }
        let l: L = resp.json().await.map_err(err_chain)?;
        for f in l.files {
            out.push(Remote {
                id: f.id,
                name: f.name,
                stamp: f.app_properties.as_ref().and_then(|m| m.get("h").cloned()),
                updated: f
                    .app_properties
                    .as_ref()
                    .and_then(|m| m.get("u"))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            });
        }
        match l.next {
            Some(n) => page = Some(n),
            None => break,
        }
    }
    Ok(out)
}

pub async fn upload(
    token: &str,
    existing: Option<&str>,
    name: &str,
    stamp: &str,
    updated: i64,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let mut meta = serde_json::json!({
        "name": name,
        "appProperties": { "h": stamp, "u": updated.to_string() }
    });
    if existing.is_none() {
        meta["parents"] = serde_json::json!(["appDataFolder"]);
    }
    let boundary = format!("daylight{}", rand_url_token(12).replace(['-', '_'], "x"));
    let mut body: Vec<u8> = Vec::new();
    body.extend(format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{meta}\r\n").as_bytes());
    body.extend(format!("--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
    body.extend(bytes);
    body.extend(format!("\r\n--{boundary}--").as_bytes());

    let c = client()?;
    let req = match existing {
        Some(id) => c.patch(format!("{UPLOAD_URL}/{id}")),
        None => c.post(UPLOAD_URL),
    };
    let resp = req
        .bearer_auth(token)
        .query(&[("uploadType", "multipart")])
        .header("Content-Type", format!("multipart/related; boundary={boundary}"))
        .body(body)
        .send()
        .await
        .map_err(err_chain)?;
    if !resp.status().is_success() {
        return Err(format!("Drive upload failed ({})", resp.status()));
    }
    Ok(())
}

pub async fn delete_remote(token: &str, id: &str) -> Result<(), String> {
    let resp = client()?
        .delete(format!("{FILES_URL}/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(err_chain)?;
    if !resp.status().is_success() && resp.status().as_u16() != 404 {
        return Err(format!("Drive delete failed ({})", resp.status()));
    }
    Ok(())
}

pub async fn download(token: &str, id: &str) -> Result<Vec<u8>, String> {
    let resp = client()?
        .get(format!("{FILES_URL}/{id}"))
        .bearer_auth(token)
        .query(&[("alt", "media")])
        .send()
        .await
        .map_err(err_chain)?;
    if !resp.status().is_success() {
        return Err(format!("Drive download failed ({})", resp.status()));
    }
    Ok(resp.bytes().await.map_err(err_chain)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_is_stable_and_sensitive() {
        assert_eq!(stamp_of(&["a", "b"]), stamp_of(&["a", "b"]));
        assert_ne!(stamp_of(&["a", "b"]), stamp_of(&["ab", ""]));
    }

    #[test]
    fn url_codec() {
        assert_eq!(enc("a b/c"), "a%20b%2Fc");
        assert_eq!(dec("a%20b%2Fc+d"), "a b/c d");
        assert_eq!(dec("100%"), "100%");
    }
}
