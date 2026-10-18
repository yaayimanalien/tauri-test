mod biometric;
mod crypto;
mod drive;
mod keystore;
mod sync;

use crypto::{Header, Key};
use drive::DriveCfg;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State, WebviewWindowBuilder};

const LOCKED: &str = "Locked";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    id: String,
    title: String,
    body: String,
    created_at: i64,
    updated_at: i64,
}

/// Everything that lives inside the encrypted vault.
#[derive(Serialize, Deserialize, Default)]
struct Payload {
    #[serde(default)]
    entries: Vec<Entry>,
    /// Google Drive credentials. Kept inside the vault so they are encrypted too.
    #[serde(default)]
    drive: Option<DriveCfg>,
    /// Time of the last successful sync (named `last_backup` for older vaults).
    #[serde(default)]
    last_backup: Option<i64>,
    /// Entries deleted on this device, so a sync can tell "deleted" from "never had it".
    #[serde(default)]
    tombstones: HashMap<String, i64>,
    /// When the key header (password wrap) last changed; the newest header wins on Drive.
    #[serde(default)]
    header_at: i64,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    header: Header,
    data: String, // base64(nonce || ciphertext)
}

struct Session {
    dek: Key,
    header: Header,
    payload: Payload,
}

struct AppState {
    dir: PathBuf,
    session: Mutex<Option<Session>>,
    /// Serialises backups so two can't race each other.
    backup: tokio::sync::Mutex<()>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/* ---------------------------- vault file I/O ---------------------------- */

fn vault_path(dir: &Path) -> PathBuf {
    dir.join("vault.dat")
}

fn write_vault(dir: &Path, header: &Header, dek: &Key, payload: &Payload) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let json = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let sealed = crypto::seal(dek, &json, crypto::VAULT_AAD)?;
    let file = VaultFile { header: header.clone(), data: B64.encode(sealed) };
    let out = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
    // Write-then-rename so a crash can't leave a half-written vault.
    let tmp = dir.join("vault.dat.tmp");
    std::fs::write(&tmp, out).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, vault_path(dir)).map_err(|e| e.to_string())
}

fn read_vault(dir: &Path) -> Result<VaultFile, String> {
    let raw = std::fs::read(vault_path(dir)).map_err(|e| e.to_string())?;
    serde_json::from_slice(&raw).map_err(|_| "Vault file is corrupted".to_string())
}

fn decrypt_payload(file: &VaultFile, dek: &Key) -> Result<Payload, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let blob = B64.decode(&file.data).map_err(|e| e.to_string())?;
    let json = crypto::open(dek, &blob, crypto::VAULT_AAD)?;
    serde_json::from_slice(&json).map_err(|e| e.to_string())
}

fn persist(dir: &Path, s: &Session) -> Result<(), String> {
    write_vault(dir, &s.header, &s.dek, &s.payload)
}

fn with_session<T>(
    state: &State<AppState>,
    f: impl FnOnce(&mut Session) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state.session.lock().unwrap();
    let s = guard.as_mut().ok_or_else(|| LOCKED.to_string())?;
    f(s)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

fn check_password_strength(pw: &str) -> Result<(), String> {
    if pw.chars().count() < 8 {
        return Err("Use at least 8 characters".into());
    }
    Ok(())
}

/* ------------------------------- status -------------------------------- */

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    exists: bool,
    unlocked: bool,
    biometric_available: bool,
    biometric_enabled: bool,
    drive_connected: bool,
    last_backup: Option<i64>,
}

#[tauri::command]
async fn vault_status(app: AppHandle, state: State<'_, AppState>) -> Result<Status, String> {
    let a = app.clone();
    let bio = blocking(move || biometric::available(&a)).await?;
    let (unlocked, drive_connected, last_backup) = {
        let g = state.session.lock().unwrap();
        match g.as_ref() {
            Some(s) => (true, s.payload.drive.is_some(), s.payload.last_backup),
            None => (false, false, None),
        }
    };
    Ok(Status {
        exists: vault_path(&state.dir).exists(),
        unlocked,
        biometric_available: bio,
        biometric_enabled: bio && keystore::exists(&state.dir),
        drive_connected,
        last_backup,
    })
}

/* ----------------------------- vault lifecycle ------------------------- */

#[tauri::command]
async fn setup_vault(password: String, state: State<'_, AppState>) -> Result<(), String> {
    check_password_strength(&password)?;
    if vault_path(&state.dir).exists() {
        return Err("A vault already exists".into());
    }
    // Import a pre-encryption diary.json if there is one.
    let old = state.dir.join("diary.json");
    let mut payload = Payload::default();
    payload.header_at = now_secs();
    let mut migrated = false;
    if let Ok(s) = std::fs::read_to_string(&old) {
        if let Ok(entries) = serde_json::from_str::<Vec<Entry>>(&s) {
            payload.entries = entries;
            migrated = true;
        }
    }
    let (header, dek) = blocking(move || crypto::create(&password)).await??;
    write_vault(&state.dir, &header, &dek, &payload)?;
    if migrated {
        // Keep the plaintext copy renamed (not deleted) in case anything went wrong.
        let _ = std::fs::rename(&old, state.dir.join("diary.json.plain-backup"));
    }
    *state.session.lock().unwrap() = Some(Session { dek, header, payload });
    Ok(())
}

#[tauri::command]
async fn unlock(password: String, state: State<'_, AppState>) -> Result<(), String> {
    let file = read_vault(&state.dir)?;
    let (dek, header, payload) = blocking(move || -> Result<_, String> {
        let dek = crypto::unwrap(&file.header, &password)?;
        let payload = decrypt_payload(&file, &dek)?;
        Ok((dek, file.header, payload))
    })
    .await??;
    *state.session.lock().unwrap() = Some(Session { dek, header, payload });
    Ok(())
}

#[tauri::command]
async fn unlock_biometric(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if !keystore::exists(&state.dir) {
        return Err("Biometric unlock isn't set up".into());
    }
    let a = app.clone();
    blocking(move || biometric::authenticate(&a, "Unlock Daylight")).await??;
    let dek = keystore::load(&state.dir)?;
    let file = read_vault(&state.dir)?;
    match decrypt_payload(&file, &dek) {
        Ok(payload) => {
            *state.session.lock().unwrap() = Some(Session { dek, header: file.header, payload });
            Ok(())
        }
        Err(_) => {
            // Stored key no longer matches this vault.
            keystore::delete(&state.dir);
            Err("Biometric unlock is out of date. Use your password.".into())
        }
    }
}

#[tauri::command]
fn lock(state: State<AppState>) {
    *state.session.lock().unwrap() = None;
}

#[tauri::command]
async fn set_biometric(app: AppHandle, enabled: bool, state: State<'_, AppState>) -> Result<(), String> {
    if !enabled {
        keystore::delete(&state.dir);
        return Ok(());
    }
    let dek = with_session(&state, |s| Ok(s.dek.clone()))?;
    let a = app.clone();
    // Prove it works before storing anything.
    blocking(move || biometric::authenticate(&a, "Turn on biometric unlock")).await??;
    keystore::save(&state.dir, &dek)
}

#[tauri::command]
async fn change_password(old: String, new: String, state: State<'_, AppState>) -> Result<(), String> {
    check_password_strength(&new)?;
    let (header, dek) = with_session(&state, |s| Ok((s.header.clone(), s.dek.clone())))?;
    let new_header = blocking(move || -> Result<Header, String> {
        crypto::unwrap(&header, &old)?; // confirms the old password
        crypto::wrap(&dek, &new)
    })
    .await??;
    with_session(&state, |s| {
        s.header = new_header;
        s.payload.header_at = now_secs();
        persist(&state.dir, s)
    })
}

/* -------------------------------- entries ------------------------------ */

#[tauri::command]
fn list_entries(state: State<AppState>) -> Result<Vec<Entry>, String> {
    with_session(&state, |s| {
        let mut v = s.payload.entries.clone();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(v)
    })
}

#[tauri::command]
fn create_entry(
    title: String,
    body: String,
    id: Option<String>,
    created_at: Option<i64>,
    state: State<AppState>,
) -> Result<Entry, String> {
    with_session(&state, |s| {
        let now = now_secs();
        // The UI may supply its own id (so a draft keeps its identity) and a
        // creation time (so an undone delete lands back in its original place).
        let id = id.filter(|i| !i.is_empty()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if s.payload.entries.iter().any(|e| e.id == id) {
            return Err("Entry already exists".into());
        }
        // Re-creating an entry cancels its deletion marker.
        s.payload.tombstones.remove(&id);
        let entry = Entry {
            id,
            title,
            body,
            created_at: created_at.unwrap_or(now),
            updated_at: now,
        };
        s.payload.entries.push(entry.clone());
        persist(&state.dir, s)?;
        Ok(entry)
    })
}

#[tauri::command]
fn update_entry(id: String, title: String, body: String, state: State<AppState>) -> Result<Entry, String> {
    with_session(&state, |s| {
        let e = s
            .payload
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "Entry not found".to_string())?;
        e.title = title;
        e.body = body;
        e.updated_at = now_secs();
        let out = e.clone();
        persist(&state.dir, s)?;
        Ok(out)
    })
}

#[tauri::command]
fn delete_entry(id: String, state: State<AppState>) -> Result<(), String> {
    with_session(&state, |s| {
        let before = s.payload.entries.len();
        s.payload.entries.retain(|e| e.id != id);
        // Remember the deletion so other devices drop it too instead of re-uploading it.
        if s.payload.entries.len() != before && s.payload.drive.is_some() {
            s.payload.tombstones.insert(id, now_secs());
        }
        persist(&state.dir, s)
    })
}

/* ------------------------------ Google Drive --------------------------- */

fn open_in_browser(url: &str) -> Result<(), String> {
    webbrowser::open(url).map_err(|e| format!("Couldn't open the browser: {e}"))
}

#[tauri::command]
async fn drive_connect(client_id: String, client_secret: String, state: State<'_, AppState>) -> Result<(), String> {
    with_session(&state, |_| Ok(()))?;
    let (client_id, client_secret) = (client_id.trim().to_string(), client_secret.trim().to_string());
    if client_id.is_empty() || client_secret.is_empty() {
        return Err("Enter both the client ID and client secret".into());
    }
    let refresh = drive::authorize(&client_id, &client_secret, open_in_browser).await?;
    with_session(&state, |s| {
        s.payload.drive = Some(DriveCfg { client_id, client_secret, refresh_token: refresh });
        persist(&state.dir, s)
    })
}

#[tauri::command]
fn drive_disconnect(state: State<AppState>) -> Result<(), String> {
    with_session(&state, |s| {
        s.payload.drive = None;
        persist(&state.dir, s)
    })
}

#[derive(Serialize)]
struct SyncResult {
    uploaded: usize,
    downloaded: usize,
    removed: usize,
    unchanged: usize,
    at: i64,
}

fn entry_aad(id: &str) -> Vec<u8> {
    format!("daylight-entry-v1:{id}").into_bytes()
}

fn tomb_aad(id: &str) -> Vec<u8> {
    format!("daylight-tomb-v1:{id}").into_bytes()
}

/// Encrypted deletion marker stored on Drive as `t-<id>`.
#[derive(Serialize, Deserialize)]
struct Tomb {
    id: String,
    deleted_at: i64,
}

const CHECK_AAD: &[u8] = b"daylight-check-v1";
const MISMATCH: &str = "This Google Drive already holds a different Daylight vault. \
Restore from it on a fresh install, or disconnect Drive here.";

fn entry_stamp(e: &Entry) -> String {
    drive::stamp_of(&[&e.id, &e.title, &e.body, &e.updated_at.to_string()])
}

/// Makes sure the Drive folder belongs to *this* vault (same data key) before we
/// change anything in it. Returns true if the marker file still has to be uploaded.
async fn verify_remote(
    token: &str,
    dek: &Key,
    files: &HashMap<String, drive::Remote>,
) -> Result<bool, String> {
    if let Some(f) = files.get("vault.chk") {
        let blob = drive::download(token, &f.id).await?;
        return crypto::open(dek, &blob, CHECK_AAD)
            .map(|_| false)
            .map_err(|_| MISMATCH.to_string());
    }
    // Older backups have no marker: probe one tombstone or entry instead.
    let probe = files
        .keys()
        .filter(|n| n.starts_with("t-"))
        .min()
        .or_else(|| files.keys().filter(|n| n.starts_with("e-")).min());
    if let Some(name) = probe {
        let aad = if name.starts_with("t-") { tomb_aad(&name[2..]) } else { entry_aad(&name[2..]) };
        let blob = drive::download(token, &files[name].id).await?;
        crypto::open(dek, &blob, &aad).map_err(|_| MISMATCH.to_string())?;
    }
    Ok(true)
}

/// Two-way sync with Google Drive: pushes local changes, pulls changes made on
/// other devices, and propagates deletions. Safe to call as often as you like.
#[tauri::command]
async fn sync_now(state: State<'_, AppState>) -> Result<SyncResult, String> {
    let _one_at_a_time = state.backup.lock().await;

    // Snapshot, so the vault isn't locked during network calls.
    let (cfg, dek, header, header_at, entries, tombs) = with_session(&state, |s| {
        let cfg = s.payload.drive.clone().ok_or("Google Drive isn't connected")?;
        Ok((
            cfg,
            s.dek.clone(),
            s.header.clone(),
            s.payload.header_at,
            s.payload.entries.clone(),
            s.payload.tombstones.clone(),
        ))
    })?;

    let token = drive::access_token(&cfg).await?;

    // Index what's on Drive by file name. Duplicates (two devices racing) are collapsed.
    let mut files: HashMap<String, drive::Remote> = HashMap::new();
    let mut duplicates: Vec<String> = Vec::new();
    for r in drive::list_remote(&token).await? {
        if let Some(cur) = files.get(&r.name) {
            if cur.updated >= r.updated {
                duplicates.push(r.id);
                continue;
            }
            duplicates.push(cur.id.clone());
        }
        files.insert(r.name.clone(), r);
    }

    let upload_check = verify_remote(&token, &dek, &files).await?;
    for id in &duplicates {
        drive::delete_remote(&token, id).await?;
    }

    // Compare both sides.
    let mut local_live: BTreeMap<String, sync::Live> = BTreeMap::new();
    let mut by_id: HashMap<&str, &Entry> = HashMap::new();
    for e in &entries {
        local_live.insert(e.id.clone(), sync::Live { updated: e.updated_at, stamp: entry_stamp(e) });
        by_id.insert(e.id.as_str(), e);
    }
    let local_dead: BTreeMap<String, i64> = tombs.iter().map(|(k, v)| (k.clone(), *v)).collect();
    let mut remote_live: BTreeMap<String, sync::Live> = BTreeMap::new();
    let mut remote_dead: BTreeMap<String, i64> = BTreeMap::new();
    for (name, f) in &files {
        if let Some(id) = name.strip_prefix("e-") {
            remote_live.insert(
                id.to_string(),
                sync::Live { updated: f.updated, stamp: f.stamp.clone().unwrap_or_default() },
            );
        } else if let Some(id) = name.strip_prefix("t-") {
            remote_dead.insert(id.to_string(), f.updated);
        }
    }
    let plan = sync::plan(&local_live, &local_dead, &remote_live, &remote_dead);

    // 1. Pull. Anything that fails to authenticate is skipped rather than trusted.
    let mut fetched: Vec<Entry> = Vec::new();
    for id in &plan.download {
        let f = &files[&format!("e-{id}")];
        let blob = drive::download(&token, &f.id).await?;
        let parsed = crypto::open(&dek, &blob, &entry_aad(id))
            .and_then(|json| serde_json::from_slice::<Entry>(&json).map_err(|e| e.to_string()));
        match parsed {
            Ok(e) if &e.id == id => fetched.push(e),
            _ => eprintln!("sync: skipped unreadable remote entry {id}"),
        }
    }
    let mut deletions: Vec<(String, i64)> = Vec::new(); // verified tombstones to apply locally
    for (id, _) in plan.local_delete.iter().chain(plan.adopt_tombstone.iter()) {
        let Some(f) = files.get(&format!("t-{id}")) else { continue };
        let blob = drive::download(&token, &f.id).await?;
        let parsed = crypto::open(&dek, &blob, &tomb_aad(id))
            .and_then(|json| serde_json::from_slice::<Tomb>(&json).map_err(|e| e.to_string()));
        match parsed {
            Ok(t) if &t.id == id => deletions.push((id.clone(), t.deleted_at)),
            _ => eprintln!("sync: skipped unreadable remote tombstone {id}"),
        }
    }

    // 2. Push.
    for id in &plan.upload {
        let Some(e) = by_id.get(id.as_str()) else { continue };
        let json = serde_json::to_vec(e).map_err(err_s)?;
        let blob = crypto::seal(&dek, &json, &entry_aad(id))?;
        let name = format!("e-{id}");
        let existing = files.get(&name).map(|f| f.id.as_str());
        drive::upload(&token, existing, &name, &entry_stamp(e), e.updated_at, blob).await?;
    }
    for (id, at) in &plan.put_tombstone {
        let json = serde_json::to_vec(&Tomb { id: id.clone(), deleted_at: *at }).map_err(err_s)?;
        let blob = crypto::seal(&dek, &json, &tomb_aad(id))?;
        let name = format!("t-{id}");
        let existing = files.get(&name).map(|f| f.id.as_str());
        let stamp = drive::stamp_of(&["t", id, &at.to_string()]);
        drive::upload(&token, existing, &name, &stamp, *at, blob).await?;
    }
    // The newest key header wins, so an old device can't overwrite a changed password.
    let header_json = serde_json::to_string(&header).map_err(err_s)?;
    let header_stamp = drive::stamp_of(&[&header_json]);
    let push_header = match files.get("header.json") {
        None => true,
        Some(f) => f.stamp.as_deref() != Some(header_stamp.as_str()) && header_at >= f.updated,
    };
    if push_header {
        let existing = files.get("header.json").map(|f| f.id.as_str());
        drive::upload(&token, existing, "header.json", &header_stamp, header_at, header_json.into_bytes())
            .await?;
    }
    if upload_check {
        let blob = crypto::seal(&dek, b"daylight", CHECK_AAD)?;
        drive::upload(&token, None, "vault.chk", &drive::stamp_of(&["chk"]), 0, blob).await?;
    }
    for name in &plan.remote_delete {
        if let Some(f) = files.get(name) {
            drive::delete_remote(&token, &f.id).await?;
        }
    }

    // 3. Apply to the local vault, without clobbering anything edited while we were online.
    let at = now_secs();
    let (downloaded, removed) = with_session(&state, |s| {
        let (mut downloaded, mut removed) = (0usize, 0usize);
        for e in fetched {
            if s.payload.tombstones.get(&e.id).is_some_and(|&d| d >= e.updated_at) {
                continue; // deleted here while we were syncing
            }
            match s.payload.entries.iter_mut().find(|x| x.id == e.id) {
                Some(cur) if cur.updated_at > e.updated_at => continue,
                Some(cur) => *cur = e.clone(),
                None => s.payload.entries.push(e.clone()),
            }
            s.payload.tombstones.remove(&e.id);
            downloaded += 1;
        }
        for (id, d) in deletions {
            if let Some(pos) = s.payload.entries.iter().position(|x| x.id == id) {
                if s.payload.entries[pos].updated_at > d {
                    continue; // edited since: keep it, the next sync will re-upload it
                }
                s.payload.entries.remove(pos);
                removed += 1;
            }
            let t = s.payload.tombstones.entry(id).or_insert(d);
            *t = (*t).max(d);
        }
        s.payload.last_backup = Some(at);
        persist(&state.dir, s)?;
        Ok((downloaded, removed))
    })?;

    Ok(SyncResult {
        uploaded: plan.upload.len(),
        downloaded,
        removed,
        unchanged: plan.unchanged,
        at,
    })
}

fn err_s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// For a fresh install: pull the key header and all entries from Drive and
/// rebuild the vault locally. The Drive password is the same one used on the
/// original device.
#[tauri::command]
async fn restore_from_drive(
    client_id: String,
    client_secret: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    if vault_path(&state.dir).exists() {
        return Err("A vault already exists on this device".into());
    }
    let (client_id, client_secret) = (client_id.trim().to_string(), client_secret.trim().to_string());
    let refresh = drive::authorize(&client_id, &client_secret, open_in_browser).await?;
    let cfg = DriveCfg { client_id, client_secret, refresh_token: refresh };

    let token = drive::access_token(&cfg).await?;
    let remote = drive::list_remote(&token).await?;
    let header_file = remote
        .iter()
        .find(|r| r.name == "header.json")
        .ok_or("No Daylight backup found in this Google account")?;
    let header: Header =
        serde_json::from_slice(&drive::download(&token, &header_file.id).await?).map_err(|_| "Backup header is corrupted")?;

    let h = header.clone();
    let dek = blocking(move || crypto::unwrap(&h, &password)).await??;

    let mut entries = Vec::new();
    for r in remote.iter().filter(|r| r.name.starts_with("e-")) {
        let id = r.name.trim_start_matches("e-");
        let blob = drive::download(&token, &r.id).await?;
        let json = crypto::open(&dek, &blob, &entry_aad(id))?;
        let e: Entry = serde_json::from_slice(&json).map_err(|e| e.to_string())?;
        if e.id != id {
            return Err("Backup contains a mismatched entry".into());
        }
        entries.push(e);
    }
    let count = entries.len();
    let payload = Payload {
        entries,
        drive: Some(cfg),
        last_backup: Some(now_secs()),
        tombstones: HashMap::new(),
        header_at: header_file.updated,
    };
    write_vault(&state.dir, &header, &dek, &payload)?;
    *state.session.lock().unwrap() = Some(Session { dek, header, payload });
    Ok(count)
}

/* --------------------------- directories / setup ----------------------- */

/// Returns the first directory in `candidates` that can be created (and is thus
/// writable), if any.
fn first_writable(candidates: &[PathBuf]) -> Option<PathBuf> {
    for dir in candidates {
        if !dir.as_os_str().is_empty() && std::fs::create_dir_all(dir).is_ok() {
            return Some(dir.clone());
        }
    }
    None
}

/// Last-resort writable folder: a `data` directory next to the current working
/// directory. This keeps the app usable in low-integrity / sandboxed
/// environments where the normal app-data folders are off-limits.
fn fallback_dir() -> PathBuf {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    dir.push("data");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Directory for the vault: app data dir first, then local data dir, then the
/// fallback folder.
fn diary_dir(app: &tauri::App) -> PathBuf {
    let candidates = [
        app.path().app_data_dir().unwrap_or_default(),
        app.path().app_local_data_dir().unwrap_or_default(),
    ];
    first_writable(&candidates).unwrap_or_else(fallback_dir)
}

/// Directory for the webview's browser data: local data dir first, then app data
/// dir, then the fallback folder. WebView2 requires this to be writable.
fn webview_dir(app: &tauri::App) -> PathBuf {
    let candidates = [
        app.path().app_local_data_dir().unwrap_or_default(),
        app.path().app_data_dir().unwrap_or_default(),
    ];
    first_writable(&candidates).unwrap_or_else(|| fallback_dir().join("webview"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(mobile)]
            app.handle().plugin(tauri_plugin_biometric::init())?;

            app.manage(AppState {
                dir: diary_dir(app),
                session: Mutex::new(None),
                backup: tokio::sync::Mutex::new(()),
            });

            // Build the main window manually so we can give WebView2 a writable
            // data directory (its default lives under the local app-data dir,
            // which is not writable in low-integrity / sandboxed environments).
            let window_config = app
                .config()
                .app
                .windows
                .first()
                .cloned()
                .expect("at least one window is configured");
            WebviewWindowBuilder::from_config(app.handle(), &window_config)?
                .data_directory(webview_dir(app))
                .build()?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            setup_vault,
            unlock,
            unlock_biometric,
            lock,
            set_biometric,
            change_password,
            list_entries,
            create_entry,
            update_entry,
            delete_entry,
            drive_connect,
            drive_disconnect,
            sync_now,
            restore_from_drive
        ])
        .run(tauri::generate_context!())
        .expect("error while running Daylight");
}
