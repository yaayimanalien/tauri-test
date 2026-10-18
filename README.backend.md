# Daylight

A minimal, Apple-style diary for desktop and mobile, built with Tauri (Rust) in
pitch-black (OLED) mode. Entries are encrypted with your password, can be unlocked
with biometrics, and are backed up incrementally to your own Google Drive.
The frontend is plain HTML/CSS/JavaScript, **no Node.js or npm required**.

## Features

- **Opens ready to type**: no buttons to press. A blank draft is always at the top of
  today with the cursor in it; it only becomes an entry once you type, so empty entries
  never pile up. `Cmd/Ctrl + N` jumps back to it. Tap any entry to edit it in place.
- **Flat, Obsidian-style timeline** on pure black: date in red, time in orange, title in
  yellow, then the body. Days run newest first; today is newest-first, earlier days read
  oldest-to-newest (flip `TODAY_NEWEST_FIRST` / `PAST_NEWEST_FIRST` at the top of `ui/app.js`).
- **Live Markdown editing** in the same pane (headings are coloured and extra bold, and full size once you tap Done): headings, bold, italic, strikethrough,
  links, images, lists, quotes, inline and fenced code.
- **Encryption**: password -> Argon2id -> wraps a random data key; entries are
  encrypted with XChaCha20-Poly1305. Nothing readable is stored on disk.
- **Biometric unlock**: Windows Hello (Windows), Face ID / Touch ID / fingerprint
  (iOS, Android). Turn it on in Settings. The password always works as a fallback.
- **Auto-lock** after 5 minutes idle or 1 minute in the background; `Cmd/Ctrl + L` locks now.
- **Two-way Google Drive sync**: only new or changed entries are sent (already
  encrypted). On every unlock, when you return to the app, every 2 minutes while it is
  open, 10 s after your last edit, on lock, and from Settings -> Sync now, Daylight
  pulls changes made on your other devices and pushes yours. Deletions sync too.
- **Restore on a new device** from the lock screen with your password.

## Project layout

```
daylight/
├── ui/                    # static frontend (no build step)
│   ├── index.html
│   ├── styles.css
│   ├── markdown.js        # dependency-free Markdown renderer + live-editor renderer
│   └── app.js
└── src-tauri/
    ├── src/
    │   ├── main.rs
    │   ├── lib.rs         # commands, vault state
    │   ├── crypto.rs      # Argon2id + XChaCha20-Poly1305 (has unit tests)
    │   ├── drive.rs       # Google OAuth (PKCE) + incremental sync (has unit tests)
    │   ├── biometric.rs   # Windows Hello / mobile biometrics
    │   └── keystore.rs    # OS credential store for biometric unlock
    ├── capabilities/
    ├── tauri.conf.json
    ├── build.rs
    └── Cargo.toml
```

## Prerequisites

- Rust toolchain (stable)
- Tauri CLI: `cargo install tauri-cli --locked`

## Run / build (desktop)

```bash
cargo tauri dev
cargo tauri build      # installers in src-tauri/target/release/bundle
```

Run the crypto/Drive unit tests with `cd src-tauri && cargo test`.

## Mobile

```bash
cargo tauri android init   # Android SDK + NDK + JDK
cargo tauri ios init       # macOS + Xcode
cargo tauri android dev
cargo tauri ios dev
```

On iOS add a `NSFaceIDUsageDescription` entry to the generated `Info.plist`.

## Passwords and recovery

There is **no password reset**. The password is the only thing that can decrypt your
entries (and your Drive backup). Use a password manager or write it down somewhere safe.
The first time you start the app you create a password; an existing plaintext
`diary.json` is imported and renamed to `diary.json.plain-backup`. Delete that file
once you've checked everything is there.

## Google Drive backup setup (one time)

Daylight uses your own Google Cloud project, so no one else holds your access.

1. Go to <https://console.cloud.google.com/>, create a project.
2. **APIs & Services -> Library**: enable **Google Drive API**.
3. **OAuth consent screen**: choose External, fill in the basics, add yourself as a
   test user. (While in "Testing", Google expires the sign-in after 7 days; click
   *Publish app* to avoid that. It's only for you.)
4. **Credentials -> Create credentials -> OAuth client ID -> Desktop app**.
5. In Daylight: Settings -> Backup, paste the client ID and secret, press
   **Connect Google Drive**, and approve in the browser tab that opens.

Only the `drive.appdata` scope is requested: Daylight can see its own hidden
app folder and nothing else in your Drive. Files there are `header.json` (the
password-wrapped key, not secret) and one encrypted `e-<id>` file per entry.

Sync is two-way. Setting up another device: lock screen -> *Restore from Google
Drive*, then it keeps itself in sync. Per entry, the most recent change wins (edits
and deletes are timestamped, so device clocks should be roughly right). Deletions are
stored on Drive as small encrypted `t-<id>` files so they reach every device.
A Drive folder that belongs to a different vault is detected and left untouched.
A password change on one device updates the Drive copy; other devices keep working
with their own password until you change it there too.

## Where entries are stored

Entries live in `vault.dat` (encrypted) inside the platform app-data directory:

- Windows: `%APPDATA%\com.daylight.diary\vault.dat`
- macOS: `~/Library/Application Support/com.daylight.diary/vault.dat`
- Linux: `~/.local/share/com.daylight.diary/vault.dat`
- iOS/Android: the app's sandboxed data directory

If those folders aren't writable the app falls back to a `data/` folder next to the
current working directory.

## Shortcuts

- `Cmd/Ctrl + N` new entry
- `Cmd/Ctrl + S` save immediately (autosave already runs as you type)
- `Cmd/Ctrl + L` lock

## Known limits

- macOS and Linux desktop have no biometric unlock yet (password only).
- Some mobile WebViews won't open the keyboard on launch without a tap (notably iOS);
  the cursor is still placed, one tap brings the keyboard up.
- Android biometric unlock keeps the key in the app's private storage rather than
  the Android Keystore.
- Google sign-in on mobile uses a local loopback redirect; it should work but is
  less tested than desktop.
- If the same entry is edited on two devices before they sync, the later edit wins
  and the earlier one is overwritten (no merge inside a single entry).
- Sync needs the vault unlocked; a locked app can't reach Drive.
