//! Biometric prompt, per platform.
//!   * Windows: Windows Hello (fingerprint / face / PIN) via UserConsentVerifier
//!   * Android / iOS: tauri-plugin-biometric
//!   * macOS / Linux: not implemented yet -> reports unavailable (password only)

use tauri::{AppHandle, Runtime};

#[cfg(windows)]
mod imp {
    use super::*;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use tauri::Manager;
    use windows::{
        core::{factory, HSTRING},
        Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
        },
        Win32::{Foundation::HWND, System::WinRT::IUserConsentVerifierInterop},
    };
    use windows_future::IAsyncOperation;

    pub fn available<R: Runtime>(_app: &AppHandle<R>) -> bool {
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.get())
            .map(|a| a == UserConsentVerifierAvailability::Available)
            .unwrap_or(false)
    }

    // Blocking: call from a worker thread, never the UI thread.
    pub fn authenticate<R: Runtime>(app: &AppHandle<R>, reason: &str) -> Result<(), String> {
        let win = app.get_webview_window("main").ok_or("window not found")?;
        let handle = win.window_handle().map_err(|e| e.to_string())?;
        let RawWindowHandle::Win32(h) = handle.as_raw() else {
            return Err("unsupported window".into());
        };
        let hwnd = HWND(h.hwnd.get() as *mut core::ffi::c_void);
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|e| e.to_string())?;
        let op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
            interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(reason))
        }
        .map_err(|e| e.to_string())?;
        match op.get().map_err(|e| e.to_string())? {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::Canceled => Err("Cancelled".into()),
            _ => Err("Windows Hello did not verify you".into()),
        }
    }
}

#[cfg(mobile)]
mod imp {
    use super::*;
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};

    pub fn available<R: Runtime>(app: &AppHandle<R>) -> bool {
        app.biometric().status().map(|s| s.is_available).unwrap_or(false)
    }

    pub fn authenticate<R: Runtime>(app: &AppHandle<R>, reason: &str) -> Result<(), String> {
        app.biometric()
            .authenticate(reason.to_string(), AuthOptions::default())
            .map_err(|e| e.to_string())
    }
}

#[cfg(not(any(windows, mobile)))]
mod imp {
    use super::*;
    pub fn available<R: Runtime>(_app: &AppHandle<R>) -> bool {
        false
    }
    pub fn authenticate<R: Runtime>(_app: &AppHandle<R>, _reason: &str) -> Result<(), String> {
        Err("Biometric unlock isn't supported on this platform yet".into())
    }
}

pub use imp::{authenticate, available};
