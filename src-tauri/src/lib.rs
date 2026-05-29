//! Tauri application wiring.
//!
//! Keep this layer thin: it exposes `proxyscope-core` functionality to the
//! frontend through Tauri commands and (in later phases) streams per-proxy
//! results back via Tauri events. No proxy logic should live here.

/// Returns the core library version. Used by the frontend as a connectivity
/// smoke test between the UI and the Rust backend.
#[tauri::command]
fn app_version() -> String {
    proxyscope_core::VERSION.to_string()
}

/// Builds and runs the ProxyScope desktop application.
///
/// # Panics
/// Panics if the Tauri runtime fails to initialize.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_version])
        .run(tauri::generate_context!())
        .expect("error while running the ProxyScope application");
}
