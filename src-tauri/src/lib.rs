//! Tauri application wiring.
//!
//! Keep this layer thin: it exposes `proxyscope-core` functionality to the
//! frontend through Tauri commands and (in later phases) streams per-proxy
//! results back via Tauri events. No proxy logic should live here.

use proxyscope_core::{DetectConfig, Protocol, ProxyEndpoint};
use serde::Serialize;

/// One row returned by [`parse_proxies`]: either a parsed endpoint or the
/// reason the input line could not be parsed.
#[derive(Serialize)]
struct ParseRow {
    line: usize,
    raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<ProxyEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// One row returned by [`detect_proxies`]: the parsed endpoint plus its
/// detected protocol (or the relevant parse/detection error).
#[derive(Serialize)]
struct DetectRow {
    line: usize,
    raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<ProxyEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Protocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detect_error: Option<String>,
}

/// Returns the core library version. Doubles as a UI <-> backend smoke test.
#[tauri::command]
fn app_version() -> String {
    proxyscope_core::VERSION.to_string()
}

/// Parses a pasted/imported proxy list without touching the network.
#[tauri::command]
fn parse_proxies(text: String) -> Vec<ParseRow> {
    proxyscope_core::parse_proxies(&text)
        .into_iter()
        .map(|parsed| {
            let (endpoint, error) = match parsed.result {
                Ok(endpoint) => (Some(endpoint), None),
                Err(err) => (None, Some(err.to_string())),
            };
            ParseRow {
                line: parsed.line_number,
                raw: parsed.raw,
                endpoint,
                error,
            }
        })
        .collect()
}

/// Parses a proxy list and detects each valid entry's protocol concurrently.
///
/// TODO (Phase 4): stream rows to the UI via Tauri events instead of returning
/// the whole batch once detection finishes.
#[tauri::command]
async fn detect_proxies(text: String) -> Vec<DetectRow> {
    let parsed = proxyscope_core::parse_proxies(&text);

    let mut rows: Vec<DetectRow> = Vec::with_capacity(parsed.len());
    // Map each detectable endpoint back to its row index so we can fill in the
    // detection result after the concurrent run completes.
    let mut detectable: Vec<(usize, ProxyEndpoint)> = Vec::new();

    for parsed in parsed {
        match parsed.result {
            Ok(endpoint) => {
                detectable.push((rows.len(), endpoint.clone()));
                rows.push(DetectRow {
                    line: parsed.line_number,
                    raw: parsed.raw,
                    endpoint: Some(endpoint),
                    protocol: None,
                    parse_error: None,
                    detect_error: None,
                });
            }
            Err(err) => rows.push(DetectRow {
                line: parsed.line_number,
                raw: parsed.raw,
                endpoint: None,
                protocol: None,
                parse_error: Some(err.to_string()),
                detect_error: None,
            }),
        }
    }

    let endpoints: Vec<ProxyEndpoint> = detectable.iter().map(|(_, ep)| ep.clone()).collect();
    let outcomes = proxyscope_core::detect_many(endpoints, DetectConfig::default(), 64).await;

    // `detect_many` preserves input order, so it aligns with `detectable`.
    for ((row_index, _), (_, outcome)) in detectable.iter().zip(outcomes) {
        rows[*row_index].protocol = outcome.protocol;
        rows[*row_index].detect_error = outcome.error;
    }

    rows
}

/// Builds and runs the ProxyScope desktop application.
///
/// # Panics
/// Panics if the Tauri runtime fails to initialize.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_version,
            parse_proxies,
            detect_proxies
        ])
        .run(tauri::generate_context!())
        .expect("error while running the ProxyScope application");
}
