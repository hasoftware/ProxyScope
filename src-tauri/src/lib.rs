//! Tauri application wiring.
//!
//! Keep this layer thin: it exposes `proxyscope-core` functionality to the
//! frontend through Tauri commands and (in later phases) streams per-proxy
//! results back via Tauri events. No proxy logic should live here.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proxyscope_core::{
    Anonymity, CheckConfig, DetectConfig, GeoIp, Protocol, ProxyEndpoint, ProxyReport,
    RotationConfig, RotationKind, ScanOptions, ScanResult,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

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

/// Parses a proxy list, auto-detects protocols, and runs the full quality
/// checks for each valid proxy, returning one report per proxy.
///
/// Uses default settings for now (GeoLite2 path, judge URL, concurrency, and
/// timeouts become user-configurable in Phase 5). TODO (Phase 4): stream
/// reports to the UI via Tauri events instead of returning the whole batch.
#[tauri::command]
async fn check_proxies(text: String) -> Vec<ProxyReport> {
    let config = CheckConfig::default();
    // No offline database yet (Phase 5 adds the path setting); allow the HTTP
    // GeoIP fallback so country/region still populate.
    let geoip = GeoIp::new(None, true);
    proxyscope_core::check_list(&text, config, geoip, 64, 64).await
}

/// One row returned by [`check_rotation`].
#[derive(Serialize)]
struct RotationRow {
    endpoint: ProxyEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Protocol>,
    kind: RotationKind,
    observed_ips: Vec<String>,
    samples: usize,
}

/// Parses a proxy list, detects protocols, and probes each proxy's rotation
/// behavior by sending several sequential requests and recording exit IPs.
///
/// `samples` overrides the burst size (default 4). Time-based probing is left
/// off here because it requires waiting; Phase 5 will expose it as a setting.
#[tauri::command]
async fn check_rotation(text: String, samples: Option<usize>) -> Vec<RotationRow> {
    let mut rotation = RotationConfig::default();
    if let Some(samples) = samples {
        rotation.samples = samples.clamp(1, 50);
    }

    proxyscope_core::rotation_list(&text, CheckConfig::default(), rotation, 64, 32)
        .await
        .into_iter()
        .map(|outcome| RotationRow {
            endpoint: outcome.endpoint,
            protocol: outcome.protocol,
            kind: outcome.report.kind,
            observed_ips: outcome.report.observed_ips,
            samples: outcome.report.samples,
        })
        .collect()
}

/// Options the frontend may pass to [`start_scan`]. Every field is optional;
/// missing values fall back to the core defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ScanRequest {
    check_rotation: bool,
    rotation_samples: Option<usize>,
    /// Plain-HTTP judge URL that echoes the requester IP and headers.
    judge_url: Option<String>,
    connect_timeout_secs: Option<u64>,
    request_timeout_secs: Option<u64>,
    /// Maximum number of proxies checked concurrently.
    concurrency: Option<usize>,
    /// Path to a GeoLite2 `.mmdb` file for offline country/region lookup.
    geolite_path: Option<String>,
    /// Whether to allow the ip-api.com HTTP fallback when offline lookup misses.
    allow_http_geoip: Option<bool>,
}

impl ScanRequest {
    /// Builds the core check configuration from the request, clamping values to
    /// sane ranges.
    fn check_config(&self) -> CheckConfig {
        let mut config = CheckConfig::default();
        if let Some(url) = self.judge_url.as_deref() {
            if !url.trim().is_empty() {
                config.judge_url = url.trim().to_string();
            }
        }
        if let Some(secs) = self.connect_timeout_secs {
            config.connect_timeout = Duration::from_secs(secs.clamp(1, 120));
        }
        if let Some(secs) = self.request_timeout_secs {
            config.request_timeout = Duration::from_secs(secs.clamp(1, 120));
        }
        config
    }

    /// Opens the GeoIP resolver described by the request.
    fn geoip(&self) -> GeoIp {
        let path = self
            .geolite_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty());
        GeoIp::new(path.map(Path::new), self.allow_http_geoip.unwrap_or(true))
    }

    /// Builds the scan options (concurrency + rotation) from the request.
    fn scan_options(&self) -> ScanOptions {
        let mut rotation = RotationConfig::default();
        if let Some(samples) = self.rotation_samples {
            rotation.samples = samples.clamp(2, 50);
        }
        ScanOptions {
            check_rotation: self.check_rotation,
            rotation,
            concurrency: self.concurrency.map(|c| c.clamp(1, 1024)).unwrap_or(64),
            ..ScanOptions::default()
        }
    }
}

/// A flat, table-ready row emitted for each proxy during a scan.
#[derive(Debug, Clone, Serialize)]
struct ScanRow {
    index: usize,
    proxy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Protocol>,
    alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtt_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anonymity: Option<Anonymity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation: Option<RotationKind>,
    observed_ips: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl From<ScanResult> for ScanRow {
    fn from(result: ScanResult) -> Self {
        let report = result.report;
        let geo = report.geo;
        Self {
            index: result.index,
            proxy: report.endpoint.address(),
            protocol: report.protocol,
            alive: report.alive,
            exit_ip: report.exit_ip,
            country_code: geo.as_ref().and_then(|g| g.country_code.clone()),
            country_name: geo.as_ref().and_then(|g| g.country_name.clone()),
            region: geo.as_ref().and_then(|g| g.region.clone()),
            connect_ms: report.connect_ms,
            rtt_ms: report.rtt_ms,
            anonymity: report.anonymity,
            rotation: result.rotation.as_ref().map(|r| r.kind),
            observed_ips: result
                .rotation
                .as_ref()
                .map(|r| r.observed_ips.len())
                .unwrap_or(0),
            error: report.error,
        }
    }
}

#[derive(Clone, Serialize)]
struct StartedPayload {
    total: usize,
    skipped: usize,
}

#[derive(Clone, Serialize)]
struct ProgressPayload {
    done: usize,
    total: usize,
}

#[derive(Clone, Serialize)]
struct FinishedPayload {
    total: usize,
}

/// Starts a scan and streams results to the UI via Tauri events.
///
/// Emits `scan-started` (with totals), then a `scan-result` and `scan-progress`
/// event per proxy as each finishes, and finally `scan-finished`. Returns the
/// number of proxies that will be scanned so the caller can size its progress
/// bar; the actual work runs in the background and does not block the UI.
#[tauri::command]
async fn start_scan(app: AppHandle, text: String, options: ScanRequest) -> usize {
    let mut endpoints: Vec<ProxyEndpoint> = Vec::new();
    let mut skipped = 0usize;
    for parsed in proxyscope_core::parse_proxies(&text) {
        match parsed.result {
            Ok(endpoint) => endpoints.push(endpoint),
            Err(_) => skipped += 1,
        }
    }

    let total = endpoints.len();
    let _ = app.emit("scan-started", StartedPayload { total, skipped });
    if total == 0 {
        let _ = app.emit("scan-finished", FinishedPayload { total: 0 });
        return 0;
    }

    let check_config = options.check_config();
    let geoip = options.geoip();
    let scan_options = options.scan_options();

    // Run the scan in the background so the command returns immediately. Each
    // completed proxy emits its row plus a progress tick; the last one closes
    // the run with `scan-finished`.
    tauri::async_runtime::spawn(async move {
        let done = Arc::new(AtomicUsize::new(0));
        let emitter = app.clone();
        proxyscope_core::scan_endpoints(
            endpoints,
            check_config,
            geoip,
            scan_options,
            move |result| {
                let _ = emitter.emit("scan-result", ScanRow::from(result));
                let completed = done.fetch_add(1, Ordering::SeqCst) + 1;
                let _ = emitter.emit(
                    "scan-progress",
                    ProgressPayload {
                        done: completed,
                        total,
                    },
                );
                if completed == total {
                    let _ = emitter.emit("scan-finished", FinishedPayload { total });
                }
            },
        )
        .await;
    });

    total
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
            detect_proxies,
            check_proxies,
            check_rotation,
            start_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running the ProxyScope application");
}
