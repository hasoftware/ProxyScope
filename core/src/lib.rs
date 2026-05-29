//! ProxyScope core library.
//!
//! This crate holds all UI-agnostic logic: proxy list parsing, protocol
//! auto-detection, and (in later phases) the concurrent quality checks. It
//! deliberately has no dependency on Tauri or any UI layer so the logic can be
//! unit-tested and reused independently of the desktop shell.

pub mod check;
pub mod detect;
pub mod geoip;
pub mod parse;
pub mod proxy;
pub mod rotation;

pub use check::{
    check_many, check_proxy, detect_local_ip, fetch_exit_ip, Anonymity, CheckConfig, CheckContext,
    ProxyReport,
};
pub use detect::{detect_many, detect_protocol, DetectConfig, DetectionOutcome};
pub use geoip::{GeoInfo, GeoIp};
pub use parse::{parse_line, parse_proxies, ParsedLine};
pub use proxy::{ParseError, Protocol, ProxyEndpoint};
pub use rotation::{
    detect_rotation, detect_rotation_many, RotationConfig, RotationKind, RotationReport,
};

use std::sync::Arc;

/// The core library version, surfaced to the UI for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// End-to-end pipeline: parse a proxy list, auto-detect each protocol, then
/// run the concurrent quality checks. Returns one [`ProxyReport`] per valid
/// proxy, in input order.
///
/// This is the single entry point the Tauri layer calls so the UI glue stays
/// thin. TODO (Phase 4): stream reports via events instead of returning a batch.
pub async fn check_list(
    input: &str,
    config: CheckConfig,
    geoip: GeoIp,
    detect_concurrency: usize,
    check_concurrency: usize,
) -> Vec<ProxyReport> {
    let endpoints: Vec<ProxyEndpoint> = parse_proxies(input)
        .into_iter()
        .filter_map(|parsed| parsed.result.ok())
        .collect();
    if endpoints.is_empty() {
        return Vec::new();
    }

    let detected = detect_many(endpoints, DetectConfig::default(), detect_concurrency).await;
    let targets: Vec<(ProxyEndpoint, Option<Protocol>)> = detected
        .into_iter()
        .map(|(endpoint, outcome)| (endpoint, outcome.protocol))
        .collect();

    let mut ctx = CheckContext::new(config, geoip);
    // Learn our own public IP once so transparent proxies can be flagged.
    ctx.config.local_ip = detect_local_ip(&ctx.config.judge_url, &ctx.http).await;

    check_many(targets, Arc::new(ctx), check_concurrency).await
}

/// One proxy's rotation result from the [`rotation_list`] pipeline.
pub struct RotationOutcome {
    pub endpoint: ProxyEndpoint,
    pub protocol: Option<Protocol>,
    pub report: RotationReport,
}

/// End-to-end rotation pipeline: parse, auto-detect protocols, then probe each
/// detectable proxy's rotation behavior. Proxies whose protocol could not be
/// detected are reported as [`RotationKind::Unknown`]. Output is in input order.
pub async fn rotation_list(
    input: &str,
    check: CheckConfig,
    rotation: RotationConfig,
    detect_concurrency: usize,
    rotation_concurrency: usize,
) -> Vec<RotationOutcome> {
    let endpoints: Vec<ProxyEndpoint> = parse_proxies(input)
        .into_iter()
        .filter_map(|parsed| parsed.result.ok())
        .collect();
    if endpoints.is_empty() {
        return Vec::new();
    }

    let detected = detect_many(endpoints, DetectConfig::default(), detect_concurrency).await;

    // Probe only the proxies with a known protocol, preserving their order.
    let targets: Vec<(ProxyEndpoint, Protocol)> = detected
        .iter()
        .filter_map(|(endpoint, outcome)| outcome.protocol.map(|p| (endpoint.clone(), p)))
        .collect();
    let mut rotations = detect_rotation_many(targets, check, rotation, rotation_concurrency)
        .await
        .into_iter();

    // Re-merge in the original order: detectable proxies consume a rotation
    // result (same order); undetected ones get an Unknown report.
    detected
        .into_iter()
        .map(|(endpoint, outcome)| match outcome.protocol {
            Some(protocol) => {
                let (_, report) = rotations
                    .next()
                    .expect("one rotation result per detectable proxy");
                RotationOutcome {
                    endpoint,
                    protocol: Some(protocol),
                    report,
                }
            }
            None => RotationOutcome {
                endpoint,
                protocol: None,
                report: RotationReport {
                    kind: RotationKind::Unknown,
                    observed_ips: Vec::new(),
                    samples: 0,
                },
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }
}
