//! Streaming scan orchestration.
//!
//! [`scan_endpoints`] runs the full per-proxy pipeline — protocol detection,
//! quality checks, and (optionally) rotation detection — concurrently, and
//! invokes a callback once per proxy *as each one finishes*. This is what lets
//! the UI fill its results table row-by-row instead of waiting for the whole
//! batch.
//!
//! The callback contract keeps this module UI-agnostic: the Tauri layer passes
//! a closure that emits a Tauri event, while tests pass one that collects into
//! a vector.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::check::{check_proxy, detect_local_ip, CheckConfig, CheckContext, ProxyReport};
use crate::detect::{detect_protocol, DetectConfig};
use crate::geoip::GeoIp;
use crate::proxy::ProxyEndpoint;
use crate::rotation::{detect_rotation, RotationConfig, RotationReport};

/// Options controlling a scan run.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub detect: DetectConfig,
    /// Whether to probe rotation behavior for proxies that came back alive.
    pub check_rotation: bool,
    pub rotation: RotationConfig,
    /// Maximum number of proxies checked concurrently.
    pub concurrency: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            detect: DetectConfig::default(),
            check_rotation: false,
            rotation: RotationConfig::default(),
            concurrency: 64,
        }
    }
}

/// The complete result for one proxy, delivered to the scan callback.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Position of the proxy in the input list.
    pub index: usize,
    pub report: ProxyReport,
    /// Present only when rotation probing ran for this proxy.
    pub rotation: Option<RotationReport>,
}

/// Runs detection + checks (+ optional rotation) for every endpoint
/// concurrently, calling `on_result` once per proxy as it completes.
///
/// Returns when all proxies have been processed. The callback may be invoked
/// from multiple tasks concurrently, hence the `Send + Sync` bound.
pub async fn scan_endpoints<F>(
    endpoints: Vec<ProxyEndpoint>,
    config: CheckConfig,
    geoip: GeoIp,
    options: ScanOptions,
    on_result: F,
) where
    F: Fn(ScanResult) + Send + Sync + 'static,
{
    if endpoints.is_empty() {
        return;
    }

    let mut ctx = CheckContext::new(config, geoip);
    // Learn our own public IP once so transparent proxies can be flagged.
    ctx.config.local_ip = detect_local_ip(&ctx.config.judge_url, &ctx.http).await;

    let ctx = Arc::new(ctx);
    let options = Arc::new(options);
    let on_result = Arc::new(on_result);
    let semaphore = Arc::new(Semaphore::new(options.concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for (index, endpoint) in endpoints.into_iter().enumerate() {
        let ctx = Arc::clone(&ctx);
        let options = Arc::clone(&options);
        let on_result = Arc::clone(&on_result);
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let _permit = semaphore.acquire().await.expect("semaphore is open");

            let detected = detect_protocol(&endpoint, &options.detect).await;
            let protocol = detected.protocol;
            let report = check_proxy(endpoint.clone(), protocol, &ctx).await;

            // Rotation is comparatively expensive (several requests), so it
            // only runs for proxies that are alive with a known protocol.
            let rotation = match (options.check_rotation && report.alive, protocol) {
                (true, Some(protocol)) => {
                    Some(detect_rotation(&endpoint, protocol, &ctx.config, &options.rotation).await)
                }
                _ => None,
            };

            on_result(ScanResult {
                index,
                report,
                rotation,
            });
        });
    }

    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A mock that answers every connection with an httpbin-like JSON body,
    /// so detection classifies it as an HTTP (CONNECT-capable) proxy and the
    /// check reads a usable exit IP.
    async fn spawn_http_mock() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let body = r#"{"origin": "203.0.113.5", "headers": {"Host": "j"}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn empty_input_invokes_nothing() {
        let calls = Arc::new(Mutex::new(0usize));
        let calls2 = Arc::clone(&calls);
        scan_endpoints(
            Vec::new(),
            CheckConfig::default(),
            GeoIp::new(None, false),
            ScanOptions::default(),
            move |_| *calls2.lock().unwrap() += 1,
        )
        .await;
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn streams_one_result_per_endpoint() {
        let addr = spawn_http_mock().await;
        let judge = format!("http://{addr}/get");

        let config = CheckConfig {
            judge_url: judge,
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            local_ip: None,
        };
        let options = ScanOptions {
            detect: DetectConfig {
                connect_timeout: Duration::from_secs(2),
                io_timeout: Duration::from_secs(2),
                probe_host: "judge.example".to_string(),
            },
            check_rotation: false,
            rotation: RotationConfig::default(),
            concurrency: 4,
        };

        let endpoints = vec![
            ProxyEndpoint::new(addr.ip().to_string(), addr.port()),
            ProxyEndpoint::new(addr.ip().to_string(), addr.port()),
        ];

        let results = Arc::new(Mutex::new(Vec::<ScanResult>::new()));
        let sink = Arc::clone(&results);
        scan_endpoints(
            endpoints,
            config,
            GeoIp::new(None, false),
            options,
            move |r| sink.lock().unwrap().push(r),
        )
        .await;

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 2);
        assert!(
            results.iter().all(|r| r.report.alive),
            "expected both alive, got {:?}",
            results
                .iter()
                .map(|r| r.report.error.clone())
                .collect::<Vec<_>>()
        );
        assert!(results
            .iter()
            .all(|r| r.report.exit_ip.as_deref() == Some("203.0.113.5")));
    }
}
