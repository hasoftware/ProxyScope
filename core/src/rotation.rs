//! Rotating-proxy detection.
//!
//! A proxy is exercised with several sequential requests and its exit IP is
//! recorded each time. From the set of observed IPs we classify the proxy as:
//! - **static** — the same exit IP throughout
//! - **per-request rotating** — a different exit IP on every request
//! - **rotating** — the exit IP changes, but not on every single request
//! - **time-based rotating** — stable within the initial burst, but a later
//!   timed probe sees a new IP
//!
//! Time-based detection is optional (it requires waiting) and is controlled by
//! [`RotationConfig::time_probe_interval`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::check::{fetch_exit_ip, CheckConfig};
use crate::proxy::{Protocol, ProxyEndpoint};

/// Tunables for rotation detection.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Number of back-to-back requests in the initial burst.
    pub samples: usize,
    /// If set, after a burst that looked static, wait this long and probe again
    /// to catch time-based rotation. `None` disables timed probing.
    pub time_probe_interval: Option<Duration>,
    /// Number of timed probes to run when `time_probe_interval` is set.
    pub time_probe_count: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            samples: 4,
            time_probe_interval: None,
            time_probe_count: 2,
        }
    }
}

/// How a proxy's exit IP behaves across requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationKind {
    /// Same exit IP on every successful request.
    Static,
    /// A distinct exit IP on every successful request.
    PerRequest,
    /// The exit IP changes, but not on every request.
    Rotating,
    /// Stable within the burst; a later timed probe saw a new IP.
    TimeBased,
    /// Could not be determined (no successful request).
    Unknown,
}

/// The outcome of rotation detection for one proxy.
#[derive(Debug, Clone, Serialize)]
pub struct RotationReport {
    pub kind: RotationKind,
    /// Distinct exit IPs observed, in first-seen order.
    pub observed_ips: Vec<String>,
    /// Number of requests that produced a usable exit IP.
    pub samples: usize,
}

/// Detects the rotation behavior of a single proxy.
pub async fn detect_rotation(
    endpoint: &ProxyEndpoint,
    protocol: Protocol,
    check: &CheckConfig,
    config: &RotationConfig,
) -> RotationReport {
    // Records a sampled IP: counts the success and tracks distinct IPs in
    // first-seen order.
    fn record(
        ip: Option<String>,
        order: &mut Vec<String>,
        seen: &mut HashSet<String>,
        successful: &mut usize,
    ) {
        if let Some(ip) = ip {
            *successful += 1;
            if seen.insert(ip.clone()) {
                order.push(ip);
            }
        }
    }

    let mut order: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut successful = 0usize;

    // Burst phase: sequential requests through the same proxy.
    for _ in 0..config.samples.max(1) {
        let ip = fetch_exit_ip(endpoint, protocol, check).await;
        record(ip, &mut order, &mut seen, &mut successful);
    }

    if successful == 0 {
        return RotationReport {
            kind: RotationKind::Unknown,
            observed_ips: order,
            samples: 0,
        };
    }

    let burst_unique = order.len();
    if burst_unique >= 2 {
        let kind = if burst_unique == successful {
            RotationKind::PerRequest
        } else {
            RotationKind::Rotating
        };
        return RotationReport {
            kind,
            observed_ips: order,
            samples: successful,
        };
    }

    // Stable within the burst: optionally probe over time for slow rotation.
    if let Some(interval) = config.time_probe_interval {
        for _ in 0..config.time_probe_count.max(1) {
            sleep(interval).await;
            let ip = fetch_exit_ip(endpoint, protocol, check).await;
            record(ip, &mut order, &mut seen, &mut successful);
        }
        if order.len() >= 2 {
            return RotationReport {
                kind: RotationKind::TimeBased,
                observed_ips: order,
                samples: successful,
            };
        }
    }

    RotationReport {
        kind: RotationKind::Static,
        observed_ips: order,
        samples: successful,
    }
}

/// Detects rotation for many proxies concurrently, bounded by `concurrency`.
///
/// Each proxy's own requests stay sequential (rotation must be observed in
/// order); only different proxies run in parallel. Results are returned in
/// input order.
pub async fn detect_rotation_many(
    targets: Vec<(ProxyEndpoint, Protocol)>,
    check: CheckConfig,
    config: RotationConfig,
    concurrency: usize,
) -> Vec<(ProxyEndpoint, RotationReport)> {
    let check = Arc::new(check);
    let config = Arc::new(config);
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for (index, (endpoint, protocol)) in targets.into_iter().enumerate() {
        let check = Arc::clone(&check);
        let config = Arc::clone(&config);
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let _permit = semaphore.acquire().await.expect("semaphore is open");
            let report = detect_rotation(&endpoint, protocol, &check, &config).await;
            (index, endpoint, report)
        });
    }

    let mut results: Vec<Option<(ProxyEndpoint, RotationReport)>> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (index, endpoint, report) = joined.expect("rotation task panicked");
        if index >= results.len() {
            results.resize_with(index + 1, || None);
        }
        results[index] = Some((endpoint, report));
    }

    results.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawns a mock HTTP proxy whose echoed exit IP is produced by `ip_for`,
    /// called with a 0-based request counter. Returns the listen address.
    async fn spawn_proxy<F>(ip_for: F) -> std::net::SocketAddr
    where
        F: Fn(usize) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let counter = Arc::clone(&counter);
                let ip = ip_for(counter.fetch_add(1, Ordering::SeqCst));
                tokio::spawn(async move {
                    let mut scratch = [0u8; 1024];
                    let _ = sock.read(&mut scratch).await;
                    let body = format!(r#"{{"origin": "{ip}"}}"#);
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

    fn fast_check() -> CheckConfig {
        CheckConfig {
            judge_url: "http://judge.example/get".to_string(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            local_ip: None,
        }
    }

    fn burst(samples: usize) -> RotationConfig {
        RotationConfig {
            samples,
            time_probe_interval: None,
            time_probe_count: 0,
        }
    }

    #[tokio::test]
    async fn classifies_static() {
        let addr = spawn_proxy(|_| "203.0.113.10".to_string()).await;
        let endpoint = ProxyEndpoint::new(addr.ip().to_string(), addr.port());
        let report = detect_rotation(&endpoint, Protocol::Http, &fast_check(), &burst(4)).await;
        assert_eq!(report.kind, RotationKind::Static);
        assert_eq!(report.observed_ips, vec!["203.0.113.10"]);
        assert_eq!(report.samples, 4);
    }

    #[tokio::test]
    async fn classifies_per_request() {
        let addr = spawn_proxy(|n| format!("203.0.113.{}", n + 1)).await;
        let endpoint = ProxyEndpoint::new(addr.ip().to_string(), addr.port());
        let report = detect_rotation(&endpoint, Protocol::Http, &fast_check(), &burst(4)).await;
        assert_eq!(report.kind, RotationKind::PerRequest);
        assert_eq!(report.observed_ips.len(), 4);
    }

    #[tokio::test]
    async fn classifies_rotating_pool() {
        // Alternates between two IPs -> changes, but not every request.
        let addr = spawn_proxy(|n| format!("203.0.113.{}", n % 2)).await;
        let endpoint = ProxyEndpoint::new(addr.ip().to_string(), addr.port());
        let report = detect_rotation(&endpoint, Protocol::Http, &fast_check(), &burst(4)).await;
        assert_eq!(report.kind, RotationKind::Rotating);
        assert_eq!(report.observed_ips.len(), 2);
        assert_eq!(report.samples, 4);
    }

    #[tokio::test]
    async fn dead_proxy_is_unknown() {
        let endpoint = ProxyEndpoint::new("203.0.113.250", 9); // discard port, unreachable
        let report = detect_rotation(&endpoint, Protocol::Http, &fast_check(), &burst(2)).await;
        assert_eq!(report.kind, RotationKind::Unknown);
        assert_eq!(report.samples, 0);
    }
}
