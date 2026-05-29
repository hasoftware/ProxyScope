//! Protocol auto-detection via raw handshakes.
//!
//! Each proxy is probed in a fixed order — SOCKS5, SOCKS4, HTTP `CONNECT`,
//! then plain HTTP — and classified by the first probe that the server speaks.
//! Every probe uses its own short-lived TCP connection because a handshake
//! consumes the stream.
//!
//! Detection is intentionally tolerant of authentication: a SOCKS5 server that
//! demands credentials still answers the greeting with version byte `0x05`,
//! and an HTTP proxy that returns `407 Proxy Authentication Required` still
//! replies with an `HTTP/` status line — both are enough to classify the
//! protocol. The actual auth round-trip is exercised later, during the
//! quality checks.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::proxy::{Protocol, ProxyEndpoint};

/// Tunables for protocol detection.
#[derive(Debug, Clone)]
pub struct DetectConfig {
    /// Maximum time to establish each TCP connection.
    pub connect_timeout: Duration,
    /// Maximum time for each read/write within a handshake.
    pub io_timeout: Duration,
    /// Hostname used to exercise the HTTP `CONNECT` and plain-HTTP probes.
    pub probe_host: String,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(8),
            io_timeout: Duration::from_secs(8),
            probe_host: "example.com".to_string(),
        }
    }
}

/// Result of detecting a single proxy's protocol.
#[derive(Debug, Clone, Serialize)]
pub struct DetectionOutcome {
    /// The detected protocol, or `None` if no probe succeeded.
    pub protocol: Option<Protocol>,
    /// The last error encountered while probing, if any (for diagnostics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DetectionOutcome {
    fn detected(protocol: Protocol) -> Self {
        Self {
            protocol: Some(protocol),
            error: None,
        }
    }

    fn undetected(error: Option<String>) -> Self {
        Self {
            protocol: None,
            error,
        }
    }
}

/// Detects the protocol of a single proxy endpoint.
///
/// MTProxy entries are reported from their input format without a network
/// probe; active MTProto probing is out of scope for now.
pub async fn detect_protocol(endpoint: &ProxyEndpoint, config: &DetectConfig) -> DetectionOutcome {
    // TODO: actively probe the MTProto handshake instead of trusting the link.
    if endpoint.is_mtproxy() {
        return DetectionOutcome::detected(Protocol::MtProxy);
    }

    let mut last_error = None;

    // Probes are tried in order; the first one the server speaks wins. Each
    // `Err` is a transport failure for that probe only, recorded for context.
    macro_rules! try_probe {
        ($protocol:expr, $probe:expr) => {
            match $probe.await {
                Ok(true) => return DetectionOutcome::detected($protocol),
                Ok(false) => {}
                Err(err) => last_error = Some(err.to_string()),
            }
        };
    }

    try_probe!(Protocol::Socks5, run_socks5(endpoint, config));
    try_probe!(Protocol::Socks4, run_socks4(endpoint, config));
    try_probe!(Protocol::Https, run_http_connect(endpoint, config));
    try_probe!(Protocol::Http, run_http_plain(endpoint, config));

    DetectionOutcome::undetected(last_error)
}

/// Detects protocols for many endpoints concurrently, bounded by `concurrency`.
///
/// Results are returned in the same order as the input. This is a stepping
/// stone for Phase 2's quality checks; Phase 4 will stream results to the UI
/// instead of returning them as a batch.
pub async fn detect_many(
    endpoints: Vec<ProxyEndpoint>,
    config: DetectConfig,
    concurrency: usize,
) -> Vec<(ProxyEndpoint, DetectionOutcome)> {
    let config = Arc::new(config);
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for (index, endpoint) in endpoints.into_iter().enumerate() {
        let config = Arc::clone(&config);
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            // The semaphore is only closed when dropped, so acquire never fails.
            let _permit = semaphore.acquire().await.expect("semaphore is open");
            let outcome = detect_protocol(&endpoint, &config).await;
            (index, endpoint, outcome)
        });
    }

    let mut results: Vec<Option<(ProxyEndpoint, DetectionOutcome)>> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (index, endpoint, outcome) = joined.expect("detection task panicked");
        if index >= results.len() {
            results.resize_with(index + 1, || None);
        }
        results[index] = Some((endpoint, outcome));
    }

    results.into_iter().flatten().collect()
}

async fn connect(endpoint: &ProxyEndpoint, config: &DetectConfig) -> io::Result<TcpStream> {
    match timeout(
        config.connect_timeout,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
}

/// SOCKS5: send a no-auth greeting and check for a `0x05` version reply.
async fn run_socks5(endpoint: &ProxyEndpoint, config: &DetectConfig) -> io::Result<bool> {
    let mut stream = connect(endpoint, config).await?;
    // VER=5, NMETHODS=1, METHOD=0x00 (no authentication).
    timeout(config.io_timeout, stream.write_all(&[0x05, 0x01, 0x00])).await??;
    let mut reply = [0u8; 2];
    timeout(config.io_timeout, stream.read_exact(&mut reply)).await??;
    Ok(reply[0] == 0x05)
}

/// SOCKS4: send a CONNECT request and check for a `0x00` reply version byte.
async fn run_socks4(endpoint: &ProxyEndpoint, config: &DetectConfig) -> io::Result<bool> {
    let mut stream = connect(endpoint, config).await?;
    // VER=4, CMD=1 (CONNECT), DSTPORT=80, DSTIP=1.1.1.1, empty USERID, NULL.
    let request = [0x04, 0x01, 0x00, 0x50, 0x01, 0x01, 0x01, 0x01, 0x00];
    timeout(config.io_timeout, stream.write_all(&request)).await??;
    let mut reply = [0u8; 8];
    timeout(config.io_timeout, stream.read_exact(&mut reply)).await??;
    // A SOCKS4 reply always carries a null version byte followed by a status
    // in the 0x5A..=0x5D range.
    Ok(reply[0] == 0x00 && (0x5A..=0x5D).contains(&reply[1]))
}

/// HTTP `CONNECT`: an `HTTP/` status line means the proxy can tunnel TLS.
async fn run_http_connect(endpoint: &ProxyEndpoint, config: &DetectConfig) -> io::Result<bool> {
    let mut stream = connect(endpoint, config).await?;
    let request = format!(
        "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n",
        host = config.probe_host
    );
    timeout(config.io_timeout, stream.write_all(request.as_bytes())).await??;
    reply_starts_with_http(&mut stream, config).await
}

/// Plain HTTP: send an absolute-form request and look for an `HTTP/` reply.
async fn run_http_plain(endpoint: &ProxyEndpoint, config: &DetectConfig) -> io::Result<bool> {
    let mut stream = connect(endpoint, config).await?;
    let request = format!(
        "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n",
        host = config.probe_host
    );
    timeout(config.io_timeout, stream.write_all(request.as_bytes())).await??;
    reply_starts_with_http(&mut stream, config).await
}

async fn reply_starts_with_http(stream: &mut TcpStream, config: &DetectConfig) -> io::Result<bool> {
    let mut buf = [0u8; 16];
    let n = timeout(config.io_timeout, stream.read(&mut buf)).await??;
    Ok(buf[..n].starts_with(b"HTTP/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn fast_config(probe_host: &str) -> DetectConfig {
        DetectConfig {
            connect_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(2),
            probe_host: probe_host.to_string(),
        }
    }

    #[tokio::test]
    async fn mtproxy_is_reported_without_probing() {
        let mut ep = ProxyEndpoint::new("1.2.3.4", 443);
        ep.scheme_hint = Some(Protocol::MtProxy);
        let outcome = detect_protocol(&ep, &fast_config("example.com")).await;
        assert_eq!(outcome.protocol, Some(Protocol::MtProxy));
    }

    #[tokio::test]
    async fn detects_socks5_against_mock() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            // Reply: VER=5, METHOD=0x00 (no auth).
            sock.write_all(&[0x05, 0x00]).await.unwrap();
        });

        let ep = ProxyEndpoint::new(addr.ip().to_string(), addr.port());
        let outcome = detect_protocol(&ep, &fast_config("example.com")).await;
        assert_eq!(outcome.protocol, Some(Protocol::Socks5));
    }

    #[tokio::test]
    async fn detects_http_connect_as_https() {
        // A server that answers every connection with an HTTP status line is
        // not SOCKS5/4, so detection falls through to the CONNECT probe.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut scratch = [0u8; 64];
                    let _ = sock.read(&mut scratch).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                });
            }
        });

        let ep = ProxyEndpoint::new(addr.ip().to_string(), addr.port());
        let outcome = detect_protocol(&ep, &fast_config("example.com")).await;
        assert_eq!(outcome.protocol, Some(Protocol::Https));
    }

    #[tokio::test]
    async fn detect_many_preserves_order() {
        let endpoints = vec![
            ProxyEndpoint::new("203.0.113.1", 1),
            ProxyEndpoint::new("203.0.113.2", 2),
            ProxyEndpoint::new("203.0.113.3", 3),
        ];
        let results = detect_many(endpoints.clone(), fast_config("example.com"), 8).await;
        let hosts: Vec<_> = results.iter().map(|(ep, _)| ep.host.clone()).collect();
        assert_eq!(hosts, vec!["203.0.113.1", "203.0.113.2", "203.0.113.3"]);
    }
}
