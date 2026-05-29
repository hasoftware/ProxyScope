//! Concurrent per-proxy quality checks.
//!
//! Each proxy is exercised by fetching a *judge* endpoint through it — a URL
//! that echoes the requester's IP and the request headers it observed. From a
//! single round-trip we derive:
//! - alive/dead (did the judge respond `2xx` through the proxy?)
//! - exit IP (the address the judge saw)
//! - latency (connection time and full round-trip time)
//! - anonymity (which forwarding headers, if any, the proxy leaked)
//! - country/region (via [`crate::geoip`], from the exit IP)
//!
//! The judge is fetched over plain HTTP via raw sockets rather than `reqwest`,
//! because we need to (a) support SOCKS4 (which `reqwest` cannot proxy through),
//! (b) measure connection time in isolation, and (c) read the headers the judge
//! echoes back. `tokio-socks` drives the SOCKS handshakes; HTTP proxies receive
//! a standard absolute-form request. `reqwest` is still used for the direct
//! (non-proxied) own-IP and GeoIP-fallback calls.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_socks::tcp::{Socks4Stream, Socks5Stream};

use crate::geoip::{GeoInfo, GeoIp};
use crate::proxy::{Protocol, ProxyEndpoint};

const USER_AGENT: &str = concat!("ProxyScope/", env!("CARGO_PKG_VERSION"));
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Tunables for the quality checks.
#[derive(Debug, Clone)]
pub struct CheckConfig {
    /// Plain-HTTP judge URL that echoes the requester IP and headers.
    pub judge_url: String,
    /// Maximum time to establish the proxy connection.
    pub connect_timeout: Duration,
    /// Maximum time for the judge request/response after connecting.
    pub request_timeout: Duration,
    /// Our own public IP, used to flag transparent proxies. When `None`,
    /// transparent detection is skipped (see [`detect_local_ip`]).
    pub local_ip: Option<String>,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            judge_url: "http://httpbin.org/get".to_string(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(15),
            local_ip: None,
        }
    }
}

/// Anonymity classification based on the forwarding headers a proxy leaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Anonymity {
    /// The proxy forwarded our real IP.
    Transparent,
    /// The proxy advertised itself (e.g. `Via`) but hid our real IP.
    Anonymous,
    /// No proxy headers and our IP is hidden.
    Elite,
}

/// The full result of checking one proxy.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyReport {
    pub endpoint: ProxyEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    pub alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymity: Option<Anonymity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProxyReport {
    fn dead(endpoint: ProxyEndpoint, protocol: Option<Protocol>, error: impl Into<String>) -> Self {
        Self {
            endpoint,
            protocol,
            alive: false,
            exit_ip: None,
            geo: None,
            connect_ms: None,
            rtt_ms: None,
            anonymity: None,
            error: Some(error.into()),
        }
    }
}

/// Shared context for a batch of checks.
pub struct CheckContext {
    pub config: CheckConfig,
    pub geoip: GeoIp,
    pub http: reqwest::Client,
}

impl CheckContext {
    /// Builds a context with a default `reqwest` client for the direct
    /// (non-proxied) own-IP and GeoIP-fallback calls.
    pub fn new(config: CheckConfig, geoip: GeoIp) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.connect_timeout + config.request_timeout)
            .build()
            .unwrap_or_default();
        Self {
            config,
            geoip,
            http,
        }
    }
}

/// Checks a single proxy and produces a [`ProxyReport`].
pub async fn check_proxy(
    endpoint: ProxyEndpoint,
    protocol: Option<Protocol>,
    ctx: &CheckContext,
) -> ProxyReport {
    let Some(proto) = protocol else {
        return ProxyReport::dead(endpoint, None, "protocol not detected");
    };

    let probe = match run_check(&endpoint, proto, &ctx.config).await {
        Ok(probe) => probe,
        Err(err) => return ProxyReport::dead(endpoint, Some(proto), err),
    };

    let alive = (200..300).contains(&probe.status);
    if !alive {
        let mut report = ProxyReport::dead(
            endpoint,
            Some(proto),
            format!("judge returned HTTP {}", probe.status),
        );
        report.connect_ms = Some(probe.connect_ms);
        report.rtt_ms = Some(probe.rtt_ms);
        return report;
    }

    let exit_ip = extract_exit_ip(&probe.body);
    let anonymity = classify_anonymity(&probe.body, ctx.config.local_ip.as_deref());

    let geo = match exit_ip.as_deref().and_then(|ip| ip.parse().ok()) {
        Some(ip) => ctx.geoip.lookup(ip, &ctx.http).await,
        None => None,
    };

    ProxyReport {
        endpoint,
        protocol: Some(proto),
        alive: true,
        exit_ip,
        geo,
        connect_ms: Some(probe.connect_ms),
        rtt_ms: Some(probe.rtt_ms),
        anonymity: Some(anonymity),
        error: None,
    }
}

/// Checks many proxies concurrently, bounded by `concurrency`.
///
/// Results are returned in input order. TODO (Phase 4): stream each
/// [`ProxyReport`] to the UI via Tauri events instead of batching.
pub async fn check_many(
    targets: Vec<(ProxyEndpoint, Option<Protocol>)>,
    ctx: Arc<CheckContext>,
    concurrency: usize,
) -> Vec<ProxyReport> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for (index, (endpoint, protocol)) in targets.into_iter().enumerate() {
        let ctx = Arc::clone(&ctx);
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let _permit = semaphore.acquire().await.expect("semaphore is open");
            let report = check_proxy(endpoint, protocol, &ctx).await;
            (index, report)
        });
    }

    let mut results: Vec<Option<ProxyReport>> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (index, report) = joined.expect("check task panicked");
        if index >= results.len() {
            results.resize_with(index + 1, || None);
        }
        results[index] = Some(report);
    }

    results.into_iter().flatten().collect()
}

/// Detects our own public IP by querying the judge directly (no proxy).
pub async fn detect_local_ip(judge_url: &str, http: &reqwest::Client) -> Option<String> {
    let body = http.get(judge_url).send().await.ok()?.text().await.ok()?;
    extract_exit_ip(&body)
}

struct Probe {
    status: u16,
    body: String,
    connect_ms: u64,
    rtt_ms: u64,
}

async fn run_check(
    endpoint: &ProxyEndpoint,
    protocol: Protocol,
    config: &CheckConfig,
) -> Result<Probe, String> {
    let (judge_host, judge_port, judge_path) = parse_http_judge(&config.judge_url)?;
    let started = Instant::now();

    let (status, body, connect_ms) = match protocol {
        Protocol::Socks5 => {
            let proxy = (endpoint.host.as_str(), endpoint.port);
            let target = (judge_host.as_str(), judge_port);
            let connect = async {
                match (&endpoint.username, &endpoint.password) {
                    (Some(user), Some(pass)) => {
                        Socks5Stream::connect_with_password(proxy, target, user, pass).await
                    }
                    _ => Socks5Stream::connect(proxy, target).await,
                }
            };
            let stream = timeout(config.connect_timeout, connect)
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|err| err.to_string())?;
            let connect_ms = elapsed_ms(started);
            let request = origin_form_request(&judge_path, &judge_host);
            let resp = talk(stream, request, config.request_timeout).await?;
            (resp.status, resp.body, connect_ms)
        }
        Protocol::Socks4 => {
            let proxy = (endpoint.host.as_str(), endpoint.port);
            let target = (judge_host.as_str(), judge_port);
            let connect = async {
                match &endpoint.username {
                    Some(user) => Socks4Stream::connect_with_userid(proxy, target, user).await,
                    None => Socks4Stream::connect(proxy, target).await,
                }
            };
            let stream = timeout(config.connect_timeout, connect)
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|err| err.to_string())?;
            let connect_ms = elapsed_ms(started);
            let request = origin_form_request(&judge_path, &judge_host);
            let resp = talk(stream, request, config.request_timeout).await?;
            (resp.status, resp.body, connect_ms)
        }
        Protocol::Http | Protocol::Https => {
            let stream = timeout(
                config.connect_timeout,
                TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
            )
            .await
            .map_err(|_| "connect timed out".to_string())?
            .map_err(|err| err.to_string())?;
            let connect_ms = elapsed_ms(started);
            let request = absolute_form_request(&judge_host, judge_port, &judge_path, endpoint);
            let resp = talk(stream, request, config.request_timeout).await?;
            (resp.status, resp.body, connect_ms)
        }
        Protocol::MtProxy => {
            return Err("MTProxy quality checks are not supported yet".to_string());
        }
    };

    Ok(Probe {
        status,
        body,
        connect_ms,
        rtt_ms: elapsed_ms(started),
    })
}

struct RawResponse {
    status: u16,
    body: String,
}

/// Sends `request` over an established stream and reads the full reply.
async fn talk<S>(
    mut stream: S,
    request: String,
    request_timeout: Duration,
) -> Result<RawResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let exchange = async move {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = Vec::with_capacity(8192);
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() >= MAX_RESPONSE_BYTES {
                break;
            }
        }
        std::io::Result::Ok(buf)
    };

    let buf = timeout(request_timeout, exchange)
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|err: std::io::Error| err.to_string())?;

    parse_response(&buf).ok_or_else(|| "malformed HTTP response from judge".to_string())
}

fn elapsed_ms(since: Instant) -> u64 {
    since.elapsed().as_millis() as u64
}

fn parse_response(buf: &[u8]) -> Option<RawResponse> {
    let text = String::from_utf8_lossy(buf);
    let status_line = text.lines().next()?;
    // e.g. "HTTP/1.1 200 OK"
    let status = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Some(RawResponse { status, body })
}

fn origin_form_request(path: &str, host: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n"
    )
}

fn absolute_form_request(host: &str, port: u16, path: &str, endpoint: &ProxyEndpoint) -> String {
    let mut request = format!(
        "GET http://{host}:{port}{path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: */*\r\n\
         Proxy-Connection: close\r\n\
         Connection: close\r\n"
    );
    if let (Some(user), Some(pass)) = (&endpoint.username, &endpoint.password) {
        let token = base64_basic(&format!("{user}:{pass}"));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    request
}

/// Extracts the exit IP from a judge response body.
///
/// Recognizes httpbin's `origin` and generic `ip` JSON fields, then falls back
/// to the first IPv4 literal found anywhere in the body.
fn extract_exit_ip(body: &str) -> Option<String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(origin) = json.get("origin").and_then(serde_json::Value::as_str) {
            let first = origin.split(',').next().unwrap_or(origin).trim();
            return Some(first.to_string());
        }
        if let Some(ip) = json.get("ip").and_then(serde_json::Value::as_str) {
            return Some(ip.to_string());
        }
    }
    first_ipv4(body)
}

fn first_ipv4(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter(|token| !token.is_empty())
        .find_map(|token| token.parse::<Ipv4Addr>().ok().map(|ip| ip.to_string()))
}

/// Classifies anonymity by scanning the judge's echoed request headers.
fn classify_anonymity(body: &str, local_ip: Option<&str>) -> Anonymity {
    const FORWARDING_HEADERS: [&str; 6] = [
        "x-forwarded-for",
        "via",
        "forwarded",
        "x-real-ip",
        "client-ip",
        "x-proxy-id",
    ];

    let lowered = body.to_ascii_lowercase();
    let exposes_real_ip = local_ip.is_some_and(|ip| body.contains(ip));
    let has_forwarding = FORWARDING_HEADERS
        .iter()
        .any(|header| lowered.contains(header));

    if exposes_real_ip {
        Anonymity::Transparent
    } else if has_forwarding {
        Anonymity::Anonymous
    } else {
        Anonymity::Elite
    }
}

/// Minimal standard base64 encoder (for HTTP Basic proxy authorization).
fn base64_basic(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn parse_http_judge(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "judge URL must use plain http:// for proxied checks".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| format!("invalid judge port: {port:?}"))?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err("judge URL has no host".to_string());
    }
    Ok((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_basic("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_basic("a"), "YQ==");
        assert_eq!(base64_basic("ab"), "YWI=");
        assert_eq!(base64_basic("abc"), "YWJj");
    }

    #[test]
    fn parses_judge_url() {
        assert_eq!(
            parse_http_judge("http://httpbin.org/get").unwrap(),
            ("httpbin.org".to_string(), 80, "/get".to_string())
        );
        assert_eq!(
            parse_http_judge("http://10.0.0.1:8080").unwrap(),
            ("10.0.0.1".to_string(), 8080, "/".to_string())
        );
        assert!(parse_http_judge("https://secure.example/").is_err());
    }

    #[test]
    fn extracts_exit_ip_from_json_and_text() {
        assert_eq!(
            extract_exit_ip(r#"{"origin": "203.0.113.7"}"#).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            extract_exit_ip(r#"{"origin": "203.0.113.7, 198.51.100.2"}"#).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            extract_exit_ip("Your IP is 198.51.100.42 today").as_deref(),
            Some("198.51.100.42")
        );
        assert_eq!(extract_exit_ip("no address here"), None);
    }

    #[test]
    fn classifies_anonymity_levels() {
        let elite = r#"{"headers": {"Host": "j", "Accept": "*/*"}}"#;
        assert_eq!(classify_anonymity(elite, Some("1.2.3.4")), Anonymity::Elite);

        let anon = r#"{"headers": {"Via": "1.1 proxy", "Host": "j"}}"#;
        assert_eq!(
            classify_anonymity(anon, Some("1.2.3.4")),
            Anonymity::Anonymous
        );

        let transparent = r#"{"headers": {"X-Forwarded-For": "1.2.3.4"}, "origin": "9.9.9.9"}"#;
        assert_eq!(
            classify_anonymity(transparent, Some("1.2.3.4")),
            Anonymity::Transparent
        );
    }

    #[tokio::test]
    async fn checks_an_http_proxy_against_mock() {
        // A mock that behaves like an HTTP forward proxy: it accepts the
        // absolute-form request and replies with an httpbin-like JSON body.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            let body = r#"{"origin": "203.0.113.99", "headers": {"Host": "j"}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(response.as_bytes()).await;
        });

        let ctx = CheckContext {
            config: CheckConfig {
                judge_url: "http://judge.example/get".to_string(),
                connect_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(2),
                local_ip: Some("198.51.100.1".to_string()),
            },
            geoip: GeoIp::new(None, false),
            http: reqwest::Client::new(),
        };

        let endpoint = ProxyEndpoint::new(addr.ip().to_string(), addr.port());
        let report = check_proxy(endpoint, Some(Protocol::Http), &ctx).await;

        assert!(report.alive, "expected alive, error: {:?}", report.error);
        assert_eq!(report.exit_ip.as_deref(), Some("203.0.113.99"));
        assert_eq!(report.anonymity, Some(Anonymity::Elite));
        assert!(report.rtt_ms.is_some());
        assert!(report.connect_ms.is_some());
    }

    #[tokio::test]
    async fn unsupported_protocol_is_dead_not_panic() {
        let ctx = CheckContext {
            config: CheckConfig::default(),
            geoip: GeoIp::new(None, false),
            http: reqwest::Client::new(),
        };
        let endpoint = ProxyEndpoint::new("1.2.3.4", 443);
        let report = check_proxy(endpoint, Some(Protocol::MtProxy), &ctx).await;
        assert!(!report.alive);
        assert!(report.error.is_some());
    }
}
