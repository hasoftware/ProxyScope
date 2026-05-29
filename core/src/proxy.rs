//! Core proxy data types shared across parsing, detection, and checking.

use serde::{Deserialize, Serialize};

/// Proxy protocol classification.
///
/// `Https` denotes an HTTP proxy that accepts the `CONNECT` method (and can
/// therefore tunnel TLS), as distinct from a plain `Http` forward proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
    Socks4,
    Socks5,
    /// MTProxy (MTProto). Recognized by input format only for now; ProxyScope
    /// does not yet actively probe the MTProto handshake.
    MtProxy,
}

impl Protocol {
    /// Lowercase wire name, e.g. `"socks5"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Socks4 => "socks4",
            Protocol::Socks5 => "socks5",
            Protocol::MtProxy => "mtproxy",
        }
    }
}

/// A single parsed proxy entry.
///
/// The `scheme_hint` records the protocol implied by the input (e.g. a
/// `socks5://` prefix), but protocol *detection* via handshakes is always
/// authoritative — the hint is only a starting guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme_hint: Option<Protocol>,
    /// MTProxy secret, present only for `tg://`/`t.me` proxy links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtproxy_secret: Option<String>,
}

impl ProxyEndpoint {
    /// Builds a bare `host:port` endpoint with no credentials or hints.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            username: None,
            password: None,
            scheme_hint: None,
            mtproxy_secret: None,
        }
    }

    /// `host:port` string for connecting or display.
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Whether this entry came from an MTProxy link.
    pub fn is_mtproxy(&self) -> bool {
        matches!(self.scheme_hint, Some(Protocol::MtProxy))
    }

    /// Whether credentials are attached.
    pub fn has_credentials(&self) -> bool {
        self.username.is_some()
    }
}

/// Why a single input line could not be parsed into a [`ProxyEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("empty line")]
    Empty,
    #[error("missing host")]
    MissingHost,
    #[error("missing port")]
    MissingPort,
    #[error("invalid port: {0:?}")]
    InvalidPort(String),
    #[error("unsupported scheme: {0:?}")]
    UnsupportedScheme(String),
    #[error("malformed proxy entry: {0}")]
    Malformed(String),
}
