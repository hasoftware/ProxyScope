//! GeoIP lookup for proxy exit IPs.
//!
//! Resolution is offline-first: a GeoLite2 (`.mmdb`) database is consulted via
//! [`maxminddb`] when available, falling back to an HTTP lookup against
//! ip-api.com only when explicitly allowed. The database is never bundled with
//! ProxyScope — the user supplies its path.

use std::net::IpAddr;
use std::path::Path;

use maxminddb::{geoip2, Reader};
use serde::Serialize;

/// Geographic information derived from a proxy's exit IP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GeoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl GeoInfo {
    fn is_empty(&self) -> bool {
        self.country_code.is_none() && self.country_name.is_none() && self.region.is_none()
    }
}

/// GeoIP resolver combining an optional offline database with an optional
/// HTTP fallback.
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
    allow_http_fallback: bool,
}

impl GeoIp {
    /// Opens the resolver. A missing or unreadable `mmdb_path` simply disables
    /// the offline path; it is not an error.
    pub fn new(mmdb_path: Option<&Path>, allow_http_fallback: bool) -> Self {
        let reader = mmdb_path.and_then(|path| Reader::open_readfile(path).ok());
        Self {
            reader,
            allow_http_fallback,
        }
    }

    /// Whether an offline GeoLite2 database was successfully loaded.
    pub fn has_database(&self) -> bool {
        self.reader.is_some()
    }

    /// Offline-only lookup. Returns `None` if there is no database or no match.
    pub fn lookup_offline(&self, ip: IpAddr) -> Option<GeoInfo> {
        let reader = self.reader.as_ref()?;
        let city: geoip2::City = reader.lookup(ip).ok()?;

        let mut info = GeoInfo::default();
        if let Some(country) = city.country {
            info.country_code = country.iso_code.map(str::to_string);
            info.country_name = country
                .names
                .and_then(|names| names.get("en").map(|name| name.to_string()));
        }
        if let Some(region) = city
            .subdivisions
            .as_ref()
            .and_then(|subs| subs.first())
            .and_then(|sub| sub.names.as_ref())
            .and_then(|names| names.get("en"))
        {
            info.region = Some(region.to_string());
        }

        if info.is_empty() {
            None
        } else {
            Some(info)
        }
    }

    /// Full lookup: offline first, then the HTTP fallback when permitted.
    pub async fn lookup(&self, ip: IpAddr, http: &reqwest::Client) -> Option<GeoInfo> {
        if let Some(info) = self.lookup_offline(ip) {
            return Some(info);
        }
        if self.allow_http_fallback {
            return http_lookup(ip, http).await;
        }
        None
    }
}

async fn http_lookup(ip: IpAddr, http: &reqwest::Client) -> Option<GeoInfo> {
    let url = format!("http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName");
    let json: serde_json::Value = http.get(url).send().await.ok()?.json().await.ok()?;

    if json.get("status").and_then(serde_json::Value::as_str) != Some("success") {
        return None;
    }

    let take = |key: &str| {
        json.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let info = GeoInfo {
        country_code: take("countryCode"),
        country_name: take("country"),
        region: take("regionName"),
    };

    if info.is_empty() {
        None
    } else {
        Some(info)
    }
}
