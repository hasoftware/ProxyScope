//! Proxy list parsing.
//!
//! Accepts the common formats found in proxy lists:
//! - `host:port`
//! - `host:port:user:pass`
//! - `scheme://[user:pass@]host:port` (http, https, socks4(a), socks5(h))
//! - `user:pass@host:port` (no scheme)
//! - `tg://proxy?server=..&port=..&secret=..` and `https://t.me/proxy?...`
//!   MTProxy links
//!
//! Blank lines and `#` comments are skipped by [`parse_proxies`].
//!
//! IPv6 hosts must be bracketed (`[::1]:1080`) and are only supported in the
//! scheme/userinfo forms; the bare colon-delimited forms assume IPv4 or
//! hostnames. TODO: broaden IPv6 support across all input shapes.

use crate::proxy::{ParseError, Protocol, ProxyEndpoint};

/// The outcome of parsing one input line, paired with its source location.
#[derive(Debug, Clone)]
pub struct ParsedLine {
    /// 1-based line number within the original input.
    pub line_number: usize,
    /// The original (trimmed) line text.
    pub raw: String,
    /// Parsed endpoint, or the reason parsing failed.
    pub result: Result<ProxyEndpoint, ParseError>,
}

/// Parses a multi-line proxy list.
///
/// Blank lines and lines beginning with `#` are skipped entirely. Every other
/// line yields one [`ParsedLine`], whose `result` is `Ok` or a [`ParseError`].
pub fn parse_proxies(input: &str) -> Vec<ParsedLine> {
    input
        .lines()
        .enumerate()
        .filter_map(|(idx, raw)| {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            Some(ParsedLine {
                line_number: idx + 1,
                raw: trimmed.to_string(),
                result: parse_line(trimmed),
            })
        })
        .collect()
}

/// Parses a single proxy line into a [`ProxyEndpoint`].
pub fn parse_line(raw: &str) -> Result<ProxyEndpoint, ParseError> {
    let line = raw.trim();
    if line.is_empty() {
        return Err(ParseError::Empty);
    }

    if is_mtproxy_link(line) {
        return parse_mtproxy(line);
    }

    if let Some(scheme_end) = line.find("://") {
        return parse_scheme_url(line, scheme_end);
    }

    // `user:pass@host:port` without an explicit scheme.
    if let Some((creds, addr)) = line.rsplit_once('@') {
        let (host, port) = split_host_port(addr)?;
        let (username, password) = split_credentials(creds);
        return Ok(ProxyEndpoint {
            host,
            port,
            username,
            password,
            scheme_hint: None,
            mtproxy_secret: None,
        });
    }

    parse_colon_delimited(line)
}

fn is_mtproxy_link(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("tg://")
        || lower.contains("t.me/proxy")
        || lower.contains("telegram.me/proxy")
}

fn parse_mtproxy(line: &str) -> Result<ProxyEndpoint, ParseError> {
    let query = line
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or_else(|| ParseError::Malformed("MTProxy link has no query string".into()))?;

    let mut server = None;
    let mut port = None;
    let mut secret = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "server" => server = Some(value.to_string()),
            "port" => port = Some(value.to_string()),
            "secret" => secret = Some(value.to_string()),
            _ => {}
        }
    }

    let host = server.ok_or(ParseError::MissingHost)?;
    let port = parse_port(&port.ok_or(ParseError::MissingPort)?)?;

    Ok(ProxyEndpoint {
        host,
        port,
        username: None,
        password: None,
        scheme_hint: Some(Protocol::MtProxy),
        mtproxy_secret: secret,
    })
}

fn parse_scheme_url(line: &str, scheme_end: usize) -> Result<ProxyEndpoint, ParseError> {
    let scheme = line[..scheme_end].to_ascii_lowercase();
    let protocol = match scheme.as_str() {
        "http" => Protocol::Http,
        "https" => Protocol::Https,
        "socks5" | "socks5h" => Protocol::Socks5,
        "socks4" | "socks4a" => Protocol::Socks4,
        other => return Err(ParseError::UnsupportedScheme(other.to_string())),
    };

    let rest = &line[scheme_end + 3..];
    // Keep only the authority component; drop any trailing path/query.
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);

    let (creds, addr) = match authority.rsplit_once('@') {
        Some((c, a)) => (Some(c), a),
        None => (None, authority),
    };

    let (host, port) = split_host_port(addr)?;
    let (username, password) = match creds {
        Some(c) => split_credentials(c),
        None => (None, None),
    };

    Ok(ProxyEndpoint {
        host,
        port,
        username,
        password,
        scheme_hint: Some(protocol),
        mtproxy_secret: None,
    })
}

fn parse_colon_delimited(line: &str) -> Result<ProxyEndpoint, ParseError> {
    let parts: Vec<&str> = line.split(':').collect();
    match parts.as_slice() {
        [host, port] => {
            let (host, port) = make_host_port(host, port)?;
            Ok(ProxyEndpoint::new(host, port))
        }
        [host, port, user, pass] => {
            let (host, port) = make_host_port(host, port)?;
            Ok(ProxyEndpoint {
                host,
                port,
                username: Some((*user).to_string()),
                password: Some((*pass).to_string()),
                scheme_hint: None,
                mtproxy_secret: None,
            })
        }
        // A single field with no colon is a host missing its port.
        [_] => Err(ParseError::MissingPort),
        _ => Err(ParseError::Malformed(format!(
            "expected host:port or host:port:user:pass, got {} fields",
            parts.len()
        ))),
    }
}

/// Splits a `host:port` authority, supporting bracketed IPv6 (`[::1]:1080`).
fn split_host_port(addr: &str) -> Result<(String, u16), ParseError> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| ParseError::Malformed("unterminated IPv6 bracket".into()))?;
        let port = after.strip_prefix(':').ok_or(ParseError::MissingPort)?;
        return make_host_port(host, port);
    }

    let (host, port) = addr.rsplit_once(':').ok_or(ParseError::MissingPort)?;
    make_host_port(host, port)
}

fn make_host_port(host: &str, port: &str) -> Result<(String, u16), ParseError> {
    if host.is_empty() {
        return Err(ParseError::MissingHost);
    }
    Ok((host.to_string(), parse_port(port)?))
}

fn parse_port(port: &str) -> Result<u16, ParseError> {
    if port.is_empty() {
        return Err(ParseError::MissingPort);
    }
    port.parse::<u16>()
        .map_err(|_| ParseError::InvalidPort(port.to_string()))
}

/// Splits a `user:pass` credential string. A missing password yields `None`.
fn split_credentials(creds: &str) -> (Option<String>, Option<String>) {
    match creds.split_once(':') {
        Some((user, pass)) => (Some(user.to_string()), Some(pass.to_string())),
        None => (Some(creds.to_string()), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port() {
        let ep = parse_line("1.2.3.4:8080").unwrap();
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.port, 8080);
        assert!(!ep.has_credentials());
        assert_eq!(ep.scheme_hint, None);
    }

    #[test]
    fn host_port_user_pass() {
        let ep = parse_line("1.2.3.4:8080:alice:s3cret").unwrap();
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.port, 8080);
        assert_eq!(ep.username.as_deref(), Some("alice"));
        assert_eq!(ep.password.as_deref(), Some("s3cret"));
    }

    #[test]
    fn scheme_with_credentials() {
        let ep = parse_line("socks5://bob:pw@10.0.0.1:1080").unwrap();
        assert_eq!(ep.host, "10.0.0.1");
        assert_eq!(ep.port, 1080);
        assert_eq!(ep.username.as_deref(), Some("bob"));
        assert_eq!(ep.password.as_deref(), Some("pw"));
        assert_eq!(ep.scheme_hint, Some(Protocol::Socks5));
    }

    #[test]
    fn scheme_aliases() {
        assert_eq!(
            parse_line("socks5h://h:1080").unwrap().scheme_hint,
            Some(Protocol::Socks5)
        );
        assert_eq!(
            parse_line("socks4a://h:1080").unwrap().scheme_hint,
            Some(Protocol::Socks4)
        );
        assert_eq!(
            parse_line("https://h:443").unwrap().scheme_hint,
            Some(Protocol::Https)
        );
    }

    #[test]
    fn scheme_strips_trailing_path() {
        let ep = parse_line("http://user:pass@host.example:3128/some/path").unwrap();
        assert_eq!(ep.host, "host.example");
        assert_eq!(ep.port, 3128);
        assert_eq!(ep.username.as_deref(), Some("user"));
    }

    #[test]
    fn userinfo_without_scheme() {
        let ep = parse_line("user:pass@1.2.3.4:8080").unwrap();
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.port, 8080);
        assert_eq!(ep.username.as_deref(), Some("user"));
        assert_eq!(ep.password.as_deref(), Some("pass"));
        assert_eq!(ep.scheme_hint, None);
    }

    #[test]
    fn bracketed_ipv6_with_scheme() {
        let ep = parse_line("socks5://[2001:db8::1]:1080").unwrap();
        assert_eq!(ep.host, "2001:db8::1");
        assert_eq!(ep.port, 1080);
    }

    #[test]
    fn mtproxy_tg_link() {
        let ep = parse_line("tg://proxy?server=1.2.3.4&port=443&secret=ee00112233").unwrap();
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.scheme_hint, Some(Protocol::MtProxy));
        assert_eq!(ep.mtproxy_secret.as_deref(), Some("ee00112233"));
        assert!(ep.is_mtproxy());
    }

    #[test]
    fn mtproxy_t_me_link() {
        let ep = parse_line("https://t.me/proxy?server=h.example&port=8888&secret=dd99").unwrap();
        assert_eq!(ep.host, "h.example");
        assert_eq!(ep.port, 8888);
        assert!(ep.is_mtproxy());
    }

    #[test]
    fn invalid_port() {
        assert!(matches!(
            parse_line("1.2.3.4:notaport"),
            Err(ParseError::InvalidPort(_))
        ));
        assert!(matches!(
            parse_line("1.2.3.4:99999"),
            Err(ParseError::InvalidPort(_))
        ));
    }

    #[test]
    fn missing_port() {
        assert!(matches!(
            parse_line("1.2.3.4"),
            Err(ParseError::MissingPort)
        ));
    }

    #[test]
    fn unsupported_scheme() {
        assert!(matches!(
            parse_line("ftp://h:21"),
            Err(ParseError::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn malformed_field_count() {
        assert!(matches!(parse_line("a:b:c"), Err(ParseError::Malformed(_))));
    }

    #[test]
    fn list_skips_blanks_and_comments() {
        let input = "\
# a comment
1.2.3.4:8080

  # indented comment
socks5://h:1080
bad line here
";
        let parsed = parse_proxies(input);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].line_number, 2);
        assert!(parsed[0].result.is_ok());
        assert!(parsed[1].result.is_ok());
        assert!(parsed[2].result.is_err());
    }
}
