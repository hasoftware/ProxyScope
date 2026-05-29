//! ProxyScope core library.
//!
//! This crate holds all UI-agnostic logic: proxy list parsing, protocol
//! auto-detection, and (in later phases) the concurrent quality checks. It
//! deliberately has no dependency on Tauri or any UI layer so the logic can be
//! unit-tested and reused independently of the desktop shell.

pub mod detect;
pub mod parse;
pub mod proxy;

pub use detect::{detect_many, detect_protocol, DetectConfig, DetectionOutcome};
pub use parse::{parse_line, parse_proxies, ParsedLine};
pub use proxy::{ParseError, Protocol, ProxyEndpoint};

/// The core library version, surfaced to the UI for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }
}
