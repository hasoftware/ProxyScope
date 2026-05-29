# ProxyScope

ProxyScope is a desktop proxy-checking tool. Paste a proxy list or import a
file, and ProxyScope auto-detects each proxy's protocol and reports its
quality: alive/dead status, exit IP, country, latency, anonymity level, and
rotation behavior.

> **Status:** early development. The scaffold is in place; proxy parsing,
> detection, and checking are being built phase by phase.

## Features (planned)

- **Input** — paste or import proxy lists in common formats:
  `ip:port`, `ip:port:user:pass`, `scheme://user:pass@ip:port`, and `tg://`
  links for MTProxy.
- **Protocol auto-detection** — HTTP / HTTPS / SOCKS4 / SOCKS5 via handshake
  probing (MTProxy detected by input format only, for now).
- **Quality checks** — alive/dead, exit IP, country/region (offline GeoLite2
  with an HTTP fallback), connect and round-trip latency, and anonymity level
  (transparent / anonymous / elite).
- **Rotation detection** — distinguish static, per-request rotating, and
  time-based rotating proxies.
- **Live results table** — rows stream in as each proxy is checked, with
  sorting, filtering, progress, and CSV/JSON export.

## Tech stack

- **Backend:** Rust (async, `tokio`)
- **Desktop shell:** Tauri v2
- **HTTP client:** `reqwest` (with the `socks` feature)
- **SOCKS handshakes:** `tokio-socks`
- **GeoIP:** `maxminddb` + GeoLite2 (offline), with an optional HTTP fallback
- **Frontend:** Vite + vanilla TypeScript

## Project layout

```
ProxyScope/
├── core/        # UI-agnostic proxy parsing, detection, and checking (Rust)
├── src-tauri/   # Tauri v2 desktop shell (thin command/event glue)
├── src/         # Frontend (TypeScript)
└── index.html   # Frontend entry point
```

## Development

Prerequisites: a recent [Rust](https://rustup.rs/) toolchain,
[Node.js](https://nodejs.org/), and the
[Tauri v2 prerequisites](https://tauri.app/start/prerequisites/) for your OS.

```bash
npm install        # install frontend dependencies
npm run tauri dev  # run the app in development mode
```

To build a release bundle:

```bash
npm run tauri build
```

## Attribution

Created and maintained by **hasoftware** (<hoanganhuet@hotmail.com>).
Please retain this attribution in derived works.

## License

The license has not been finalized yet. Until a `LICENSE` file is added, all
rights are reserved by the author. Do not use ProxyScope for unauthorized
access or any unlawful activity.
