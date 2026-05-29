# ProxyScope

ProxyScope is a desktop proxy-checking tool. Paste a proxy list or import a
file, and ProxyScope auto-detects each proxy's protocol and reports its
quality: alive/dead status, exit IP, country, latency, anonymity level, and
rotation behavior. Results stream into a live table as each proxy is checked.

## Features

- **Input** — paste or import proxy lists in common formats:
  - `ip:port`
  - `ip:port:user:pass`
  - `scheme://user:pass@ip:port` (`http`, `https`, `socks4(a)`, `socks5(h)`)
  - `user:pass@ip:port`
  - `tg://proxy?server=…&port=…&secret=…` and `https://t.me/proxy?…` (MTProxy)
- **Protocol auto-detection** — HTTP / HTTPS / SOCKS4 / SOCKS5 via ordered
  handshake probing. MTProxy is recognized by input format only (active
  MTProto probing is not implemented yet).
- **Quality checks** — alive/dead, exit IP, country/region, connect and
  round-trip latency, and anonymity level (transparent / anonymous / elite),
  derived from a single request through a judge endpoint.
- **Rotation detection** — sends several sequential requests and classifies the
  proxy as static, per-request rotating, rotating, or time-based rotating,
  reporting the set of observed exit IPs.
- **Live results table** — rows stream in as each proxy is checked, with a
  progress bar, text/status filtering, click-to-sort columns, and CSV/JSON
  export.

## Tech stack

- **Backend:** Rust (async, `tokio`)
- **Desktop shell:** Tauri v2
- **HTTP client:** `reqwest` (with the `socks` feature) for direct calls
- **SOCKS handshakes:** `tokio-socks`
- **GeoIP:** `maxminddb` + GeoLite2 (offline), with an optional ip-api.com
  HTTP fallback
- **Frontend:** Vite + vanilla TypeScript

## Project layout

```
ProxyScope/
├── core/        # UI-agnostic proxy parsing, detection, checks, rotation (Rust)
│   └── src/     #   parse · detect · check · geoip · rotation · scan
├── src-tauri/   # Tauri v2 desktop shell (thin command/event glue)
├── src/         # Frontend (TypeScript)
└── index.html   # Frontend entry point
```

The Rust workspace separates the UI-agnostic `proxyscope-core` crate from the
`src-tauri` desktop shell. Per-proxy results are streamed to the UI via Tauri
events, so the interface stays responsive during large scans.

## How it works

Each proxy is exercised by fetching a **judge** endpoint through it — a plain
HTTP URL that echoes back the requester's IP and the request headers it saw.
From one round-trip ProxyScope derives:

- **alive/dead** — did the judge respond `2xx` through the proxy?
- **exit IP** — the address the judge observed (e.g. httpbin's `origin`)
- **latency** — connection time and full round-trip time
- **anonymity** — which forwarding headers (`Via`, `X-Forwarded-For`, …) the
  proxy leaked, and whether it exposed your real IP
- **country/region** — looked up from the exit IP

The judge is fetched over raw sockets (not `reqwest`) so SOCKS4 is supported,
connection time can be isolated, and the echoed headers can be read directly.

## Settings

Open the **Settings** panel in the app to adjust (persisted locally):

- **Judge URL** — a plain-HTTP endpoint that echoes the requester IP and
  headers. Default: `http://httpbin.org/get`. It must be `http://` (not
  `https://`) because it is fetched through the proxy.
- **Concurrency** — how many proxies are checked at once.
- **Connect / request timeouts** — in seconds.
- **GeoLite2 database path** — path to a `GeoLite2-City.mmdb` file for offline
  country/region lookup. Download it from MaxMind (free account required).
  ProxyScope does not bundle or redistribute the database.
- **Allow HTTP GeoIP fallback** — when offline lookup misses (or no database is
  set), query ip-api.com instead.

## Development

Prerequisites: a recent [Rust](https://rustup.rs/) toolchain,
[Node.js](https://nodejs.org/), and the
[Tauri v2 prerequisites](https://tauri.app/start/prerequisites/) for your OS.

```bash
npm install        # install frontend dependencies
npm run tauri dev  # run the app in development mode
```

Build a release bundle:

```bash
npm run tauri build
```

Run the checks (matches CI expectations):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build      # type-check + bundle the frontend
```

## Attribution

Created and maintained by **hasoftware**. Please retain this attribution in
derived works (see [`NOTICE`](NOTICE)).

## Responsible use

ProxyScope is intended for testing proxies you own or are authorized to assess.
Please do not use it for unauthorized access or any unlawful activity.

## License

Licensed under the [Apache License 2.0](LICENSE). See [`NOTICE`](NOTICE) for
attribution requirements.
