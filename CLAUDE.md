# ProxyScope — Project Context

## Overview
ProxyScope is a desktop proxy-checking tool. Users paste a proxy list or
import a file; the tool auto-detects each proxy's protocol and reports its
quality (alive/dead, exit IP, country, latency, anonymity, rotation behavior).

## Tech Stack
- Backend: Rust (async, `tokio`)
- Desktop shell: Tauri v2
- HTTP client: `reqwest` with the `socks` feature
- SOCKS raw handshakes: `tokio-socks`
- GeoIP: `maxminddb` + GeoLite2 database (offline). Provide a fallback
  HTTP lookup (e.g. ip-api.com) behind a config flag.
- Frontend: keep it simple (vanilla TS or a light framework); the priority
  is a fast, live-updating results table.

## Repository & Authorship
- Repo: https://github.com/hasoftware/ProxyScope
- Author / git identity: hasoftware <hoanganhuet@hotmail.com>

## Commit Conventions (MANDATORY)
- Configure git locally: user.name = "hasoftware",
  user.email = "hoanganhuet@hotmail.com". Commit ONLY under this identity.
- Do NOT add any "Co-Authored-By: Claude" trailer or any AI attribution.
  Do NOT mention Claude / AI in commit messages.
- All commit messages, issue titles/bodies, code comments, and the README
  must be in English.
- Workflow for each bug fix or feature:
  1. Open a GitHub issue describing the work.
  2. Implement and commit.
  3. Reference the issue in the commit so it auto-closes
     (e.g. "Fix proxy parser whitespace handling (Fixes #12)").
- Use Conventional Commits style: feat:, fix:, refactor:, docs:, chore:.

## Code Conventions
- Run `cargo fmt` and `cargo clippy` before committing; keep clippy clean.
- Separate concerns: a `core` Rust module (proxy parsing, detection,
  checking) that is UI-agnostic, plus thin Tauri command/event glue.
- Stream per-proxy results to the UI via Tauri events — never block the UI.

## License
This project is open and shared, but must (a) require attribution to
hasoftware and (b) discourage abuse / illegal use.
NOTE: A field-of-use restriction ("no illegal use") is incompatible with the
OSI definition of open source. Before writing LICENSE, confirm with the
author which model to use:
  - MIT or Apache-2.0  -> true open source + attribution (no abuse clause)
  - PolyForm / custom  -> source-available WITH an anti-abuse clause
Do not write the final LICENSE until this choice is confirmed.
