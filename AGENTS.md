## PingX

PingX is a Rust network diagnostic CLI for concurrent ICMP, TCP, and HTTP probing, GeoIP lookup, and JSON output. Read `README.md` and the relevant source before changing behavior; the implementation is authoritative when documentation disagrees.

## Structure

- `src/cli.rs`, `src/config.rs`, `src/main.rs`: CLI parsing, configuration, and startup.
- `src/session.rs`: probe lifecycle, concurrency, and result aggregation.
- `src/pinger/`: ICMP, TCP, and HTTP probe implementations.
- `src/geoip/`: GeoIP database download, lookup, and output. Configuration and databases live under `~/.config/pingx/`.
- `src/happy_eyeballs.rs` and `src/utils.rs`: address selection and shared networking utilities.
- `misc/surge-ping/` is a separate vendored/reference checkout; do not treat its sources as PingX modules or modify it for PingX behavior changes unless explicitly required.

## Constraints

- Preserve IPv4 and IPv6 behavior and the documented CLI contract.
- Interface binding is implemented for Unix. With `-I`, name resolution uses system DNS servers bound to a matching interface source address, HTTP disables proxies, and TCP/ICMP sockets bind to the interface. Check each path before changing or claiming guarantees.
- Windows has CI build and test coverage, but Unix-only interface-binding code is unavailable there; don't describe the whole application as Windows-unsupported.
- Linux ICMP prefers unprivileged DGRAM sockets and may fall back to RAW sockets requiring `CAP_NET_RAW`.
- Keep network I/O asynchronous and preserve per-target result/statistics separation. ICMP uses a shared client per address family to dispatch replies to individual probes.
- Treat `README.md`, CLI help, and implementation as the behavior contract; don't reintroduce a separate spec/proposal workflow.

## Checks

Tests are mostly inline unit tests, with a small number of Tokio tests; prefer adding focused tests beside the code they cover. For Rust changes, run relevant tests, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --release` when practical. CI runs Clippy and release tests on Linux x86_64, macOS x86_64/ARM64, and Windows x86_64; report platform checks that cannot be run locally.
