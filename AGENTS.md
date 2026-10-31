## PingX

PingX is a Rust network diagnostic CLI for concurrent ICMP, half-open TCP SYN, UDP, and HTTP Ping; ICMP/UDP/TCP traceroute; GeoIP lookup; and JSON output. It supports Unix interface binding, a macOS privileged helper, and Windows WinDivert-backed TCP/UDP Ping and traceroute. Read `README.md` and the relevant source before changing behavior; the implementation is authoritative when documentation disagrees.

## Structure

- `src/cli.rs`, `src/config.rs`, `src/main.rs`: CLI parsing, configuration, and startup.
- `src/session.rs`: Ping lifecycle, concurrency, result aggregation, and Ping/GeoIP JSON output.
- `src/traceroute.rs`: single-target traceroute scheduling, reply parsing, hop aggregation, and human/JSON output.
- `src/pinger/`: ICMP, TCP SYN, UDP, and HTTP Ping implementations.
- `src/probe/`: raw TCP/UDP packet construction, platform-specific capture, and ICMP error classification.
- `src/helper.rs`: macOS privileged-helper installation, client, daemon, and protocol. `src/windivert.rs` provides Windows packet capture and injection.
- `src/geoip/`: GeoIP database download, lookup, and output. Configuration and databases live under `~/.config/pingx/`.
- `src/happy_eyeballs.rs` and `src/utils.rs`: address selection and shared networking utilities.
- `misc/surge-ping/` is a separate vendored/reference checkout; do not treat its sources as PingX modules or modify it for PingX behavior changes unless explicitly required.

## Constraints

- Preserve IPv4 and IPv6 behavior and the documented CLI contract.
- Preserve target selection unless deliberately changing the contract: auto mode maps `HOST` to ICMP, `HOST:PORT` to TCP, and HTTP URLs to HTTP; `-T`/`-U` override host targets and default omitted ports to 80/33434.
- Preserve the JSON output contract: `--json` writes to stdout and consumes no following argument; `--json=FILE` writes to `FILE`.
- Traceroute requires exactly one target and rejects HTTP/GeoIP modes. `-s` is total IP packet size in traceroute, not Ping payload size. Traceroute JSON is emitted only after the target is reached, and an existing output file must remain untouched on failure.
- Interface binding is implemented for Unix. With `-I`, DNS uses system nameservers through a matching interface source address; ICMP/TCP/UDP Ping, all traceroute sockets, HTTP, and GeoIP downloads bind to the interface, and HTTP/GeoIP requests disable proxies. Check each path before changing or claiming guarantees.
- Windows has CI build and test coverage. UDP/TCP Ping and all traceroute modes require Administrator access and WinDivert 2.2.2; ICMP Ping uses the IP Helper API. Unix-only interface binding is unavailable there, so don't describe the whole application as Windows-unsupported.
- Linux ICMP Ping prefers unprivileged DGRAM sockets and may fall back to RAW sockets requiring `CAP_NET_RAW`. TCP SYN Ping and ICMP/TCP traceroute use RAW sockets; Linux UDP Ping/traceroute use UDP error queues.
- On macOS, TCP/UDP Ping and all traceroute modes use the helper unless PingX is already root. ICMP Ping uses unprivileged DGRAM sockets when available; HTTP and GeoIP stay in the normal user process and cannot share a helper request with privileged targets.
- Keep network I/O asynchronous and preserve per-target result/statistics separation. Unix ICMP Ping uses a shared client per address family to dispatch replies to individual probes.
- Treat `README.md`, CLI help, and implementation as the behavior contract; don't reintroduce a separate spec/proposal workflow.

## Checks

Tests are mostly inline unit tests, with a small number of Tokio tests; prefer adding focused tests beside the code they cover. For Rust changes, run a Debug build, relevant tests, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --release` when practical. CI runs Debug builds, Clippy, and release tests on Linux x86_64, macOS x86_64/ARM64, and Windows x86_64; report platform checks that cannot be run locally.

## Commits

- Use Conventional Commits: `<type>(<scope>): <subject>`. Most commits should have a one-line subject; only especially large commits spanning many files need a body describing the details.
