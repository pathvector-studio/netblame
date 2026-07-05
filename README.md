# netblame

English | [日本語](README.ja.md)

**Is it *really* the network's fault?**

"The internet is slow", "the site won't load" — but is the culprit your router, DNS, the path in between, or the server itself? `netblame` is a single-binary CLI: give it one URL or host, it runs a staged diagnosis and **names the most likely culprit in plain language, with evidence**.

```
$ netblame https://example.com
...
【判定】 問題は見つかりませんでした。少なくとも今、この宛先への経路は健全です
(Verdict: No problem found. The path to this destination is healthy right now.)
```

> ⚠️ **Prototype.** Verdict thresholds are heuristics and may misjudge unusual network setups — feedback welcome. Verified on Linux (macOS best-effort, Windows not yet supported). **Output messages are currently Japanese**; English output is on the roadmap.

## Install

### Binary (recommended)

Download a Linux/macOS binary from [Releases](https://github.com/pathvector-studio/netblame/releases) and put it on your PATH.

### From source

Requires Rust 1.85+.

```bash
git clone https://github.com/pathvector-studio/netblame.git
cd netblame
cargo build --release
# binary at target/release/netblame
```

## Usage

```bash
netblame <target> [flags]
```

- `<target>`: a URL (`https://example.com/path`, `http://host:8080`) or `host[:port]`
  - `https` scheme or bare host → port 443 with TLS
  - `http` scheme → port 80, no TLS
  - `host:port` (other than 443/80) → plain TCP diagnosis (TLS/HTTP skipped)

| Flag | Meaning | Default |
|---|---|---|
| `--json` | Emit the full machine-readable report (report + verdict) as JSON | - |
| `--timeout <secs>` | Per-probe timeout | 5 |
| `--samples <n>` | Number of latency samples | 5 |
| `--no-color` | Disable colored output | - |

**Exit codes**: `0` = no problem / `1` = problem detected / `2` = usage or internal error

## How it works

### Diagnosis stages (`src/probe/`)

Measurement and judgment are strictly separated: each stage only appends facts to a `Report` and never decides what is wrong.

1. **Environment** (`env.rs`) — parses `/etc/resolv.conf` (nameservers, search domains), checks `/etc/hosts` for overriding entries, detects proxy env vars (`http_proxy` / `https_proxy` / `NO_PROXY`, …)
2. **DNS** (`dns.rs`) — resolves the name 4 ways and compares: (a) system resolver (getaddrinfo), (b) direct queries to each resolv.conf nameserver (hickory-resolver), (c) 1.1.1.1, (d) 8.8.8.8. Records answers, outcome (OK/NXDOMAIN/SERVFAIL/timeout) and latency per source
3. **TCP** (`tcp.rs`) — connects N times to up to 3 resolved IPs (including both IPv4/IPv6 when present), measuring success rate and min/avg/max; distinguishes refused (port closed) from timeout (filtered)
4. **TLS** (`tls.rs`) — verified handshake via rustls + webpki-roots; records TLS version, days until certificate expiry, hostname match. On verification failure it reconnects **without verification (read-only, diagnostic only)** to extract the presented issuer, and flags middlebox fingerprints (Zscaler, FortiGate, …) as probable TLS interception
5. **HTTP** (`http.rs`) — GET via reqwest (rustls backend); status, redirect chain (max 5), TTFB and total time
6. **Path quality** (`path.rs`) — N TCP connect-pings to the primary IP; computes loss %, average RTT and jitter (stddev)

### Verdict engine (`src/verdict.rs`)

`fn judge(report: &Report) -> Verdict` is a **pure function with no I/O** (covered by unit tests) that picks exactly one culprit category from the evidence:

`LocalDnsBroken` / `LocalDnsSlow` / `DnsAnswerMismatch` / `NameDoesNotExist` / `TcpBlocked` / `Ipv6Broken` / `TlsCertExpired` / `TlsCertInvalid` / `TlsIntercepted` / `ProxyInterference` / `UnstablePath` / `ServerSlow` / `ServerDown` / `NoProblem`

Selected reasoning rules (in priority order):

- NXDOMAIN from every source → the name doesn't exist (the network is innocent)
- Public DNS resolves but local doesn't → local DNS is down
- Local and public answers disjoint + connection fails → reported neutrally as a local/public answer mismatch (split-horizon / filtering / rewriting)
- All TCP refused → server-side port closed; all timeout → filtered or unreachable
- IPv6 dead while IPv4 fine → broken IPv6 path (common in the wild)
- Fast connect (<100ms) but slow TTFB (>1000ms) → **the server is slow, the network is fine**
- Loss ≥10% or jitter >50ms → unstable path

Non-primary findings (hosts overrides, proxy presence, CDN answer differences, soon-to-expire certificates) are attached as secondary notes.

## Development

```bash
cargo test           # verdict engine + parser unit tests
cargo clippy         # zero warnings
cargo build --release
```

## Roadmap

- **traceroute / MTU probing** — localize the fault (home vs ISP vs far side), detect PMTUD black holes (the classic VPN failure); needs CAP_NET_RAW handling
- **English output** (`--lang en`)
- **QUIC/HTTP3** — detect the "UDP 443 blocked, only HTTP/3 broken" class of failures
- **Watch mode** — `netblame --watch` to catch intermittent problems with a timestamped timeline
- **Report-sharing service** — one command to upload a `--json` report and get a short URL you can hand to your IT desk or ISP support

## License

MIT
