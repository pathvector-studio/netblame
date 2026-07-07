# netblame

English | [日本語](README.ja.md)

**Is it *really* the network's fault?**

"The internet is slow", "the site won't load" — but is the culprit your router, DNS, the path in between, or the server itself? `netblame` is a single-binary CLI: give it one URL or host, it runs a staged diagnosis and **names the most likely culprit in plain language, with evidence**.

```
$ netblame https://example.com
...
[VERDICT] No problem found. The path to this destination is healthy right now
```

Output is available in English and Japanese (`--lang en|ja`, auto-detected from your locale).

> ⚠️ **Prototype.** Verdict thresholds are heuristics and may misjudge unusual network setups — feedback welcome. Verified on Linux (macOS best-effort, Windows not yet supported).

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
| `--lang <en\|ja>` | Output language | auto-detect from locale |
| `--watch [<secs>]` | Repeat the diagnosis on an interval, print a timestamped timeline; Ctrl-C shows a summary | 30 |
| `--trace` | Always run the hop-level path trace (see below) | auto |
| `--share` | After the diagnosis, upload the full report and print a shareable URL (see below) | - |
| `--share-url <base>` | Share server base URL to upload to | env `NETBLAME_SHARE_URL`, else `https://share.pathvector.dev` |

**Path trace auto-trigger**: without `--trace`, the hop-level trace stage runs automatically only when an earlier stage found a path problem (a TCP target timed out, packet loss > 0%, or high jitter). It adds up to ~15-30 s in the worst case, so it is skipped when everything is healthy. The trace uses tracepath-style probing (UDP + `IP_RECVERR`, **no root required**) and is **Linux-only** — on other platforms a note is printed and the stage is skipped.

**QUIC/HTTP3 probe**: the QUIC probe stage runs automatically (no flag needed) for `https` targets only, right after the HTTP stage. It is cross-platform (Linux and macOS).

**Exit codes**: `0` = no problem / `1` = problem detected / `2` = usage or internal error

## How it works

### Diagnosis stages (`src/probe/`)

Measurement and judgment are strictly separated: each stage only appends facts to a `Report` and never decides what is wrong.

1. **Environment** (`env.rs`) — parses `/etc/resolv.conf` (nameservers, search domains), checks `/etc/hosts` for overriding entries, detects proxy env vars (`http_proxy` / `https_proxy` / `NO_PROXY`, …)
2. **DNS** (`dns.rs`) — resolves the name 4 ways and compares: (a) system resolver (getaddrinfo), (b) direct queries to each resolv.conf nameserver (hickory-resolver), (c) 1.1.1.1, (d) 8.8.8.8. Records answers, outcome (OK/NXDOMAIN/SERVFAIL/timeout) and latency per source
3. **TCP** (`tcp.rs`) — connects N times to up to 3 resolved IPs (including both IPv4/IPv6 when present), measuring success rate and min/avg/max; distinguishes refused (port closed) from timeout (filtered)
4. **TLS** (`tls.rs`) — verified handshake via rustls + webpki-roots; records TLS version, days until certificate expiry, hostname match. On verification failure it reconnects **without verification (read-only, diagnostic only)** to extract the presented issuer, and flags middlebox fingerprints (Zscaler, FortiGate, …) as probable TLS interception
5. **HTTP** (`http.rs`) — GET via reqwest (rustls backend); status, redirect chain (max 5), TTFB and total time; also captures the `alt-svc` response header and records whether HTTP/3 (`h3`) is advertised
6. **QUIC/HTTP3** (`quic.rs`) — runs after the HTTP stage, **only for `https` targets**: attempts a real QUIC handshake (ALPN `h3`, rustls + webpki-roots, same verification policy as the TLS stage) to the resolved IP and measures handshake time, distinguishing a clean success from a timeout (nothing comes back — the UDP-443-blocked signature), a handshake error (the server responded but negotiation failed — not a network problem), or a local error
7. **Path quality** (`path.rs`) — N TCP connect-pings to the primary IP; computes loss %, average RTT and jitter (stddev)
8. **Path trace** (`trace.rs`, Linux only, no root) — tracepath-style traceroute: an unprivileged UDP socket with `IP_RECVERR` receives ICMP time-exceeded / port-unreachable errors via `MSG_ERRQUEUE`, mapping each hop's router address and RTT (TTL 1-30, 2 probes/hop, 1 s timeout). Then DF-flagged datagrams of decreasing size (1500 → 1024) are sent with `IP_PMTUDISC_PROBE` to measure the path MTU and — crucially — whether oversized packets produce ICMP frag-needed replies or silently vanish (the PMTUD black hole signature)

### Verdict engine (`src/verdict.rs`)

`fn judge(report: &Report) -> Verdict` is a **pure function with no I/O** (covered by unit tests) that picks exactly one culprit category from the evidence:

`LocalDnsBroken` / `LocalDnsSlow` / `DnsAnswerMismatch` / `NameDoesNotExist` / `TcpBlocked` / `Ipv6Broken` / `TlsCertExpired` / `TlsCertInvalid` / `TlsIntercepted` / `ProxyInterference` / `UnstablePath` / `PmtuBlackhole` / `Udp443Blocked` / `ServerSlow` / `ServerDown` / `NoProblem`

Selected reasoning rules (in priority order):

- NXDOMAIN from every source → the name doesn't exist (the network is innocent)
- Public DNS resolves but local doesn't → local DNS is down
- Local and public answers disjoint + connection fails → reported neutrally as a local/public answer mismatch (split-horizon / filtering / rewriting)
- All TCP refused → server-side port closed; all timeout → filtered or unreachable
- IPv6 dead while IPv4 fine → broken IPv6 path (common in the wild)
- Fast connect (<100ms) but slow TTFB (>1000ms) → **the server is slow, the network is fine**
- Loss ≥10% or jitter >50ms → unstable path
- TCP connects fine, but path MTU < 1500 **and** oversized DF probes vanish without any ICMP frag-needed reply → **`PmtuBlackhole`** — small packets pass while large transfers stall, the classic VPN/tunnel failure. Next step: check the tunnel MTU / enable MSS clamping
- TCP + TLS + HTTP all healthy, HTTP/3 was advertised via `alt-svc`, **and** every QUIC handshake attempt times out (no response at all) → **`Udp443Blocked`** — a firewall is most likely dropping UDP 443. This is intentionally the **lowest-priority** verdict: if anything bigger is wrong, that culprit wins and the QUIC finding is attached as a secondary note instead; if HTTP/3 isn't advertised in the first place, a QUIC timeout is expected and stays a secondary note, never a verdict
- When the culprit is path-related (`TcpBlocked` / `ServerDown` / `UnstablePath`) and hop data exists, the evidence gains "last responding hop: <ip> (hop N of ~M)" and the next step gains a localization hint: dies at hop 1-2 → your home network (router/gateway); early hops → ISP; deep in the path → the far side

Non-primary findings (hosts overrides, proxy presence, CDN answer differences, soon-to-expire certificates, non-blocking QUIC/HTTP3 anomalies) are attached as secondary notes.

## Development

```bash
cargo test           # verdict engine + trace analysis + parser unit tests
cargo clippy         # zero warnings
cargo build --release
```

## Watch mode

Intermittent problems are the worst to diagnose — `--watch` keeps re-running the diagnosis and shows when things break:

```
$ netblame --watch 30 https://example.com
watching every 30s — press Ctrl-C to stop and show a summary
10:12:42 ✓ OK (dns 1ms / tcp 16ms / ttfb 83ms / loss 0%)
10:13:12 ✗ [VERDICT] Local DNS is not responding while public DNS works
...
── Watch summary
runs: 42 / ok: 40 (95%)
```

## Report sharing (`--share`)

Sometimes the fastest way to get help is to hand someone a link instead of a wall of terminal output:

```
$ netblame --share https://example.com
...
Report shared: https://share.pathvector.dev/r/ab12cd34ef
```

`--share` runs the normal diagnosis first (full output still prints to your terminal), then uploads the same JSON payload as `--json` — plus `netblame_version` and `created_lang` so the server can render it — to `{base}/api/reports`. The base URL is, in priority order: `--share-url <url>`, the `NETBLAME_SHARE_URL` environment variable, then `https://share.pathvector.dev` (a hosted instance is planned but not live yet — until then, uploads to the default URL will simply fail).

Upload failures print a localized warning and never change the process exit code — that code always reflects the diagnosis result, not whether the upload succeeded. `--share` cannot be combined with `--watch`.

### Self-hosting the share server

The server is a second, optional binary (`netblame-share`) built from the same crate behind a feature flag, so the default `netblame` binary and release artifacts are completely unaffected by it:

```bash
cargo build --release --features share-server
# binary at target/release/netblame-share
```

```
netblame-share [flags]

--port <port>              Port to listen on (default 8788)
--data-dir <dir>           Where to store report JSON files (default ./share-data)
--max-body-kb <kb>         Max accepted upload size (default 256)
--retention-days <days>    Delete stored reports older than this (default 30, pruned on every upload)
--rate-limit <n>           Max uploads per IP per rolling minute (default 20)
--public-url <url>         Public base URL used to build share links (default: derived from the request's Host header)
```

Endpoints: `POST /api/reports` (upload, returns `{"id", "url"}`), `GET /r/{id}` (server-rendered HTML report page, no JS), `GET /api/reports/{id}` (raw JSON).

Point your own `netblame` runs at it with `--share-url http://your-host:8788` or `export NETBLAME_SHARE_URL=http://your-host:8788`.

Minimal systemd unit:

```ini
[Unit]
Description=netblame-share
After=network.target

[Service]
ExecStart=/usr/local/bin/netblame-share --port 8788 --data-dir /var/lib/netblame-share --public-url https://share.example.com
Restart=on-failure
DynamicUser=yes
StateDirectory=netblame-share

[Install]
WantedBy=multi-user.target
```

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT
