//! `netblame-share`: a small self-hostable server for `netblame --share`.
//!
//! ```text
//! netblame-share --port 8788 --data-dir ./share-data --max-body-kb 256 \
//!     --retention-days 30 --rate-limit 20
//! ```
//!
//! Endpoints:
//! - `POST /api/reports` — upload a report JSON body, get back `{id, url}`
//! - `GET /r/{id}` — server-rendered HTML report page
//! - `GET /api/reports/{id}` — raw JSON for a stored report
//!
//! All of the interesting logic (id generation, retention pruning, HTML
//! rendering, rate limiting) is pure and unit-tested in
//! `netblame::share::server::*`; this file is just the axum wiring.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use netblame::i18n::Lang;
use netblame::share::server::id::generate_id;
use netblame::share::server::ratelimit::SlidingWindowLimiter;
use netblame::share::server::render::{render_not_found_page, render_report_page};
use netblame::share::server::retention::files_to_prune;
use serde_json::Value;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Self-hostable server for netblame report sharing.
#[derive(Parser, Debug)]
#[command(name = "netblame-share", version, about)]
struct Args {
    /// Port to listen on
    #[arg(long, default_value_t = 8788)]
    port: u16,

    /// Directory to store report JSON files in
    #[arg(long, default_value = "./share-data")]
    data_dir: PathBuf,

    /// Maximum accepted request body size, in KiB
    #[arg(long, default_value_t = 256)]
    max_body_kb: u64,

    /// Delete stored reports older than this many days (checked on every
    /// upload)
    #[arg(long, default_value_t = 30)]
    retention_days: u32,

    /// Max uploads allowed per IP per rolling minute
    #[arg(long, default_value_t = 20)]
    rate_limit: u32,

    /// Public base URL to build share links from (e.g.
    /// https://share.example.com). If unset, the request's Host header is
    /// used with an https:// prefix.
    #[arg(long)]
    public_url: Option<String>,
}

struct AppState {
    data_dir: PathBuf,
    max_body_bytes: u64,
    retention_days: u32,
    public_url: Option<String>,
    limiter: SlidingWindowLimiter,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    fs::create_dir_all(&args.data_dir).unwrap_or_else(|e| {
        eprintln!(
            "netblame-share: failed to create data dir {:?}: {e}",
            args.data_dir
        );
        std::process::exit(1);
    });

    let state = Arc::new(AppState {
        data_dir: args.data_dir.clone(),
        max_body_bytes: args.max_body_kb * 1024,
        retention_days: args.retention_days,
        public_url: args.public_url.clone(),
        limiter: SlidingWindowLimiter::new(args.rate_limit, Duration::from_secs(60)),
    });

    let app = Router::new()
        .route("/api/reports", post(create_report))
        .route("/api/reports/{id}", get(get_report_json))
        .route("/r/{id}", get(get_report_html))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("netblame-share: listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("netblame-share: failed to bind {addr}: {e}");
            std::process::exit(1);
        });
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("netblame-share: server error: {e}");
        std::process::exit(1);
    });
}

/// Extracts the caller's IP for rate limiting: prefers the first hop of
/// `X-Forwarded-For` (set by a reverse proxy) and falls back to the raw
/// peer address from the TCP connection. The header is trusted
/// unconditionally, so the server must sit behind a proxy that overwrites it.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or(peer.ip())
}

async fn create_report(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers, peer);
    if !state.limiter.allow(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    if body.len() as u64 > state.max_body_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, "report body too large").into_response();
    }

    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")).into_response();
        }
    };

    // Must at least look like a netblame report: a `verdict` object.
    if !value.get("verdict").is_some_and(Value::is_object) {
        return (
            StatusCode::BAD_REQUEST,
            "missing or invalid \"verdict\" object",
        )
            .into_response();
    }

    prune_old_reports(&state.data_dir, state.retention_days);

    let id = generate_id();
    let path = state.data_dir.join(format!("{id}.json"));
    if let Err(e) = fs::write(&path, &body) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store report: {e}"),
        )
            .into_response();
    }

    let base = public_base_url(&state, &headers);
    let url = format!("{base}/r/{id}");
    Json(serde_json::json!({ "id": id, "url": url })).into_response()
}

/// Determines the public base URL used to build share links: `--public-url`
/// if set (trailing slashes stripped), else `http://{Host}` from the request
/// (`http://localhost` if there is no usable Host header).
fn public_base_url(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(u) = &state.public_url {
        return u.trim_end_matches('/').to_string();
    }
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("http://{host}")
}

fn prune_old_reports(data_dir: &StdPath, retention_days: u32) {
    let Ok(entries) = fs::read_dir(data_dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    let mut named: Vec<(String, std::time::SystemTime)> = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if let Some(name) = entry.file_name().to_str() {
            named.push((name.to_string(), modified));
        }
    }
    let borrowed: Vec<(&str, std::time::SystemTime)> =
        named.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    for stale in files_to_prune(borrowed, now, retention_days) {
        let _ = fs::remove_file(data_dir.join(stale));
    }
}

fn load_report(data_dir: &StdPath, id: &str) -> Option<Value> {
    if !netblame::share::server::id::is_valid_id(id) {
        return None;
    }
    let path = data_dir.join(format!("{id}.json"));
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

async fn get_report_json(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match load_report(&state.data_dir, &id) {
        Some(value) => Json(value).into_response(),
        None => (StatusCode::NOT_FOUND, "report not found").into_response(),
    }
}

async fn get_report_html(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match load_report(&state.data_dir, &id) {
        Some(value) => Html(render_report_page(&id, &value)).into_response(),
        None => (StatusCode::NOT_FOUND, Html(render_not_found_page(Lang::Ja))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn peer() -> SocketAddr {
        "203.0.113.9:54321".parse().unwrap()
    }

    fn peer_ip() -> IpAddr {
        peer().ip()
    }

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    fn xff(value: &str) -> HeaderMap {
        headers_with("x-forwarded-for", value)
    }

    fn state_with(public_url: Option<&str>) -> AppState {
        AppState {
            data_dir: PathBuf::from("./unused"),
            max_body_bytes: 0,
            retention_days: 0,
            public_url: public_url.map(str::to_string),
            limiter: SlidingWindowLimiter::new(1, Duration::from_secs(60)),
        }
    }

    #[test]
    fn client_ip_without_header_uses_peer() {
        assert_eq!(client_ip(&HeaderMap::new(), peer()), peer_ip());
    }

    #[test]
    fn client_ip_single_forwarded_ip_wins_over_peer() {
        // X-Forwarded-For は無条件に信頼される（peer が誰でも採用）
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_ip(&xff("198.51.100.7"), peer()), ip);
    }

    #[test]
    fn client_ip_takes_first_of_comma_separated_list() {
        // 先頭（クライアント側）を採り、後続のプロキシ段は無視する
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            client_ip(&xff("198.51.100.7, 10.0.0.1, 10.0.0.2"), peer()),
            ip
        );
        assert_eq!(client_ip(&xff("198.51.100.7,10.0.0.1"), peer()), ip);
    }

    #[test]
    fn client_ip_trims_surrounding_whitespace() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_ip(&xff("  198.51.100.7  "), peer()), ip);
        assert_eq!(client_ip(&xff("\t198.51.100.7 \t, 10.0.0.1"), peer()), ip);
    }

    #[test]
    fn client_ip_invalid_first_entry_falls_back_to_peer() {
        // 先頭が不正なら 2 番目以降が妥当でも peer（次の要素は探さない）
        assert_eq!(client_ip(&xff("unknown, 198.51.100.7"), peer()), peer_ip());
        assert_eq!(client_ip(&xff("not-an-ip"), peer()), peer_ip());
        assert_eq!(client_ip(&xff("999.1.1.1"), peer()), peer_ip());
    }

    #[test]
    fn client_ip_empty_or_blank_value_falls_back_to_peer() {
        assert_eq!(client_ip(&xff(""), peer()), peer_ip());
        assert_eq!(client_ip(&xff("   "), peer()), peer_ip());
        // 先頭が空要素なら 2 番目が妥当でも peer
        assert_eq!(client_ip(&xff(", 198.51.100.7"), peer()), peer_ip());
    }

    #[test]
    fn client_ip_with_port_or_brackets_falls_back_to_peer() {
        // IpAddr としてパースできない形式（ポート付き・角括弧付き）は不正扱い
        assert_eq!(client_ip(&xff("198.51.100.7:8080"), peer()), peer_ip());
        assert_eq!(client_ip(&xff("[2001:db8::1]"), peer()), peer_ip());
        assert_eq!(client_ip(&xff("[2001:db8::1]:8080"), peer()), peer_ip());
    }

    #[test]
    fn client_ip_parses_ipv6_forwarded_value() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(client_ip(&xff("2001:db8::1"), peer()), ip);
        assert_eq!(client_ip(&xff("2001:db8::1, 10.0.0.1"), peer()), ip);
        let lo: IpAddr = "::1".parse().unwrap();
        assert_eq!(client_ip(&xff("::1"), peer()), lo);
    }

    #[test]
    fn client_ip_ipv6_peer_is_returned_as_is() {
        let p: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        assert_eq!(client_ip(&HeaderMap::new(), p), p.ip());
        assert_eq!(client_ip(&xff("garbage"), p), p.ip());
    }

    #[test]
    fn client_ip_non_ascii_header_value_falls_back_to_peer() {
        // HeaderValue は 0x80 以上のバイトを許すが、to_str は可視 ASCII とスペース・タブのみ通すので peer へ
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"198.51.100.7\xff").unwrap(),
        );
        assert_eq!(client_ip(&h, peer()), peer_ip());

        // 妥当な UTF-8 でも非 ASCII を含めば同様（先頭が妥当な IP でも採用されない）
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes("198.51.100.7, é".as_bytes()).unwrap(),
        );
        assert_eq!(client_ip(&h, peer()), peer_ip());
    }

    #[test]
    fn client_ip_header_name_is_case_insensitive() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_bytes(b"X-Forwarded-For").unwrap(),
            HeaderValue::from_static("198.51.100.7"),
        );
        assert_eq!(client_ip(&h, peer()), ip);
    }

    #[test]
    fn client_ip_uses_only_first_of_repeated_headers() {
        // 同名ヘッダが複数あっても HeaderMap::get は最初の 1 本だけを返す
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.8"));
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_ip(&h, peer()), ip);
    }

    #[test]
    fn client_ip_ignores_other_proxy_headers() {
        // X-Real-IP / Forwarded は見ない
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.7"));
        h.insert("forwarded", HeaderValue::from_static("for=198.51.100.8"));
        assert_eq!(client_ip(&h, peer()), peer_ip());
    }

    #[test]
    fn public_base_url_prefers_configured_value() {
        let s = state_with(Some("https://share.example.com"));
        // 設定があれば Host ヘッダは無視される
        let h = headers_with("host", "internal:8788");
        assert_eq!(public_base_url(&s, &h), "https://share.example.com");
        assert_eq!(
            public_base_url(&s, &HeaderMap::new()),
            "https://share.example.com"
        );
    }

    #[test]
    fn public_base_url_trims_trailing_slashes_of_configured_value() {
        let s = state_with(Some("https://share.example.com/"));
        assert_eq!(
            public_base_url(&s, &HeaderMap::new()),
            "https://share.example.com"
        );
        // 複数のスラッシュもまとめて落とす
        let s = state_with(Some("https://share.example.com///"));
        assert_eq!(
            public_base_url(&s, &HeaderMap::new()),
            "https://share.example.com"
        );
        // パス部分は保持し、末尾だけ落とす
        let s = state_with(Some("https://example.com/share/"));
        assert_eq!(
            public_base_url(&s, &HeaderMap::new()),
            "https://example.com/share"
        );
    }

    #[test]
    fn public_base_url_configured_value_is_not_otherwise_normalized() {
        // 空文字列は「設定あり」扱いで、そのまま空の base になる
        let s = state_with(Some(""));
        assert_eq!(public_base_url(&s, &HeaderMap::new()), "");
        // スキーム無し・前後の空白もそのまま
        let s = state_with(Some("share.example.com"));
        assert_eq!(public_base_url(&s, &HeaderMap::new()), "share.example.com");
        let s = state_with(Some(" https://x.example "));
        assert_eq!(
            public_base_url(&s, &HeaderMap::new()),
            " https://x.example "
        );
    }

    #[test]
    fn public_base_url_falls_back_to_http_scheme_with_host_header() {
        // 現状の実装のスキームは http（https ではない）
        let s = state_with(None);
        let h = headers_with("host", "share.example.com");
        assert_eq!(public_base_url(&s, &h), "http://share.example.com");
    }

    #[test]
    fn public_base_url_keeps_port_in_host_header() {
        let s = state_with(None);
        let h = headers_with("host", "127.0.0.1:8788");
        assert_eq!(public_base_url(&s, &h), "http://127.0.0.1:8788");
    }

    #[test]
    fn public_base_url_embeds_host_header_as_is_without_trimming() {
        // Host 由来の値は末尾スラッシュ除去も検証もされず、そのまま埋め込まれる
        let s = state_with(None);
        let h = headers_with("host", "share.example.com/");
        assert_eq!(public_base_url(&s, &h), "http://share.example.com/");
    }

    #[test]
    fn public_base_url_without_host_uses_localhost() {
        let s = state_with(None);
        assert_eq!(public_base_url(&s, &HeaderMap::new()), "http://localhost");
    }

    #[test]
    fn public_base_url_non_ascii_host_uses_localhost() {
        let s = state_with(None);
        let mut h = HeaderMap::new();
        h.insert(
            "host",
            HeaderValue::from_bytes(b"share\xff.example").unwrap(),
        );
        assert_eq!(public_base_url(&s, &h), "http://localhost");
    }

    #[test]
    fn public_base_url_ignores_x_forwarded_headers() {
        // X-Forwarded-Host / X-Forwarded-Proto は見ない
        let s = state_with(None);
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("internal:8788"));
        h.insert(
            "x-forwarded-host",
            HeaderValue::from_static("share.example.com"),
        );
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(public_base_url(&s, &h), "http://internal:8788");
    }
}
