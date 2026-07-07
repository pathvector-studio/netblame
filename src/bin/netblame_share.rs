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
/// peer address from the TCP connection.
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
/// if set, else `scheme://Host` from the request (defaulting to https).
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
