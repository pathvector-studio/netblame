//! Message catalog: every user-facing string, in English and Japanese.
//!
//! The probes and the verdict engine produce structured data only; this
//! module turns that data into text for the selected language. No other
//! module may contain user-facing string literals.

use crate::report::{DnsOutcome, TruncationReason};
use crate::verdict::{Evidence, Finding, Headline};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Output language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    En,
    Ja,
}

impl Lang {
    /// Auto-detect from the environment: the first non-empty of
    /// LC_ALL / LC_MESSAGES / LANG decides; a value containing "ja"
    /// selects Japanese, anything else selects English.
    pub fn detect() -> Self {
        let vars = ["LC_ALL", "LC_MESSAGES", "LANG"].map(|k| std::env::var(k).ok());
        detect_from(vars.iter().map(|v| v.as_deref()))
    }
}

/// Pure detection logic (testable without touching the process env).
pub fn detect_from<'a>(vars: impl IntoIterator<Item = Option<&'a str>>) -> Lang {
    for v in vars.into_iter().flatten() {
        if v.is_empty() {
            continue;
        }
        return if v.to_ascii_lowercase().contains("ja") {
            Lang::Ja
        } else {
            Lang::En
        };
    }
    Lang::En
}

/// Keys for fixed (parameter-free) messages.
#[derive(Debug, Clone, Copy)]
pub enum MsgKey {
    StageEnv,
    StageDns,
    StageTcp,
    StageTls,
    StageHttp,
    StageQuic,
    StagePath,
    StageTrace,
    TraceUnsupported,
    TraceNoData,
    NoNameservers,
    HostsNoOverride,
    NoProxyVars,
    DnsSkippedIpLiteral,
    NoResolvedIps,
    TlsSkippedNoTcp,
    HttpSkippedNoTcp,
    CertChainOk,
    VerdictLabel,
    EvidenceLabel,
    NotesLabel,
    NextStepLabel,
    Bullet,
    UnknownError,
    ErrorPrefix,
    JsonWatchConflict,
    WatchSummaryHeader,
    WatchProblemsHeader,
    ShareWatchConflict,
}

pub fn msg(lang: Lang, key: MsgKey) -> &'static str {
    use Lang::*;
    use MsgKey::*;
    match key {
        StageEnv => match lang {
            En => "Environment",
            Ja => "環境",
        },
        StageDns => "DNS",
        StageTcp => "TCP",
        StageTls => "TLS",
        StageHttp => "HTTP",
        StageQuic => match lang {
            En => "QUIC/HTTP3",
            Ja => "QUIC/HTTP3",
        },
        StagePath => match lang {
            En => "Path quality",
            Ja => "経路品質",
        },
        StageTrace => match lang {
            En => "Path trace",
            Ja => "経路トレース",
        },
        TraceUnsupported => match lang {
            En => "hop tracing requires Linux (tracepath-style probing)",
            Ja => "ホップ単位のトレースは Linux のみ対応です (tracepath 方式)",
        },
        TraceNoData => match lang {
            En => "no hop data (ICMP replies may be filtered on this network)",
            Ja => "ホップ情報なし (このネットワークでは ICMP 応答がフィルタされている可能性)",
        },
        NoNameservers => match lang {
            En => "no nameservers found in resolv.conf",
            Ja => "resolv.conf にネームサーバが見つかりません",
        },
        HostsNoOverride => match lang {
            En => "/etc/hosts: no overrides",
            Ja => "/etc/hosts: 上書きなし",
        },
        NoProxyVars => match lang {
            En => "proxy environment variables: none",
            Ja => "プロキシ環境変数: なし",
        },
        DnsSkippedIpLiteral => match lang {
            En => "target is an IP literal, skipping name resolution",
            Ja => "ターゲットは IP リテラルのため名前解決をスキップ",
        },
        NoResolvedIps => match lang {
            En => "no IPs to connect to (name resolution failed)",
            Ja => "接続先 IP がありません (名前解決に失敗)",
        },
        TlsSkippedNoTcp => match lang {
            En => "skipping TLS because no TCP connection could be established",
            Ja => "TCP 接続が確立できないため TLS 診断をスキップ",
        },
        HttpSkippedNoTcp => match lang {
            En => "skipping HTTP because no TCP connection could be established",
            Ja => "TCP 接続が確立できないため HTTP 診断をスキップ",
        },
        CertChainOk => match lang {
            En => "certificate chain verified: OK, hostname matches",
            Ja => "証明書チェーン検証: OK / ホスト名一致",
        },
        VerdictLabel => match lang {
            En => "[VERDICT]",
            Ja => "【判定】",
        },
        EvidenceLabel => match lang {
            En => "[EVIDENCE]",
            Ja => "【根拠】",
        },
        NotesLabel => match lang {
            En => "[NOTES]",
            Ja => "【所見】",
        },
        NextStepLabel => match lang {
            En => "[NEXT STEP]",
            Ja => "【次の一手】",
        },
        Bullet => match lang {
            En => "• ",
            Ja => "・",
        },
        UnknownError => match lang {
            En => "unknown error",
            Ja => "不明なエラー",
        },
        ErrorPrefix => match lang {
            En => "error",
            Ja => "エラー",
        },
        JsonWatchConflict => match lang {
            En => "--json cannot be combined with --watch",
            Ja => "--json と --watch は同時に指定できません",
        },
        WatchSummaryHeader => match lang {
            En => "Watch summary",
            Ja => "監視サマリ",
        },
        WatchProblemsHeader => match lang {
            En => "Problems seen:",
            Ja => "検出した問題:",
        },
        ShareWatchConflict => match lang {
            En => "--share cannot be combined with --watch",
            Ja => "--share と --watch は同時に指定できません",
        },
    }
}

// ── General / stage-line helpers ────────────────────────────────────────

pub fn diagnosing_line(lang: Lang, host: &str, port: u16) -> String {
    match lang {
        Lang::En => format!("diagnosing {host} (port {port})…"),
        Lang::Ja => format!("{host} (port {port}) を診断します…"),
    }
}

pub fn nameservers_line(lang: Lang, list: &str) -> String {
    match lang {
        Lang::En => format!("nameservers: {list}"),
        Lang::Ja => format!("ネームサーバ: {list}"),
    }
}

pub fn search_domains_line(lang: Lang, list: &str) -> String {
    match lang {
        Lang::En => format!("search domains: {list}"),
        Lang::Ja => format!("search ドメイン: {list}"),
    }
}

pub fn hosts_override_line(lang: Lang, host: &str, ip: &str) -> String {
    match lang {
        Lang::En => format!("/etc/hosts overrides {host} with {ip}"),
        Lang::Ja => format!("/etc/hosts が {host} を {ip} に上書きしています"),
    }
}

pub fn proxy_detected_line(lang: Lang, key: &str, value: &str) -> String {
    match lang {
        Lang::En => format!("proxy detected: {key}={value}"),
        Lang::Ja => format!("プロキシ検出: {key}={value}"),
    }
}

pub fn dns_ok_line(lang: Lang, label: &str, count: usize, ms: &str, ips: &str) -> String {
    match lang {
        Lang::En => format!("{label}: {count} answers ({ms}) [{ips}]"),
        Lang::Ja => format!("{label}: {count} 件の回答 ({ms}) [{ips}]"),
    }
}

pub fn dns_nxdomain_line(lang: Lang, label: &str) -> String {
    match lang {
        Lang::En => format!("{label}: NXDOMAIN (name does not exist)"),
        Lang::Ja => format!("{label}: NXDOMAIN (名前が存在しない)"),
    }
}

pub fn dns_servfail_line(_lang: Lang, label: &str) -> String {
    format!("{label}: SERVFAIL")
}

pub fn dns_timeout_line(lang: Lang, label: &str) -> String {
    match lang {
        Lang::En => format!("{label}: timed out"),
        Lang::Ja => format!("{label}: タイムアウト"),
    }
}

pub fn dns_error_line(_lang: Lang, label: &str, error: &str) -> String {
    format!("{label}: {error}")
}

fn family(ip: &IpAddr) -> &'static str {
    if ip.is_ipv6() {
        "IPv6"
    } else {
        "IPv4"
    }
}

#[allow(clippy::too_many_arguments)]
pub fn tcp_ok_line(
    lang: Lang,
    ip: &IpAddr,
    port: u16,
    successes: u32,
    samples: u32,
    min: &str,
    avg: &str,
    max: &str,
) -> String {
    let fam = family(ip);
    match lang {
        Lang::En => format!(
            "{fam} {ip}:{port} connected {successes}/{samples} (min/avg/max {min}/{avg}/{max})"
        ),
        Lang::Ja => format!(
            "{fam} {ip}:{port} 接続成功 {successes}/{samples} (min/avg/max {min}/{avg}/{max})"
        ),
    }
}

pub fn tcp_refused_line(lang: Lang, ip: &IpAddr, port: u16) -> String {
    let fam = family(ip);
    match lang {
        Lang::En => format!("{fam} {ip}:{port} connection refused (port closed, host is alive)"),
        Lang::Ja => format!("{fam} {ip}:{port} 接続拒否 (ポートは閉じているがホストは生存)"),
    }
}

pub fn tcp_timeout_line(lang: Lang, ip: &IpAddr, port: u16) -> String {
    let fam = family(ip);
    match lang {
        Lang::En => format!("{fam} {ip}:{port} timed out (filtered or unreachable)"),
        Lang::Ja => format!("{fam} {ip}:{port} タイムアウト (フィルタ/到達不能)"),
    }
}

pub fn tcp_error_line(lang: Lang, ip: &IpAddr, port: u16, error: &str) -> String {
    let fam = family(ip);
    match lang {
        Lang::En => format!("{fam} {ip}:{port} failed: {error}"),
        Lang::Ja => format!("{fam} {ip}:{port} 失敗: {error}"),
    }
}

pub fn tls_handshake_ok_line(lang: Lang, version: &str, ms: &str) -> String {
    match lang {
        Lang::En => format!("handshake OK: {version} ({ms})"),
        Lang::Ja => format!("ハンドシェイク成功: {version} ({ms})"),
    }
}

pub fn cert_expired_ago_line(lang: Lang, days: i64) -> String {
    match lang {
        Lang::En => format!("certificate expired {days} days ago"),
        Lang::Ja => format!("証明書は {days} 日前に失効"),
    }
}

pub fn cert_days_left_line(lang: Lang, days: i64) -> String {
    match lang {
        Lang::En => format!("certificate valid for {days} more days"),
        Lang::Ja => format!("証明書の残り有効期間: {days} 日"),
    }
}

pub fn cert_verify_failed_line(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("certificate verification failed: {error}"),
        Lang::Ja => format!("証明書検証失敗: {error}"),
    }
}

pub fn presented_issuer_line(lang: Lang, issuer: &str, middlebox_suspected: bool) -> String {
    match (lang, middlebox_suspected) {
        (Lang::En, true) => format!("presented issuer: {issuer} (possible middlebox)"),
        (Lang::En, false) => format!("presented issuer: {issuer}"),
        (Lang::Ja, true) => format!("提示された発行者: {issuer} (ミドルボックスの疑い)"),
        (Lang::Ja, false) => format!("提示された発行者: {issuer}"),
    }
}

pub fn http_redirect_line(lang: Lang, hop: &str) -> String {
    match lang {
        Lang::En => format!("redirect: {hop}"),
        Lang::Ja => format!("リダイレクト: {hop}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn http_result_line(
    lang: Lang,
    url: &str,
    status: u16,
    dns: &str,
    connect: &str,
    tls: &str,
    ttfb: &str,
    total: &str,
) -> String {
    match lang {
        Lang::En => format!(
            "GET {url} → {status} (DNS {dns} / connect {connect} / TLS {tls} / TTFB {ttfb} / total {total})"
        ),
        Lang::Ja => format!(
            "GET {url} → {status} (DNS {dns} / 接続 {connect} / TLS {tls} / TTFB {ttfb} / 合計 {total})"
        ),
    }
}

pub fn http_status_with_error_line(lang: Lang, url: &str, status: u16, error: &str) -> String {
    match lang {
        Lang::En => format!("GET {url} → {status} but errored: {error}"),
        Lang::Ja => format!("GET {url} → {status} だがエラー: {error}"),
    }
}

pub fn http_failed_line(lang: Lang, url: &str, error: &str) -> String {
    match lang {
        Lang::En => format!("GET {url} failed: {error}"),
        Lang::Ja => format!("GET {url} 失敗: {error}"),
    }
}

pub fn http_no_result_line(lang: Lang, url: &str) -> String {
    match lang {
        Lang::En => format!("GET {url}: no result"),
        Lang::Ja => format!("GET {url}: 結果なし"),
    }
}

// ── QUIC/HTTP3 (v0.4) ───────────────────────────────────────────────────

pub fn quic_handshake_ok_line(lang: Lang, ms: &str, alpn: &str) -> String {
    match lang {
        Lang::En => format!("QUIC handshake OK: {ms} ({alpn})"),
        Lang::Ja => format!("QUIC ハンドシェイク成功: {ms} ({alpn})"),
    }
}

pub fn quic_timeout_line(lang: Lang, port: u16) -> String {
    match lang {
        Lang::En => format!("no response on UDP {port} (timeout)"),
        Lang::Ja => format!("UDP {port} 応答なし (タイムアウト)"),
    }
}

pub fn quic_handshake_error_line(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("QUIC handshake failed: {error}"),
        Lang::Ja => format!("QUIC ハンドシェイク失敗: {error}"),
    }
}

pub fn quic_local_error_line(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("could not run the QUIC probe locally: {error}"),
        Lang::Ja => format!("QUIC プローブをローカルで実行できませんでした: {error}"),
    }
}

pub fn h3_not_advertised_line(lang: Lang) -> String {
    match lang {
        Lang::En => "HTTP/3 is not advertised (no alt-svc)".to_string(),
        Lang::Ja => "HTTP/3 は広告されていません (alt-svc なし)".to_string(),
    }
}

pub fn h3_advertised_line(lang: Lang, alt_svc: &str) -> String {
    match lang {
        Lang::En => format!("HTTP/3 advertised via alt-svc: {alt_svc}"),
        Lang::Ja => format!("alt-svc で HTTP/3 が広告されています: {alt_svc}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn path_line(
    lang: Lang,
    sent: u32,
    loss_pct: f64,
    min: &str,
    avg: &str,
    max: &str,
    jitter: &str,
) -> String {
    match lang {
        Lang::En => format!(
            "{sent} probes: loss {loss_pct:.0}% / RTT min/avg/max {min}/{avg}/{max} / jitter {jitter}"
        ),
        Lang::Ja => format!(
            "{sent} 回プローブ: ロス {loss_pct:.0}% / RTT min/avg/max {min}/{avg}/{max} / ジッタ {jitter}"
        ),
    }
}

// ── Path trace (stage 7) ────────────────────────────────────────────────

/// 応答があったホップの 1 行 (例: "  3  203.0.113.45  12ms")
pub fn trace_hop_line(_lang: Lang, index: u8, addr: &str, rtt: &str) -> String {
    format!("{index:>2}  {addr}  {rtt}")
}

/// 無応答ホップの 1 行 (例: "  4  *  (no reply)")
pub fn trace_hop_noreply_line(lang: Lang, index: u8) -> String {
    match lang {
        Lang::En => format!("{index:>2}  *  (no reply)"),
        Lang::Ja => format!("{index:>2}  *  (応答なし)"),
    }
}

pub fn trace_dest_reached_line(lang: Lang, hops: u8) -> String {
    match lang {
        Lang::En => format!("destination reached in {hops} hops"),
        Lang::Ja => format!("宛先に到達 ({hops} ホップ)"),
    }
}

pub fn path_mtu_line(lang: Lang, mtu: u16) -> String {
    match lang {
        Lang::En => format!("Path MTU: {mtu}"),
        Lang::Ja => format!("経路 MTU: {mtu}"),
    }
}

pub fn trace_failed_line(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("hop trace failed: {error}"),
        Lang::Ja => format!("経路トレース失敗: {error}"),
    }
}

// Linux の trace プローブからのみ呼ばれる (他プラットフォームでは未使用)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn probe_trace_timeout(lang: Lang) -> String {
    match lang {
        Lang::En => "hop trace timed out".to_string(),
        Lang::Ja => "経路トレースがタイムアウト".to_string(),
    }
}

pub fn json_serialize_failed(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("failed to serialize JSON: {error}"),
        Lang::Ja => format!("JSON 出力に失敗: {error}"),
    }
}

// ── Report sharing (--share, v0.5) ──────────────────────────────────────

pub fn share_uploading_line(lang: Lang, base_url: &str) -> String {
    match lang {
        Lang::En => format!("uploading report to {base_url}…"),
        Lang::Ja => format!("{base_url} にレポートをアップロードしています…"),
    }
}

pub fn share_success_line(lang: Lang, url: &str) -> String {
    match lang {
        Lang::En => format!("Report shared: {url}"),
        Lang::Ja => format!("レポートを共有しました: {url}"),
    }
}

pub fn share_failed_line(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("could not share the report: {error}"),
        Lang::Ja => format!("レポートの共有に失敗しました: {error}"),
    }
}

// ── Target parse errors ─────────────────────────────────────────────────

pub fn parse_error(lang: Lang, e: &crate::ParseError) -> String {
    use crate::ParseError::*; // re-exported at crate root (see lib.rs)
    match e {
        UnsupportedScheme(raw) => match lang {
            Lang::En => format!("unsupported scheme: {raw}"),
            Lang::Ja => format!("未対応のスキームです: {raw}"),
        },
        EmptyHost => match lang {
            Lang::En => "empty host name".to_string(),
            Lang::Ja => "ホスト名が空です".to_string(),
        },
        UnclosedIpv6 => match lang {
            Lang::En => "missing ']' in IPv6 literal".to_string(),
            Lang::Ja => "IPv6 リテラルの ']' がありません".to_string(),
        },
        InvalidPort(p) => match lang {
            Lang::En => format!("invalid port number: {p}"),
            Lang::Ja => format!("ポート番号が不正です: {p}"),
        },
    }
}

// ── Strings generated inside probes ─────────────────────────────────────

pub fn label_system_resolver(lang: Lang) -> String {
    match lang {
        Lang::En => "system resolver".to_string(),
        Lang::Ja => "システムリゾルバ".to_string(),
    }
}

pub fn label_local_ns(lang: Lang, ns: &IpAddr) -> String {
    match lang {
        Lang::En => format!("local {ns}"),
        Lang::Ja => format!("ローカル {ns}"),
    }
}

pub fn probe_resolver_init_failed(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("resolver init failed: {error}"),
        Lang::Ja => format!("リゾルバ初期化失敗: {error}"),
    }
}

pub fn probe_no_records(lang: Lang, code: &str) -> String {
    match lang {
        Lang::En => format!("no records ({code})"),
        Lang::Ja => format!("レコードなし ({code})"),
    }
}

pub fn probe_response_code(lang: Lang, code: &str) -> String {
    match lang {
        Lang::En => format!("response code {code}"),
        Lang::Ja => format!("応答コード {code}"),
    }
}

pub fn probe_no_attempts(lang: Lang) -> String {
    match lang {
        Lang::En => "no attempts".to_string(),
        Lang::Ja => "試行なし".to_string(),
    }
}

pub fn probe_tcp_connect_timeout(lang: Lang) -> String {
    match lang {
        Lang::En => "TCP connect timed out".to_string(),
        Lang::Ja => "TCP 接続タイムアウト".to_string(),
    }
}

pub fn probe_tcp_connect_failed(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("TCP connect failed: {error}"),
        Lang::Ja => format!("TCP 接続失敗: {error}"),
    }
}

pub fn probe_tls_handshake_timeout(lang: Lang) -> String {
    match lang {
        Lang::En => "TLS handshake timed out".to_string(),
        Lang::Ja => "TLS ハンドシェイクタイムアウト".to_string(),
    }
}

pub fn probe_http_client_init_failed(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("failed to build HTTP client: {error}"),
        Lang::Ja => format!("HTTP クライアント初期化失敗: {error}"),
    }
}

pub fn probe_too_many_redirects(lang: Lang, max: usize) -> String {
    match lang {
        Lang::En => format!("more than {max} redirects"),
        Lang::Ja => format!("リダイレクトが {max} 回を超過"),
    }
}

pub fn probe_no_location_header(lang: Lang) -> String {
    match lang {
        Lang::En => "redirect response has no Location header".to_string(),
        Lang::Ja => "リダイレクト応答に Location ヘッダがない".to_string(),
    }
}

pub fn probe_body_read_failed(lang: Lang, error: &str) -> String {
    match lang {
        Lang::En => format!("failed to read body: {error}"),
        Lang::Ja => format!("ボディ受信失敗: {error}"),
    }
}

// ── Verdict rendering ───────────────────────────────────────────────────

pub fn dns_outcome_label(lang: Lang, o: &DnsOutcome) -> String {
    match o {
        DnsOutcome::Ok => "OK".into(),
        DnsOutcome::NxDomain => "NXDOMAIN".into(),
        DnsOutcome::ServFail => "SERVFAIL".into(),
        DnsOutcome::Timeout => match lang {
            Lang::En => "timeout".into(),
            Lang::Ja => "タイムアウト".into(),
        },
        DnsOutcome::Error(e) => match lang {
            Lang::En => format!("error: {e}"),
            Lang::Ja => format!("エラー: {e}"),
        },
    }
}

/// The one-line culprit statement.
pub fn headline(lang: Lang, h: &Headline) -> String {
    use Headline::*;
    match h {
        NameDoesNotExist { host } => match lang {
            Lang::En => {
                format!("The domain \"{host}\" does not exist. This is not a network problem")
            }
            Lang::Ja => {
                format!("ドメイン「{host}」は存在しません。ネットワークのせいではありません")
            }
        },
        LocalDnsBroken => match lang {
            Lang::En => "Your local DNS resolver is not working".into(),
            Lang::Ja => "ローカル DNS リゾルバが機能していません".into(),
        },
        LocalDnsSlow => match lang {
            Lang::En => "Your local DNS resolver is slow, dragging down everything".into(),
            Lang::Ja => "ローカル DNS リゾルバが遅く、全体の体感を悪化させています".into(),
        },
        OutboundDead => match lang {
            Lang::En => {
                "All outbound traffic is failing. Your network connection itself is down".into()
            }
            Lang::Ja => "外向きの通信が全滅しています。ネットワーク接続自体に問題があります".into(),
        },
        DnsAnswerMismatch => match lang {
            Lang::En => {
                "Local and public DNS give different answers, and the connection fails".into()
            }
            Lang::Ja => {
                "ローカル DNS とパブリック DNS で回答が異なり、接続にも失敗しています".into()
            }
        },
        ServerDown { port } => match lang {
            Lang::En => format!("The server is up, but nothing is listening on port {port}"),
            Lang::Ja => format!("サーバは生きていますが、ポート {port} で何も待ち受けていません"),
        },
        TcpBlocked { port } => match lang {
            Lang::En => {
                format!("TCP connections to port {port} time out (filtered or unreachable)")
            }
            Lang::Ja => {
                format!("ポート {port} への TCP 接続がタイムアウトします (フィルタ/到達不能)")
            }
        },
        Ipv6Broken => match lang {
            Lang::En => "Your IPv6 path is broken (IPv4 is fine)".into(),
            Lang::Ja => "IPv6 経路が壊れています (IPv4 は正常)".into(),
        },
        TlsCertExpired => match lang {
            Lang::En => {
                "The server's TLS certificate has expired. This is not a network problem".into()
            }
            Lang::Ja => {
                "サーバの TLS 証明書が期限切れです。ネットワークのせいではありません".into()
            }
        },
        TlsIntercepted => match lang {
            Lang::En => "Your TLS traffic is most likely being intercepted in transit".into(),
            Lang::Ja => "TLS 通信が途中で傍受されている可能性が高いです".into(),
        },
        TlsCertInvalid => match lang {
            Lang::En => {
                "The server's TLS certificate is invalid (chain verification failed)".into()
            }
            Lang::Ja => "サーバの TLS 証明書が不正です (チェーン検証失敗)".into(),
        },
        ProxyInterference => match lang {
            Lang::En => "A proxy setting is most likely interfering with your traffic".into(),
            Lang::Ja => "プロキシ設定が通信を妨げている可能性が高いです".into(),
        },
        ServerSlow => match lang {
            Lang::En => "The server is slow to respond. The network is fine".into(),
            Lang::Ja => "サーバ側の応答が遅いです。ネットワークは正常です".into(),
        },
        UnstablePath => match lang {
            Lang::En => "The network path is unstable (high packet loss / jitter)".into(),
            Lang::Ja => "ネットワーク経路が不安定です (パケットロス/ジッタ大)".into(),
        },
        PmtuBlackhole => match lang {
            Lang::En => {
                "Path MTU is restricted and PMTUD is broken — large packets vanish silently (black hole)"
                    .into()
            }
            Lang::Ja => {
                "経路 MTU が制限されているのに PMTUD が機能していません — 大きいパケットが黙って消えます (ブラックホール)"
                    .into()
            }
        },
        Udp443Blocked => match lang {
            Lang::En => {
                "TCP works fine, but UDP 443 (QUIC/HTTP3) is completely unreachable".into()
            }
            Lang::Ja => {
                "TCP は正常ですが、UDP 443 (QUIC/HTTP3) には全く到達できません".into()
            }
        },
        NoProblem => match lang {
            Lang::En => {
                "No problem found. The path to this destination is healthy right now".into()
            }
            Lang::Ja => {
                "問題は見つかりませんでした。少なくとも今、この宛先への経路は健全です".into()
            }
        },
    }
}

/// The suggested action for each verdict.
pub fn next_step(lang: Lang, h: &Headline) -> &'static str {
    use Headline::*;
    match h {
        NameDoesNotExist { .. } => match lang {
            Lang::En => "Check the hostname for typos. If it should be correct, the domain registration may have lapsed",
            Lang::Ja => "ホスト名のタイプミスを確認してください。正しいはずなら、ドメインの有効期限切れの可能性があります",
        },
        LocalDnsBroken => match lang {
            Lang::En => "Restart your router, or switch your DNS servers to 1.1.1.1 / 8.8.8.8 as a workaround",
            Lang::Ja => "ルータの再起動、または DNS サーバを 1.1.1.1 / 8.8.8.8 に変更して回避できます",
        },
        LocalDnsSlow => match lang {
            Lang::En => "Switching your DNS servers to 1.1.1.1 or 8.8.8.8 should noticeably help",
            Lang::Ja => "DNS サーバを 1.1.1.1 または 8.8.8.8 に変更すると改善が見込めます",
        },
        OutboundDead => match lang {
            Lang::En => "Check your cable/Wi-Fi and router. Other sites should be failing too",
            Lang::Ja => "ケーブル/Wi-Fi 接続とルータの状態を確認してください。他のサイトも開けないはずです",
        },
        DnsAnswerMismatch => match lang {
            Lang::En => "On a corporate network, ask your administrator. At home, check your router's DNS settings and any security software",
            Lang::Ja => "社内ネットワークなら管理者に確認を。家庭ならルータの DNS 設定とセキュリティソフトを確認してください",
        },
        ServerDown { .. } => match lang {
            Lang::En => "Double-check the port number. If it is correct, the service on the server is down",
            Lang::Ja => "ポート番号が正しいか確認してください。正しければサーバ側のサービス停止です",
        },
        TcpBlocked { .. } => match lang {
            Lang::En => "Try from another network (e.g. phone tethering) to isolate it. If it works there, a filter on this network is the culprit",
            Lang::Ja => "別ネットワーク (スマホのテザリング等) から試して切り分けてください。そちらで繋がるなら今のネットワークのフィルタが原因です",
        },
        Ipv6Broken => match lang {
            Lang::En => "Check the IPv6 settings on your router and ISP line. As a stopgap, you can disable IPv6 in the OS",
            Lang::Ja => "ルータ/回線の IPv6 設定を確認してください。応急処置として OS で IPv6 を無効化する手もあります",
        },
        TlsCertExpired => match lang {
            Lang::En => "Ask the server administrator to renew the certificate — or renew it yourself if it is your site",
            Lang::Ja => "サーバ管理者に証明書の更新を依頼してください。自分のサイトなら証明書を更新してください",
        },
        TlsIntercepted => match lang {
            Lang::En => "On a corporate network this means SSL inspection is on. Ask your administrator, or install the corporate CA certificate",
            Lang::Ja => "社内ネットワークなら SSL インスペクションが有効です。管理者に確認するか、社の CA 証明書を導入してください",
        },
        TlsCertInvalid => match lang {
            Lang::En => "Check that the URL is correct. If it is, the server's certificate is most likely misconfigured",
            Lang::Ja => "URL が正しいか確認してください。正しければサーバ側の証明書設定ミスの可能性が高いです",
        },
        ProxyInterference => match lang {
            Lang::En => "Temporarily `unset http_proxy https_proxy` and retry. If that fixes it, the proxy setting is the culprit",
            Lang::Ja => "unset http_proxy https_proxy で一時解除して再試行してください。直るならプロキシ設定が犯人です",
        },
        ServerSlow => match lang {
            Lang::En => "Tweaking your line or router will not help. Contact the server administrator, or retry later",
            Lang::Ja => "回線やルータをいじっても改善しません。サーバ管理者への連絡か、時間を置いての再試行を",
        },
        UnstablePath => match lang {
            Lang::En => "On Wi-Fi, try a wired connection or the 5 GHz band. If already wired, the problem may be on your ISP's side",
            Lang::Ja => "Wi-Fi なら有線接続か 5GHz 帯への変更を試してください。有線なら回線事業者側の問題の可能性があります",
        },
        PmtuBlackhole => match lang {
            Lang::En => "Check the MTU setting on your VPN/tunnel, and enable MSS clamping on the router. Lowering the interface MTU to the detected path MTU is a quick workaround",
            Lang::Ja => "VPN/トンネルの MTU 設定を確認し、ルータで MSS clamp (TCP MSS 調整) を有効化してください。インタフェースの MTU を検出値まで下げるのが応急処置になります",
        },
        Udp443Blocked => match lang {
            Lang::En => "Browsers silently fall back to HTTP/2, so this is easy to miss — but it adds latency on the first connection and breaks services that require HTTP/3. Check your firewall rules for UDP 443",
            Lang::Ja => "ブラウザは HTTP/2 にフォールバックするため気づきにくいが、初回接続の遅延や HTTP/3 前提のサービスで問題になります。FW ルールで UDP 443 を確認してください",
        },
        NoProblem => match lang {
            Lang::En => "If the problem is intermittent, run this again while the symptom is happening",
            Lang::Ja => "問題が断続的なら、症状が出ている最中にもう一度実行してください",
        },
    }
}

/// One evidence bullet.
pub fn evidence_line(lang: Lang, e: &Evidence) -> String {
    use Evidence::*;
    match e {
        AllSourcesNxDomain => match lang {
            Lang::En => "Every DNS server queried answered NXDOMAIN (no such name)".into(),
            Lang::Ja => "問い合わせた全ての DNS サーバが NXDOMAIN (そんな名前は無い) と回答".into(),
        },
        PublicDnsAgrees => match lang {
            Lang::En => "Public DNS (1.1.1.1 / 8.8.8.8) gives the same answer".into(),
            Lang::Ja => "パブリック DNS (1.1.1.1 / 8.8.8.8) でも同じ回答".into(),
        },
        PublicDnsResolves => match lang {
            Lang::En => "Public DNS (1.1.1.1 / 8.8.8.8) resolves the name fine".into(),
            Lang::Ja => "パブリック DNS (1.1.1.1 / 8.8.8.8) では名前解決に成功".into(),
        },
        LocalDnsSourceFailed { label, outcome } => {
            let o = dns_outcome_label(lang, outcome);
            match lang {
                Lang::En => format!("{label} failed ({o})"),
                Lang::Ja => format!("{label} ({o}) は失敗"),
            }
        }
        AllDnsUnresponsive => match lang {
            Lang::En => "Neither local DNS nor public DNS (1.1.1.1 / 8.8.8.8) responds".into(),
            Lang::Ja => "ローカル DNS もパブリック DNS (1.1.1.1 / 8.8.8.8) も応答しない".into(),
        },
        OutboundBlockedSuspected => match lang {
            Lang::En => {
                "Outbound UDP/TCP is most likely not getting through at all, before DNS even matters"
                    .into()
            }
            Lang::Ja => "名前解決以前に、外への UDP/TCP が通っていない可能性が高い".into(),
        },
        LocalDnsAnswers { ips } => match lang {
            Lang::En => format!("local answers: {}", ips.join(", ")),
            Lang::Ja => format!("ローカル側の回答: {}", ips.join(", ")),
        },
        PublicDnsAnswers { ips } => match lang {
            Lang::En => format!("public answers: {}", ips.join(", ")),
            Lang::Ja => format!("パブリック側の回答: {}", ips.join(", ")),
        },
        SplitHorizonSuspected => match lang {
            Lang::En => "Possible split-horizon DNS, filtering, or DNS rewriting".into(),
            Lang::Ja => "スプリットホライズン DNS、フィルタリング、または DNS 書き換えの可能性".into(),
        },
        AllConnectionsRefused => match lang {
            Lang::En => "Every connection attempt was immediately refused (RST)".into(),
            Lang::Ja => "全ての接続試行が RST (connection refused) で即座に拒否された".into(),
        },
        HostReachable => match lang {
            Lang::En => "The host itself is reachable — the network path is fine".into(),
            Lang::Ja => "ホストまでは到達できている = ネットワーク経路は正常".into(),
        },
        DnsOkTcpTimedOut => match lang {
            Lang::En => "Name resolution succeeds, but TCP connections time out on every IP".into(),
            Lang::Ja => "名前解決は成功しているが、TCP 接続が全ての IP でタイムアウト".into(),
        },
        FirewallOrDeadPath => match lang {
            Lang::En => "A firewall along the way is dropping the traffic, or the path is dead".into(),
            Lang::Ja => "途中のファイアウォールで落とされているか、経路が死んでいる".into(),
        },
        Ipv6ConnectFailed { count } => match lang {
            Lang::En => format!("TCP connections to all {count} IPv6 addresses failed"),
            Lang::Ja => format!("IPv6 アドレスへの TCP 接続が {count} 件全て失敗"),
        },
        Ipv4Works => match lang {
            Lang::En => {
                "IPv4 connections succeed — fallback keeps things working, but connection setup gets slower"
                    .into()
            }
            Lang::Ja => "IPv4 への接続は成功 — フォールバックで繋がるが、接続開始が遅くなる".into(),
        },
        CertExpiredDaysAgo { days } => match lang {
            Lang::En => format!("The certificate expired {days} days ago"),
            Lang::Ja => format!("証明書は {days} 日前に失効"),
        },
        TcpFineSoPathOk => match lang {
            Lang::En => "TCP connects fine — the path itself is healthy".into(),
            Lang::Ja => "TCP 接続までは正常 = 経路は問題なし".into(),
        },
        PresentedIssuer { issuer } => match lang {
            Lang::En => format!("presented certificate issuer: {issuer}"),
            Lang::Ja => format!("提示された証明書の発行者: {issuer}"),
        },
        MiddleboxIssuer => match lang {
            Lang::En => {
                "The issuer looks like a middlebox (firewall/proxy product), not a real certificate authority"
                    .into()
            }
            Lang::Ja => {
                "本来の認証局ではなく、ミドルボックス (FW/プロキシ製品) 由来と思われる発行者".into()
            }
        },
        ChainVerifyFailed { error } => match lang {
            Lang::En => format!("certificate chain verification failed: {error}"),
            Lang::Ja => format!("証明書チェーンの検証に失敗: {error}"),
        },
        HostnameMismatch => match lang {
            Lang::En => "The certificate's hostname does not match the target".into(),
            Lang::Ja => "証明書のホスト名がターゲットと一致しない".into(),
        },
        ProxyVarsDetected { vars } => match lang {
            Lang::En => format!("proxy environment variables detected: {}", vars.join(", ")),
            Lang::Ja => format!("プロキシ環境変数を検出: {}", vars.join(", ")),
        },
        TcpOkHttpFailed => match lang {
            Lang::En => "Direct TCP connections succeed, yet the HTTP request fails".into(),
            Lang::Ja => "TCP 直結は成功するのに、HTTP リクエストは失敗".into(),
        },
        HttpErrorDetail { error } => match lang {
            Lang::En => format!("HTTP error: {error}"),
            Lang::Ja => format!("HTTP エラー: {error}"),
        },
        ConnectFast { ms } => match lang {
            Lang::En => format!("TCP connects in {ms:.0}ms — the path is healthy"),
            Lang::Ja => format!("TCP 接続は {ms:.0}ms と高速 = 経路は健全"),
        },
        TtfbSlow { ms } => match lang {
            Lang::En => format!("yet the first byte of the response (TTFB) takes {ms:.0}ms"),
            Lang::Ja => format!("しかし最初の応答 (TTFB) まで {ms:.0}ms かかっている"),
        },
        ServerSideProcessing => match lang {
            Lang::En => "The slow part is server-side processing (application/database)".into(),
            Lang::Ja => "遅いのはサーバの処理 (アプリ/DB) 側".into(),
        },
        ProbeLoss { sent, lost, pct } => match lang {
            Lang::En => format!("{lost} of {sent} connection probes failed ({pct:.0}% loss)"),
            Lang::Ja => format!("接続プローブ {sent} 回中 {lost} 回失敗 (ロス率 {pct:.0}%)"),
        },
        RttStats { avg, jitter } => match lang {
            Lang::En => format!("RTT average {avg:.0}ms / jitter {jitter:.0}ms"),
            Lang::Ja => format!("RTT 平均 {avg:.0}ms / ジッタ {jitter:.0}ms"),
        },
        UnstablePathSymptom => match lang {
            Lang::En => {
                "An unstable path — the classic cause of \"it feels slow\" and \"it keeps cutting out\""
                    .into()
            }
            Lang::Ja => "経路が不安定 — 体感の「重い」「途切れる」の典型パターン".into(),
        },
        LocalDnsLatency { ms } => match lang {
            Lang::En => format!("local DNS takes {ms:.0}ms to answer"),
            Lang::Ja => format!("ローカル DNS の応答に {ms:.0}ms"),
        },
        PublicDnsLatency { ms } => match lang {
            Lang::En => format!("public DNS (1.1.1.1 / 8.8.8.8) answers in {ms:.0}ms"),
            Lang::Ja => format!("パブリック DNS (1.1.1.1 / 8.8.8.8) は {ms:.0}ms と高速"),
        },
        LatencyAddedEveryPage => match lang {
            Lang::En => "That difference is added to every page you open".into(),
            Lang::Ja => "ページを開くたびにこの差が上乗せされる".into(),
        },
        DnsHealthy => match lang {
            Lang::En => "name resolution: OK".into(),
            Lang::Ja => "名前解決: 正常".into(),
        },
        TcpHealthy { ms } => match lang {
            Lang::En => format!("TCP connect: OK ({ms:.0}ms)"),
            Lang::Ja => format!("TCP 接続: 正常 ({ms:.0}ms)"),
        },
        TlsHealthy { version, days } => match lang {
            Lang::En => format!("TLS: OK ({version}, certificate valid for {days} more days)"),
            Lang::Ja => format!("TLS: 正常 ({version}, 証明書残り {days} 日)"),
        },
        HttpHealthy { status, ttfb } => format!("HTTP: {status} (TTFB {ttfb:.0}ms)"),
        PathHealthy { loss_pct, jitter } => match lang {
            Lang::En => format!("path quality: loss {loss_pct:.0}% / jitter {jitter:.0}ms"),
            Lang::Ja => format!("経路品質: ロス {loss_pct:.0}% / ジッタ {jitter:.0}ms"),
        },
        AllStagesOk => match lang {
            Lang::En => "no anomalies in any stage that ran".into(),
            Lang::Ja => "実施した全ステージで異常なし".into(),
        },
        LastRespondingHop { ip, index, path_len } => match lang {
            Lang::En => format!("last responding hop: {ip} (hop {index} of ~{path_len})"),
            Lang::Ja => format!("最後に応答したホップ: {ip} (ホップ {index} / 推定経路長 ~{path_len})"),
        },
        PmtuBlackholeObserved { mtu } => match lang {
            Lang::En => format!(
                "path MTU is {mtu} bytes, yet oversized DF packets trigger no ICMP notification (PMTUD black hole)"
            ),
            Lang::Ja => format!(
                "経路 MTU が {mtu} バイトだが、超過パケットへの ICMP 通知が返ってこない (PMTUD ブラックホール)"
            ),
        },
        TcpTlsHttpHealthySoQuicIsolated => match lang {
            Lang::En => {
                "TCP 443 is healthy (TLS handshake and HTTP request both succeeded) — the problem is isolated to UDP 443"
                    .into()
            }
            Lang::Ja => {
                "TCP 443 は正常 (TLS ハンドシェイク・HTTP リクエストともに成功) — 問題は UDP 443 に限定されている"
                    .into()
            }
        },
        QuicAllTimedOut => match lang {
            Lang::En => "every QUIC handshake attempt got no response at all".into(),
            Lang::Ja => "QUIC ハンドシェイクの試行が全て無応答".into(),
        },
        Udp443LikelyFiltered => match lang {
            Lang::En => {
                "TCP 443 works fine, but every QUIC attempt over UDP 443 goes unanswered — a firewall is most likely dropping UDP 443"
                    .into()
            }
            Lang::Ja => {
                "TCP 443 は正常だが UDP 443 の QUIC が全て無応答 — ファイアウォールが UDP 443 を落としている可能性が高い"
                    .into()
            }
        },
    }
}

/// 障害ゾーン (最後に応答したホップの位置) に応じた切り分けガイダンス。
/// 【次の一手】の末尾に追記される。
pub fn zone_guidance(lang: Lang, zone: crate::probe::trace::HopZone) -> &'static str {
    use crate::probe::trace::HopZone;
    match zone {
        HopZone::Home => match lang {
            Lang::En => "The trace stops inside your home network (hop 1-2) — check or reboot your router/home gateway first",
            Lang::Ja => "トレースは宅内 (ホップ 1-2) で止まっています — まずルータ/ホームゲートウェイの確認・再起動を",
        },
        HopZone::Isp => match lang {
            Lang::En => "The trace stops in the early hops — likely inside your ISP's network; include the hop list when contacting them",
            Lang::Ja => "トレースは序盤のホップで止まっています — ISP 網内の可能性が高いので、問い合わせ時にホップ一覧を添えてください",
        },
        HopZone::FarSide => match lang {
            Lang::En => "The trace gets deep into the path — the problem is most likely on the far side (destination network)",
            Lang::Ja => "トレースは経路の奥まで到達しています — 対岸 (相手側ネットワーク) の問題の可能性が高いです",
        },
    }
}

/// 【次の一手】本文にゾーンガイダンスを連結する
pub fn append_guidance(base: &str, guidance: &str) -> String {
    format!("{base} — {guidance}")
}

/// One secondary-finding bullet.
pub fn finding_line(lang: Lang, f: &Finding) -> String {
    use Finding::*;
    match f {
        HostsOverride { host, ip } => match lang {
            Lang::En => format!(
                "/etc/hosts has an override for \"{host}\" ({ip}) — connections ignore DNS"
            ),
            Lang::Ja => format!(
                "/etc/hosts に「{host}」の上書きエントリあり ({ip}) — DNS を無視して接続しています"
            ),
        },
        ProxyEnvPresent { names } => match lang {
            Lang::En => format!("proxy environment variables are set: {}", names.join(", ")),
            Lang::Ja => format!("プロキシ環境変数が設定されています: {}", names.join(", ")),
        },
        DnsAnswersDiffer { local, public } => match lang {
            Lang::En => format!(
                "local and public DNS answers differ (local: {} / public: {}) — this can be normal with CDNs",
                local.join(", "),
                public.join(", ")
            ),
            Lang::Ja => format!(
                "ローカル DNS とパブリック DNS で回答が異なります (ローカル: {} / パブリック: {}) — CDN なら正常なこともあります",
                local.join(", "),
                public.join(", ")
            ),
        },
        CertExpiresSoon { days } => match lang {
            Lang::En => format!("the TLS certificate expires in only {days} days"),
            Lang::Ja => format!("TLS 証明書の残り有効期間が {days} 日と短い"),
        },
        QuicBrokenSecondary { h3_advertised } => match (lang, h3_advertised) {
            (Lang::En, true) => {
                "HTTP/3 is advertised (alt-svc) but the QUIC handshake did not succeed — likely UDP 443 is blocked, secondary to the bigger issue above".into()
            }
            (Lang::En, false) => {
                "the QUIC handshake did not succeed (HTTP/3 is not advertised on this response, so this may not matter)".into()
            }
            (Lang::Ja, true) => {
                "HTTP/3 は広告されている (alt-svc) が QUIC ハンドシェイクは失敗 — UDP 443 遮断の可能性があるが、上記のより大きな問題に付随する所見".into()
            }
            (Lang::Ja, false) => {
                "QUIC ハンドシェイクは失敗 (このレスポンスでは HTTP/3 が広告されていないため、実害は無い可能性が高い)".into()
            }
        },
        QuicTimeoutNoH3Expected => match lang {
            Lang::En => {
                "QUIC (UDP 443) got no response, but this server does not advertise HTTP/3 here — likely just unsupported on this IP, not a network block".into()
            }
            Lang::Ja => {
                "QUIC (UDP 443) は無応答だが、このサーバはここで HTTP/3 を広告していない — ネットワーク遮断ではなく、この IP では単に未対応の可能性が高い".into()
            }
        },
    }
}

// ── Watch mode ──────────────────────────────────────────────────────────

pub fn watch_start_line(lang: Lang, interval_secs: u64) -> String {
    match lang {
        Lang::En => {
            format!("watching every {interval_secs}s — press Ctrl-C to stop and show a summary")
        }
        Lang::Ja => {
            format!("{interval_secs} 秒間隔で監視します — Ctrl-C で終了してサマリを表示します")
        }
    }
}

pub fn watch_ok_details(_lang: Lang, dns: &str, tcp: &str, ttfb: &str, loss: &str) -> String {
    format!("OK (dns {dns} / tcp {tcp} / ttfb {ttfb} / loss {loss})")
}

pub fn watch_runs_line(lang: Lang, runs: u32, ok: u32, ok_pct: f64) -> String {
    match lang {
        Lang::En => format!("runs: {runs} / ok: {ok} ({ok_pct:.0}%)"),
        Lang::Ja => format!("実行回数: {runs} / 正常: {ok} ({ok_pct:.0}%)"),
    }
}

// ── Truncation (--max-time / Ctrl-C) ──────────────────────────────────────

pub fn truncated_header_line(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "[TRUNCATED] diagnosis stopped early — results below are partial",
        Lang::Ja => "【打ち切り】診断は途中で終了しました — 以下は部分的な結果です",
    }
}

pub fn truncation_reason_line(lang: Lang, reason: TruncationReason) -> String {
    match (lang, reason) {
        (Lang::En, TruncationReason::MaxTimeExceeded) => {
            "reason: --max-time deadline exceeded".to_string()
        }
        (Lang::En, TruncationReason::Interrupted) => "reason: interrupted (Ctrl-C)".to_string(),
        (Lang::Ja, TruncationReason::MaxTimeExceeded) => "理由: --max-time の期限切れ".to_string(),
        (Lang::Ja, TruncationReason::Interrupted) => "理由: 中断 (Ctrl-C)".to_string(),
    }
}

pub fn stages_ran_line(lang: Lang, list: &str) -> String {
    match lang {
        Lang::En => format!("stages completed: {list}"),
        Lang::Ja => format!("完了したステージ: {list}"),
    }
}

pub fn stages_skipped_line(lang: Lang, list: &str) -> String {
    match lang {
        Lang::En => format!("stages skipped: {list}"),
        Lang::Ja => format!("未実行のステージ: {list}"),
    }
}

pub fn watch_problem_line(
    lang: Lang,
    headline: &str,
    count: u32,
    first: &str,
    last: &str,
) -> String {
    match lang {
        Lang::En => format!("{headline} — {count} times (first {first} / last {last})"),
        Lang::Ja => format!("{headline} — {count} 回 (初回 {first} / 最終 {last})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_detection() {
        // LC_ALL wins, "ja" anywhere in the value selects Japanese
        assert_eq!(
            detect_from([Some("ja_JP.UTF-8"), None, Some("en_US.UTF-8")]),
            Lang::Ja
        );
        // first non-empty decides
        assert_eq!(
            detect_from([None, Some("en_US.UTF-8"), Some("ja_JP.UTF-8")]),
            Lang::En
        );
        // C locale and empty values fall back to English
        assert_eq!(detect_from([Some(""), None, Some("C.UTF-8")]), Lang::En);
        assert_eq!(detect_from([None::<&str>, None, None]), Lang::En);
    }
}
