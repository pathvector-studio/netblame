//! netblame — "Is it really the network's fault?"
//! Runs a staged diagnosis (environment → DNS → TCP → TLS → HTTP → path
//! quality) against a URL/host and names the most likely culprit, with
//! evidence, in plain English or Japanese.

use clap::Parser;
use netblame::deadline::{should_stop, Deadline};
use netblame::i18n::{self, msg, Lang, MsgKey};
use netblame::report::{
    self, Completeness, DnsOutcome, Report, StageDuration, StageName, TargetInfo, TcpOutcome,
    TraceReport, TruncationReason,
};
use netblame::verdict::{self, judge, Culprit, RenderedVerdict, Verdict};
use netblame::{probe, share, ParseError};
use owo_colors::{OwoColorize, Stream::Stdout};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Is it really the network's fault? Staged network diagnosis CLI that names the culprit with evidence.
#[derive(Parser, Debug)]
#[command(name = "netblame", version, about, arg_required_else_help = true)]
struct Args {
    /// Diagnosis target: a URL (https://example.com/path) or host[:port]
    target: String,

    /// Emit a machine-readable JSON report
    #[arg(long)]
    json: bool,

    /// Per-probe timeout in seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// Overall wall-clock deadline in seconds for the entire diagnosis
    /// (curl-style). Unset by default: total time is unbounded and only
    /// --timeout (per probe) applies, as before. When set, remaining stages
    /// are skipped once the deadline passes and a partial report is printed
    /// (exit code 3 if no verdict was reached yet)
    #[arg(long, value_name = "SECS")]
    max_time: Option<u64>,

    /// Number of latency samples
    #[arg(long, default_value_t = 5)]
    samples: u32,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Output language (default: auto-detect from LC_ALL/LC_MESSAGES/LANG)
    #[arg(long, value_enum)]
    lang: Option<Lang>,

    /// Repeat the diagnosis every SECS seconds (default 30) and print a
    /// timestamped timeline; Ctrl-C stops and prints a summary
    #[arg(long, value_name = "SECS", num_args = 0..=1, default_missing_value = "30")]
    watch: Option<u64>,

    /// Always run the hop-level path trace (tracepath-style, Linux only).
    /// Without this flag it runs automatically only when a path problem
    /// (TCP timeout, packet loss, high jitter) is detected
    #[arg(long)]
    trace: bool,

    /// After the diagnosis, upload the full report to a share server and
    /// print a shareable URL. Upload failures are printed as a warning; the
    /// process exit code still reflects the diagnosis result, not the upload
    #[arg(long)]
    share: bool,

    /// Base URL of the share server to upload to (default: env
    /// NETBLAME_SHARE_URL, falling back to https://share.pathvector.dev)
    #[arg(long, value_name = "URL")]
    share_url: Option<String>,
}

/// パース済みターゲット
#[derive(Debug)]
struct Target {
    host: String,
    port: u16,
    use_tls: bool,
    do_http: bool,
    path: String,
}

fn parse_target(raw: &str) -> Result<Target, ParseError> {
    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        (Some(true), r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        (Some(false), r)
    } else if raw.contains("://") {
        return Err(ParseError::UnsupportedScheme(raw.to_string()));
    } else {
        (None, raw)
    };

    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() {
        return Err(ParseError::EmptyHost);
    }

    // IPv6 リテラル [::1]:443 に対応
    let (host, explicit_port) = if let Some(rest6) = hostport.strip_prefix('[') {
        let end = rest6.find(']').ok_or(ParseError::UnclosedIpv6)?;
        let host = rest6[..end].to_string();
        let after = &rest6[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(
                p.parse::<u16>()
                    .map_err(|_| ParseError::InvalidPort(p.to_string()))?,
            )
        } else {
            None
        };
        (host, port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        // "::1" のような素の IPv6 は ':' を複数含む → その場合はポートなしとみなす
        if h.contains(':') || p.contains(':') {
            (hostport.to_string(), None)
        } else {
            (
                h.to_string(),
                Some(
                    p.parse::<u16>()
                        .map_err(|_| ParseError::InvalidPort(p.to_string()))?,
                ),
            )
        }
    } else {
        (hostport.to_string(), None)
    };

    let (port, use_tls, do_http) = match (scheme, explicit_port) {
        (Some(true), p) => (p.unwrap_or(443), true, true),
        (Some(false), p) => (p.unwrap_or(80), false, true),
        // 素のホスト: 443/TLS/HTTPS 扱い
        (None, None) => (443, true, true),
        // host:port 指定: 443 なら TLS、80 なら HTTP、それ以外は素の TCP 診断
        (None, Some(443)) => (443, true, true),
        (None, Some(80)) => (80, false, true),
        (None, Some(p)) => (p, false, false),
    };

    Ok(Target {
        host,
        port,
        use_tls,
        do_http,
        path,
    })
}

struct Printer {
    quiet: bool,
    lang: Lang,
}

impl Printer {
    fn section(&self, key: MsgKey) {
        if !self.quiet {
            println!(
                "\n{} {}",
                "──".if_supports_color(Stdout, |t| t.dimmed()),
                msg(self.lang, key).if_supports_color(Stdout, |t| t.bold())
            );
        }
    }
    fn ok(&self, msg: &str) {
        if !self.quiet {
            println!("  {} {}", "✓".if_supports_color(Stdout, |t| t.green()), msg);
        }
    }
    fn warn(&self, msg: &str) {
        if !self.quiet {
            println!(
                "  {} {}",
                "⚠".if_supports_color(Stdout, |t| t.yellow()),
                msg
            );
        }
    }
    fn fail(&self, msg: &str) {
        if !self.quiet {
            println!("  {} {}", "✗".if_supports_color(Stdout, |t| t.red()), msg);
        }
    }
    /// 記号なしのインデント行 (ホップ一覧など)
    fn plain(&self, msg: &str) {
        if !self.quiet {
            println!("  {msg}");
        }
    }
}

fn fmt_ms(ms: Option<f64>) -> String {
    ms.map_or("-".to_string(), |v| format!("{v:.0}ms"))
}

/// ステージ別所要時間と、`--max-time` / Ctrl-C による打ち切り情報を
/// 集計するヘルパー。`diagnose` の中で各ステージの実行前後にこれを使う。
struct StageTracker {
    durations: Vec<StageDuration>,
    ran: Vec<StageName>,
    all_stages: [StageName; 8],
}

impl StageTracker {
    fn new() -> Self {
        Self {
            durations: Vec::new(),
            ran: Vec::new(),
            all_stages: [
                StageName::Env,
                StageName::Dns,
                StageName::Tcp,
                StageName::Tls,
                StageName::Http,
                StageName::Quic,
                StageName::Path,
                StageName::Trace,
            ],
        }
    }

    /// ステージ実行を計測しつつ実行する。
    async fn record<T>(
        &mut self,
        stage: StageName,
        fut: impl std::future::Future<Output = T>,
    ) -> T {
        let start = Instant::now();
        let out = fut.await;
        self.durations.push(StageDuration {
            stage,
            ms: start.elapsed().as_secs_f64() * 1000.0,
        });
        self.ran.push(stage);
        out
    }

    /// 同期ステージ (env など) 用。
    fn record_sync<T>(&mut self, stage: StageName, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let out = f();
        self.durations.push(StageDuration {
            stage,
            ms: start.elapsed().as_secs_f64() * 1000.0,
        });
        self.ran.push(stage);
        out
    }

    /// まだ実行していないステージの一覧 (未実行 = スキップ扱い)。
    fn skipped(&self) -> Vec<StageName> {
        self.all_stages
            .iter()
            .copied()
            .filter(|s| !self.ran.contains(s))
            .collect()
    }

    fn into_completeness(self, truncated_reason: Option<TruncationReason>) -> Completeness {
        // 「未実行」は打ち切り時にだけ意味のある概念として報告する。完走時
        // (truncated_reason == None) は TLS/HTTP/QUIC/Trace などターゲットの
        // 性質上そもそも実行しないステージが普通にあり、それを "skipped" と
        // 呼ぶと打ち切りと紛らわしくなるため空のままにする。
        let skipped = if truncated_reason.is_some() {
            self.skipped()
        } else {
            Vec::new()
        };
        Completeness {
            complete: truncated_reason.is_none(),
            truncated_reason,
            ran_stages: self.ran,
            skipped_stages: skipped,
        }
    }
}

/// 全ステージを実行して Report と Verdict を返す。
/// `p.quiet` が false ならステージごとの結果を逐次表示する。
/// `deadline` が `Some` かつ既に過ぎている場合、まだ実行していない
/// ステージ以降はスキップし、そこまでの結果で打ち切りレポートを返す。
async fn diagnose(
    target: &Target,
    timeout: Duration,
    samples: u32,
    force_trace: bool,
    p: &Printer,
    deadline: Option<&Deadline>,
) -> (Report, Verdict) {
    let lang = p.lang;
    let mut stages = StageTracker::new();

    // ── ステージ1: 環境 ─────────────────────────────
    p.section(MsgKey::StageEnv);
    let env_report = stages.record_sync(StageName::Env, || probe::env::run(&target.host));
    if env_report.nameservers.is_empty() {
        p.warn(msg(lang, MsgKey::NoNameservers));
    } else {
        p.ok(&i18n::nameservers_line(
            lang,
            &env_report
                .nameservers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if !env_report.search_domains.is_empty() {
        p.ok(&i18n::search_domains_line(
            lang,
            &env_report.search_domains.join(", "),
        ));
    }
    match &env_report.hosts_override {
        Some(ip) => p.warn(&i18n::hosts_override_line(lang, &target.host, ip)),
        None => p.ok(msg(lang, MsgKey::HostsNoOverride)),
    }
    if env_report.proxies.is_empty() {
        p.ok(msg(lang, MsgKey::NoProxyVars));
    } else {
        for (k, v) in &env_report.proxies {
            p.warn(&i18n::proxy_detected_line(lang, k, v));
        }
    }

    // ── ステージ2: DNS ─────────────────────────────
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            report::DnsReport::default(),
            report::TcpReport::default(),
            None,
            None,
            None,
            None,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    p.section(MsgKey::StageDns);
    let dns_report = stages
        .record(
            StageName::Dns,
            probe::dns::run(&target.host, &env_report.nameservers, timeout, lang),
        )
        .await;
    if dns_report.skipped {
        p.ok(msg(lang, MsgKey::DnsSkippedIpLiteral));
    } else {
        for src in &dns_report.sources {
            match &src.outcome {
                DnsOutcome::Ok => p.ok(&i18n::dns_ok_line(
                    lang,
                    &src.label,
                    src.ips.len(),
                    &fmt_ms(src.latency_ms),
                    &src.ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )),
                DnsOutcome::NxDomain => p.fail(&i18n::dns_nxdomain_line(lang, &src.label)),
                DnsOutcome::ServFail => p.fail(&i18n::dns_servfail_line(lang, &src.label)),
                DnsOutcome::Timeout => p.fail(&i18n::dns_timeout_line(lang, &src.label)),
                DnsOutcome::Error(e) => p.fail(&i18n::dns_error_line(lang, &src.label, e)),
            }
        }
    }

    // 接続に使う IP 候補: システム → ローカル → パブリックの優先順で最初に成功したもの
    let resolved_ips: Vec<IpAddr> = if let Ok(ip) = target.host.parse::<IpAddr>() {
        vec![ip]
    } else {
        dns_report
            .sources
            .iter()
            .filter(|s| s.is_ok() && !s.ips.is_empty())
            .map(|s| s.ips.clone())
            .next()
            .unwrap_or_default()
    };

    // ── ステージ3: TCP ─────────────────────────────
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            dns_report,
            report::TcpReport::default(),
            None,
            None,
            None,
            None,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    p.section(MsgKey::StageTcp);
    let tcp_report = if resolved_ips.is_empty() {
        p.fail(msg(lang, MsgKey::NoResolvedIps));
        stages.ran.push(StageName::Tcp);
        report::TcpReport::default()
    } else {
        let r = stages
            .record(
                StageName::Tcp,
                probe::tcp::run(&resolved_ips, target.port, samples, timeout, lang),
            )
            .await;
        for probe in &r.probes {
            match &probe.outcome {
                TcpOutcome::Ok => p.ok(&i18n::tcp_ok_line(
                    lang,
                    &probe.ip,
                    probe.port,
                    probe.successes,
                    probe.samples,
                    &fmt_ms(probe.min_ms),
                    &fmt_ms(probe.avg_ms),
                    &fmt_ms(probe.max_ms),
                )),
                TcpOutcome::Refused => p.fail(&i18n::tcp_refused_line(lang, &probe.ip, probe.port)),
                TcpOutcome::Timeout => p.fail(&i18n::tcp_timeout_line(lang, &probe.ip, probe.port)),
                TcpOutcome::Error(e) => {
                    p.fail(&i18n::tcp_error_line(lang, &probe.ip, probe.port, e))
                }
            }
        }
        r
    };

    let primary_ip = tcp_report
        .probes
        .iter()
        .find(|pr| pr.is_ok())
        .map(|pr| pr.ip)
        .or_else(|| resolved_ips.first().copied());

    let tcp_any_ok = tcp_report.probes.iter().any(|pr| pr.is_ok());

    // ── ステージ4: TLS ─────────────────────────────
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            dns_report,
            tcp_report,
            None,
            None,
            None,
            None,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    let tls_report = if target.use_tls {
        p.section(MsgKey::StageTls);
        match primary_ip {
            Some(ip) if tcp_any_ok => {
                let r = stages
                    .record(
                        StageName::Tls,
                        probe::tls::run(&target.host, ip, target.port, timeout, lang),
                    )
                    .await;
                if r.verified {
                    p.ok(&i18n::tls_handshake_ok_line(
                        lang,
                        r.version.as_deref().unwrap_or("?"),
                        &fmt_ms(r.handshake_ms),
                    ));
                    if let Some(days) = r.days_until_expiry {
                        if days < 0 {
                            p.fail(&i18n::cert_expired_ago_line(lang, -days));
                        } else if days <= 14 {
                            p.warn(&i18n::cert_days_left_line(lang, days));
                        } else {
                            p.ok(&i18n::cert_days_left_line(lang, days));
                        }
                    }
                    p.ok(msg(lang, MsgKey::CertChainOk));
                } else {
                    p.fail(&i18n::cert_verify_failed_line(
                        lang,
                        r.error
                            .as_deref()
                            .unwrap_or(msg(lang, MsgKey::UnknownError)),
                    ));
                    if let Some(issuer) = &r.presented_issuer {
                        p.warn(&i18n::presented_issuer_line(
                            lang,
                            issuer,
                            r.interception_suspected,
                        ));
                    }
                }
                Some(r)
            }
            _ => {
                p.fail(msg(lang, MsgKey::TlsSkippedNoTcp));
                None
            }
        }
    } else {
        None
    };

    // ── ステージ5: HTTP ────────────────────────────
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            dns_report,
            tcp_report,
            tls_report,
            None,
            None,
            None,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    let http_report = if target.do_http && tcp_any_ok {
        p.section(MsgKey::StageHttp);
        let scheme = if target.use_tls { "https" } else { "http" };
        let host_for_url = if target.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", target.host)
        } else {
            target.host.clone()
        };
        let default_port = if target.use_tls { 443 } else { 80 };
        let url = if target.port == default_port {
            format!("{scheme}://{host_for_url}{}", target.path)
        } else {
            format!("{scheme}://{host_for_url}:{}{}", target.port, target.path)
        };
        let mut r = stages
            .record(StageName::Http, probe::http::run(&url, timeout, lang))
            .await;
        // 内訳時間は各ステージの実測値を転記する
        r.dns_ms = dns_report
            .sources
            .iter()
            .find(|s| s.is_ok())
            .and_then(|s| s.latency_ms);
        r.connect_ms = tcp_report.probes.iter().find_map(|pr| pr.avg_ms);
        r.tls_ms = tls_report.as_ref().and_then(|t| t.handshake_ms);

        for hop in &r.redirect_chain {
            p.ok(&i18n::http_redirect_line(lang, hop));
        }
        match (r.status, &r.error) {
            (Some(status), None) => {
                let line = i18n::http_result_line(
                    lang,
                    &url,
                    status,
                    &fmt_ms(r.dns_ms),
                    &fmt_ms(r.connect_ms),
                    &fmt_ms(r.tls_ms),
                    &fmt_ms(r.ttfb_ms),
                    &fmt_ms(r.total_ms),
                );
                if (200..400).contains(&status) {
                    p.ok(&line);
                } else {
                    p.warn(&line);
                }
            }
            (status, Some(e)) => {
                if let Some(s) = status {
                    p.fail(&i18n::http_status_with_error_line(lang, &url, s, e));
                } else {
                    p.fail(&i18n::http_failed_line(lang, &url, e));
                }
            }
            (None, None) => p.fail(&i18n::http_no_result_line(lang, &url)),
        }
        Some(r)
    } else {
        if target.do_http && !p.quiet {
            p.section(MsgKey::StageHttp);
            p.fail(msg(lang, MsgKey::HttpSkippedNoTcp));
        }
        None
    };

    // ── ステージ: QUIC/HTTP3 (https ターゲットのみ、HTTP ステージの後) ──
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            dns_report,
            tcp_report,
            tls_report,
            http_report,
            None,
            None,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    let quic_report = match primary_ip {
        Some(ip) if target.use_tls && target.do_http && tcp_any_ok => {
            p.section(MsgKey::StageQuic);
            let r = stages
                .record(
                    StageName::Quic,
                    probe::quic::run(&target.host, ip, target.port, timeout),
                )
                .await;
            let h3_advertised = http_report.as_ref().is_some_and(|h| h.h3_advertised);
            match &r.outcome {
                report::QuicOutcome::Ok {
                    handshake_ms,
                    negotiated_alpn,
                } => {
                    p.ok(&i18n::quic_handshake_ok_line(
                        lang,
                        &fmt_ms(Some(*handshake_ms)),
                        negotiated_alpn.as_deref().unwrap_or("?"),
                    ));
                }
                report::QuicOutcome::Timeout => {
                    p.fail(&i18n::quic_timeout_line(lang, target.port));
                }
                report::QuicOutcome::HandshakeError(e) => {
                    p.warn(&i18n::quic_handshake_error_line(lang, e));
                }
                report::QuicOutcome::LocalError(e) => {
                    p.warn(&i18n::quic_local_error_line(lang, e));
                }
            }
            if let Some(http) = &http_report {
                match &http.alt_svc {
                    Some(alt_svc) if h3_advertised => {
                        p.ok(&i18n::h3_advertised_line(lang, alt_svc));
                    }
                    _ => {
                        p.warn(&i18n::h3_not_advertised_line(lang));
                    }
                }
            }
            Some(r)
        }
        _ => None,
    };

    // ── ステージ6: 経路品質 ─────────────────────────
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            dns_report,
            tcp_report,
            tls_report,
            http_report,
            quic_report,
            None,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    let path_report = match primary_ip {
        Some(ip) if tcp_any_ok => {
            p.section(MsgKey::StagePath);
            let r = stages
                .record(
                    StageName::Path,
                    probe::path::run(ip, target.port, samples, timeout),
                )
                .await;
            let line = i18n::path_line(
                lang,
                r.sent,
                r.loss_pct,
                &fmt_ms(r.min_ms),
                &fmt_ms(r.avg_ms),
                &fmt_ms(r.max_ms),
                &fmt_ms(r.jitter_ms),
            );
            if r.loss_pct >= 10.0 || r.jitter_ms.is_some_and(|j| j > 50.0) {
                p.warn(&line);
            } else {
                p.ok(&line);
            }
            Some(r)
        }
        _ => None,
    };

    // ── ステージ7: 経路トレース ─────────────────────
    // --trace 指定時は常に実行。それ以外は、前段で経路系の問題
    // (TCP タイムアウト / ロス / ジッタ大) が出たときだけ自動実行する
    // (最悪 15-30 秒かかるため、健全時はスキップ)。
    let tcp_timed_out = tcp_report
        .probes
        .iter()
        .any(|pr| pr.outcome == TcpOutcome::Timeout);
    let path_bad = path_report.as_ref().is_some_and(|r| {
        r.loss_pct > 0.0
            || r.jitter_ms
                .is_some_and(|j| j > verdict::JITTER_MS_THRESHOLD)
    });
    if should_stop(deadline) {
        return truncated_report(
            target,
            env_report,
            dns_report,
            tcp_report,
            tls_report,
            http_report,
            quic_report,
            path_report,
            None,
            stages,
            TruncationReason::MaxTimeExceeded,
        );
    }
    let trace_report = match primary_ip {
        Some(ip) if force_trace || tcp_timed_out || path_bad => {
            p.section(MsgKey::StageTrace);
            let r = stages
                .record(StageName::Trace, probe::trace::run(ip, lang))
                .await;
            print_trace(&r, p);
            Some(r)
        }
        _ => None,
    };

    // ── 判定 ───────────────────────────────────────
    let durations = stages.durations.clone();
    let full_report = build_report(
        target,
        env_report,
        dns_report,
        tcp_report,
        tls_report,
        http_report,
        quic_report,
        path_report,
        trace_report,
        stages.into_completeness(None),
        durations,
    );

    let verdict = judge(&full_report);
    (full_report, verdict)
}

/// `Report` を組み立てる。完走時・打ち切り時の両方から使う共通ヘルパー。
#[allow(clippy::too_many_arguments)]
fn build_report(
    target: &Target,
    env_report: report::EnvReport,
    dns_report: report::DnsReport,
    tcp_report: report::TcpReport,
    tls_report: Option<report::TlsReport>,
    http_report: Option<report::HttpReport>,
    quic_report: Option<report::QuicReport>,
    path_report: Option<report::PathReport>,
    trace_report: Option<TraceReport>,
    completeness: Completeness,
    stage_durations: Vec<StageDuration>,
) -> Report {
    Report {
        target: TargetInfo {
            host: target.host.clone(),
            port: target.port,
            use_tls: target.use_tls,
            do_http: target.do_http,
            path: target.path.clone(),
            is_ip_literal: target.host.parse::<IpAddr>().is_ok(),
        },
        env: env_report,
        dns: dns_report,
        tcp: tcp_report,
        tls: tls_report,
        http: http_report,
        quic: quic_report,
        path: path_report,
        trace: trace_report,
        completeness,
        stage_durations,
    }
}

/// `--max-time` (または Ctrl-C) による打ち切り時に、そこまでの結果で
/// Report/Verdict を組み立てる。`judge` はそれまでに埋まったフィールドだけを
/// 見て、既に犯人を特定できていればそれを返す (例: TCP 全滅が確定した後に
/// 打ち切られた場合はそのまま TcpBlocked になる)。
#[allow(clippy::too_many_arguments)]
fn truncated_report(
    target: &Target,
    env_report: report::EnvReport,
    dns_report: report::DnsReport,
    tcp_report: report::TcpReport,
    tls_report: Option<report::TlsReport>,
    http_report: Option<report::HttpReport>,
    quic_report: Option<report::QuicReport>,
    path_report: Option<report::PathReport>,
    trace_report: Option<TraceReport>,
    stages: StageTracker,
    reason: TruncationReason,
) -> (Report, Verdict) {
    let durations = stages.durations.clone();
    let full_report = build_report(
        target,
        env_report,
        dns_report,
        tcp_report,
        tls_report,
        http_report,
        quic_report,
        path_report,
        trace_report,
        stages.into_completeness(Some(reason)),
        durations,
    );
    let verdict = judge(&full_report);
    (full_report, verdict)
}

/// 経路トレースステージの結果を表示する
fn print_trace(r: &TraceReport, p: &Printer) {
    let lang = p.lang;
    match r {
        TraceReport::Unsupported => p.warn(msg(lang, MsgKey::TraceUnsupported)),
        TraceReport::Failed(e) => p.warn(&i18n::trace_failed_line(lang, e)),
        TraceReport::Ran(data) => {
            if data.hops.is_empty() {
                p.warn(msg(lang, MsgKey::TraceNoData));
            }
            for hop in &data.hops {
                match &hop.addr {
                    Some(ip) => p.plain(&i18n::trace_hop_line(
                        lang,
                        hop.index,
                        &ip.to_string(),
                        &fmt_ms(hop.rtt_ms),
                    )),
                    None => p.plain(&i18n::trace_hop_noreply_line(lang, hop.index)),
                }
            }
            if data.dest_reached {
                if let Some(last) = data.hops.last() {
                    p.ok(&i18n::trace_dest_reached_line(lang, last.index));
                }
            }
            let analysis = probe::trace::analyze_mtu(data.kernel_mtu, &data.mtu_probes);
            if let Some(mtu) = analysis.path_mtu {
                let line = i18n::path_mtu_line(lang, mtu);
                if analysis.blackhole {
                    p.warn(&line);
                } else {
                    p.ok(&line);
                }
            }
        }
    }
}

/// 【判定】/【根拠】/【所見】/【次の一手】ブロックを表示する
fn print_verdict_block(rendered: &RenderedVerdict, lang: Lang) {
    println!();
    let style = if rendered.culprit == Culprit::NoProblem {
        owo_colors::Style::new().green().bold()
    } else {
        owo_colors::Style::new().red().bold()
    };
    let headline = format!(
        "{}",
        rendered
            .headline
            .if_supports_color(Stdout, |t| t.style(style))
    );
    println!(
        "{} {}",
        msg(lang, MsgKey::VerdictLabel).if_supports_color(Stdout, |t| t.bold()),
        headline
    );
    println!(
        "{}",
        msg(lang, MsgKey::EvidenceLabel).if_supports_color(Stdout, |t| t.bold())
    );
    let bullet = msg(lang, MsgKey::Bullet);
    for e in &rendered.evidence {
        println!("  {bullet}{e}");
    }
    if !rendered.secondary.is_empty() {
        println!(
            "{}",
            msg(lang, MsgKey::NotesLabel).if_supports_color(Stdout, |t| t.bold())
        );
        for s in &rendered.secondary {
            println!("  {bullet}{}", s.if_supports_color(Stdout, |t| t.yellow()));
        }
    }
    println!(
        "{} {}",
        msg(lang, MsgKey::NextStepLabel).if_supports_color(Stdout, |t| t.bold()),
        rendered.next_step
    );
}

/// --watch 用: 検出した問題ごとの統計
struct ProblemStat {
    culprit: Culprit,
    headline: String,
    count: u32,
    first: String,
    last: String,
}

/// --watch モード: 診断をループし、1 行タイムラインとサマリを出す
/// `max_time_secs` を指定すると、各回の診断1回ごとにその秒数のデッドラインを適用する
/// (--watch の反復自体を止めるものではない)。
async fn watch_loop(
    target: &Target,
    timeout: Duration,
    samples: u32,
    interval_secs: u64,
    force_trace: bool,
    max_time_secs: Option<u64>,
    lang: Lang,
) -> ! {
    let interval = Duration::from_secs(interval_secs.max(1));
    println!("{}", i18n::watch_start_line(lang, interval.as_secs()));

    let quiet = Printer { quiet: true, lang };
    let mut runs = 0u32;
    let mut ok_runs = 0u32;
    let mut prev_culprit: Option<Culprit> = None;
    let mut problems: Vec<ProblemStat> = Vec::new();

    loop {
        let deadline = max_time_secs.map(Deadline::from_secs);
        let outcome = tokio::select! {
            r = diagnose(target, timeout, samples, force_trace, &quiet, deadline.as_ref()) => Some(r),
            _ = tokio::signal::ctrl_c() => None,
        };
        let Some((report, verdict)) = outcome else {
            break;
        };
        runs += 1;
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let rendered = verdict.render(lang);

        if verdict.culprit == Culprit::NoProblem {
            ok_runs += 1;
            let dns = fmt_ms(
                report
                    .dns
                    .sources
                    .iter()
                    .find(|s| s.is_ok())
                    .and_then(|s| s.latency_ms),
            );
            let tcp = fmt_ms(report.tcp.probes.iter().find_map(|pr| pr.avg_ms));
            let ttfb = fmt_ms(report.http.as_ref().and_then(|h| h.ttfb_ms));
            let loss = report
                .path
                .as_ref()
                .map_or("-".to_string(), |p| format!("{:.0}%", p.loss_pct));
            println!(
                "{ts} {} {}",
                "✓".if_supports_color(Stdout, |t| t.green()),
                i18n::watch_ok_details(lang, &dns, &tcp, &ttfb, &loss)
            );
        } else {
            println!(
                "{ts} {} {}",
                "✗".if_supports_color(Stdout, |t| t.red()),
                rendered.headline.if_supports_color(Stdout, |t| t.red())
            );
            match problems.iter_mut().find(|s| s.culprit == verdict.culprit) {
                Some(stat) => {
                    stat.count += 1;
                    stat.last = ts.clone();
                }
                None => problems.push(ProblemStat {
                    culprit: verdict.culprit,
                    headline: rendered.headline.clone(),
                    count: 1,
                    first: ts.clone(),
                    last: ts.clone(),
                }),
            }
        }

        // 判定カテゴリが変わったらフルの判定ブロックを表示する
        // (初回は問題がある場合のみ)
        let changed = match prev_culprit {
            Some(prev) => prev != verdict.culprit,
            None => verdict.culprit != Culprit::NoProblem,
        };
        if changed {
            print_verdict_block(&rendered, lang);
            println!();
        }
        prev_culprit = Some(verdict.culprit);

        let stop = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            _ = tokio::signal::ctrl_c() => true,
        };
        if stop {
            break;
        }
    }

    // ── サマリ ─────────────────────────────────────
    println!(
        "\n{} {}",
        "──".if_supports_color(Stdout, |t| t.dimmed()),
        msg(lang, MsgKey::WatchSummaryHeader).if_supports_color(Stdout, |t| t.bold())
    );
    let ok_pct = if runs > 0 {
        ok_runs as f64 * 100.0 / runs as f64
    } else {
        0.0
    };
    println!("{}", i18n::watch_runs_line(lang, runs, ok_runs, ok_pct));
    if !problems.is_empty() {
        println!("{}", msg(lang, MsgKey::WatchProblemsHeader));
        let bullet = msg(lang, MsgKey::Bullet);
        for s in &problems {
            println!(
                "  {bullet}{}",
                i18n::watch_problem_line(lang, &s.headline, s.count, &s.first, &s.last)
            );
        }
    }

    std::process::exit(if problems.is_empty() { 0 } else { 1 });
}

#[tokio::main]
async fn main() {
    // rustls の暗号プロバイダ (ring) をプロセス既定として登録
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();
    let lang = args.lang.unwrap_or_else(Lang::detect);

    if args.no_color || !std::io::stdout().is_terminal() {
        owo_colors::set_override(false);
    }

    let err_prefix = msg(lang, MsgKey::ErrorPrefix);

    let target = match parse_target(&args.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{err_prefix}: {}", i18n::parse_error(lang, &e));
            std::process::exit(2);
        }
    };

    let timeout = Duration::from_secs(args.timeout.max(1));
    let samples = args.samples.max(1);

    if let Some(interval) = args.watch {
        if args.json {
            eprintln!("{err_prefix}: {}", msg(lang, MsgKey::JsonWatchConflict));
            std::process::exit(2);
        }
        if args.share {
            eprintln!("{err_prefix}: {}", msg(lang, MsgKey::ShareWatchConflict));
            std::process::exit(2);
        }
        watch_loop(
            &target,
            timeout,
            samples,
            interval,
            args.trace,
            args.max_time,
            lang,
        )
        .await;
    }

    let p = Printer {
        quiet: args.json,
        lang,
    };

    if !args.json {
        let host_colored = format!("{}", target.host.if_supports_color(Stdout, |t| t.cyan()));
        println!(
            "{} {}",
            "netblame:".if_supports_color(Stdout, |t| t.bold()),
            i18n::diagnosing_line(lang, &host_colored, target.port)
        );
    }

    let deadline = args.max_time.map(Deadline::from_secs);

    // Ctrl-C (SIGINT) 中でも、それまでに得られた結果を捨てずに済むよう
    // 診断とレースさせる。割り込まれた場合は「そこまでの env ステージだけ」の
    // 打ち切りレポートになるが、何も出さずに終了する v0.5 までの挙動よりは
    // はるかにマシ (要件2: 沈黙終了を二度と起こさない)。
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let interrupted_flag = interrupted.clone();
    let diagnose_fut = diagnose(&target, timeout, samples, args.trace, &p, deadline.as_ref());
    tokio::pin!(diagnose_fut);
    let (full_report, verdict) = tokio::select! {
        r = &mut diagnose_fut => r,
        _ = tokio::signal::ctrl_c() => {
            interrupted_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            // 診断タスク自体は協調的にしか止められないので、直近のステージ
            // 境界チェックに任せず、ここでは受信した事実だけ記録して
            // 「env のみ完了」の打ち切りレポートを即座に返す。
            let stages = StageTracker::new();
            let env_report = probe::env::run(&target.host);
            truncated_report(
                &target,
                env_report,
                report::DnsReport::default(),
                report::TcpReport::default(),
                None,
                None,
                None,
                None,
                None,
                stages,
                TruncationReason::Interrupted,
            )
        }
    };
    let rendered = verdict.render(lang);
    let truncated = !full_report.completeness.complete;

    if args.json {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            report: &'a Report,
            verdict: &'a RenderedVerdict,
        }
        match serde_json::to_string_pretty(&JsonOutput {
            report: &full_report,
            verdict: &rendered,
        }) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!(
                    "{err_prefix}: {}",
                    i18n::json_serialize_failed(lang, &e.to_string())
                );
                std::process::exit(2);
            }
        }
    } else {
        if truncated {
            print_truncation_notice(&full_report, lang);
        }
        print_verdict_block(&rendered, lang);
    }

    if args.share {
        upload_report(&full_report, &rendered, lang, args.share_url.as_deref()).await;
    }

    std::process::exit(exit_code(&full_report, &verdict));
}

/// 終了コードを決定する。
/// - 0: 問題なし (完走)
/// - 1: 犯人を特定 (完走、または打ち切り前に既に特定できていた場合を含む)
/// - 2: 使い方・内部エラー (main の他の分岐で使用、ここでは出さない)
/// - 3: `--max-time` / Ctrl-C により打ち切られ、かつ犯人を特定できなかった
fn exit_code(report: &Report, verdict: &Verdict) -> i32 {
    if !report.completeness.complete && verdict.culprit == Culprit::NoProblem {
        3
    } else if verdict.culprit == Culprit::NoProblem {
        0
    } else {
        1
    }
}

/// 打ち切られたレポートであることをテキストモードで明示する
fn print_truncation_notice(report: &Report, lang: Lang) {
    let reason = report
        .completeness
        .truncated_reason
        .map(|r| i18n::truncation_reason_line(lang, r));
    let ran: Vec<&str> = report
        .completeness
        .ran_stages
        .iter()
        .map(|s| s.as_str())
        .collect();
    let skipped: Vec<&str> = report
        .completeness
        .skipped_stages
        .iter()
        .map(|s| s.as_str())
        .collect();
    println!();
    let style = owo_colors::Style::new().yellow().bold();
    println!(
        "{}",
        i18n::truncated_header_line(lang).if_supports_color(Stdout, |t| t.style(style))
    );
    if let Some(r) = reason {
        println!("  {r}");
    }
    println!("  {}", i18n::stages_ran_line(lang, &ran.join(", ")));
    if !skipped.is_empty() {
        println!("  {}", i18n::stages_skipped_line(lang, &skipped.join(", ")));
    }
}

/// --share: POST the full JSON payload to the share server and print the
/// resulting URL. Failures are printed as a localized warning but never
/// change the process exit code — the diagnosis result already decided that.
async fn upload_report(
    report: &Report,
    rendered: &RenderedVerdict,
    lang: Lang,
    share_url: Option<&str>,
) {
    let base_url = share::resolve_base_url(
        share_url,
        std::env::var("NETBLAME_SHARE_URL").ok().as_deref(),
    );
    let payload = share::SharePayload {
        report,
        verdict: rendered,
        netblame_version: env!("CARGO_PKG_VERSION"),
        created_lang: lang,
    };

    let endpoint = format!("{base_url}/api/reports");
    let client = reqwest::Client::new();
    let result = client.post(&endpoint).json(&payload).send().await;

    match result {
        Ok(resp) if resp.status().is_success() => match resp.json::<share::ShareResponse>().await {
            Ok(share_resp) => {
                println!("{}", i18n::share_success_line(lang, &share_resp.url));
            }
            Err(e) => {
                eprintln!(
                    "{} {}",
                    "⚠".if_supports_color(Stdout, |t| t.yellow()),
                    i18n::share_failed_line(lang, &e.to_string())
                );
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!(
                "{} {}",
                "⚠".if_supports_color(Stdout, |t| t.yellow()),
                i18n::share_failed_line(lang, &format!("{status}: {body}"))
            );
        }
        Err(e) => {
            eprintln!(
                "{} {}",
                "⚠".if_supports_color(Stdout, |t| t.yellow()),
                i18n::share_failed_line(lang, &e.to_string())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_url() {
        let t = parse_target("https://example.com/path?q=1").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert!(t.use_tls);
        assert!(t.do_http);
        assert_eq!(t.path, "/path?q=1");
    }

    #[test]
    fn parse_http_url_with_port() {
        let t = parse_target("http://example.com:8080").unwrap();
        assert_eq!(t.port, 8080);
        assert!(!t.use_tls);
        assert!(t.do_http);
    }

    #[test]
    fn parse_bare_host() {
        let t = parse_target("example.com").unwrap();
        assert_eq!(t.port, 443);
        assert!(t.use_tls);
        assert!(t.do_http);
    }

    #[test]
    fn parse_host_port_plain_tcp() {
        let t = parse_target("example.com:81").unwrap();
        assert_eq!(t.port, 81);
        assert!(!t.use_tls);
        assert!(!t.do_http);
    }

    #[test]
    fn parse_ipv6_literal() {
        let t = parse_target("[2606:2800::1]:8443").unwrap();
        assert_eq!(t.host, "2606:2800::1");
        assert_eq!(t.port, 8443);
    }

    // ── --max-time / 打ち切り ────────────────────────────────────────────

    fn quiet_printer() -> Printer {
        Printer {
            quiet: true,
            lang: Lang::En,
        }
    }

    /// 既に期限切れのデッドラインを渡すと、env ステージ (同期・即完了) だけが
    /// 実行され、それ以降は境界チェックで即座にスキップされる。
    /// 何も問題の証拠が集まらないので判定は NoProblem のままだが、
    /// `completeness.complete` は false になり、exit_code は 3 (打ち切り・
    /// 未結論) を返す。
    #[tokio::test]
    async fn diagnose_stops_immediately_when_deadline_already_expired() {
        let target = parse_target("192.0.2.1:9999").unwrap(); // IP literal, plain TCP (port != 80/443)
        let deadline = Deadline::already_expired();
        let p = quiet_printer();
        let (report, verdict) = diagnose(
            &target,
            Duration::from_secs(5),
            1,
            false,
            &p,
            Some(&deadline),
        )
        .await;

        assert!(!report.completeness.complete);
        assert_eq!(
            report.completeness.truncated_reason,
            Some(TruncationReason::MaxTimeExceeded)
        );
        assert_eq!(report.completeness.ran_stages, vec![StageName::Env]);
        assert!(report.completeness.skipped_stages.contains(&StageName::Dns));
        assert!(report.completeness.skipped_stages.contains(&StageName::Tcp));
        // 未実行のステージは None/空のまま
        assert!(report.dns.sources.is_empty());
        assert!(report.tcp.probes.is_empty());
        assert!(report.tls.is_none());
        assert_eq!(verdict.culprit, Culprit::NoProblem);
        assert_eq!(exit_code(&report, &verdict), 3);
    }

    /// デッドラインが TCP ステージの完了後・Path ステージの前に切れる場合:
    /// TCP は最後まで実行されて結果 (今回はタイムアウト) が残り、Path 以降は
    /// スキップされる。TCP 全滅は judge の主犯確定ルールなので、打ち切られて
    /// いても犯人は特定済み → exit_code は 1 (通常の犯人特定コード) になる
    /// べきで、3 (未結論) にはならない。
    ///
    /// 192.0.2.1 (TEST-NET-1, RFC 5737) はドキュメント用に予約された未使用
    /// アドレスで、経路上で確実にブラックホールされる (SYN への応答が一切
    /// 返らない) ため、TCP 接続は必ず --timeout いっぱいまでブロックする。
    /// これを利用して「TCP ステージは完走するがその時点で既に --max-time は
    /// 過ぎている」という状況を確定的に再現する。
    #[tokio::test]
    async fn diagnose_truncated_after_culprit_found_keeps_normal_exit_code() {
        let target = parse_target("192.0.2.1:9999").unwrap();
        let probe_timeout = Duration::from_millis(300);
        // TCP 開始時点ではまだ切れていないが、TCP が timeout いっぱいまで
        // ブロックしている間に確実に過ぎる短いデッドライン
        let deadline = Deadline::from_millis(50);
        let p = quiet_printer();
        let (report, verdict) =
            diagnose(&target, probe_timeout, 1, false, &p, Some(&deadline)).await;

        assert!(!report.completeness.complete);
        assert_eq!(
            report.completeness.truncated_reason,
            Some(TruncationReason::MaxTimeExceeded)
        );
        assert!(report.completeness.ran_stages.contains(&StageName::Tcp));
        assert!(report
            .completeness
            .skipped_stages
            .contains(&StageName::Path));
        assert_eq!(verdict.culprit, Culprit::TcpBlocked);
        assert_eq!(exit_code(&report, &verdict), 1);
    }

    /// デッドライン未指定 (`--max-time` なし) では従来通り最後まで走り、
    /// `completeness.complete` は true のまま。
    ///
    /// ポートを閉じたローカルアドレス (bind 直後に drop) を使う: 接続は
    /// ECONNREFUSED で瞬時に終わるので、`tcp_timed_out` が false のままとなり
    /// 経路トレースの自動起動 (最悪 15-30 秒) が発火しない。ブラックホール
    /// アドレスを使うと trace が自動実行されテストが極端に遅くなるため避ける。
    #[tokio::test]
    async fn diagnose_without_deadline_runs_to_completion() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = parse_target(&format!("127.0.0.1:{port}")).unwrap();
        let p = quiet_printer();
        let (report, verdict) =
            diagnose(&target, Duration::from_millis(200), 1, false, &p, None).await;

        assert!(report.completeness.complete);
        assert!(report.completeness.truncated_reason.is_none());
        assert!(report.completeness.skipped_stages.is_empty());
        // TLS/HTTP/QUIC/Path は tcp_any_ok が false のため元々実行対象外
        // (打ち切りとは無関係の、通常のスキップ) であり、ran_stages には
        // 現れない。
        assert!(report.completeness.ran_stages.contains(&StageName::Env));
        assert!(report.completeness.ran_stages.contains(&StageName::Dns));
        assert!(report.completeness.ran_stages.contains(&StageName::Tcp));
        assert_eq!(verdict.culprit, Culprit::ServerDown);
        assert_eq!(exit_code(&report, &verdict), 1);
    }

    /// ステージ別所要時間が記録され、実行したステージの数だけエントリがある。
    #[tokio::test]
    async fn diagnose_records_stage_durations() {
        let target = parse_target("192.0.2.1:9999").unwrap();
        let deadline = Deadline::already_expired();
        let p = quiet_printer();
        let (report, _verdict) = diagnose(
            &target,
            Duration::from_secs(5),
            1,
            false,
            &p,
            Some(&deadline),
        )
        .await;

        // env だけ実行されたはずなので、所要時間エントリも1件
        assert_eq!(report.stage_durations.len(), 1);
        assert_eq!(report.stage_durations[0].stage, StageName::Env);
        assert!(report.stage_durations[0].ms >= 0.0);
    }

    #[test]
    fn exit_code_healthy_is_zero() {
        let mut r = verdict::judge(&minimal_healthy_report());
        r.secondary.clear();
        let report = minimal_healthy_report();
        assert_eq!(exit_code(&report, &r), 0);
    }

    /// 判定に必要な最低限のフィールドだけ埋めた Report (exit_code のテスト用)
    fn minimal_healthy_report() -> Report {
        Report {
            target: TargetInfo {
                host: "example.com".into(),
                port: 443,
                use_tls: true,
                do_http: true,
                path: "/".into(),
                is_ip_literal: false,
            },
            env: report::EnvReport::default(),
            dns: report::DnsReport::default(),
            tcp: report::TcpReport::default(),
            tls: None,
            http: None,
            quic: None,
            path: None,
            trace: None,
            completeness: Completeness::default(),
            stage_durations: Vec::new(),
        }
    }

    #[test]
    fn parse_bad_scheme() {
        assert!(matches!(
            parse_target("ftp://example.com"),
            Err(ParseError::UnsupportedScheme(_))
        ));
    }
}
