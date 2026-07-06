//! netblame — "Is it really the network's fault?"
//! Runs a staged diagnosis (environment → DNS → TCP → TLS → HTTP → path
//! quality) against a URL/host and names the most likely culprit, with
//! evidence, in plain English or Japanese.

mod i18n;
mod probe;
mod report;
mod verdict;

use clap::Parser;
use i18n::{msg, Lang, MsgKey};
use owo_colors::{OwoColorize, Stream::Stdout};
use report::{DnsOutcome, Report, TargetInfo, TcpOutcome, TraceReport};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::time::Duration;
use verdict::{judge, Culprit, RenderedVerdict, Verdict};

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

/// ターゲット文字列のパースエラー (文言は i18n::parse_error が担当)
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    UnsupportedScheme(String),
    EmptyHost,
    UnclosedIpv6,
    InvalidPort(String),
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

/// 全ステージを実行して Report と Verdict を返す。
/// `p.quiet` が false ならステージごとの結果を逐次表示する。
async fn diagnose(
    target: &Target,
    timeout: Duration,
    samples: u32,
    force_trace: bool,
    p: &Printer,
) -> (Report, Verdict) {
    let lang = p.lang;

    // ── ステージ1: 環境 ─────────────────────────────
    p.section(MsgKey::StageEnv);
    let env_report = probe::env::run(&target.host);
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
    p.section(MsgKey::StageDns);
    let dns_report = probe::dns::run(&target.host, &env_report.nameservers, timeout, lang).await;
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
    p.section(MsgKey::StageTcp);
    let tcp_report = if resolved_ips.is_empty() {
        p.fail(msg(lang, MsgKey::NoResolvedIps));
        report::TcpReport::default()
    } else {
        let r = probe::tcp::run(&resolved_ips, target.port, samples, timeout, lang).await;
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
    let tls_report = if target.use_tls {
        p.section(MsgKey::StageTls);
        match primary_ip {
            Some(ip) if tcp_any_ok => {
                let r = probe::tls::run(&target.host, ip, target.port, timeout, lang).await;
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
        let mut r = probe::http::run(&url, timeout, lang).await;
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
    let quic_report = match primary_ip {
        Some(ip) if target.use_tls && target.do_http && tcp_any_ok => {
            p.section(MsgKey::StageQuic);
            let r = probe::quic::run(&target.host, ip, target.port, timeout).await;
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
    let path_report = match primary_ip {
        Some(ip) if tcp_any_ok => {
            p.section(MsgKey::StagePath);
            let r = probe::path::run(ip, target.port, samples, timeout).await;
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
    let trace_report = match primary_ip {
        Some(ip) if force_trace || tcp_timed_out || path_bad => {
            p.section(MsgKey::StageTrace);
            let r = probe::trace::run(ip, lang).await;
            print_trace(&r, p);
            Some(r)
        }
        _ => None,
    };

    // ── 判定 ───────────────────────────────────────
    let full_report = Report {
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
    };

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
async fn watch_loop(
    target: &Target,
    timeout: Duration,
    samples: u32,
    interval_secs: u64,
    force_trace: bool,
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
        let outcome = tokio::select! {
            r = diagnose(target, timeout, samples, force_trace, &quiet) => Some(r),
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
        watch_loop(&target, timeout, samples, interval, args.trace, lang).await;
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

    let (full_report, verdict) = diagnose(&target, timeout, samples, args.trace, &p).await;
    let rendered = verdict.render(lang);

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
        print_verdict_block(&rendered, lang);
    }

    std::process::exit(if verdict.culprit == Culprit::NoProblem {
        0
    } else {
        1
    });
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

    #[test]
    fn parse_bad_scheme() {
        assert!(matches!(
            parse_target("ftp://example.com"),
            Err(ParseError::UnsupportedScheme(_))
        ));
    }
}
