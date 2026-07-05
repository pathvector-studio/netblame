//! blame — 「それ、本当にネットワークのせい?」
//! URL/ホストに対して段階診断 (環境→DNS→TCP→TLS→HTTP→経路品質) を行い、
//! 最も可能性の高い犯人を平易な日本語で名指しする。

mod probe;
mod report;
mod verdict;

use clap::Parser;
use owo_colors::{OwoColorize, Stream::Stdout};
use report::{DnsOutcome, Report, TargetInfo, TcpOutcome};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::time::Duration;
use verdict::{judge, Culprit};

/// それ、本当にネットワークのせい? — 段階診断で犯人を名指しする CLI
#[derive(Parser, Debug)]
#[command(name = "blame", version, about, arg_required_else_help = true)]
struct Args {
    /// 診断対象: URL (https://example.com/path) または host[:port]
    target: String,

    /// 機械可読な JSON レポートを出力する
    #[arg(long)]
    json: bool,

    /// 各プローブのタイムアウト秒数
    #[arg(long, default_value_t = 5)]
    timeout: u64,

    /// レイテンシ計測のサンプル数
    #[arg(long, default_value_t = 5)]
    samples: u32,

    /// 色つき出力を無効にする
    #[arg(long)]
    no_color: bool,
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

fn parse_target(raw: &str) -> Result<Target, String> {
    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        (Some(true), r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        (Some(false), r)
    } else if raw.contains("://") {
        return Err(format!("未対応のスキームです: {raw}"));
    } else {
        (None, raw)
    };

    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() {
        return Err("ホスト名が空です".to_string());
    }

    // IPv6 リテラル [::1]:443 に対応
    let (host, explicit_port) = if let Some(rest6) = hostport.strip_prefix('[') {
        let end = rest6
            .find(']')
            .ok_or_else(|| "IPv6 リテラルの ']' がありません".to_string())?;
        let host = rest6[..end].to_string();
        let after = &rest6[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(p.parse::<u16>().map_err(|_| format!("ポート番号が不正です: {p}"))?)
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
                Some(p.parse::<u16>().map_err(|_| format!("ポート番号が不正です: {p}"))?),
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
}

impl Printer {
    fn section(&self, name: &str) {
        if !self.quiet {
            println!(
                "\n{} {}",
                "──".if_supports_color(Stdout, |t| t.dimmed()),
                name.if_supports_color(Stdout, |t| t.bold())
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
            println!("  {} {}", "⚠".if_supports_color(Stdout, |t| t.yellow()), msg);
        }
    }
    fn fail(&self, msg: &str) {
        if !self.quiet {
            println!("  {} {}", "✗".if_supports_color(Stdout, |t| t.red()), msg);
        }
    }
}

fn fmt_ms(ms: Option<f64>) -> String {
    ms.map_or("-".to_string(), |v| format!("{v:.0}ms"))
}

#[tokio::main]
async fn main() {
    // rustls の暗号プロバイダ (ring) をプロセス既定として登録
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();

    if args.no_color || !std::io::stdout().is_terminal() {
        owo_colors::set_override(false);
    }

    let target = match parse_target(&args.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("エラー: {e}");
            std::process::exit(2);
        }
    };

    let timeout = Duration::from_secs(args.timeout.max(1));
    let samples = args.samples.max(1);
    let p = Printer { quiet: args.json };

    if !args.json {
        println!(
            "{} {} (port {}) を診断します…",
            "blame:".if_supports_color(Stdout, |t| t.bold()),
            target.host.if_supports_color(Stdout, |t| t.cyan()),
            target.port
        );
    }

    // ── ステージ1: 環境 ─────────────────────────────
    p.section("環境");
    let env_report = probe::env::run(&target.host);
    if env_report.nameservers.is_empty() {
        p.warn("resolv.conf にネームサーバが見つかりません");
    } else {
        p.ok(&format!(
            "ネームサーバ: {}",
            env_report
                .nameservers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !env_report.search_domains.is_empty() {
        p.ok(&format!(
            "search ドメイン: {}",
            env_report.search_domains.join(", ")
        ));
    }
    match &env_report.hosts_override {
        Some(ip) => p.warn(&format!(
            "/etc/hosts が {} を {} に上書きしています",
            target.host, ip
        )),
        None => p.ok("/etc/hosts: 上書きなし"),
    }
    if env_report.proxies.is_empty() {
        p.ok("プロキシ環境変数: なし");
    } else {
        for (k, v) in &env_report.proxies {
            p.warn(&format!("プロキシ検出: {k}={v}"));
        }
    }

    // ── ステージ2: DNS ─────────────────────────────
    p.section("DNS");
    let dns_report = probe::dns::run(&target.host, &env_report.nameservers, timeout).await;
    if dns_report.skipped {
        p.ok("ターゲットは IP リテラルのため名前解決をスキップ");
    } else {
        for src in &dns_report.sources {
            match &src.outcome {
                DnsOutcome::Ok => p.ok(&format!(
                    "{}: {} 件の回答 ({}) [{}]",
                    src.label,
                    src.ips.len(),
                    fmt_ms(src.latency_ms),
                    src.ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                DnsOutcome::NxDomain => p.fail(&format!("{}: NXDOMAIN (名前が存在しない)", src.label)),
                DnsOutcome::ServFail => p.fail(&format!("{}: SERVFAIL", src.label)),
                DnsOutcome::Timeout => p.fail(&format!("{}: タイムアウト", src.label)),
                DnsOutcome::Error(e) => p.fail(&format!("{}: {}", src.label, e)),
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
    p.section("TCP");
    let tcp_report = if resolved_ips.is_empty() {
        p.fail("接続先 IP がありません (名前解決に失敗)");
        report::TcpReport::default()
    } else {
        let r = probe::tcp::run(&resolved_ips, target.port, samples, timeout).await;
        for probe in &r.probes {
            let fam = if probe.ip.is_ipv6() { "IPv6" } else { "IPv4" };
            match &probe.outcome {
                TcpOutcome::Ok => p.ok(&format!(
                    "{} {}:{} 接続成功 {}/{} (min/avg/max {}/{}/{})",
                    fam,
                    probe.ip,
                    probe.port,
                    probe.successes,
                    probe.samples,
                    fmt_ms(probe.min_ms),
                    fmt_ms(probe.avg_ms),
                    fmt_ms(probe.max_ms)
                )),
                TcpOutcome::Refused => p.fail(&format!(
                    "{} {}:{} 接続拒否 (ポートは閉じているがホストは生存)",
                    fam, probe.ip, probe.port
                )),
                TcpOutcome::Timeout => p.fail(&format!(
                    "{} {}:{} タイムアウト (フィルタ/到達不能)",
                    fam, probe.ip, probe.port
                )),
                TcpOutcome::Error(e) => {
                    p.fail(&format!("{} {}:{} 失敗: {}", fam, probe.ip, probe.port, e))
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
        p.section("TLS");
        match primary_ip {
            Some(ip) if tcp_any_ok => {
                let r = probe::tls::run(&target.host, ip, target.port, timeout).await;
                if r.verified {
                    p.ok(&format!(
                        "ハンドシェイク成功: {} ({})",
                        r.version.as_deref().unwrap_or("?"),
                        fmt_ms(r.handshake_ms)
                    ));
                    if let Some(days) = r.days_until_expiry {
                        if days < 0 {
                            p.fail(&format!("証明書は {} 日前に失効", -days));
                        } else if days <= 14 {
                            p.warn(&format!("証明書の残り有効期間: {days} 日"));
                        } else {
                            p.ok(&format!("証明書の残り有効期間: {days} 日"));
                        }
                    }
                    p.ok("証明書チェーン検証: OK / ホスト名一致");
                } else {
                    p.fail(&format!(
                        "証明書検証失敗: {}",
                        r.error.as_deref().unwrap_or("不明なエラー")
                    ));
                    if let Some(issuer) = &r.presented_issuer {
                        if r.interception_suspected {
                            p.warn(&format!("提示された発行者: {issuer} (ミドルボックスの疑い)"));
                        } else {
                            p.warn(&format!("提示された発行者: {issuer}"));
                        }
                    }
                }
                Some(r)
            }
            _ => {
                p.fail("TCP 接続が確立できないため TLS 診断をスキップ");
                None
            }
        }
    } else {
        None
    };

    // ── ステージ5: HTTP ────────────────────────────
    let http_report = if target.do_http && tcp_any_ok {
        p.section("HTTP");
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
        let mut r = probe::http::run(&url, timeout).await;
        // 内訳時間は各ステージの実測値を転記する
        r.dns_ms = dns_report
            .sources
            .iter()
            .find(|s| s.is_ok())
            .and_then(|s| s.latency_ms);
        r.connect_ms = tcp_report.probes.iter().find_map(|pr| pr.avg_ms);
        r.tls_ms = tls_report.as_ref().and_then(|t| t.handshake_ms);

        for hop in &r.redirect_chain {
            p.ok(&format!("リダイレクト: {hop}"));
        }
        match (r.status, &r.error) {
            (Some(status), None) => {
                let line = format!(
                    "GET {} → {} (DNS {} / 接続 {} / TLS {} / TTFB {} / 合計 {})",
                    url,
                    status,
                    fmt_ms(r.dns_ms),
                    fmt_ms(r.connect_ms),
                    fmt_ms(r.tls_ms),
                    fmt_ms(r.ttfb_ms),
                    fmt_ms(r.total_ms)
                );
                if (200..400).contains(&status) {
                    p.ok(&line);
                } else {
                    p.warn(&line);
                }
            }
            (status, Some(e)) => {
                if let Some(s) = status {
                    p.fail(&format!("GET {url} → {s} だがエラー: {e}"));
                } else {
                    p.fail(&format!("GET {url} 失敗: {e}"));
                }
            }
            (None, None) => p.fail(&format!("GET {url}: 結果なし")),
        }
        Some(r)
    } else {
        if target.do_http && !args.json {
            p.section("HTTP");
            p.fail("TCP 接続が確立できないため HTTP 診断をスキップ");
        }
        None
    };

    // ── ステージ6: 経路品質 ─────────────────────────
    let path_report = match primary_ip {
        Some(ip) if tcp_any_ok => {
            p.section("経路品質");
            let r = probe::path::run(ip, target.port, samples, timeout).await;
            let line = format!(
                "{} 回プローブ: ロス {:.0}% / RTT min/avg/max {}/{}/{} / ジッタ {}",
                r.sent,
                r.loss_pct,
                fmt_ms(r.min_ms),
                fmt_ms(r.avg_ms),
                fmt_ms(r.max_ms),
                fmt_ms(r.jitter_ms)
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
        path: path_report,
    };

    let verdict = judge(&full_report);

    if args.json {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            report: &'a Report,
            verdict: &'a verdict::Verdict,
        }
        match serde_json::to_string_pretty(&JsonOutput {
            report: &full_report,
            verdict: &verdict,
        }) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("エラー: JSON 出力に失敗: {e}");
                std::process::exit(2);
            }
        }
    } else {
        println!();
        let style = if verdict.culprit == Culprit::NoProblem {
            owo_colors::Style::new().green().bold()
        } else {
            owo_colors::Style::new().red().bold()
        };
        let headline = format!(
            "{}",
            verdict.headline.if_supports_color(Stdout, |t| t.style(style))
        );
        println!(
            "{} {}",
            "【判定】".if_supports_color(Stdout, |t| t.bold()),
            headline
        );
        println!("{}", "【根拠】".if_supports_color(Stdout, |t| t.bold()));
        for e in &verdict.evidence {
            println!("  ・{e}");
        }
        if !verdict.secondary.is_empty() {
            println!("{}", "【所見】".if_supports_color(Stdout, |t| t.bold()));
            for s in &verdict.secondary {
                println!("  ・{}", s.if_supports_color(Stdout, |t| t.yellow()));
            }
        }
        println!(
            "{} {}",
            "【次の一手】".if_supports_color(Stdout, |t| t.bold()),
            verdict.next_step
        );
    }

    std::process::exit(if verdict.culprit == Culprit::NoProblem { 0 } else { 1 });
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
        assert!(parse_target("ftp://example.com").is_err());
    }
}
