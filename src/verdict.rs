//! 判定エンジン。`judge` は Report を受け取り、最も可能性の高い犯人を
//! 1つ選んで根拠と次の一手を返す純粋関数 (I/O なし、ユニットテスト可能)。
//!
//! `judge` はロケール非依存の構造化データ (犯人カテゴリ + 根拠 enum) を返し、
//! 文字列化は `Verdict::render` + `i18n` が言語ごとに行う。

use crate::i18n::{self, Lang};
use crate::probe::trace::{self, HopZone};
use crate::report::{DnsOutcome, Report, TcpOutcome, TraceData, TraceReport};
use serde::Serialize;

/// 犯人カテゴリ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Culprit {
    /// ローカル DNS が死んでいる (パブリックは動く)
    LocalDnsBroken,
    /// ローカル DNS が遅い
    LocalDnsSlow,
    /// ローカルとパブリックで DNS 回答が異なる
    DnsAnswerMismatch,
    /// 名前が存在しない (NXDOMAIN) — ネットワークのせいではない
    NameDoesNotExist,
    /// TCP がタイムアウト (フィルタ/到達不能)
    TcpBlocked,
    /// IPv6 経路が壊れている (IPv4 は正常)
    Ipv6Broken,
    /// TLS 証明書の期限切れ
    TlsCertExpired,
    /// TLS 証明書が不正 (チェーン検証失敗など)
    TlsCertInvalid,
    /// TLS 傍受 (ミドルボックス) の疑い
    TlsIntercepted,
    /// プロキシ設定による干渉の疑い
    ProxyInterference,
    /// 経路が不安定 (ロス/ジッタ大)
    UnstablePath,
    /// PMTUD ブラックホール (経路 MTU 制限 + ICMP 通知の欠落)
    PmtuBlackhole,
    /// サーバの応答が遅い (ネットワークは正常)
    ServerSlow,
    /// サーバがダウンしている / ポートが閉じている
    ServerDown,
    /// 問題なし
    NoProblem,
}

impl Culprit {
    /// ロケール非依存の機械可読コード
    pub fn code(self) -> &'static str {
        match self {
            Culprit::LocalDnsBroken => "local_dns_broken",
            Culprit::LocalDnsSlow => "local_dns_slow",
            Culprit::DnsAnswerMismatch => "dns_answer_mismatch",
            Culprit::NameDoesNotExist => "name_does_not_exist",
            Culprit::TcpBlocked => "tcp_blocked",
            Culprit::Ipv6Broken => "ipv6_broken",
            Culprit::TlsCertExpired => "tls_cert_expired",
            Culprit::TlsCertInvalid => "tls_cert_invalid",
            Culprit::TlsIntercepted => "tls_intercepted",
            Culprit::ProxyInterference => "proxy_interference",
            Culprit::UnstablePath => "unstable_path",
            Culprit::PmtuBlackhole => "pmtu_blackhole",
            Culprit::ServerSlow => "server_slow",
            Culprit::ServerDown => "server_down",
            Culprit::NoProblem => "no_problem",
        }
    }
}

/// 【判定】1行に必要なデータ。犯人カテゴリ + パラメータ。
/// (TcpBlocked は「外向き全滅」と「特定ポートのみ」で文言が異なるため分離)
#[derive(Debug, Clone, PartialEq)]
pub enum Headline {
    NameDoesNotExist { host: String },
    LocalDnsBroken,
    LocalDnsSlow,
    OutboundDead,
    DnsAnswerMismatch,
    ServerDown { port: u16 },
    TcpBlocked { port: u16 },
    Ipv6Broken,
    TlsCertExpired,
    TlsIntercepted,
    TlsCertInvalid,
    ProxyInterference,
    ServerSlow,
    UnstablePath,
    PmtuBlackhole,
    NoProblem,
}

/// 【根拠】1項目。ロケール非依存の構造化データ。
#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    AllSourcesNxDomain,
    PublicDnsAgrees,
    PublicDnsResolves,
    LocalDnsSourceFailed { label: String, outcome: DnsOutcome },
    AllDnsUnresponsive,
    OutboundBlockedSuspected,
    LocalDnsAnswers { ips: Vec<String> },
    PublicDnsAnswers { ips: Vec<String> },
    SplitHorizonSuspected,
    AllConnectionsRefused,
    HostReachable,
    DnsOkTcpTimedOut,
    FirewallOrDeadPath,
    Ipv6ConnectFailed { count: usize },
    Ipv4Works,
    CertExpiredDaysAgo { days: i64 },
    TcpFineSoPathOk,
    PresentedIssuer { issuer: String },
    MiddleboxIssuer,
    ChainVerifyFailed { error: String },
    HostnameMismatch,
    ProxyVarsDetected { vars: Vec<String> },
    TcpOkHttpFailed,
    HttpErrorDetail { error: String },
    ConnectFast { ms: f64 },
    TtfbSlow { ms: f64 },
    ServerSideProcessing,
    ProbeLoss { sent: u32, lost: u32, pct: f64 },
    RttStats { avg: f64, jitter: f64 },
    UnstablePathSymptom,
    LocalDnsLatency { ms: f64 },
    PublicDnsLatency { ms: f64 },
    LatencyAddedEveryPage,
    DnsHealthy,
    TcpHealthy { ms: f64 },
    TlsHealthy { version: String, days: i64 },
    HttpHealthy { status: u16, ttfb: f64 },
    PathHealthy { loss_pct: f64, jitter: f64 },
    AllStagesOk,
    LastRespondingHop { ip: String, index: u8, path_len: u8 },
    PmtuBlackholeObserved { mtu: u16 },
}

/// 【所見】(副次的な発見) 1項目。
#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    HostsOverride {
        host: String,
        ip: String,
    },
    ProxyEnvPresent {
        names: Vec<String>,
    },
    DnsAnswersDiffer {
        local: Vec<String>,
        public: Vec<String>,
    },
    CertExpiresSoon {
        days: i64,
    },
}

/// 判定結果 (構造化データ)。文字列化は `render` で行う。
#[derive(Debug, Clone)]
pub struct Verdict {
    pub culprit: Culprit,
    pub headline: Headline,
    pub evidence: Vec<Evidence>,
    pub secondary: Vec<Finding>,
    /// 経路トレースによる障害位置の推定 (宅内/ISP/対岸)。
    /// あれば【次の一手】に切り分けガイダンスを追記する。
    pub zone_hint: Option<HopZone>,
}

impl Verdict {
    fn new(culprit: Culprit, headline: Headline, evidence: Vec<Evidence>) -> Self {
        Self {
            culprit,
            headline,
            evidence,
            secondary: Vec::new(),
            zone_hint: None,
        }
    }

    /// 指定言語で文字列化する。JSON 出力にもそのまま使う。
    pub fn render(&self, lang: Lang) -> RenderedVerdict {
        let base_next = i18n::next_step(lang, &self.headline);
        let next_step = match self.zone_hint {
            Some(zone) => i18n::append_guidance(base_next, i18n::zone_guidance(lang, zone)),
            None => base_next.to_string(),
        };
        RenderedVerdict {
            culprit: self.culprit,
            culprit_code: self.culprit.code(),
            headline: i18n::headline(lang, &self.headline),
            evidence: self
                .evidence
                .iter()
                .map(|e| i18n::evidence_line(lang, e))
                .collect(),
            next_step,
            secondary: self
                .secondary
                .iter()
                .map(|f| i18n::finding_line(lang, f))
                .collect(),
        }
    }
}

/// 言語を選んで文字列化した判定結果 (表示・JSON 用)
#[derive(Debug, Clone, Serialize)]
pub struct RenderedVerdict {
    pub culprit: Culprit,
    /// ロケール非依存の機械可読コード (例: "no_problem")
    pub culprit_code: &'static str,
    pub headline: String,
    pub evidence: Vec<String>,
    pub next_step: String,
    pub secondary: Vec<String>,
}

const SLOW_LOCAL_DNS_MS: f64 = 200.0;
const FAST_PUBLIC_DNS_MS: f64 = 100.0;
const SLOW_TTFB_MS: f64 = 1000.0;
const FAST_CONNECT_MS: f64 = 100.0;
const LOSS_PCT_THRESHOLD: f64 = 10.0;
/// 経路トレースの自動起動判定でも使う (main 参照)
pub const JITTER_MS_THRESHOLD: f64 = 50.0;

/// レポートから犯人を判定する純粋関数
pub fn judge(report: &Report) -> Verdict {
    let d = DnsView::from(report);
    let t = TcpView::from(report);

    let mut secondary = collect_secondary(report, &d, &t);

    let mut verdict = judge_primary(report, &d, &t);
    verdict.secondary.append(&mut secondary);
    attach_trace_hint(report, &mut verdict);
    verdict
}

/// 実行済みの経路トレースデータがあれば取り出す
fn trace_data(report: &Report) -> Option<&TraceData> {
    match report.trace.as_ref()? {
        TraceReport::Ran(data) => Some(data),
        _ => None,
    }
}

/// 経路系の判定 (TcpBlocked / ServerDown / UnstablePath) に対して、
/// トレース結果から「どこで壊れているか」の根拠とガイダンスを付与する
fn attach_trace_hint(report: &Report, verdict: &mut Verdict) {
    if !matches!(
        verdict.culprit,
        Culprit::TcpBlocked | Culprit::ServerDown | Culprit::UnstablePath
    ) {
        return;
    }
    let Some(td) = trace_data(report) else {
        return;
    };
    let Some(loc) = trace::localize_failure(&td.hops, td.dest_reached) else {
        return;
    };
    verdict.evidence.push(Evidence::LastRespondingHop {
        ip: loc.last_hop.to_string(),
        index: loc.last_index,
        path_len: loc.path_len_estimate,
    });
    // 宛先まで到達している場合、止まった場所からのゾーン推定は意味を
    // 持たないのでガイダンスは付けない
    if !td.dest_reached {
        verdict.zone_hint = Some(loc.zone);
    }
}

/// DNS 結果の要約ビュー
struct DnsView {
    /// DNS ステージを実施したか
    ran: bool,
    /// ローカル系 (システム + resolv.conf 直接) に Ok があるか
    local_ok: bool,
    /// パブリック系に Ok があるか
    public_ok: bool,
    /// 何かしら Ok があるか
    any_ok: bool,
    /// 回答した (timeout/error 以外の) ソースが全て NXDOMAIN か
    all_nxdomain: bool,
    /// ローカルとパブリックの回答 IP 集合が非交差か
    answers_disjoint: bool,
    /// ローカル系の最速レイテンシ
    local_best_ms: Option<f64>,
    /// パブリック系の最速レイテンシ
    public_best_ms: Option<f64>,
    local_failures: Vec<(String, DnsOutcome)>,
    local_ips: Vec<String>,
    public_ips: Vec<String>,
}

impl DnsView {
    fn from(report: &Report) -> Self {
        let srcs = &report.dns.sources;
        let ran = !report.dns.skipped && !srcs.is_empty();
        let local_ok = srcs.iter().any(|s| s.is_local() && s.is_ok());
        let public_ok = srcs.iter().any(|s| s.is_public() && s.is_ok());
        let any_ok = local_ok || public_ok;

        let answered: Vec<_> = srcs
            .iter()
            .filter(|s| !matches!(s.outcome, DnsOutcome::Timeout | DnsOutcome::Error(_)))
            .collect();
        let all_nxdomain =
            !answered.is_empty() && answered.iter().all(|s| s.outcome == DnsOutcome::NxDomain);

        let mut local_ips: Vec<String> = srcs
            .iter()
            .filter(|s| s.is_local() && s.is_ok())
            .flat_map(|s| s.ips.iter().map(|ip| ip.to_string()))
            .collect();
        local_ips.sort();
        local_ips.dedup();
        let mut public_ips: Vec<String> = srcs
            .iter()
            .filter(|s| s.is_public() && s.is_ok())
            .flat_map(|s| s.ips.iter().map(|ip| ip.to_string()))
            .collect();
        public_ips.sort();
        public_ips.dedup();
        let answers_disjoint = !local_ips.is_empty()
            && !public_ips.is_empty()
            && local_ips.iter().all(|ip| !public_ips.contains(ip));

        let best = |pred: &dyn Fn(&&crate::report::DnsSourceResult) -> bool| {
            srcs.iter()
                .filter(|s| pred(s) && s.is_ok())
                .filter_map(|s| s.latency_ms)
                .fold(None, |acc: Option<f64>, v| {
                    Some(acc.map_or(v, |a| a.min(v)))
                })
        };
        let local_best_ms = best(&|s| s.is_local());
        let public_best_ms = best(&|s| s.is_public());

        let local_failures = srcs
            .iter()
            .filter(|s| s.is_local() && !s.is_ok())
            .map(|s| (s.label.clone(), s.outcome.clone()))
            .collect();

        Self {
            ran,
            local_ok,
            public_ok,
            any_ok,
            all_nxdomain,
            answers_disjoint,
            local_best_ms,
            public_best_ms,
            local_failures,
            local_ips,
            public_ips,
        }
    }
}

/// TCP 結果の要約ビュー
struct TcpView {
    ran: bool,
    any_ok: bool,
    all_fail: bool,
    /// 全滅時、全て Refused だったか
    all_refused: bool,
    v4_total: usize,
    v4_ok: usize,
    v6_total: usize,
    v6_ok: usize,
    best_connect_ms: Option<f64>,
}

impl TcpView {
    fn from(report: &Report) -> Self {
        let probes = &report.tcp.probes;
        let ran = !probes.is_empty();
        let any_ok = probes.iter().any(|p| p.is_ok());
        let all_fail = ran && !any_ok;
        let all_refused = all_fail && probes.iter().all(|p| p.outcome == TcpOutcome::Refused);
        let v4: Vec<_> = probes.iter().filter(|p| p.ip.is_ipv4()).collect();
        let v6: Vec<_> = probes.iter().filter(|p| p.ip.is_ipv6()).collect();
        let best_connect_ms = probes
            .iter()
            .filter_map(|p| p.avg_ms)
            .fold(None, |acc: Option<f64>, v| {
                Some(acc.map_or(v, |a| a.min(v)))
            });
        Self {
            ran,
            any_ok,
            all_fail,
            all_refused,
            v4_total: v4.len(),
            v4_ok: v4.iter().filter(|p| p.is_ok()).count(),
            v6_total: v6.len(),
            v6_ok: v6.iter().filter(|p| p.is_ok()).count(),
            best_connect_ms,
        }
    }
}

fn judge_primary(report: &Report, d: &DnsView, t: &TcpView) -> Verdict {
    let host = &report.target.host;

    // 1. NXDOMAIN: 名前が存在しない — ネットワークのせいではない
    if d.ran && d.all_nxdomain {
        return Verdict::new(
            Culprit::NameDoesNotExist,
            Headline::NameDoesNotExist { host: host.clone() },
            vec![Evidence::AllSourcesNxDomain, Evidence::PublicDnsAgrees],
        );
    }

    // 2. ローカル DNS 死亡: パブリックは引けるのにローカルが引けない
    if d.ran && d.public_ok && !d.local_ok {
        let mut ev = vec![Evidence::PublicDnsResolves];
        for (label, outcome) in &d.local_failures {
            ev.push(Evidence::LocalDnsSourceFailed {
                label: label.clone(),
                outcome: outcome.clone(),
            });
        }
        return Verdict::new(Culprit::LocalDnsBroken, Headline::LocalDnsBroken, ev);
    }

    // 3. DNS 全滅 (NXDOMAIN ではなく、パブリックにも届かない) — 外向き通信自体が怪しい
    if d.ran && !d.any_ok && !d.all_nxdomain {
        return Verdict::new(
            Culprit::TcpBlocked,
            Headline::OutboundDead,
            vec![
                Evidence::AllDnsUnresponsive,
                Evidence::OutboundBlockedSuspected,
            ],
        );
    }

    // 4. DNS 回答不一致 + 接続失敗: 中立的に報告
    if d.ran && d.answers_disjoint && (t.all_fail || tls_failed(report)) {
        return Verdict::new(
            Culprit::DnsAnswerMismatch,
            Headline::DnsAnswerMismatch,
            vec![
                Evidence::LocalDnsAnswers {
                    ips: d.local_ips.clone(),
                },
                Evidence::PublicDnsAnswers {
                    ips: d.public_ips.clone(),
                },
                Evidence::SplitHorizonSuspected,
            ],
        );
    }

    // 5. TCP 全滅
    if t.all_fail {
        if t.all_refused {
            return Verdict::new(
                Culprit::ServerDown,
                Headline::ServerDown {
                    port: report.target.port,
                },
                vec![Evidence::AllConnectionsRefused, Evidence::HostReachable],
            );
        }
        return Verdict::new(
            Culprit::TcpBlocked,
            Headline::TcpBlocked {
                port: report.target.port,
            },
            vec![Evidence::DnsOkTcpTimedOut, Evidence::FirewallOrDeadPath],
        );
    }

    // 6. IPv6 だけ死んでいる
    if t.v6_total > 0 && t.v6_ok == 0 && t.v4_total > 0 && t.v4_ok > 0 {
        return Verdict::new(
            Culprit::Ipv6Broken,
            Headline::Ipv6Broken,
            vec![
                Evidence::Ipv6ConnectFailed { count: t.v6_total },
                Evidence::Ipv4Works,
            ],
        );
    }

    // 7. TLS 系
    if let Some(tls) = &report.tls {
        if tls.cert_expired {
            let days = tls.days_until_expiry.map(|d| -d).unwrap_or(0);
            return Verdict::new(
                Culprit::TlsCertExpired,
                Headline::TlsCertExpired,
                vec![
                    Evidence::CertExpiredDaysAgo { days },
                    Evidence::TcpFineSoPathOk,
                ],
            );
        }
        if tls.interception_suspected {
            let issuer = tls.presented_issuer.clone().unwrap_or_else(|| "?".into());
            return Verdict::new(
                Culprit::TlsIntercepted,
                Headline::TlsIntercepted,
                vec![
                    Evidence::PresentedIssuer { issuer },
                    Evidence::MiddleboxIssuer,
                ],
            );
        }
        if !tls.verified && tls.error.is_some() {
            let mut ev = vec![Evidence::ChainVerifyFailed {
                error: tls.error.clone().unwrap_or_default(),
            }];
            if let Some(issuer) = &tls.presented_issuer {
                ev.push(Evidence::PresentedIssuer {
                    issuer: issuer.clone(),
                });
            }
            if tls.hostname_matches == Some(false) {
                ev.push(Evidence::HostnameMismatch);
            }
            return Verdict::new(Culprit::TlsCertInvalid, Headline::TlsCertInvalid, ev);
        }
    }

    // 7.5. PMTUD ブラックホール: TCP 接続 (小パケット) は通るのに、
    // 経路 MTU が 1500 未満で超過 DF パケットへの ICMP 通知が返らない
    // → 大きな転送だけが黙って死ぬ、VPN/トンネルの典型事故
    if t.any_ok {
        if let Some(td) = trace_data(report) {
            let analysis = trace::analyze_mtu(td.kernel_mtu, &td.mtu_probes);
            if analysis.blackhole {
                if let Some(mtu) = analysis.path_mtu {
                    return Verdict::new(
                        Culprit::PmtuBlackhole,
                        Headline::PmtuBlackhole,
                        vec![
                            Evidence::PmtuBlackholeObserved { mtu },
                            Evidence::TcpFineSoPathOk,
                        ],
                    );
                }
            }
        }
    }

    // 8. プロキシ干渉: プロキシ設定あり + TCP は通るのに HTTP が失敗
    if !report.env.proxies.is_empty() && t.any_ok {
        if let Some(http) = &report.http {
            if http.error.is_some() && http.status.is_none() {
                let vars: Vec<String> = report
                    .env
                    .proxies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                return Verdict::new(
                    Culprit::ProxyInterference,
                    Headline::ProxyInterference,
                    vec![
                        Evidence::ProxyVarsDetected { vars },
                        Evidence::TcpOkHttpFailed,
                        Evidence::HttpErrorDetail {
                            error: http.error.clone().unwrap_or_default(),
                        },
                    ],
                );
            }
        }
    }

    // 9. サーバが遅い: 接続は速いのに TTFB が遅い
    if let Some(http) = &report.http {
        if let (Some(ttfb), Some(connect)) = (http.ttfb_ms, t.best_connect_ms) {
            if ttfb > SLOW_TTFB_MS && connect < FAST_CONNECT_MS {
                return Verdict::new(
                    Culprit::ServerSlow,
                    Headline::ServerSlow,
                    vec![
                        Evidence::ConnectFast { ms: connect },
                        Evidence::TtfbSlow { ms: ttfb },
                        Evidence::ServerSideProcessing,
                    ],
                );
            }
        }
    }

    // 10. 経路不安定
    if let Some(path) = &report.path {
        let lossy = path.loss_pct >= LOSS_PCT_THRESHOLD;
        let jittery = path.jitter_ms.is_some_and(|j| j > JITTER_MS_THRESHOLD);
        if lossy || jittery {
            let mut ev = Vec::new();
            if lossy {
                ev.push(Evidence::ProbeLoss {
                    sent: path.sent,
                    lost: path.lost,
                    pct: path.loss_pct,
                });
            }
            if let (Some(avg), Some(j)) = (path.avg_ms, path.jitter_ms) {
                ev.push(Evidence::RttStats { avg, jitter: j });
            }
            ev.push(Evidence::UnstablePathSymptom);
            return Verdict::new(Culprit::UnstablePath, Headline::UnstablePath, ev);
        }
    }

    // 11. ローカル DNS が遅い
    if let (Some(local), Some(public)) = (d.local_best_ms, d.public_best_ms) {
        if local > SLOW_LOCAL_DNS_MS && public < FAST_PUBLIC_DNS_MS {
            return Verdict::new(
                Culprit::LocalDnsSlow,
                Headline::LocalDnsSlow,
                vec![
                    Evidence::LocalDnsLatency { ms: local },
                    Evidence::PublicDnsLatency { ms: public },
                    Evidence::LatencyAddedEveryPage,
                ],
            );
        }
    }

    // 12. 問題なし
    let mut ev = Vec::new();
    if d.ran && d.any_ok {
        ev.push(Evidence::DnsHealthy);
    }
    if t.ran && t.any_ok {
        if let Some(c) = t.best_connect_ms {
            ev.push(Evidence::TcpHealthy { ms: c });
        }
    }
    if let Some(tls) = &report.tls {
        if tls.verified {
            ev.push(Evidence::TlsHealthy {
                version: tls.version.clone().unwrap_or_else(|| "?".into()),
                days: tls.days_until_expiry.unwrap_or(0),
            });
        }
    }
    if let Some(http) = &report.http {
        if let Some(status) = http.status {
            ev.push(Evidence::HttpHealthy {
                status,
                ttfb: http.ttfb_ms.unwrap_or(0.0),
            });
        }
    }
    if let Some(path) = &report.path {
        ev.push(Evidence::PathHealthy {
            loss_pct: path.loss_pct,
            jitter: path.jitter_ms.unwrap_or(0.0),
        });
    }
    if ev.is_empty() {
        ev.push(Evidence::AllStagesOk);
    }
    Verdict::new(Culprit::NoProblem, Headline::NoProblem, ev)
}

fn tls_failed(report: &Report) -> bool {
    report
        .tls
        .as_ref()
        .is_some_and(|t| !t.verified && t.error.is_some())
}

/// 主判定に含まれない副次的所見を集める
fn collect_secondary(report: &Report, d: &DnsView, t: &TcpView) -> Vec<Finding> {
    let mut s = Vec::new();
    if let Some(over) = &report.env.hosts_override {
        s.push(Finding::HostsOverride {
            host: report.target.host.clone(),
            ip: over.clone(),
        });
    }
    if !report.env.proxies.is_empty() {
        let names: Vec<_> = report.env.proxies.iter().map(|(k, _)| k.clone()).collect();
        s.push(Finding::ProxyEnvPresent { names });
    }
    if d.answers_disjoint && !(t.all_fail || tls_failed(report)) {
        s.push(Finding::DnsAnswersDiffer {
            local: d.local_ips.clone(),
            public: d.public_ips.clone(),
        });
    }
    if let Some(tls) = &report.tls {
        if tls.verified {
            if let Some(days) = tls.days_until_expiry {
                if (0..=14).contains(&days) {
                    s.push(Finding::CertExpiresSoon { days });
                }
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, last))
    }
    fn ip6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946,
        ))
    }

    fn dns_src(
        source: DnsSource,
        label: &str,
        outcome: DnsOutcome,
        ips: Vec<IpAddr>,
        ms: f64,
    ) -> DnsSourceResult {
        DnsSourceResult {
            source,
            label: label.into(),
            outcome,
            ips,
            latency_ms: Some(ms),
        }
    }

    fn healthy_dns() -> DnsReport {
        DnsReport {
            skipped: false,
            sources: vec![
                dns_src(
                    DnsSource::System,
                    "システム",
                    DnsOutcome::Ok,
                    vec![ip4(34)],
                    12.0,
                ),
                dns_src(
                    DnsSource::Local("192.168.1.1".parse().unwrap()),
                    "ローカル 192.168.1.1",
                    DnsOutcome::Ok,
                    vec![ip4(34)],
                    15.0,
                ),
                dns_src(
                    DnsSource::Public("1.1.1.1".parse().unwrap()),
                    "1.1.1.1",
                    DnsOutcome::Ok,
                    vec![ip4(34)],
                    20.0,
                ),
                dns_src(
                    DnsSource::Public("8.8.8.8".parse().unwrap()),
                    "8.8.8.8",
                    DnsOutcome::Ok,
                    vec![ip4(34)],
                    22.0,
                ),
            ],
        }
    }

    fn ok_probe(ip: IpAddr) -> TcpProbe {
        TcpProbe {
            ip,
            port: 443,
            samples: 5,
            successes: 5,
            outcome: TcpOutcome::Ok,
            min_ms: Some(10.0),
            avg_ms: Some(12.0),
            max_ms: Some(15.0),
        }
    }

    fn fail_probe(ip: IpAddr, outcome: TcpOutcome) -> TcpProbe {
        TcpProbe {
            ip,
            port: 443,
            samples: 5,
            successes: 0,
            outcome,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
        }
    }

    fn healthy_tls() -> TlsReport {
        TlsReport {
            verified: true,
            version: Some("TLS 1.3".into()),
            days_until_expiry: Some(120),
            hostname_matches: Some(true),
            cert_expired: false,
            presented_issuer: Some("DigiCert Global G3".into()),
            interception_suspected: false,
            handshake_ms: Some(30.0),
            error: None,
        }
    }

    fn healthy_http() -> HttpReport {
        HttpReport {
            status: Some(200),
            redirect_chain: vec![],
            dns_ms: Some(12.0),
            connect_ms: Some(12.0),
            tls_ms: Some(30.0),
            ttfb_ms: Some(80.0),
            total_ms: Some(120.0),
            error: None,
        }
    }

    fn healthy_path() -> PathReport {
        PathReport {
            ip: ip4(34),
            port: 443,
            sent: 5,
            lost: 0,
            loss_pct: 0.0,
            min_ms: Some(10.0),
            avg_ms: Some(12.0),
            max_ms: Some(14.0),
            jitter_ms: Some(1.5),
        }
    }

    /// 全ステージ正常のベースレポート
    fn base_report() -> Report {
        Report {
            target: TargetInfo {
                host: "example.com".into(),
                port: 443,
                use_tls: true,
                do_http: true,
                path: "/".into(),
                is_ip_literal: false,
            },
            env: EnvReport::default(),
            dns: healthy_dns(),
            tcp: TcpReport {
                probes: vec![ok_probe(ip4(34))],
            },
            tls: Some(healthy_tls()),
            http: Some(healthy_http()),
            path: Some(healthy_path()),
            trace: None,
        }
    }

    /// 経路トレース結果 (Ran) を組み立てるヘルパ
    fn trace_ran(
        hops: Vec<TraceHop>,
        dest_reached: bool,
        kernel_mtu: Option<u16>,
        mtu_probes: Vec<MtuProbe>,
    ) -> Option<TraceReport> {
        Some(TraceReport::Ran(TraceData {
            hops,
            dest_reached,
            kernel_mtu,
            mtu_probes,
        }))
    }

    fn thop(index: u8, addr: Option<&str>) -> TraceHop {
        TraceHop {
            index,
            addr: addr.map(|a| a.parse().unwrap()),
            rtt_ms: addr.map(|_| 10.0),
        }
    }

    #[test]
    fn no_problem() {
        let r = base_report();
        assert_eq!(judge(&r).culprit, Culprit::NoProblem);
    }

    #[test]
    fn name_does_not_exist() {
        let mut r = base_report();
        for s in &mut r.dns.sources {
            s.outcome = DnsOutcome::NxDomain;
            s.ips.clear();
        }
        r.tcp.probes.clear();
        r.tls = None;
        r.http = None;
        r.path = None;
        assert_eq!(judge(&r).culprit, Culprit::NameDoesNotExist);
    }

    #[test]
    fn local_dns_broken() {
        let mut r = base_report();
        for s in &mut r.dns.sources {
            if s.is_local() {
                s.outcome = DnsOutcome::Timeout;
                s.ips.clear();
                s.latency_ms = None;
            }
        }
        // TCP 以降はパブリック回答で成功した想定でも、主犯はローカル DNS
        assert_eq!(judge(&r).culprit, Culprit::LocalDnsBroken);
    }

    #[test]
    fn local_dns_slow() {
        let mut r = base_report();
        for s in &mut r.dns.sources {
            if s.is_local() {
                s.latency_ms = Some(450.0);
            }
        }
        assert_eq!(judge(&r).culprit, Culprit::LocalDnsSlow);
    }

    #[test]
    fn dns_answer_mismatch_with_failure() {
        let mut r = base_report();
        // ローカルの回答をパブリックと非交差にする
        let hijack: IpAddr = "10.0.0.99".parse().unwrap();
        for s in &mut r.dns.sources {
            if s.is_local() {
                s.ips = vec![hijack];
            }
        }
        // 接続も失敗している
        r.tcp.probes = vec![fail_probe(hijack, TcpOutcome::Timeout)];
        r.tls = None;
        r.http = None;
        r.path = None;
        assert_eq!(judge(&r).culprit, Culprit::DnsAnswerMismatch);
    }

    #[test]
    fn dns_answer_mismatch_but_working_is_secondary() {
        let mut r = base_report();
        let cdn: IpAddr = "104.16.1.1".parse().unwrap();
        for s in &mut r.dns.sources {
            if s.is_local() {
                s.ips = vec![cdn];
            }
        }
        let v = judge(&r);
        assert_eq!(v.culprit, Culprit::NoProblem);
        assert!(v
            .secondary
            .iter()
            .any(|s| matches!(s, Finding::DnsAnswersDiffer { .. })));
    }

    #[test]
    fn tcp_blocked() {
        let mut r = base_report();
        r.tcp.probes = vec![
            fail_probe(ip4(34), TcpOutcome::Timeout),
            fail_probe(ip6(), TcpOutcome::Timeout),
        ];
        r.tls = None;
        r.http = None;
        r.path = None;
        assert_eq!(judge(&r).culprit, Culprit::TcpBlocked);
    }

    #[test]
    fn server_down_refused() {
        let mut r = base_report();
        r.tcp.probes = vec![fail_probe(ip4(34), TcpOutcome::Refused)];
        r.tls = None;
        r.http = None;
        r.path = None;
        assert_eq!(judge(&r).culprit, Culprit::ServerDown);
    }

    #[test]
    fn ipv6_broken() {
        let mut r = base_report();
        r.tcp.probes = vec![ok_probe(ip4(34)), fail_probe(ip6(), TcpOutcome::Timeout)];
        assert_eq!(judge(&r).culprit, Culprit::Ipv6Broken);
    }

    #[test]
    fn tls_cert_expired() {
        let mut r = base_report();
        let tls = r.tls.as_mut().unwrap();
        tls.verified = false;
        tls.cert_expired = true;
        tls.days_until_expiry = Some(-30);
        tls.error = Some("certificate expired".into());
        r.http = None;
        assert_eq!(judge(&r).culprit, Culprit::TlsCertExpired);
    }

    #[test]
    fn tls_intercepted() {
        let mut r = base_report();
        let tls = r.tls.as_mut().unwrap();
        tls.verified = false;
        tls.error = Some("invalid peer certificate: UnknownIssuer".into());
        tls.presented_issuer = Some("CN=Zscaler Intermediate Root CA".into());
        tls.interception_suspected = true;
        r.http = None;
        assert_eq!(judge(&r).culprit, Culprit::TlsIntercepted);
    }

    #[test]
    fn tls_cert_invalid() {
        let mut r = base_report();
        let tls = r.tls.as_mut().unwrap();
        tls.verified = false;
        tls.hostname_matches = Some(false);
        tls.error = Some("invalid peer certificate: NotValidForName".into());
        tls.presented_issuer = Some("CN=Let's Encrypt R11".into());
        r.http = None;
        assert_eq!(judge(&r).culprit, Culprit::TlsCertInvalid);
    }

    #[test]
    fn proxy_interference() {
        let mut r = base_report();
        r.env.proxies = vec![("https_proxy".into(), "http://proxy.corp:8080".into())];
        r.http = Some(HttpReport {
            status: None,
            error: Some("error sending request: proxy connect failed".into()),
            ..HttpReport::default()
        });
        r.tls = Some(healthy_tls());
        assert_eq!(judge(&r).culprit, Culprit::ProxyInterference);
    }

    #[test]
    fn server_slow() {
        let mut r = base_report();
        let http = r.http.as_mut().unwrap();
        http.ttfb_ms = Some(4200.0);
        http.total_ms = Some(4300.0);
        assert_eq!(judge(&r).culprit, Culprit::ServerSlow);
    }

    #[test]
    fn unstable_path() {
        let mut r = base_report();
        r.path = Some(PathReport {
            ip: ip4(34),
            port: 443,
            sent: 10,
            lost: 3,
            loss_pct: 30.0,
            min_ms: Some(10.0),
            avg_ms: Some(90.0),
            max_ms: Some(400.0),
            jitter_ms: Some(120.0),
        });
        assert_eq!(judge(&r).culprit, Culprit::UnstablePath);
    }

    #[test]
    fn pmtu_blackhole_detected() {
        // TCP は通るが、経路 MTU 1280 超の DF パケットが ICMP 通知なしで消える
        let mut r = base_report();
        r.trace = trace_ran(
            vec![thop(1, Some("192.168.1.1")), thop(2, Some("10.0.0.1"))],
            true,
            Some(1500),
            vec![
                MtuProbe {
                    size: 1500,
                    outcome: MtuProbeOutcome::Silent,
                },
                MtuProbe {
                    size: 1400,
                    outcome: MtuProbeOutcome::Silent,
                },
                MtuProbe {
                    size: 1280,
                    outcome: MtuProbeOutcome::Delivered,
                },
            ],
        );
        let v = judge(&r);
        assert_eq!(v.culprit, Culprit::PmtuBlackhole);
        assert!(v
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::PmtuBlackholeObserved { mtu: 1280 })));
    }

    #[test]
    fn healthy_mtu_trace_stays_no_problem() {
        // --trace 強制実行で経路 MTU 1500 が確認できた場合は問題なしのまま
        let mut r = base_report();
        r.trace = trace_ran(
            vec![thop(1, Some("192.168.1.1")), thop(2, Some("93.184.216.34"))],
            true,
            Some(1500),
            vec![MtuProbe {
                size: 1500,
                outcome: MtuProbeOutcome::Delivered,
            }],
        );
        assert_eq!(judge(&r).culprit, Culprit::NoProblem);
    }

    #[test]
    fn pmtud_working_is_not_blackhole_verdict() {
        // ICMP frag-needed が返っている = PMTUD は機能 → ブラックホールではない
        let mut r = base_report();
        r.trace = trace_ran(
            vec![],
            true,
            Some(1400),
            vec![MtuProbe {
                size: 1500,
                outcome: MtuProbeOutcome::FragNeeded { mtu: Some(1400) },
            }],
        );
        assert_eq!(judge(&r).culprit, Culprit::NoProblem);
    }

    #[test]
    fn tcp_blocked_gains_hop_localization() {
        // TCP 全滅 + トレースがホップ 4 で止まる → ISP ゾーンのガイダンス
        let mut r = base_report();
        r.tcp.probes = vec![fail_probe(ip4(34), TcpOutcome::Timeout)];
        r.tls = None;
        r.http = None;
        r.path = None;
        r.trace = trace_ran(
            vec![
                thop(1, Some("192.168.1.1")),
                thop(2, Some("10.0.0.1")),
                thop(3, Some("100.64.0.1")),
                thop(4, Some("203.0.113.1")),
                thop(5, None),
                thop(6, None),
            ],
            false,
            None,
            vec![],
        );
        let v = judge(&r);
        assert_eq!(v.culprit, Culprit::TcpBlocked);
        assert_eq!(v.zone_hint, Some(crate::probe::trace::HopZone::Isp));
        assert!(v.evidence.iter().any(|e| matches!(
            e,
            Evidence::LastRespondingHop {
                index: 4,
                path_len: 6,
                ..
            }
        )));
        // レンダリング: 根拠にホップ、次の一手にゾーンガイダンス
        let en = v.render(Lang::En);
        assert!(en
            .evidence
            .iter()
            .any(|e| e.contains("last responding hop: 203.0.113.1 (hop 4 of ~6)")));
        assert!(en.next_step.contains("ISP's network"));
        let ja = v.render(Lang::Ja);
        assert!(ja
            .evidence
            .iter()
            .any(|e| e.contains("最後に応答したホップ: 203.0.113.1")));
        assert!(ja.next_step.contains("ISP 網内"));
    }

    #[test]
    fn tcp_blocked_home_zone_when_hop_one_only() {
        let mut r = base_report();
        r.tcp.probes = vec![fail_probe(ip4(34), TcpOutcome::Timeout)];
        r.tls = None;
        r.http = None;
        r.path = None;
        r.trace = trace_ran(
            vec![thop(1, Some("192.168.1.1")), thop(2, None), thop(3, None)],
            false,
            None,
            vec![],
        );
        let v = judge(&r);
        assert_eq!(v.zone_hint, Some(crate::probe::trace::HopZone::Home));
        let ja = v.render(Lang::Ja);
        assert!(ja.next_step.contains("宅内"));
    }

    #[test]
    fn render_pmtu_blackhole_en_and_ja() {
        let mut r = base_report();
        r.trace = trace_ran(
            vec![],
            true,
            Some(1400),
            vec![
                MtuProbe {
                    size: 1500,
                    outcome: MtuProbeOutcome::Silent,
                },
                MtuProbe {
                    size: 1472,
                    outcome: MtuProbeOutcome::Silent,
                },
            ],
        );
        let v = judge(&r);
        assert_eq!(v.culprit, Culprit::PmtuBlackhole);
        let en = v.render(Lang::En);
        assert_eq!(en.culprit_code, "pmtu_blackhole");
        assert!(en.headline.contains("black hole"));
        assert!(en.evidence.iter().any(|e| e.contains("1400 bytes")));
        assert!(en.next_step.contains("MSS clamping"));
        let ja = v.render(Lang::Ja);
        assert!(ja.headline.contains("ブラックホール"));
        assert!(ja
            .evidence
            .iter()
            .any(|e| e.contains("経路 MTU が 1400 バイト")));
        assert!(ja.next_step.contains("MSS clamp"));
    }

    #[test]
    fn hosts_override_is_reported_as_secondary() {
        let mut r = base_report();
        r.env.hosts_override = Some("127.0.0.1".into());
        let v = judge(&r);
        assert_eq!(v.culprit, Culprit::NoProblem);
        assert!(v
            .secondary
            .iter()
            .any(|s| matches!(s, Finding::HostsOverride { .. })));
    }

    // ── レンダリング (言語別) ───────────────────────────────

    #[test]
    fn render_no_problem_en_and_ja() {
        let v = judge(&base_report());
        let en = v.render(Lang::En);
        assert_eq!(en.culprit_code, "no_problem");
        assert!(en.headline.contains("No problem found"));
        assert!(en.headline.contains("healthy right now"));
        assert!(en.next_step.contains("intermittent"));
        assert!(en
            .evidence
            .iter()
            .any(|e| e.contains("name resolution: OK")));
        let ja = v.render(Lang::Ja);
        assert!(ja.headline.contains("問題は見つかりませんでした"));
        assert!(ja.next_step.contains("もう一度実行"));
        assert!(ja.evidence.iter().any(|e| e.contains("名前解決: 正常")));
    }

    #[test]
    fn render_tcp_blocked_en_and_ja() {
        let mut r = base_report();
        r.tcp.probes = vec![fail_probe(ip4(34), TcpOutcome::Timeout)];
        r.tls = None;
        r.http = None;
        r.path = None;
        let v = judge(&r);
        let en = v.render(Lang::En);
        assert!(en.headline.contains("port 443"));
        assert!(en.headline.contains("time out"));
        assert!(en.next_step.contains("another network"));
        let ja = v.render(Lang::Ja);
        assert!(ja.headline.contains("ポート 443"));
        assert!(ja.headline.contains("タイムアウト"));
        assert!(ja.next_step.contains("テザリング"));
    }

    #[test]
    fn render_tls_cert_expired_en_and_ja() {
        let mut r = base_report();
        let tls = r.tls.as_mut().unwrap();
        tls.verified = false;
        tls.cert_expired = true;
        tls.days_until_expiry = Some(-30);
        tls.error = Some("certificate expired".into());
        r.http = None;
        let v = judge(&r);
        let en = v.render(Lang::En);
        assert!(en.headline.contains("certificate has expired"));
        assert!(en.headline.contains("not a network problem"));
        assert!(en
            .evidence
            .iter()
            .any(|e| e.contains("expired 30 days ago")));
        let ja = v.render(Lang::Ja);
        assert!(ja.headline.contains("証明書が期限切れ"));
        assert!(ja.evidence.iter().any(|e| e.contains("30 日前に失効")));
    }

    #[test]
    fn render_name_does_not_exist_en_and_ja() {
        let mut r = base_report();
        for s in &mut r.dns.sources {
            s.outcome = DnsOutcome::NxDomain;
            s.ips.clear();
        }
        r.tcp.probes.clear();
        r.tls = None;
        r.http = None;
        r.path = None;
        let v = judge(&r);
        let en = v.render(Lang::En);
        assert!(en.headline.contains("\"example.com\" does not exist"));
        assert!(en.evidence.iter().any(|e| e.contains("NXDOMAIN")));
        let ja = v.render(Lang::Ja);
        assert!(ja.headline.contains("「example.com」は存在しません"));
    }
}
