//! 判定エンジン。`judge` は Report を受け取り、最も可能性の高い犯人を
//! 1つ選んで根拠と次の一手を返す純粋関数 (I/O なし、ユニットテスト可能)。

use crate::report::{DnsOutcome, Report, TcpOutcome};
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
    /// サーバの応答が遅い (ネットワークは正常)
    ServerSlow,
    /// サーバがダウンしている / ポートが閉じている
    ServerDown,
    /// 問題なし
    NoProblem,
}

/// 判定結果
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub culprit: Culprit,
    /// 【判定】一行の犯人ステートメント
    pub headline: String,
    /// 【根拠】
    pub evidence: Vec<String>,
    /// 【次の一手】
    pub next_step: String,
    /// 副次的な所見
    pub secondary: Vec<String>,
}

impl Verdict {
    fn new(culprit: Culprit, headline: &str, evidence: Vec<String>, next_step: &str) -> Self {
        Self {
            culprit,
            headline: headline.to_string(),
            evidence,
            next_step: next_step.to_string(),
            secondary: Vec::new(),
        }
    }
}

const SLOW_LOCAL_DNS_MS: f64 = 200.0;
const FAST_PUBLIC_DNS_MS: f64 = 100.0;
const SLOW_TTFB_MS: f64 = 1000.0;
const FAST_CONNECT_MS: f64 = 100.0;
const LOSS_PCT_THRESHOLD: f64 = 10.0;
const JITTER_MS_THRESHOLD: f64 = 50.0;

/// レポートから犯人を判定する純粋関数
pub fn judge(report: &Report) -> Verdict {
    let d = DnsView::from(report);
    let t = TcpView::from(report);

    let mut secondary = collect_secondary(report, &d, &t);

    let mut verdict = judge_primary(report, &d, &t);
    verdict.secondary.append(&mut secondary);
    verdict
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
    local_fail_labels: Vec<String>,
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
        let all_nxdomain = !answered.is_empty()
            && answered.iter().all(|s| s.outcome == DnsOutcome::NxDomain);

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

        let local_fail_labels = srcs
            .iter()
            .filter(|s| s.is_local() && !s.is_ok())
            .map(|s| format!("{} ({})", s.label, outcome_ja(&s.outcome)))
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
            local_fail_labels,
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
            .fold(None, |acc: Option<f64>, v| Some(acc.map_or(v, |a| a.min(v))));
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

fn outcome_ja(o: &DnsOutcome) -> String {
    match o {
        DnsOutcome::Ok => "OK".into(),
        DnsOutcome::NxDomain => "NXDOMAIN".into(),
        DnsOutcome::ServFail => "SERVFAIL".into(),
        DnsOutcome::Timeout => "タイムアウト".into(),
        DnsOutcome::Error(e) => format!("エラー: {e}"),
    }
}

fn judge_primary(report: &Report, d: &DnsView, t: &TcpView) -> Verdict {
    let host = &report.target.host;

    // 1. NXDOMAIN: 名前が存在しない — ネットワークのせいではない
    if d.ran && d.all_nxdomain {
        return Verdict::new(
            Culprit::NameDoesNotExist,
            &format!("ドメイン「{host}」は存在しません。ネットワークのせいではありません"),
            vec![
                "問い合わせた全ての DNS サーバが NXDOMAIN (そんな名前は無い) と回答".into(),
                "パブリック DNS (1.1.1.1 / 8.8.8.8) でも同じ回答".into(),
            ],
            "ホスト名のタイプミスを確認してください。正しいはずなら、ドメインの有効期限切れの可能性があります",
        );
    }

    // 2. ローカル DNS 死亡: パブリックは引けるのにローカルが引けない
    if d.ran && d.public_ok && !d.local_ok {
        let mut ev = vec!["パブリック DNS (1.1.1.1 / 8.8.8.8) では名前解決に成功".into()];
        for f in &d.local_fail_labels {
            ev.push(format!("{f} は失敗"));
        }
        return Verdict::new(
            Culprit::LocalDnsBroken,
            "ローカル DNS リゾルバが機能していません",
            ev,
            "ルータの再起動、または DNS サーバを 1.1.1.1 / 8.8.8.8 に変更して回避できます",
        );
    }

    // 3. DNS 全滅 (NXDOMAIN ではなく、パブリックにも届かない) — 外向き通信自体が怪しい
    if d.ran && !d.any_ok && !d.all_nxdomain {
        return Verdict::new(
            Culprit::TcpBlocked,
            "外向きの通信が全滅しています。ネットワーク接続自体に問題があります",
            vec![
                "ローカル DNS もパブリック DNS (1.1.1.1 / 8.8.8.8) も応答しない".into(),
                "名前解決以前に、外への UDP/TCP が通っていない可能性が高い".into(),
            ],
            "ケーブル/Wi-Fi 接続とルータの状態を確認してください。他のサイトも開けないはずです",
        );
    }

    // 4. DNS 回答不一致 + 接続失敗: 中立的に報告
    if d.ran && d.answers_disjoint && (t.all_fail || tls_failed(report)) {
        return Verdict::new(
            Culprit::DnsAnswerMismatch,
            "ローカル DNS とパブリック DNS で回答が異なり、接続にも失敗しています",
            vec![
                format!("ローカル側の回答: {}", d.local_ips.join(", ")),
                format!("パブリック側の回答: {}", d.public_ips.join(", ")),
                "スプリットホライズン DNS、フィルタリング、または DNS 書き換えの可能性".into(),
            ],
            "社内ネットワークなら管理者に確認を。家庭ならルータの DNS 設定とセキュリティソフトを確認してください",
        );
    }

    // 5. TCP 全滅
    if t.all_fail {
        if t.all_refused {
            return Verdict::new(
                Culprit::ServerDown,
                &format!(
                    "サーバは生きていますが、ポート {} で何も待ち受けていません",
                    report.target.port
                ),
                vec![
                    "全ての接続試行が RST (connection refused) で即座に拒否された".into(),
                    "ホストまでは到達できている = ネットワーク経路は正常".into(),
                ],
                "ポート番号が正しいか確認してください。正しければサーバ側のサービス停止です",
            );
        }
        return Verdict::new(
            Culprit::TcpBlocked,
            &format!(
                "ポート {} への TCP 接続がタイムアウトします (フィルタ/到達不能)",
                report.target.port
            ),
            vec![
                "名前解決は成功しているが、TCP 接続が全ての IP でタイムアウト".into(),
                "途中のファイアウォールで落とされているか、経路が死んでいる".into(),
            ],
            "別ネットワーク (スマホのテザリング等) から試して切り分けてください。そちらで繋がるなら今のネットワークのフィルタが原因です",
        );
    }

    // 6. IPv6 だけ死んでいる
    if t.v6_total > 0 && t.v6_ok == 0 && t.v4_total > 0 && t.v4_ok > 0 {
        return Verdict::new(
            Culprit::Ipv6Broken,
            "IPv6 経路が壊れています (IPv4 は正常)",
            vec![
                format!("IPv6 アドレスへの TCP 接続が {} 件全て失敗", t.v6_total),
                "IPv4 への接続は成功 — フォールバックで繋がるが、接続開始が遅くなる".into(),
            ],
            "ルータ/回線の IPv6 設定を確認してください。応急処置として OS で IPv6 を無効化する手もあります",
        );
    }

    // 7. TLS 系
    if let Some(tls) = &report.tls {
        if tls.cert_expired {
            let days = tls.days_until_expiry.map(|d| -d).unwrap_or(0);
            return Verdict::new(
                Culprit::TlsCertExpired,
                "サーバの TLS 証明書が期限切れです。ネットワークのせいではありません",
                vec![
                    format!("証明書は {days} 日前に失効"),
                    "TCP 接続までは正常 = 経路は問題なし".into(),
                ],
                "サーバ管理者に証明書の更新を依頼してください。自分のサイトなら証明書を更新してください",
            );
        }
        if tls.interception_suspected {
            let issuer = tls.presented_issuer.as_deref().unwrap_or("不明");
            return Verdict::new(
                Culprit::TlsIntercepted,
                "TLS 通信が途中で傍受されている可能性が高いです",
                vec![
                    format!("提示された証明書の発行者: {issuer}"),
                    "本来の認証局ではなく、ミドルボックス (FW/プロキシ製品) 由来と思われる発行者".into(),
                ],
                "社内ネットワークなら SSL インスペクションが有効です。管理者に確認するか、社の CA 証明書を導入してください",
            );
        }
        if !tls.verified && tls.error.is_some() {
            let mut ev = vec![format!(
                "証明書チェーンの検証に失敗: {}",
                tls.error.as_deref().unwrap_or("")
            )];
            if let Some(issuer) = &tls.presented_issuer {
                ev.push(format!("提示された証明書の発行者: {issuer}"));
            }
            if tls.hostname_matches == Some(false) {
                ev.push("証明書のホスト名がターゲットと一致しない".into());
            }
            return Verdict::new(
                Culprit::TlsCertInvalid,
                "サーバの TLS 証明書が不正です (チェーン検証失敗)",
                ev,
                "URL が正しいか確認してください。正しければサーバ側の証明書設定ミスの可能性が高いです",
            );
        }
    }

    // 8. プロキシ干渉: プロキシ設定あり + TCP は通るのに HTTP が失敗
    if !report.env.proxies.is_empty() && t.any_ok {
        if let Some(http) = &report.http {
            if http.error.is_some() && http.status.is_none() {
                let vars: Vec<_> = report
                    .env
                    .proxies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                return Verdict::new(
                    Culprit::ProxyInterference,
                    "プロキシ設定が通信を妨げている可能性が高いです",
                    vec![
                        format!("プロキシ環境変数を検出: {}", vars.join(", ")),
                        "TCP 直結は成功するのに、HTTP リクエストは失敗".into(),
                        format!(
                            "HTTP エラー: {}",
                            report
                                .http
                                .as_ref()
                                .and_then(|h| h.error.as_deref())
                                .unwrap_or("")
                        ),
                    ],
                    "unset http_proxy https_proxy で一時解除して再試行してください。直るならプロキシ設定が犯人です",
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
                    "サーバ側の応答が遅いです。ネットワークは正常です",
                    vec![
                        format!("TCP 接続は {connect:.0}ms と高速 = 経路は健全"),
                        format!("しかし最初の応答 (TTFB) まで {ttfb:.0}ms かかっている"),
                        "遅いのはサーバの処理 (アプリ/DB) 側".into(),
                    ],
                    "回線やルータをいじっても改善しません。サーバ管理者への連絡か、時間を置いての再試行を",
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
                ev.push(format!(
                    "接続プローブ {} 回中 {} 回失敗 (ロス率 {:.0}%)",
                    path.sent, path.lost, path.loss_pct
                ));
            }
            if let (Some(avg), Some(j)) = (path.avg_ms, path.jitter_ms) {
                ev.push(format!("RTT 平均 {avg:.0}ms / ジッタ {j:.0}ms"));
            }
            ev.push("経路が不安定 — 体感の「重い」「途切れる」の典型パターン".into());
            return Verdict::new(
                Culprit::UnstablePath,
                "ネットワーク経路が不安定です (パケットロス/ジッタ大)",
                ev,
                "Wi-Fi なら有線接続か 5GHz 帯への変更を試してください。有線なら回線事業者側の問題の可能性があります",
            );
        }
    }

    // 11. ローカル DNS が遅い
    if let (Some(local), Some(public)) = (d.local_best_ms, d.public_best_ms) {
        if local > SLOW_LOCAL_DNS_MS && public < FAST_PUBLIC_DNS_MS {
            return Verdict::new(
                Culprit::LocalDnsSlow,
                "ローカル DNS リゾルバが遅く、全体の体感を悪化させています",
                vec![
                    format!("ローカル DNS の応答に {local:.0}ms"),
                    format!("パブリック DNS (1.1.1.1 / 8.8.8.8) は {public:.0}ms と高速"),
                    "ページを開くたびにこの差が上乗せされる".into(),
                ],
                "DNS サーバを 1.1.1.1 または 8.8.8.8 に変更すると改善が見込めます",
            );
        }
    }

    // 12. 問題なし
    let mut ev = Vec::new();
    if d.ran && d.any_ok {
        ev.push("名前解決: 正常".into());
    }
    if t.ran && t.any_ok {
        if let Some(c) = t.best_connect_ms {
            ev.push(format!("TCP 接続: 正常 ({c:.0}ms)"));
        }
    }
    if let Some(tls) = &report.tls {
        if tls.verified {
            ev.push(format!(
                "TLS: 正常 ({}, 証明書残り {} 日)",
                tls.version.as_deref().unwrap_or("?"),
                tls.days_until_expiry.unwrap_or(0)
            ));
        }
    }
    if let Some(http) = &report.http {
        if let Some(status) = http.status {
            ev.push(format!(
                "HTTP: {status} (TTFB {:.0}ms)",
                http.ttfb_ms.unwrap_or(0.0)
            ));
        }
    }
    if let Some(path) = &report.path {
        ev.push(format!(
            "経路品質: ロス {:.0}% / ジッタ {:.0}ms",
            path.loss_pct,
            path.jitter_ms.unwrap_or(0.0)
        ));
    }
    if ev.is_empty() {
        ev.push("実施した全ステージで異常なし".into());
    }
    Verdict::new(
        Culprit::NoProblem,
        "問題は見つかりませんでした。少なくとも今、この宛先への経路は健全です",
        ev,
        "問題が断続的なら、症状が出ている最中にもう一度実行してください",
    )
}

fn tls_failed(report: &Report) -> bool {
    report.tls.as_ref().is_some_and(|t| !t.verified && t.error.is_some())
}

/// 主判定に含まれない副次的所見を集める
fn collect_secondary(report: &Report, d: &DnsView, t: &TcpView) -> Vec<String> {
    let mut s = Vec::new();
    if let Some(over) = &report.env.hosts_override {
        s.push(format!(
            "/etc/hosts に「{}」の上書きエントリあり ({over}) — DNS を無視して接続しています",
            report.target.host
        ));
    }
    if !report.env.proxies.is_empty() {
        let vars: Vec<_> = report.env.proxies.iter().map(|(k, _)| k.clone()).collect();
        s.push(format!(
            "プロキシ環境変数が設定されています: {}",
            vars.join(", ")
        ));
    }
    if d.answers_disjoint && !(t.all_fail || tls_failed(report)) {
        s.push(format!(
            "ローカル DNS とパブリック DNS で回答が異なります (ローカル: {} / パブリック: {}) — CDN なら正常なこともあります",
            d.local_ips.join(", "),
            d.public_ips.join(", ")
        ));
    }
    if t.v6_total > 0 && t.v6_ok == 0 && t.v4_ok > 0 && t.all_fail {
        // 全滅時は主判定側で扱う
    }
    if let Some(tls) = &report.tls {
        if tls.verified {
            if let Some(days) = tls.days_until_expiry {
                if (0..=14).contains(&days) {
                    s.push(format!("TLS 証明書の残り有効期間が {days} 日と短い"));
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
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946))
    }

    fn dns_src(source: DnsSource, label: &str, outcome: DnsOutcome, ips: Vec<IpAddr>, ms: f64) -> DnsSourceResult {
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
                dns_src(DnsSource::System, "システム", DnsOutcome::Ok, vec![ip4(34)], 12.0),
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
        assert!(v.secondary.iter().any(|s| s.contains("回答が異なります")));
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
    fn hosts_override_is_reported_as_secondary() {
        let mut r = base_report();
        r.env.hosts_override = Some("127.0.0.1".into());
        let v = judge(&r);
        assert_eq!(v.culprit, Culprit::NoProblem);
        assert!(v.secondary.iter().any(|s| s.contains("/etc/hosts")));
    }
}
