//! 診断レポートのデータ構造。全ステージの計測結果を保持し、
//! verdict エンジン (`judge`) への入力となる。I/O は一切含まない。

use serde::Serialize;
use std::net::IpAddr;

/// 診断対象
#[derive(Debug, Clone, Serialize)]
pub struct TargetInfo {
    /// ホスト名 (または IP リテラル)
    pub host: String,
    pub port: u16,
    /// TLS ハンドシェイクを行うか
    pub use_tls: bool,
    /// HTTP GET を行うか (http/https URL または素のホスト)
    pub do_http: bool,
    /// HTTP リクエストパス
    pub path: String,
    /// ターゲットが IP リテラルか (DNS ステージをスキップ)
    pub is_ip_literal: bool,
}

/// ステージ1: 環境
#[derive(Debug, Clone, Default, Serialize)]
pub struct EnvReport {
    /// /etc/resolv.conf のネームサーバ
    pub nameservers: Vec<IpAddr>,
    /// /etc/resolv.conf の search ドメイン
    pub search_domains: Vec<String>,
    /// /etc/hosts にターゲットを上書きするエントリがあれば、その IP
    pub hosts_override: Option<String>,
    /// 検出されたプロキシ環境変数 (変数名, 値)
    pub proxies: Vec<(String, String)>,
    /// NO_PROXY / no_proxy の値
    pub no_proxy: Option<String>,
}

/// DNS 問い合わせ先の種別
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", content = "addr")]
pub enum DnsSource {
    /// システムリゾルバ (getaddrinfo 相当)
    System,
    /// resolv.conf に書かれたローカルネームサーバへの直接問い合わせ
    Local(IpAddr),
    /// パブリック DNS (1.1.1.1 / 8.8.8.8)
    Public(IpAddr),
}

/// DNS 問い合わせ結果の分類
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "code", content = "detail")]
pub enum DnsOutcome {
    Ok,
    NxDomain,
    ServFail,
    Timeout,
    Error(String),
}

/// ステージ2: DNS (1問い合わせ先ぶん)
#[derive(Debug, Clone, Serialize)]
pub struct DnsSourceResult {
    pub source: DnsSource,
    /// 表示用ラベル (例: "システム", "ローカル 192.168.1.1")
    pub label: String,
    pub outcome: DnsOutcome,
    pub ips: Vec<IpAddr>,
    pub latency_ms: Option<f64>,
}

impl DnsSourceResult {
    pub fn is_ok(&self) -> bool {
        self.outcome == DnsOutcome::Ok
    }
    pub fn is_local(&self) -> bool {
        matches!(self.source, DnsSource::System | DnsSource::Local(_))
    }
    pub fn is_public(&self) -> bool {
        matches!(self.source, DnsSource::Public(_))
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsReport {
    pub sources: Vec<DnsSourceResult>,
    /// DNS ステージをスキップしたか (IP リテラル指定時)
    pub skipped: bool,
}

/// TCP 接続の結果分類
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "code", content = "detail")]
pub enum TcpOutcome {
    Ok,
    Refused,
    Timeout,
    Error(String),
}

/// ステージ3: TCP (1 IP ぶん)
#[derive(Debug, Clone, Serialize)]
pub struct TcpProbe {
    pub ip: IpAddr,
    pub port: u16,
    pub samples: u32,
    pub successes: u32,
    pub outcome: TcpOutcome,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
}

impl TcpProbe {
    pub fn is_ok(&self) -> bool {
        self.successes > 0
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TcpReport {
    pub probes: Vec<TcpProbe>,
}

/// ステージ4: TLS
#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsReport {
    /// 証明書チェーンの検証に成功したか
    pub verified: bool,
    /// ネゴシエートされた TLS バージョン (例: "TLS 1.3")
    pub version: Option<String>,
    /// 証明書の有効期限までの日数 (負なら期限切れ)
    pub days_until_expiry: Option<i64>,
    /// ホスト名が証明書と一致するか
    pub hostname_matches: Option<bool>,
    /// 証明書が期限切れか
    pub cert_expired: bool,
    /// 提示された証明書の発行者 (検証失敗時に無検証接続で取得)
    pub presented_issuer: Option<String>,
    /// 発行者名からミドルボックス (TLS 傍受装置) が疑われるか
    pub interception_suspected: bool,
    pub handshake_ms: Option<f64>,
    pub error: Option<String>,
}

/// ステージ5: HTTP
#[derive(Debug, Clone, Default, Serialize)]
pub struct HttpReport {
    pub status: Option<u16>,
    /// リダイレクトチェーン (例: "301 -> https://example.com/")
    pub redirect_chain: Vec<String>,
    /// DNS 解決時間 (ステージ2の計測値)
    pub dns_ms: Option<f64>,
    /// TCP 接続時間 (ステージ3の計測値)
    pub connect_ms: Option<f64>,
    /// TLS ハンドシェイク時間 (ステージ4の計測値)
    pub tls_ms: Option<f64>,
    /// 最初のレスポンスヘッダ受信までの時間 (最終ホップ)
    pub ttfb_ms: Option<f64>,
    /// ボディ受信完了までの合計時間
    pub total_ms: Option<f64>,
    pub error: Option<String>,
    /// 最終応答の alt-svc ヘッダに h3 が含まれるか (HTTP/3 が広告されているか)
    pub h3_advertised: bool,
    /// alt-svc ヘッダの生値 (あれば)
    pub alt_svc: Option<String>,
}

/// QUIC ハンドシェイクの結果分類
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "code", content = "detail")]
pub enum QuicOutcome {
    /// ハンドシェイク成功
    Ok {
        handshake_ms: f64,
        /// ネゴシエートされた ALPN (例: "h3")
        negotiated_alpn: Option<String>,
    },
    /// 何も返ってこない (UDP 443 ブロックの兆候)
    Timeout,
    /// サーバは応答したが、ネゴシエーションに失敗した (ネットワーク遮断ではない)
    HandshakeError(String),
    /// ローカル側のエラー (ソケット確保失敗など)
    LocalError(String),
}

/// ステージ: QUIC/HTTP3 (https ターゲットでのみ実行)
#[derive(Debug, Clone, Serialize)]
pub struct QuicReport {
    pub outcome: QuicOutcome,
}

/// ステージ6: 経路品質
#[derive(Debug, Clone, Serialize)]
pub struct PathReport {
    pub ip: IpAddr,
    pub port: u16,
    pub sent: u32,
    pub lost: u32,
    pub loss_pct: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// ジッタ (RTT の標準偏差)
    pub jitter_ms: Option<f64>,
}

/// ステージ7: 経路トレースの 1 ホップぶんの結果
#[derive(Debug, Clone, Serialize)]
pub struct TraceHop {
    /// TTL (1 始まり)
    pub index: u8,
    /// 応答したルータのアドレス (無応答なら None)
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
}

/// DF ビット付き MTU プローブ 1 発の結果分類
// 構築するのは Linux 専用の trace プローブのみ (非 Linux では dead_code 扱いになる)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "code", content = "detail")]
pub enum MtuProbeOutcome {
    /// 送信できたが、ICMP も宛先応答も返ってこなかった
    Silent,
    /// ICMP fragmentation-needed / packet-too-big を受信 (経路上の MTU ヒント付き)
    FragNeeded { mtu: Option<u32> },
    /// 宛先まで届いた (port-unreachable が返った = このサイズは経路を通る)
    Delivered,
    /// 送信自体が失敗 (EMSGSIZE 等 = ローカル側の MTU 超過)
    LocalError,
}

/// DF ビット付き MTU プローブ 1 発 (パケットサイズと結果)
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MtuProbe {
    /// IP パケット全体のサイズ (バイト)
    pub size: u16,
    pub outcome: MtuProbeOutcome,
}

/// ステージ7: 経路トレース + PMTU 検出の計測データ
#[derive(Debug, Clone, Default, Serialize)]
pub struct TraceData {
    pub hops: Vec<TraceHop>,
    /// 宛先自体からの応答 (port-unreachable) を確認できたか
    pub dest_reached: bool,
    /// カーネルが把握している経路 MTU (getsockopt IP_MTU)
    pub kernel_mtu: Option<u16>,
    pub mtu_probes: Vec<MtuProbe>,
}

/// ステージ7 の結果。Linux 以外では Unsupported。
/// (どの variant が構築されるかはプラットフォーム依存だが、
/// 表示コードは常に全 variant を扱うため dead_code を許可する)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", content = "data")]
#[allow(dead_code)]
pub enum TraceReport {
    /// トレースを実行した (ホップ 0 件でも Ran)
    Ran(TraceData),
    /// このプラットフォームでは非対応 (tracepath 方式は Linux のみ)
    Unsupported,
    /// 実行したが失敗した (サンドボックス等)
    Failed(String),
}

/// 実行された/スキップされたステージの名前 (JSON では小文字の識別子)。
/// `--max-time` による打ち切りの報告と、ステージ別所要時間の両方で使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageName {
    Env,
    Dns,
    Tcp,
    Tls,
    Http,
    Quic,
    Path,
    Trace,
}

impl StageName {
    pub fn as_str(self) -> &'static str {
        match self {
            StageName::Env => "env",
            StageName::Dns => "dns",
            StageName::Tcp => "tcp",
            StageName::Tls => "tls",
            StageName::Http => "http",
            StageName::Quic => "quic",
            StageName::Path => "path",
            StageName::Trace => "trace",
        }
    }
}

/// 1ステージぶんの所要時間 (ミリ秒)。今後のドッグフーディングで
/// 「どのステージが時間を食っているか」を JSON から直接読めるようにする。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StageDuration {
    pub stage: StageName,
    pub ms: f64,
}

/// 診断の完了状況。`--max-time` (または Ctrl-C) による打ち切りがあったかどうか、
/// および実行/未実行のステージ一覧を記録する。JSON にも `"complete"` として
/// そのまま出す。
#[derive(Debug, Clone, Serialize)]
pub struct Completeness {
    /// 全ステージを完走したか (途中終了なら false)
    pub complete: bool,
    /// 打ち切りの理由 (完走なら None)
    pub truncated_reason: Option<TruncationReason>,
    /// 実行された (完了した) ステージ
    pub ran_stages: Vec<StageName>,
    /// `--max-time` / 割り込みにより未実行だったステージ
    pub skipped_stages: Vec<StageName>,
}

impl Default for Completeness {
    fn default() -> Self {
        Self {
            complete: true,
            truncated_reason: None,
            ran_stages: Vec::new(),
            skipped_stages: Vec::new(),
        }
    }
}

/// 打ち切りの理由
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    /// `--max-time` の全体デッドラインに到達した
    MaxTimeExceeded,
    /// Ctrl-C (SIGINT) を受信した
    Interrupted,
}

/// 全ステージの結果を束ねた診断レポート
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: TargetInfo,
    pub env: EnvReport,
    pub dns: DnsReport,
    pub tcp: TcpReport,
    pub tls: Option<TlsReport>,
    pub http: Option<HttpReport>,
    pub quic: Option<QuicReport>,
    pub path: Option<PathReport>,
    pub trace: Option<TraceReport>,
    /// 打ち切り (`--max-time` / Ctrl-C) の情報。通常完走時も常に埋める。
    pub completeness: Completeness,
    /// ステージ別所要時間 (計測できた分だけ、実行順)
    pub stage_durations: Vec<StageDuration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    /// 全変種の一覧。テストはこの配列を回して検証する。
    /// 注意: この配列自体は網羅性を検査されない (追加漏れはコンパイルでは検知できない)。
    /// 新変種の追加時にコンパイルエラーで気づかせる役目は、下の `exhaustive` の match が負う。
    const ALL_STAGES: [StageName; 8] = [
        StageName::Env,
        StageName::Dns,
        StageName::Tcp,
        StageName::Tls,
        StageName::Http,
        StageName::Quic,
        StageName::Path,
        StageName::Trace,
    ];

    /// `StageName` に変種を足すと、この match が非網羅になりコンパイルエラーになる。
    /// その時に上の `ALL_STAGES` (と `stage_name_values_are_fixed_snake_case` の期待値) も
    /// 更新する、という合図のための関数 (実行はされない)。本番の `as_str` の match も網羅的だが、
    /// 将来 `as_str` が `_ =>` などになってもこのテスト側の検知が残るよう、独立して持っている。
    #[allow(dead_code)]
    fn exhaustive(s: StageName) {
        match s {
            StageName::Env
            | StageName::Dns
            | StageName::Tcp
            | StageName::Tls
            | StageName::Http
            | StageName::Quic
            | StageName::Path
            | StageName::Trace => {}
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn dns_result(source: DnsSource) -> DnsSourceResult {
        DnsSourceResult {
            source,
            label: String::new(),
            outcome: DnsOutcome::Ok,
            ips: vec![],
            latency_ms: None,
        }
    }

    fn tcp_probe(successes: u32) -> TcpProbe {
        TcpProbe {
            ip: ip("192.0.2.1"),
            port: 443,
            samples: 3,
            successes,
            outcome: TcpOutcome::Ok,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
        }
    }

    #[test]
    fn stage_name_json_matches_as_str_for_all_variants() {
        for s in ALL_STAGES {
            assert_eq!(to_value(s).unwrap(), json!(s.as_str()), "{s:?}");
        }
    }

    #[test]
    fn stage_name_values_are_fixed_snake_case() {
        let got: Vec<&str> = ALL_STAGES.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            got,
            ["env", "dns", "tcp", "tls", "http", "quic", "path", "trace"]
        );
    }

    #[test]
    fn tcp_outcome_json_shape() {
        assert_eq!(
            to_value(TcpOutcome::Error("x".into())).unwrap(),
            json!({"code": "Error", "detail": "x"})
        );
        assert_eq!(to_value(TcpOutcome::Ok).unwrap(), json!({"code": "Ok"}));
        assert_eq!(
            to_value(TcpOutcome::Refused).unwrap(),
            json!({"code": "Refused"})
        );
        assert_eq!(
            to_value(TcpOutcome::Timeout).unwrap(),
            json!({"code": "Timeout"})
        );
    }

    #[test]
    fn dns_outcome_json_shape() {
        assert_eq!(
            to_value(DnsOutcome::Error("x".into())).unwrap(),
            json!({"code": "Error", "detail": "x"})
        );
        assert_eq!(to_value(DnsOutcome::Ok).unwrap(), json!({"code": "Ok"}));
        assert_eq!(
            to_value(DnsOutcome::NxDomain).unwrap(),
            json!({"code": "NxDomain"})
        );
        assert_eq!(
            to_value(DnsOutcome::ServFail).unwrap(),
            json!({"code": "ServFail"})
        );
        assert_eq!(
            to_value(DnsOutcome::Timeout).unwrap(),
            json!({"code": "Timeout"})
        );
    }

    #[test]
    fn dns_source_json_shape() {
        assert_eq!(
            to_value(DnsSource::System).unwrap(),
            json!({"kind": "System"})
        );
        assert_eq!(
            to_value(DnsSource::Local(ip("192.168.1.1"))).unwrap(),
            json!({"kind": "Local", "addr": "192.168.1.1"})
        );
        assert_eq!(
            to_value(DnsSource::Public(ip("1.1.1.1"))).unwrap(),
            json!({"kind": "Public", "addr": "1.1.1.1"})
        );
    }

    #[test]
    fn quic_outcome_json_shape() {
        assert_eq!(
            to_value(QuicOutcome::Ok {
                handshake_ms: 12.5,
                negotiated_alpn: Some("h3".into()),
            })
            .unwrap(),
            json!({"code": "Ok", "detail": {"handshake_ms": 12.5, "negotiated_alpn": "h3"}})
        );
        assert_eq!(
            to_value(QuicOutcome::Ok {
                handshake_ms: 1.0,
                negotiated_alpn: None,
            })
            .unwrap(),
            json!({"code": "Ok", "detail": {"handshake_ms": 1.0, "negotiated_alpn": null}})
        );
        assert_eq!(
            to_value(QuicOutcome::Timeout).unwrap(),
            json!({"code": "Timeout"})
        );
        assert_eq!(
            to_value(QuicOutcome::HandshakeError("x".into())).unwrap(),
            json!({"code": "HandshakeError", "detail": "x"})
        );
        assert_eq!(
            to_value(QuicOutcome::LocalError("x".into())).unwrap(),
            json!({"code": "LocalError", "detail": "x"})
        );
    }

    #[test]
    fn mtu_probe_outcome_json_shape() {
        assert_eq!(
            to_value(MtuProbeOutcome::Silent).unwrap(),
            json!({"code": "Silent"})
        );
        assert_eq!(
            to_value(MtuProbeOutcome::Delivered).unwrap(),
            json!({"code": "Delivered"})
        );
        assert_eq!(
            to_value(MtuProbeOutcome::LocalError).unwrap(),
            json!({"code": "LocalError"})
        );
        assert_eq!(
            to_value(MtuProbeOutcome::FragNeeded { mtu: Some(1400) }).unwrap(),
            json!({"code": "FragNeeded", "detail": {"mtu": 1400}})
        );
        assert_eq!(
            to_value(MtuProbeOutcome::FragNeeded { mtu: None }).unwrap(),
            json!({"code": "FragNeeded", "detail": {"mtu": null}})
        );
    }

    #[test]
    fn trace_report_json_shape() {
        assert_eq!(
            to_value(TraceReport::Unsupported).unwrap(),
            json!({"status": "Unsupported"})
        );
        assert_eq!(
            to_value(TraceReport::Failed("x".into())).unwrap(),
            json!({"status": "Failed", "data": "x"})
        );
        assert_eq!(
            to_value(TraceReport::Ran(TraceData::default())).unwrap(),
            json!({"status": "Ran", "data": {
                "hops": [],
                "dest_reached": false,
                "kernel_mtu": null,
                "mtu_probes": []
            }})
        );
    }

    #[test]
    fn truncation_reason_json_is_snake_case() {
        assert_eq!(
            to_value(TruncationReason::MaxTimeExceeded).unwrap(),
            json!("max_time_exceeded")
        );
        assert_eq!(
            to_value(TruncationReason::Interrupted).unwrap(),
            json!("interrupted")
        );
    }

    #[test]
    fn completeness_default_json_shape() {
        assert_eq!(
            to_value(Completeness::default()).unwrap(),
            json!({
                "complete": true,
                "truncated_reason": null,
                "ran_stages": [],
                "skipped_stages": []
            })
        );
    }

    #[test]
    fn stage_duration_json_shape() {
        assert_eq!(
            to_value(StageDuration {
                stage: StageName::Dns,
                ms: 12.5
            })
            .unwrap(),
            json!({"stage": "dns", "ms": 12.5})
        );
    }

    #[test]
    fn dns_source_result_is_local_and_is_public() {
        let sys = dns_result(DnsSource::System);
        assert!(sys.is_local());
        assert!(!sys.is_public());

        let local = dns_result(DnsSource::Local(ip("192.168.1.1")));
        assert!(local.is_local());
        assert!(!local.is_public());

        let public = dns_result(DnsSource::Public(ip("1.1.1.1")));
        assert!(!public.is_local());
        assert!(public.is_public());
    }

    #[test]
    fn dns_source_result_is_ok_follows_outcome() {
        assert!(dns_result(DnsSource::System).is_ok());
        for outcome in [
            DnsOutcome::NxDomain,
            DnsOutcome::ServFail,
            DnsOutcome::Timeout,
            DnsOutcome::Error("x".into()),
        ] {
            let mut r = dns_result(DnsSource::System);
            r.outcome = outcome;
            assert!(!r.is_ok());
        }
    }

    #[test]
    fn tcp_probe_is_ok_depends_on_successes_only() {
        assert!(!tcp_probe(0).is_ok());
        assert!(tcp_probe(1).is_ok());
        assert!(tcp_probe(3).is_ok());
        // outcome が Ok でなくても successes > 0 なら is_ok (実装の挙動を固定)
        let mut p = tcp_probe(1);
        p.outcome = TcpOutcome::Timeout;
        assert!(p.is_ok());
    }
}
