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
}
