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

/// 全ステージの結果を束ねた診断レポート
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: TargetInfo,
    pub env: EnvReport,
    pub dns: DnsReport,
    pub tcp: TcpReport,
    pub tls: Option<TlsReport>,
    pub http: Option<HttpReport>,
    pub path: Option<PathReport>,
}
