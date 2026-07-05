//! ステージ4: TLS 診断
//! rustls + webpki-roots で検証つきハンドシェイクを行い、失敗した場合は
//! 「無検証 (診断専用・読み取りのみ)」で再接続して提示された証明書を調べる。
//! 発行者名にミドルボックス製品の痕跡があれば TLS 傍受の疑いを立てる。

use crate::report::TlsReport;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// TLS 傍受装置 (ミドルボックス) によく現れる発行者名のキーワード
const MIDDLEBOX_KEYWORDS: &[&str] = &[
    "firewall",
    "zscaler",
    "fortigate",
    "fortinet",
    "bluecoat",
    "blue coat",
    "palo alto",
    "netskope",
    "sophos",
    "watchguard",
    "sonicwall",
    "barracuda",
    "untangle",
    "squid",
    "mitmproxy",
    "ssl inspection",
    "proxy",
];

/// 証明書 DER から (発行者DN, 有効期限までの日数, 期限切れか) を取り出す
fn inspect_cert(der: &[u8]) -> (Option<String>, Option<i64>, bool) {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => {
            let issuer = cert.issuer().to_string();
            let not_after = cert.validity().not_after.timestamp();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let days = (not_after - now) / 86_400;
            (Some(issuer), Some(days), not_after < now)
        }
        Err(_) => (None, None, false),
    }
}

fn looks_like_middlebox(issuer: &str) -> bool {
    let lower = issuer.to_ascii_lowercase();
    MIDDLEBOX_KEYWORDS.iter().any(|k| lower.contains(k))
}

/// 検証を一切行わない診断専用の証明書検証器。
/// この接続では GET などのデータ送信は行わず、ハンドシェイクで提示された
/// 証明書を読むだけに留める。
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        other => format!("{other:?}"),
    }
}

struct HandshakeOutcome {
    version: Option<String>,
    first_cert: Option<Vec<u8>>,
    handshake_ms: f64,
}

/// TCP 接続 + TLS ハンドシェイクを行う。verify=false なら無検証。
async fn handshake(
    host: &str,
    addr: SocketAddr,
    timeout: Duration,
    verify: bool,
) -> Result<HandshakeOutcome, String> {
    let config = if verify {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "TCP 接続タイムアウト".to_string())?
        .map_err(|e| format!("TCP 接続失敗: {e}"))?;

    let start = Instant::now();
    let stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "TLS ハンドシェイクタイムアウト".to_string())?
        .map_err(|e| e.to_string())?;
    let handshake_ms = start.elapsed().as_secs_f64() * 1000.0;

    let (_, conn) = stream.get_ref();
    let version = conn.protocol_version().map(version_name);
    let first_cert = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|c| c.as_ref().to_vec());
    // ここでデータは一切送らない (読み取り専用の診断)

    Ok(HandshakeOutcome {
        version,
        first_cert,
        handshake_ms,
    })
}

/// TLS ステージを実行する
pub async fn run(host: &str, ip: IpAddr, port: u16, timeout: Duration) -> TlsReport {
    let addr = SocketAddr::new(ip, port);
    let mut report = TlsReport::default();

    match handshake(host, addr, timeout, true).await {
        Ok(out) => {
            report.verified = true;
            report.hostname_matches = Some(true);
            report.version = out.version;
            report.handshake_ms = Some(out.handshake_ms);
            if let Some(der) = out.first_cert {
                let (issuer, days, expired) = inspect_cert(&der);
                report.presented_issuer = issuer;
                report.days_until_expiry = days;
                report.cert_expired = expired;
            }
        }
        Err(err) => {
            report.verified = false;
            report.error = Some(err.clone());
            let lower = err.to_ascii_lowercase();
            if lower.contains("expired") {
                report.cert_expired = true;
            }
            if lower.contains("notvalidforname") || lower.contains("not valid for name") {
                report.hostname_matches = Some(false);
            }

            // 提示された証明書を調べるため、無検証 (診断専用) で再接続する
            if let Ok(out) = handshake(host, addr, timeout, false).await {
                report.version = out.version;
                report.handshake_ms = Some(out.handshake_ms);
                if let Some(der) = out.first_cert {
                    let (issuer, days, expired) = inspect_cert(&der);
                    if let Some(issuer) = &issuer {
                        report.interception_suspected = looks_like_middlebox(issuer);
                    }
                    report.presented_issuer = issuer;
                    report.days_until_expiry = days;
                    if expired {
                        report.cert_expired = true;
                    }
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn middlebox_detection() {
        assert!(looks_like_middlebox("CN=Zscaler Intermediate Root CA"));
        assert!(looks_like_middlebox("CN=FortiGate CA, O=Fortinet"));
        assert!(!looks_like_middlebox("CN=DigiCert TLS RSA SHA256 2020 CA1"));
        assert!(!looks_like_middlebox("CN=R11, O=Let's Encrypt"));
    }
}
