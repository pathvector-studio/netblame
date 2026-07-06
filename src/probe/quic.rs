//! QUIC/HTTP3 プローブ (v0.4)
//! `https` ターゲット (TLS on 443 or 明示的な https URL) に対してのみ、
//! HTTP ステージの後で実行する。ALPN "h3" で実際に QUIC ハンドシェイクを
//! 試み、以下を区別する:
//!   - Ok: ハンドシェイク成功 (ネゴシエートされた ALPN も記録)
//!   - Timeout: 何も返ってこない (UDP 443 がブロックされている典型パターン)
//!   - HandshakeError: サーバは応答したがネゴシエーションに失敗
//!     (ネットワーク遮断ではない)
//!   - LocalError: ソケット確保などローカル側のエラー
//!
//! rustls (ring プロバイダ) + webpki-roots で検証つきハンドシェイクを行う
//! (tls.rs と同じ検証方針)。データ送信は一切行わない (診断専用)。

use crate::report::{QuicOutcome, QuicReport};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use quinn::rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// QUIC/HTTP3 ステージを実行する
pub async fn run(host: &str, ip: IpAddr, port: u16, timeout: Duration) -> QuicReport {
    let outcome = probe(host, ip, port, timeout).await;
    QuicReport { outcome }
}

async fn probe(host: &str, ip: IpAddr, port: u16, timeout: Duration) -> QuicOutcome {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut rustls_config = RustlsClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = match QuicClientConfig::try_from(rustls_config) {
        Ok(c) => c,
        Err(e) => return QuicOutcome::LocalError(e.to_string()),
    };

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    // ハンドシェイクが返ってこないケースは呼び出し側の timeout で判定するため、
    // トランスポート層の idle timeout は少し長めに保つ (早期の内部タイムアウトで
    // Timeout と HandshakeError の分類がブレないようにする)。
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(None);
    client_config.transport_config(Arc::new(transport));

    let bind_addr: SocketAddr = if ip.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };

    let endpoint = match Endpoint::client(bind_addr) {
        Ok(e) => e,
        Err(e) => return QuicOutcome::LocalError(e.to_string()),
    };

    let addr = SocketAddr::new(ip, port);
    let connecting = match endpoint.connect_with(client_config, addr, host) {
        Ok(c) => c,
        Err(e) => return QuicOutcome::LocalError(e.to_string()),
    };

    let start = Instant::now();
    match tokio::time::timeout(timeout, connecting).await {
        Err(_) => QuicOutcome::Timeout,
        Ok(Err(e)) => QuicOutcome::HandshakeError(e.to_string()),
        Ok(Ok(conn)) => {
            let handshake_ms = start.elapsed().as_secs_f64() * 1000.0;
            let negotiated_alpn = conn
                .handshake_data()
                .and_then(|data| data.downcast::<HandshakeData>().ok())
                .and_then(|data| data.protocol)
                .map(|p: Vec<u8>| String::from_utf8_lossy(&p).to_string());
            // 診断専用: データは送らずクローズする
            conn.close(0u32.into(), b"netblame diagnostic probe");
            endpoint.wait_idle().await;
            QuicOutcome::Ok {
                handshake_ms,
                negotiated_alpn,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_variants_are_distinguishable() {
        assert_eq!(QuicOutcome::Timeout, QuicOutcome::Timeout);
        assert_ne!(
            QuicOutcome::Timeout,
            QuicOutcome::HandshakeError("x".into())
        );
        assert_ne!(
            QuicOutcome::Ok {
                handshake_ms: 10.0,
                negotiated_alpn: Some("h3".into())
            },
            QuicOutcome::Timeout
        );
    }
}
