//! ステージ3: TCP 接続診断
//! 解決済み IP (最大3つ、v4/v6 両方を含むよう選択) へ N 回接続し、
//! 成功率とハンドシェイク時間を計測する。

use crate::report::{TcpOutcome, TcpProbe, TcpReport};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// 候補 IP から最大3つ選ぶ。IPv4/IPv6 が両方あれば両方含める。
pub fn pick_targets(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut seen = Vec::new();
    for ip in ips {
        if !seen.contains(ip) {
            seen.push(*ip);
        }
    }
    let v4: Vec<_> = seen.iter().copied().filter(IpAddr::is_ipv4).collect();
    let v6: Vec<_> = seen.iter().copied().filter(IpAddr::is_ipv6).collect();

    let mut out = Vec::new();
    // v4 と v6 を交互に詰めて、両ファミリを必ずカバーする
    let mut i4 = v4.into_iter();
    let mut i6 = v6.into_iter();
    while out.len() < 3 {
        match (i4.next(), i6.next()) {
            (None, None) => break,
            (a, b) => {
                if let Some(ip) = a {
                    out.push(ip);
                }
                if out.len() < 3 {
                    if let Some(ip) = b {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

/// 単一 IP:port への 1 回の接続試行
async fn connect_once(addr: SocketAddr, timeout: Duration) -> Result<f64, TcpOutcome> {
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Err(_) => Err(TcpOutcome::Timeout),
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                Err(TcpOutcome::Refused)
            } else {
                Err(TcpOutcome::Error(e.to_string()))
            }
        }
        Ok(Ok(_stream)) => Ok(start.elapsed().as_secs_f64() * 1000.0),
    }
}

/// 1つの IP に対して samples 回接続を試す
pub async fn probe_ip(ip: IpAddr, port: u16, samples: u32, timeout: Duration) -> TcpProbe {
    let addr = SocketAddr::new(ip, port);
    let mut times = Vec::new();
    let mut failures: Vec<TcpOutcome> = Vec::new();

    for i in 0..samples {
        match connect_once(addr, timeout).await {
            Ok(ms) => times.push(ms),
            Err(outcome) => failures.push(outcome),
        }
        if i + 1 < samples {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let successes = times.len() as u32;
    let outcome = if successes > 0 {
        TcpOutcome::Ok
    } else {
        // 失敗の最頻値 (refused 優先で分類が明確なものを選ぶ)
        if failures.contains(&TcpOutcome::Refused) {
            TcpOutcome::Refused
        } else if failures.contains(&TcpOutcome::Timeout) {
            TcpOutcome::Timeout
        } else {
            failures
                .into_iter()
                .next()
                .unwrap_or(TcpOutcome::Error("試行なし".into()))
        }
    };

    let (min_ms, avg_ms, max_ms) = if times.is_empty() {
        (None, None, None)
    } else {
        let min = times.iter().copied().fold(f64::INFINITY, f64::min);
        let max = times.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let avg = times.iter().sum::<f64>() / times.len() as f64;
        (Some(min), Some(avg), Some(max))
    };

    TcpProbe {
        ip,
        port,
        samples,
        successes,
        outcome,
        min_ms,
        avg_ms,
        max_ms,
    }
}

/// TCP ステージを実行する
pub async fn run(ips: &[IpAddr], port: u16, samples: u32, timeout: Duration) -> TcpReport {
    let targets = pick_targets(ips);
    let mut probes = Vec::new();
    for ip in targets {
        probes.push(probe_ip(ip, port, samples, timeout).await);
    }
    TcpReport { probes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_targets_mixes_families() {
        let ips: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "1.2.3.5".parse().unwrap(),
            "1.2.3.6".parse().unwrap(),
            "2606:2800::1".parse().unwrap(),
        ];
        let picked = pick_targets(&ips);
        assert_eq!(picked.len(), 3);
        assert!(picked.iter().any(|ip| ip.is_ipv6()));
        assert!(picked.iter().any(|ip| ip.is_ipv4()));
    }
}
