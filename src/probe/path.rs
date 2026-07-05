//! ステージ6: 経路品質
//! 主要 IP へ TCP connect ping を samples 回打ち、ロス率・平均 RTT・
//! ジッタ (標準偏差) を計測する。

use crate::report::PathReport;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// 経路品質ステージを実行する
pub async fn run(ip: IpAddr, port: u16, samples: u32, timeout: Duration) -> PathReport {
    let addr = SocketAddr::new(ip, port);
    let mut rtts: Vec<f64> = Vec::new();
    let mut lost = 0u32;

    for i in 0..samples {
        let start = Instant::now();
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => rtts.push(start.elapsed().as_secs_f64() * 1000.0),
            _ => lost += 1,
        }
        if i + 1 < samples {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let (min_ms, avg_ms, max_ms, jitter_ms) = stats(&rtts);

    PathReport {
        ip,
        port,
        sent: samples,
        lost,
        loss_pct: if samples > 0 {
            lost as f64 * 100.0 / samples as f64
        } else {
            0.0
        },
        min_ms,
        avg_ms,
        max_ms,
        jitter_ms,
    }
}

/// (min, avg, max, stddev)
fn stats(values: &[f64]) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    if values.is_empty() {
        return (None, None, None, None);
    }
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|v| (v - avg).powi(2)).sum::<f64>() / values.len() as f64;
    (Some(min), Some(avg), Some(max), Some(var.sqrt()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_basic() {
        let (min, avg, max, jitter) = stats(&[10.0, 12.0, 14.0]);
        assert_eq!(min, Some(10.0));
        assert_eq!(avg, Some(12.0));
        assert_eq!(max, Some(14.0));
        assert!(jitter.unwrap() > 1.0 && jitter.unwrap() < 2.0);
    }

    #[test]
    fn stats_empty() {
        assert_eq!(stats(&[]), (None, None, None, None));
    }
}
