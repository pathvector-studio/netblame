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

    // ---- stats: 現在の挙動を固定するテスト ----

    #[test]
    fn stats_single_value() {
        // 1 件なら min = avg = max、標準偏差は 0
        assert_eq!(stats(&[5.0]), (Some(5.0), Some(5.0), Some(5.0), Some(0.0)));
    }

    #[test]
    fn stats_all_equal() {
        assert_eq!(
            stats(&[7.5, 7.5, 7.5, 7.5]),
            (Some(7.5), Some(7.5), Some(7.5), Some(0.0))
        );
    }

    #[test]
    fn stats_unsorted_input() {
        // 入力順に依存せず min / max を取る
        let (min, avg, max, jitter) = stats(&[14.0, 10.0, 12.0]);
        assert_eq!(min, Some(10.0));
        assert_eq!(avg, Some(12.0));
        assert_eq!(max, Some(14.0));
        // 昇順入力 (stats_basic) と同じ値になる
        assert_eq!(jitter, stats(&[10.0, 12.0, 14.0]).3);
    }

    #[test]
    fn stats_jitter_is_population_stddev() {
        // 母集団標準偏差 (n で割る)。[2,4,4,4,5,5,7,9] は平均 5・標準偏差 2
        let (_, avg, _, jitter) = stats(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert_eq!(avg, Some(5.0));
        assert_eq!(jitter, Some(2.0));
    }

    #[test]
    fn stats_two_values() {
        // [10, 20]: 平均 15、母標準偏差 5 (標本標準偏差なら約 7.07)
        assert_eq!(
            stats(&[10.0, 20.0]),
            (Some(10.0), Some(15.0), Some(20.0), Some(5.0))
        );
    }

    #[test]
    fn stats_negative_and_zero_values() {
        // 負値・0 もそのまま扱う (検証しない)
        let (min, avg, max, _) = stats(&[-2.0, 0.0, 2.0]);
        assert_eq!(min, Some(-2.0));
        assert_eq!(avg, Some(0.0));
        assert_eq!(max, Some(2.0));
    }

    #[test]
    fn stats_nan_current_behavior() {
        // NaN を含んでもパニックしない。f64::min / f64::max は NaN を無視するので
        // min / max は NaN 以外の値になるが、avg と stddev は NaN に汚染される。
        // min/max と avg が食い違うのでバグっぽいが修正しない。
        let (min, avg, max, jitter) = stats(&[10.0, f64::NAN, 20.0]);
        assert_eq!(min, Some(10.0));
        assert_eq!(max, Some(20.0));
        assert!(avg.unwrap().is_nan());
        assert!(jitter.unwrap().is_nan());
    }

    #[test]
    fn stats_only_nan_current_behavior() {
        // NaN だけの場合、min / max は fold の初期値 (INFINITY / NEG_INFINITY) のまま返る。
        // min > max になる (バグっぽいが修正しない)
        let (min, avg, max, jitter) = stats(&[f64::NAN]);
        assert_eq!(min, Some(f64::INFINITY));
        assert_eq!(max, Some(f64::NEG_INFINITY));
        assert!(avg.unwrap().is_nan());
        assert!(jitter.unwrap().is_nan());
    }

    #[test]
    fn stats_infinity_current_behavior() {
        // 無限大が混ざると avg は inf、stddev は NaN (inf - inf) になる
        let (min, avg, max, jitter) = stats(&[1.0, f64::INFINITY]);
        assert_eq!(min, Some(1.0));
        assert_eq!(max, Some(f64::INFINITY));
        assert_eq!(avg, Some(f64::INFINITY));
        assert!(jitter.unwrap().is_nan());
    }
}
