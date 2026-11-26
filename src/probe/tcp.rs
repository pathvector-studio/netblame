//! ステージ3: TCP 接続診断
//! 解決済み IP (最大3つ、v4/v6 両方を含むよう選択) へ N 回接続し、
//! 成功率とハンドシェイク時間を計測する。

use crate::i18n::{self, Lang};
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

/// IP 内の outcome 集約規則。
///
/// - 成功が1回でもあれば `Ok` (失敗が混ざっていても `Ok`)
/// - 全失敗なら、`Refused` が1つでもあれば `Refused`、なければ `Timeout` が
///   1つでもあれば `Timeout` (この判定は失敗の並び順に依らない)
/// - どちらもなければ(`Error(..)` のみ)試行順で最初の失敗を返す (こちらは順序に依存する)
/// - 失敗も0件 (samples=0) なら `Error(probe_no_attempts)`
fn aggregate_outcome(successes: u32, failures: Vec<TcpOutcome>, lang: Lang) -> TcpOutcome {
    if successes > 0 {
        TcpOutcome::Ok
    } else {
        // 全失敗: 件数ではなく優先順位で選ぶ (Refused > Timeout > 最初の Error)
        if failures.contains(&TcpOutcome::Refused) {
            TcpOutcome::Refused
        } else if failures.contains(&TcpOutcome::Timeout) {
            TcpOutcome::Timeout
        } else {
            failures
                .into_iter()
                .next()
                .unwrap_or(TcpOutcome::Error(i18n::probe_no_attempts(lang)))
        }
    }
}

/// 1つの IP に対して samples 回接続を試す
pub async fn probe_ip(
    ip: IpAddr,
    port: u16,
    samples: u32,
    timeout: Duration,
    lang: Lang,
) -> TcpProbe {
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
    let outcome = aggregate_outcome(successes, failures, lang);

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
pub async fn run(
    ips: &[IpAddr],
    port: u16,
    samples: u32,
    timeout: Duration,
    lang: Lang,
) -> TcpReport {
    let targets = pick_targets(ips);
    let mut probes = Vec::new();
    for ip in targets {
        probes.push(probe_ip(ip, port, samples, timeout, lang).await);
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pick_targets_dedups_keeping_first_seen_order() {
        // 同じファミリ内の重複は1回だけに畳まれ、順序は初出順（v4 同士、v6 同士の相対順）。
        // 重複除去がないと v4 の2件目が 1.2.3.5 の重複になり、3件目が 1.2.3.4 にならない。
        let ips = vec![
            ip("1.2.3.5"),
            ip("1.2.3.5"),
            ip("1.2.3.4"),
            ip("2606:2800::1"),
            ip("2606:2800::1"),
            ip("2606:2800::2"),
        ];
        assert_eq!(
            pick_targets(&ips),
            vec![ip("1.2.3.5"), ip("2606:2800::1"), ip("1.2.3.4")]
        );
    }

    #[test]
    fn pick_targets_dedups_same_ip_repeated() {
        let ips = vec![ip("1.2.3.4"), ip("1.2.3.4"), ip("1.2.3.4")];
        assert_eq!(pick_targets(&ips), vec![ip("1.2.3.4")]);
    }

    #[test]
    fn pick_targets_dedups_v6_only_input() {
        // v4 を含まない入力でも v6 の重複は畳まれる（出力に効く形で固定）。
        // 重複除去がないと [::1, ::1, ::2] のまま3件返ってしまう。
        let ips = vec![ip("2001:db8::1"), ip("2001:db8::1"), ip("2001:db8::2")];
        assert_eq!(
            pick_targets(&ips),
            vec![ip("2001:db8::1"), ip("2001:db8::2")]
        );
    }

    #[test]
    fn pick_targets_interleaves_v4_then_v6() {
        // v4 a,b,c と v6 x,y,z → [a, x, b]（3件で打ち切り）
        let ips = vec![
            ip("1.2.3.4"),
            ip("1.2.3.5"),
            ip("1.2.3.6"),
            ip("2606:2800::1"),
            ip("2606:2800::2"),
            ip("2606:2800::3"),
        ];
        assert_eq!(
            pick_targets(&ips),
            vec![ip("1.2.3.4"), ip("2606:2800::1"), ip("1.2.3.5")]
        );
    }

    #[test]
    fn pick_targets_v6_first_in_input_still_starts_with_v4() {
        // 入力で v6 が先でも出力は v4 が先頭、v6 は1本含まれる
        let ips = vec![
            ip("2606:2800::1"),
            ip("2606:2800::2"),
            ip("2606:2800::3"),
            ip("1.2.3.4"),
            ip("1.2.3.5"),
            ip("1.2.3.6"),
        ];
        assert_eq!(
            pick_targets(&ips),
            vec![ip("1.2.3.4"), ip("2606:2800::1"), ip("1.2.3.5")]
        );
    }

    #[test]
    fn pick_targets_single_v4_fills_with_v6() {
        // v4 が1件だけなら残りは v6 で埋まる
        let ips = vec![
            ip("2606:2800::1"),
            ip("2606:2800::2"),
            ip("2606:2800::3"),
            ip("1.2.3.4"),
        ];
        assert_eq!(
            pick_targets(&ips),
            vec![ip("1.2.3.4"), ip("2606:2800::1"), ip("2606:2800::2")]
        );
    }

    #[test]
    fn pick_targets_v4_only_takes_first_three() {
        let ips: Vec<IpAddr> = (1..=5).map(|n| ip(&format!("1.2.3.{n}"))).collect();
        assert_eq!(
            pick_targets(&ips),
            vec![ip("1.2.3.1"), ip("1.2.3.2"), ip("1.2.3.3")]
        );
    }

    #[test]
    fn pick_targets_v6_only_takes_first_three() {
        let ips: Vec<IpAddr> = (1..=5).map(|n| ip(&format!("2606:2800::{n}"))).collect();
        assert_eq!(
            pick_targets(&ips),
            vec![ip("2606:2800::1"), ip("2606:2800::2"), ip("2606:2800::3")]
        );
    }

    #[test]
    fn pick_targets_never_exceeds_three() {
        // v4/v6 の件数を変えても常に3件以下
        for n4 in 0..=6u32 {
            for n6 in 0..=6u32 {
                let mut ips: Vec<IpAddr> = (1..=n4).map(|n| ip(&format!("1.2.3.{n}"))).collect();
                ips.extend((1..=n6).map(|n| ip(&format!("2606:2800::{n}"))));
                let picked = pick_targets(&ips);
                assert!(picked.len() <= 3, "n4={n4} n6={n6}: {picked:?}");
                assert_eq!(picked.len(), (n4 + n6).min(3) as usize);
            }
        }
    }

    #[test]
    fn pick_targets_two_or_fewer_returns_all() {
        let ips = vec![ip("1.2.3.4"), ip("2606:2800::1")];
        assert_eq!(pick_targets(&ips), vec![ip("1.2.3.4"), ip("2606:2800::1")]);
        // v6 が先に入力されても v4 → v6 の順で返る
        let ips = vec![ip("2606:2800::1"), ip("1.2.3.4")];
        assert_eq!(pick_targets(&ips), vec![ip("1.2.3.4"), ip("2606:2800::1")]);
        assert_eq!(pick_targets(&[ip("1.2.3.4")]), vec![ip("1.2.3.4")]);
    }

    #[test]
    fn pick_targets_empty_returns_empty() {
        assert!(pick_targets(&[]).is_empty());
    }

    fn err(s: &str) -> TcpOutcome {
        TcpOutcome::Error(s.to_string())
    }

    #[test]
    fn aggregate_outcome_any_success_is_ok_even_with_mixed_failures() {
        let failures = vec![TcpOutcome::Refused, TcpOutcome::Timeout, err("x")];
        assert_eq!(aggregate_outcome(1, failures, Lang::En), TcpOutcome::Ok);
    }

    #[test]
    fn aggregate_outcome_all_refused_is_refused() {
        let failures = vec![TcpOutcome::Refused, TcpOutcome::Refused];
        assert_eq!(
            aggregate_outcome(0, failures, Lang::En),
            TcpOutcome::Refused
        );
    }

    #[test]
    fn aggregate_outcome_timeout_then_refused_is_refused() {
        let failures = vec![TcpOutcome::Timeout, TcpOutcome::Refused];
        assert_eq!(
            aggregate_outcome(0, failures, Lang::En),
            TcpOutcome::Refused
        );
    }

    #[test]
    fn aggregate_outcome_error_then_refused_is_refused() {
        let failures = vec![err("a"), TcpOutcome::Refused];
        assert_eq!(
            aggregate_outcome(0, failures, Lang::En),
            TcpOutcome::Refused
        );
    }

    #[test]
    fn aggregate_outcome_error_then_timeout_is_timeout() {
        let failures = vec![err("a"), TcpOutcome::Timeout];
        assert_eq!(
            aggregate_outcome(0, failures, Lang::En),
            TcpOutcome::Timeout
        );
    }

    #[test]
    fn aggregate_outcome_all_timeout_is_timeout() {
        let failures = vec![TcpOutcome::Timeout, TcpOutcome::Timeout];
        assert_eq!(
            aggregate_outcome(0, failures, Lang::En),
            TcpOutcome::Timeout
        );
    }

    #[test]
    fn aggregate_outcome_errors_only_returns_first_error() {
        let failures = vec![err("a"), err("b")];
        assert_eq!(aggregate_outcome(0, failures, Lang::En), err("a"));
    }

    #[test]
    fn aggregate_outcome_no_attempts_is_no_attempts_error() {
        assert_eq!(
            aggregate_outcome(0, vec![], Lang::En),
            TcpOutcome::Error(i18n::probe_no_attempts(Lang::En))
        );
    }
}
