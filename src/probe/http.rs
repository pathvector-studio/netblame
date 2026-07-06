//! ステージ5: HTTP 診断
//! reqwest (rustls バックエンド) で GET を発行し、ステータス・リダイレクト
//! チェーン (最大5ホップ)・TTFB・合計時間を計測する。
//! DNS / TCP / TLS の内訳時間は各ステージの実測値を main 側で埋める。

use crate::i18n::{self, Lang};
use crate::report::HttpReport;
use std::time::{Duration, Instant};

const MAX_REDIRECTS: usize = 5;

/// HTTP ステージを実行する
pub async fn run(url: &str, timeout: Duration, lang: Lang) -> HttpReport {
    let mut report = HttpReport::default();

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout * 2)
        .user_agent(concat!("netblame/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            report.error = Some(i18n::probe_http_client_init_failed(lang, &e.to_string()));
            return report;
        }
    };

    let total_start = Instant::now();
    let mut current = url.to_string();

    for hop in 0..=MAX_REDIRECTS {
        let hop_start = Instant::now();
        let resp = match client.get(&current).send().await {
            Ok(r) => r,
            Err(e) => {
                report.error = Some(e.to_string());
                report.total_ms = Some(total_start.elapsed().as_secs_f64() * 1000.0);
                return report;
            }
        };
        // send() はレスポンスヘッダ受信までブロックする ≒ このホップの TTFB
        let ttfb = hop_start.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status();

        if status.is_redirection() {
            if hop == MAX_REDIRECTS {
                report.status = Some(status.as_u16());
                report.error = Some(i18n::probe_too_many_redirects(lang, MAX_REDIRECTS));
                report.total_ms = Some(total_start.elapsed().as_secs_f64() * 1000.0);
                return report;
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            match location {
                Some(loc) => {
                    // 相対 URL の解決
                    let next = match reqwest::Url::parse(&current)
                        .ok()
                        .and_then(|base| base.join(&loc).ok())
                    {
                        Some(u) => u.to_string(),
                        None => loc.clone(),
                    };
                    report
                        .redirect_chain
                        .push(format!("{} -> {}", status.as_u16(), next));
                    current = next;
                    continue;
                }
                None => {
                    report.status = Some(status.as_u16());
                    report.error = Some(i18n::probe_no_location_header(lang));
                    report.total_ms = Some(total_start.elapsed().as_secs_f64() * 1000.0);
                    return report;
                }
            }
        }

        // 最終ホップ: ボディを読み切って合計時間を出す
        report.status = Some(status.as_u16());
        report.ttfb_ms = Some(ttfb);
        match resp.bytes().await {
            Ok(_) => {}
            Err(e) => {
                report.error = Some(i18n::probe_body_read_failed(lang, &e.to_string()));
            }
        }
        report.total_ms = Some(total_start.elapsed().as_secs_f64() * 1000.0);
        return report;
    }

    report
}
