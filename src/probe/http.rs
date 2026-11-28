//! ステージ5: HTTP 診断
//! reqwest (rustls バックエンド) で GET を発行し、ステータス・リダイレクト
//! チェーン (最大5ホップ)・TTFB・合計時間を計測する。
//! DNS / TCP / TLS の内訳時間は各ステージの実測値を main 側で埋める。
//! 最終応答の alt-svc ヘッダも記録し、HTTP/3 (h3) が広告されているか調べる
//! (v0.4: QUIC プローブ判定の材料になる)。

use crate::i18n::{self, Lang};
use crate::report::HttpReport;
use std::time::{Duration, Instant};

const MAX_REDIRECTS: usize = 5;

/// alt-svc ヘッダの値に h3 (h3, h3-29 等の draft 版含む) が含まれるか判定する。
/// 例: `h3=":443"; ma=86400, h3-29=":443"; ma=86400`
pub fn parses_h3(alt_svc: &str) -> bool {
    alt_svc
        .split(',')
        .map(str::trim)
        .any(|entry| entry.starts_with("h3=") || entry.starts_with("h3-"))
}

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
        if let Some(alt_svc) = resp
            .headers()
            .get(reqwest::header::ALT_SVC)
            .and_then(|v| v.to_str().ok())
        {
            report.h3_advertised = parses_h3(alt_svc);
            report.alt_svc = Some(alt_svc.to_string());
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_h3_from_alt_svc() {
        assert!(parses_h3(r#"h3=":443"; ma=86400"#));
        assert!(parses_h3(r#"h3-29=":443"; ma=86400"#));
        assert!(parses_h3(r#"h2=":443"; ma=2592000, h3=":443"; ma=2592000"#));
    }

    #[test]
    fn no_h3_in_alt_svc() {
        assert!(!parses_h3(r#"h2=":443"; ma=2592000"#));
        assert!(!parses_h3(""));
    }

    // ---- parses_h3: 現在の挙動を固定するテスト ----

    #[test]
    fn parses_h3_draft_versions() {
        // `h3-` で始まるエントリはすべて h3 扱い (h3-29 / h3-27 など)
        assert!(parses_h3(r#"h3-27=":443""#));
        assert!(parses_h3(r#"h3-Q050=":443"; ma=86400"#));
        // 実装は `h3-` の後ろを検証しない (現在の挙動)
        assert!(parses_h3(r#"h3-=":443""#));
        assert!(parses_h3(r#"h3-foo=":443""#));
    }

    #[test]
    fn parses_h3_clear_is_false() {
        // `clear` は広告の取り消しなので h3 ではない
        assert!(!parses_h3("clear"));
    }

    #[test]
    fn parses_h3_multiple_entries() {
        // h3 が先頭・末尾・途中のいずれでも検出する
        assert!(parses_h3(r#"h3=":443", h2=":443""#));
        assert!(parses_h3(r#"h2=":443", h3=":443""#));
        assert!(parses_h3(r#"h2=":443", h3=":443", h3-29=":443""#));
        // h2 / quic だけなら false
        assert!(!parses_h3(r#"h2=":443", h2=":8443""#));
        assert!(!parses_h3(r#"quic=":443"; v="46,43", h2=":443""#));
    }

    #[test]
    fn parses_h3_whitespace() {
        // エントリ前後の空白 (タブ含む) は trim される
        assert!(parses_h3(r#"   h3=":443""#));
        assert!(parses_h3("\th3=\":443\"\t"));
        assert!(parses_h3(r#"h2=":443" ,   h3=":443""#));
        // カンマ直後の空白なしでも検出する
        assert!(parses_h3(r#"h2=":443",h3=":443""#));
        // `=` の前に空白があると検出しない (RFC 7230 のトークン文法上も不正)
        assert!(!parses_h3(r#"h3 =":443""#));
        // 空白だけ・カンマだけ
        assert!(!parses_h3("   "));
        assert!(!parses_h3(","));
        assert!(!parses_h3(" , , "));
    }

    #[test]
    fn parses_h3_is_case_sensitive() {
        // ALPN プロトコル ID は大文字小文字を区別するので `H3` は認識しない
        assert!(!parses_h3(r#"H3=":443""#));
        assert!(!parses_h3(r#"H3-29=":443""#));
        assert!(!parses_h3(r#"h2=":443", H3=":443""#));
    }

    #[test]
    fn parses_h3_substring_is_not_match() {
        // エントリ先頭が `h3=` / `h3-` でなければ部分文字列では一致しない
        assert!(!parses_h3(r#"xh3=":443""#));
        assert!(!parses_h3(r#"h2=":443"; ma=h3"#));
        assert!(!parses_h3(r#"h2=":443"; persist=1; h3=":443""#));
        assert!(!parses_h3("h3"));
        assert!(!parses_h3("h30=\":443\""));
        assert!(!parses_h3(r#"h2="h3.example.com:443""#));
    }

    #[test]
    fn parses_h3_authority_not_validated() {
        // authority が空でも `h3=` で始まれば true (ポートやホストは見ない)
        assert!(parses_h3("h3="));
        assert!(parses_h3(r#"h3="""#));
        assert!(parses_h3(r#"h3="other.example.com:8443""#));
    }

    #[test]
    fn parses_h3_comma_inside_quoted_string_current_behavior() {
        // RFC 7838 では引用文字列内のカンマはエントリ区切りではないが、
        // 実装は単純に `,` で分割するため、引用内の `h3=` を拾って true になる (バグっぽいが修正しない)
        assert!(parses_h3(r#"h2="a, h3=b""#));
        // 引用内でも `quic` の v="46,43" のような値は無害 (`43"` は h3 で始まらない)
        assert!(!parses_h3(r#"quic=":443"; v="46,43""#));
    }
}
