//! ステージ1: 環境チェック
//! /etc/resolv.conf, /etc/hosts, プロキシ環境変数を調べる。

use crate::report::EnvReport;
use std::net::IpAddr;

/// resolv.conf の内容をパースする (テスト可能なように文字列を受け取る)
pub fn parse_resolv_conf(content: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut nameservers = Vec::new();
    let mut search = Vec::new();
    for line in content.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("nameserver") => {
                if let Some(addr) = parts.next() {
                    // %interface 付き IPv6 (fe80::1%eth0) はスコープを落として解釈
                    let addr = addr.split('%').next().unwrap_or(addr);
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        nameservers.push(ip);
                    }
                }
            }
            Some("search") | Some("domain") => {
                search.extend(parts.map(str::to_string));
            }
            _ => {}
        }
    }
    (nameservers, search)
}

/// /etc/hosts からターゲットホストを上書きするエントリを探す
pub fn find_hosts_override(content: &str, host: &str) -> Option<String> {
    let host_lower = host.to_ascii_lowercase();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let ip = parts.next()?.to_string();
        // parts の先頭が消費済みなのでこのまま名前部分を走査
        for name in parts {
            if name.to_ascii_lowercase() == host_lower {
                return Some(ip);
            }
        }
    }
    None
}

/// プロキシ環境変数を検出する
pub fn detect_proxies() -> (Vec<(String, String)>, Option<String>) {
    let mut proxies = Vec::new();
    for key in [
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                proxies.push((key.to_string(), v));
            }
        }
    }
    let no_proxy = ["no_proxy", "NO_PROXY"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    (proxies, no_proxy)
}

/// 環境ステージを実行する
pub fn run(host: &str) -> EnvReport {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let (nameservers, search_domains) = parse_resolv_conf(&resolv);

    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let hosts_override = find_hosts_override(&hosts, host);

    let (proxies, no_proxy) = detect_proxies();

    EnvReport {
        nameservers,
        search_domains,
        hosts_override,
        proxies,
        no_proxy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolv_conf() {
        let content = "# comment\nnameserver 192.168.1.1\nnameserver 8.8.8.8 # inline\nsearch example.local corp.local\noptions ndots:1\n";
        let (ns, search) = parse_resolv_conf(content);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].to_string(), "192.168.1.1");
        assert_eq!(search, vec!["example.local", "corp.local"]);
    }

    #[test]
    fn finds_hosts_override() {
        let content = "127.0.0.1 localhost\n10.0.0.5 example.com www.example.com # note\n";
        assert_eq!(
            find_hosts_override(content, "example.com"),
            Some("10.0.0.5".to_string())
        );
        assert_eq!(find_hosts_override(content, "other.com"), None);
    }

    // ---- parse_resolv_conf: 現在の挙動を固定するテスト ----

    #[test]
    fn resolv_conf_empty_input() {
        let (ns, search) = parse_resolv_conf("");
        assert!(ns.is_empty());
        assert!(search.is_empty());
        let (ns, search) = parse_resolv_conf("\n\n  \n\t\n");
        assert!(ns.is_empty());
        assert!(search.is_empty());
    }

    #[test]
    fn resolv_conf_comment_lines_hash_and_semicolon() {
        // `#` 始まりも `;` 始まりもコメントとして無視する
        let content = "# nameserver 1.1.1.1\n; nameserver 2.2.2.2\nnameserver 9.9.9.9\n  # search indented.example\n";
        let (ns, search) = parse_resolv_conf(content);
        assert_eq!(ns, vec!["9.9.9.9".parse::<IpAddr>().unwrap()]);
        assert!(search.is_empty());
    }

    #[test]
    fn resolv_conf_inline_comments() {
        // 行末の `#` / `;` 以降は捨てる。空白が前に無くても (`8.8.8.8#x`) 切る
        let content = "nameserver 8.8.8.8 # a\nnameserver 1.1.1.1 ; b\nnameserver 9.9.9.9#c\nsearch a.example ; b.example\ndomain c.example#d.example\n";
        let (ns, search) = parse_resolv_conf(content);
        let expected: Vec<IpAddr> = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ns, expected);
        assert_eq!(search, vec!["a.example", "c.example"]);
    }

    #[test]
    fn resolv_conf_ipv6_nameserver() {
        let (ns, _) = parse_resolv_conf("nameserver 2001:4860:4860::8888\nnameserver ::1\n");
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].to_string(), "2001:4860:4860::8888");
        assert_eq!(ns[1].to_string(), "::1");
        assert!(ns.iter().all(|ip| ip.is_ipv6()));
    }

    #[test]
    fn resolv_conf_ipv6_zone_id_is_stripped() {
        // `%eth0` は落として IP だけ取り出す (zone 情報は保持しない)
        let (ns, _) = parse_resolv_conf("nameserver fe80::1%eth0\nnameserver fe80::2%12\n");
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].to_string(), "fe80::1");
        assert_eq!(ns[1].to_string(), "fe80::2");
    }

    #[test]
    fn resolv_conf_zone_id_edge_cases() {
        // `%` の前が空 (`%eth0`) なら不正な IP として捨てる
        let (ns, _) = parse_resolv_conf("nameserver %eth0\nnameserver 8.8.8.8%eth0\n");
        // IPv4 に zone が付いていても `%` 以降を落とすので受理される (現在の挙動)
        assert_eq!(ns, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn resolv_conf_invalid_ip_is_skipped() {
        let content = "nameserver not-an-ip\nnameserver 999.1.1.1\nnameserver 1.2.3\nnameserver example.com\nnameserver\nnameserver 8.8.4.4\n";
        let (ns, _) = parse_resolv_conf(content);
        assert_eq!(ns, vec!["8.8.4.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn resolv_conf_nameserver_extra_tokens_ignored() {
        // 2 つ目以降のトークンは無視 (1 行 1 サーバー)
        let (ns, _) = parse_resolv_conf("nameserver 1.1.1.1 8.8.8.8\n");
        assert_eq!(ns, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn resolv_conf_keywords_are_case_sensitive() {
        // 大文字のキーワードは認識しない (実装は完全一致)
        let (ns, search) =
            parse_resolv_conf("NAMESERVER 1.1.1.1\nSearch a.example\nDomain b.example\n");
        assert!(ns.is_empty());
        assert!(search.is_empty());
    }

    #[test]
    fn resolv_conf_unknown_directives_ignored() {
        let content = "options ndots:2 timeout:1\nsortlist 10.0.0.0/8\nnameserverX 1.1.1.1\n";
        let (ns, search) = parse_resolv_conf(content);
        assert!(ns.is_empty());
        assert!(search.is_empty());
    }

    #[test]
    fn resolv_conf_multiple_search_lines_are_accumulated() {
        // 実 resolv.conf (glibc) は最後の search/domain だけが有効だが、
        // 実装は全行のドメインを出現順にすべて連結する (現在の挙動)
        let content = "search a.example b.example\nsearch c.example\n";
        let (_, search) = parse_resolv_conf(content);
        assert_eq!(search, vec!["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn resolv_conf_duplicate_search_domains_are_not_deduplicated() {
        let content = "search a.example a.example\nsearch a.example\n";
        let (_, search) = parse_resolv_conf(content);
        assert_eq!(search, vec!["a.example", "a.example", "a.example"]);
    }

    #[test]
    fn resolv_conf_search_and_domain_both_present() {
        // search と domain は区別せず、出現順に同じ Vec へ積む
        // (実 resolv.conf では後に書かれた方が優先され、もう一方は上書きされる)
        let content = "domain d.example\nsearch s1.example s2.example\n";
        let (_, search) = parse_resolv_conf(content);
        assert_eq!(search, vec!["d.example", "s1.example", "s2.example"]);
        let content = "search s1.example\ndomain d.example\n";
        let (_, search) = parse_resolv_conf(content);
        assert_eq!(search, vec!["s1.example", "d.example"]);
    }

    #[test]
    fn resolv_conf_search_without_domains_is_empty() {
        let (_, search) = parse_resolv_conf("search\ndomain   \n");
        assert!(search.is_empty());
    }

    #[test]
    fn resolv_conf_extra_whitespace_and_tabs() {
        let content = "  nameserver \t 192.168.0.1  \n\tnameserver\t10.0.0.1\t\nsearch \t a.example\t\t b.example  \n";
        let (ns, search) = parse_resolv_conf(content);
        let expected: Vec<IpAddr> = ["192.168.0.1", "10.0.0.1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ns, expected);
        assert_eq!(search, vec!["a.example", "b.example"]);
    }

    #[test]
    fn resolv_conf_crlf_line_endings() {
        let (ns, search) = parse_resolv_conf("nameserver 1.1.1.1\r\nsearch a.example\r\n");
        assert_eq!(ns, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(search, vec!["a.example"]);
    }

    #[test]
    fn resolv_conf_nameserver_order_and_duplicates_preserved() {
        let (ns, _) =
            parse_resolv_conf("nameserver 8.8.8.8\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n");
        let expected: Vec<IpAddr> = ["8.8.8.8", "1.1.1.1", "8.8.8.8"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ns, expected);
    }

    // ---- find_hosts_override: 現在の挙動を固定するテスト ----

    #[test]
    fn hosts_empty_input() {
        assert_eq!(find_hosts_override("", "example.com"), None);
        assert_eq!(find_hosts_override("\n\n", "example.com"), None);
    }

    #[test]
    fn hosts_matches_any_alias_on_the_line() {
        let content = "10.0.0.5 example.com www.example.com api.example.com\n";
        for name in ["example.com", "www.example.com", "api.example.com"] {
            assert_eq!(
                find_hosts_override(content, name),
                Some("10.0.0.5".to_string()),
                "{name}"
            );
        }
    }

    #[test]
    fn hosts_match_is_case_insensitive_both_sides() {
        let content = "10.0.0.5 Example.COM\n";
        assert_eq!(
            find_hosts_override(content, "example.com"),
            Some("10.0.0.5".to_string())
        );
        assert_eq!(
            find_hosts_override(content, "EXAMPLE.com"),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn hosts_no_partial_or_prefix_match() {
        let content = "10.0.0.5 www.example.com\n";
        assert_eq!(find_hosts_override(content, "example.com"), None);
        assert_eq!(find_hosts_override(content, "www.example.co"), None);
        assert_eq!(find_hosts_override(content, "www"), None);
        assert_eq!(find_hosts_override(content, "www.example.com.evil"), None);
        // 末尾ドット付き (FQDN 表記) も別物として扱う
        assert_eq!(find_hosts_override(content, "www.example.com."), None);
    }

    #[test]
    fn hosts_ip_column_is_not_matched_as_hostname() {
        // 先頭列 (IP) は名前としては比較しない
        assert_eq!(find_hosts_override("10.0.0.5 foo\n", "10.0.0.5"), None);
    }

    #[test]
    fn hosts_inline_comment_is_stripped() {
        let content = "10.0.0.5 foo.example # bar.example\n";
        assert_eq!(
            find_hosts_override(content, "foo.example"),
            Some("10.0.0.5".to_string())
        );
        assert_eq!(find_hosts_override(content, "bar.example"), None);
        // `#` が空白なしで続いても切る
        let content = "10.0.0.5 foo.example#bar.example\n";
        assert_eq!(
            find_hosts_override(content, "foo.example"),
            Some("10.0.0.5".to_string())
        );
        assert_eq!(find_hosts_override(content, "bar.example"), None);
    }

    #[test]
    fn hosts_semicolon_is_not_a_comment() {
        // resolv.conf と違い hosts では `;` をコメント扱いしない (/etc/hosts の仕様どおり)
        let content = "10.0.0.5 foo.example ; bar.example\n";
        assert_eq!(
            find_hosts_override(content, "bar.example"),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn hosts_commented_out_entry_is_ignored_when_it_is_the_only_line() {
        assert_eq!(
            find_hosts_override("# 10.0.0.5 example.com\n", "example.com"),
            None
        );
    }

    #[test]
    fn hosts_ipv6_address() {
        let content =
            "::1 localhost ip6-localhost\n2001:db8::1 v6.example\nfe80::1%lo0 zone.example\n";
        assert_eq!(
            find_hosts_override(content, "ip6-localhost"),
            Some("::1".to_string())
        );
        // IP 列は文字列のまま返す (パース・検証はしない)。zone id も保持される
        let content = "2001:db8::1 v6.example\n";
        assert_eq!(
            find_hosts_override(content, "v6.example"),
            Some("2001:db8::1".to_string())
        );
        let content = "fe80::1%lo0 zone.example\n";
        assert_eq!(
            find_hosts_override(content, "zone.example"),
            Some("fe80::1%lo0".to_string())
        );
    }

    #[test]
    fn hosts_ip_column_is_not_validated() {
        assert_eq!(
            find_hosts_override("not-an-ip foo.example\n", "foo.example"),
            Some("not-an-ip".to_string())
        );
    }

    #[test]
    fn hosts_line_with_ip_only_is_skipped() {
        let content = "10.0.0.1\n10.0.0.2 foo.example\n";
        assert_eq!(
            find_hosts_override(content, "foo.example"),
            Some("10.0.0.2".to_string())
        );
    }

    #[test]
    fn hosts_first_matching_line_wins() {
        let content = "10.0.0.1 foo.example\n10.0.0.2 foo.example\n";
        assert_eq!(
            find_hosts_override(content, "foo.example"),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn hosts_tabs_and_extra_whitespace() {
        let content = "  10.0.0.5\t\t foo.example \t bar.example  \n";
        assert_eq!(
            find_hosts_override(content, "bar.example"),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn hosts_empty_host_argument_matches_nothing() {
        assert_eq!(find_hosts_override("10.0.0.5 foo.example\n", ""), None);
    }

    // 注意: 現在の実装は `parts.next()?` のため、空行・コメント行・空白だけの行に
    // 当たった時点で関数全体が None を返し、それ以降の行を見ない (バグの疑い)。
    // 修正する場合はこれらのテストの期待値を Some(..) に変えること。
    #[test]
    fn hosts_blank_line_stops_search_current_behavior() {
        let content = "127.0.0.1 localhost\n\n10.0.0.5 foo.example\n";
        assert_eq!(find_hosts_override(content, "foo.example"), None);
    }

    #[test]
    fn hosts_comment_line_stops_search_current_behavior() {
        let content = "# managed by tool\n10.0.0.5 foo.example\n";
        assert_eq!(find_hosts_override(content, "foo.example"), None);
        let content = "127.0.0.1 localhost\n   \t \n10.0.0.5 foo.example\n";
        assert_eq!(find_hosts_override(content, "foo.example"), None);
    }

    #[test]
    fn hosts_match_before_blank_line_is_still_found() {
        let content = "10.0.0.5 foo.example\n\n10.0.0.6 bar.example\n";
        assert_eq!(
            find_hosts_override(content, "foo.example"),
            Some("10.0.0.5".to_string())
        );
        assert_eq!(find_hosts_override(content, "bar.example"), None);
    }
}
