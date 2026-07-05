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
    for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"] {
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
}
