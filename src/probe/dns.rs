//! ステージ2: DNS 診断
//! ホスト名を4系統 (システム / resolv.conf の各ネームサーバ / 1.1.1.1 / 8.8.8.8)
//! で解決し、回答・結果コード・レイテンシを比較する。

use crate::report::{DnsOutcome, DnsReport, DnsSource, DnsSourceResult};
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::Resolver;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

const CLOUDFLARE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
const GOOGLE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));

/// システムリゾルバ (getaddrinfo 相当) での解決
async fn query_system(host: &str, timeout: Duration) -> DnsSourceResult {
    let host_owned = host.to_string();
    let start = Instant::now();
    let joined = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || (host_owned.as_str(), 0u16).to_socket_addrs().map(|it| it.map(|sa| sa.ip()).collect::<Vec<_>>())),
    )
    .await;
    let latency = start.elapsed().as_secs_f64() * 1000.0;

    let (outcome, ips, latency_ms) = match joined {
        Err(_) => (DnsOutcome::Timeout, Vec::new(), None),
        Ok(Err(e)) => (DnsOutcome::Error(format!("join error: {e}")), Vec::new(), None),
        Ok(Ok(Err(e))) => {
            // getaddrinfo は NXDOMAIN と SERVFAIL を区別しにくいが、
            // メッセージから推測する
            let msg = e.to_string();
            let outcome = if msg.contains("Name or service not known")
                || msg.contains("failed to lookup address")
                || msg.contains("nodename nor servname")
            {
                DnsOutcome::NxDomain
            } else {
                DnsOutcome::Error(msg)
            };
            (outcome, Vec::new(), Some(latency))
        }
        Ok(Ok(Ok(mut ips))) => {
            ips.sort();
            ips.dedup();
            (DnsOutcome::Ok, ips, Some(latency))
        }
    };

    DnsSourceResult {
        source: DnsSource::System,
        label: "システムリゾルバ".to_string(),
        outcome,
        ips,
        latency_ms,
    }
}

/// 特定のネームサーバへ直接問い合わせる
async fn query_direct(host: &str, ns: IpAddr, source: DnsSource, label: String, timeout: Duration) -> DnsSourceResult {
    let mut config = ResolverConfig::from_parts(None, Vec::new(), vec![NameServerConfig::udp_and_tcp(ns)]);
    // from_parts で足りるが、明示のためこのまま
    let _ = &mut config;

    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        opts.cache_size = 0;
    }

    let resolver = match builder.build() {
        Ok(r) => r,
        Err(e) => {
            return DnsSourceResult {
                source,
                label,
                outcome: DnsOutcome::Error(format!("リゾルバ初期化失敗: {e}")),
                ips: Vec::new(),
                latency_ms: None,
            }
        }
    };

    // search ドメインが付かないよう FQDN (末尾ドット) で問い合わせる
    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };

    let start = Instant::now();
    // hickory 自体のタイムアウトに加えて全体の保険をかける
    let result = tokio::time::timeout(timeout + Duration::from_millis(500), resolver.lookup_ip(fqdn.as_str())).await;
    let latency = start.elapsed().as_secs_f64() * 1000.0;

    let (outcome, ips, latency_ms) = match result {
        Err(_) => (DnsOutcome::Timeout, Vec::new(), None),
        Ok(Ok(lookup)) => {
            let mut ips: Vec<IpAddr> = lookup.iter().collect();
            ips.sort();
            ips.dedup();
            (DnsOutcome::Ok, ips, Some(latency))
        }
        Ok(Err(e)) => (classify_error(&e), Vec::new(), Some(latency)),
    };

    DnsSourceResult {
        source,
        label,
        outcome,
        ips,
        latency_ms,
    }
}

fn classify_error(e: &NetError) -> DnsOutcome {
    match e {
        NetError::Timeout => DnsOutcome::Timeout,
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            if no_records.response_code == ResponseCode::NXDomain {
                DnsOutcome::NxDomain
            } else {
                DnsOutcome::Error(format!("レコードなし ({})", no_records.response_code))
            }
        }
        NetError::Dns(DnsError::ResponseCode(code)) => {
            if *code == ResponseCode::ServFail {
                DnsOutcome::ServFail
            } else {
                DnsOutcome::Error(format!("応答コード {code}"))
            }
        }
        other => DnsOutcome::Error(other.to_string()),
    }
}

/// DNS ステージを実行する
pub async fn run(host: &str, local_nameservers: &[IpAddr], timeout: Duration) -> DnsReport {
    // IP リテラルなら DNS は不要
    if host.parse::<IpAddr>().is_ok() {
        return DnsReport {
            sources: Vec::new(),
            skipped: true,
        };
    }

    let mut sources = Vec::new();

    // (a) システムリゾルバ
    sources.push(query_system(host, timeout).await);

    // (b) resolv.conf の各ネームサーバ (パブリック DNS と重複していても実測する)
    for &ns in local_nameservers.iter().take(3) {
        sources.push(
            query_direct(
                host,
                ns,
                DnsSource::Local(ns),
                format!("ローカル {ns}"),
                timeout,
            )
            .await,
        );
    }

    // (c) 1.1.1.1, (d) 8.8.8.8
    for (ns, name) in [(CLOUDFLARE, "1.1.1.1 (Cloudflare)"), (GOOGLE, "8.8.8.8 (Google)")] {
        sources.push(
            query_direct(host, ns, DnsSource::Public(ns), name.to_string(), timeout).await,
        );
    }

    DnsReport {
        sources,
        skipped: false,
    }
}
