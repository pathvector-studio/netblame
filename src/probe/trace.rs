//! ステージ7: 経路トレース + PMTU 検出 (tracepath 方式、root 不要)
//!
//! Linux では非特権 UDP ソケットに IP_RECVERR を設定すると、TTL 超過や
//! port-unreachable の ICMP エラーを MSG_ERRQUEUE 経由で受信できる
//! (`tracepath` と同じ仕組み)。TTL を 1..=30 まで増やしながら UDP
//! データグラムを送り、ホップごとのルータアドレスと RTT を記録する。
//!
//! あわせて IP_PMTUDISC_PROBE で DF ビット付きの大きなデータグラムを送り、
//! 経路 MTU と「超過パケットが ICMP 通知なしで消えるか」(PMTUD
//! ブラックホールの証拠) を観測する。
//!
//! 判定に使う純粋ロジック (`analyze_mtu` / `localize_failure`) は
//! プラットフォーム非依存で、ユニットテストで検証する。

use crate::report::{MtuProbe, MtuProbeOutcome, TraceHop};
use std::net::IpAddr;

// ── 純粋ロジック (プラットフォーム非依存・テスト対象) ────────────────────

/// 標準的なイーサネット MTU。これ未満なら「経路のどこかが細い」とみなす。
const ETHERNET_MTU: u16 = 1500;

/// MTU プローブ結果の解析
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MtuAnalysis {
    /// 推定経路 MTU (ICMP 通知 > 宛先到達サイズ > カーネル値 の優先順)
    pub path_mtu: Option<u16>,
    /// PMTUD ブラックホールの証拠あり: 経路 MTU が 1500 未満なのに、
    /// 超過サイズの DF パケットが ICMP 通知なしで黙って消えている
    pub blackhole: bool,
}

/// MTU プローブ結果から経路 MTU とブラックホール兆候を判定する純粋関数。
///
/// ブラックホール判定の条件 (すべて満たす場合のみ):
/// - ICMP fragmentation-needed が 1 度も観測されていない
/// - 推定経路 MTU が 1500 未満
/// - 経路 MTU を超えるサイズのプローブが「送信できたのに無応答」(Silent)
/// - 無応答の最小サイズ > 宛先到達の最大サイズ (単調性 — ICMP レート制限に
///   よる取りこぼしをブラックホールと誤認しないため)
pub fn analyze_mtu(kernel_mtu: Option<u16>, probes: &[MtuProbe]) -> MtuAnalysis {
    let mut icmp_seen = false;
    let mut icmp_mtu: Option<u16> = None;
    let mut max_delivered: Option<u16> = None;
    let mut min_silent: Option<u16> = None;

    for p in probes {
        match p.outcome {
            MtuProbeOutcome::FragNeeded { mtu } => {
                icmp_seen = true;
                if let Some(m) = mtu {
                    let m = m.min(u32::from(u16::MAX)) as u16;
                    icmp_mtu = Some(icmp_mtu.map_or(m, |c| c.min(m)));
                }
            }
            MtuProbeOutcome::Delivered => {
                max_delivered = Some(max_delivered.map_or(p.size, |c| c.max(p.size)));
            }
            MtuProbeOutcome::Silent => {
                min_silent = Some(min_silent.map_or(p.size, |c| c.min(p.size)));
            }
            MtuProbeOutcome::LocalError => {}
        }
    }

    let path_mtu = icmp_mtu.or(max_delivered).or(kernel_mtu);
    let blackhole = !icmp_seen
        && path_mtu.is_some_and(|m| m < ETHERNET_MTU)
        && min_silent.zip(path_mtu).is_some_and(|(s, m)| s > m);

    MtuAnalysis {
        path_mtu,
        blackhole,
    }
}

/// 障害箇所のおおまかなゾーン (最後に応答したホップの位置から推定)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopZone {
    /// ホップ 1-2: 宅内 (ルータ/ホームゲートウェイ) 側
    Home,
    /// 序盤のホップ: ISP 網内の可能性が高い
    Isp,
    /// 経路の奥まで到達: 対岸 (相手側ネットワーク) の可能性が高い
    FarSide,
}

/// 宅内とみなす最終応答ホップの上限
const HOME_MAX_HOP: u8 = 2;
/// ISP 網内とみなす最終応答ホップの上限 (これを超えたら対岸側)
const ISP_MAX_HOP: u8 = 6;

/// ホップ単位の障害位置推定
#[derive(Debug, Clone, PartialEq)]
pub struct HopLocalization {
    /// 最後に応答したホップのアドレス
    pub last_hop: IpAddr,
    /// そのホップ番号 (TTL)
    pub last_index: u8,
    /// 推定経路長 (宛先到達時はそのホップ番号、未到達時は探索した最大 TTL)
    pub path_len_estimate: u8,
    pub zone: HopZone,
}

/// ホップ一覧から「どこまで応答があったか」を求める純粋関数。
/// 応答したホップが 1 つもなければ None。
pub fn localize_failure(hops: &[TraceHop], dest_reached: bool) -> Option<HopLocalization> {
    let last = hops.iter().rev().find(|h| h.addr.is_some())?;
    let last_hop = last.addr?;
    let max_probed = hops.iter().map(|h| h.index).max().unwrap_or(last.index);
    let path_len_estimate = if dest_reached { last.index } else { max_probed };
    let zone = if last.index <= HOME_MAX_HOP {
        HopZone::Home
    } else if last.index <= ISP_MAX_HOP {
        HopZone::Isp
    } else {
        HopZone::FarSide
    };
    Some(HopLocalization {
        last_hop,
        last_index: last.index,
        path_len_estimate,
        zone,
    })
}

// ── ステージ実行 (Linux: tracepath 方式 / それ以外: Unsupported) ─────────

#[cfg(target_os = "linux")]
pub async fn run(dest: IpAddr, lang: crate::i18n::Lang) -> crate::report::TraceReport {
    use crate::report::TraceReport;
    use std::time::Duration;

    // ワーストケース (30 ホップ × 2 プローブ × 1 秒 + MTU プローブ) でも
    // ここで必ず打ち切る。失敗しても診断全体は続行する。
    let guarded = tokio::time::timeout(
        Duration::from_secs(75),
        tokio::task::spawn_blocking(move || linux::trace(dest)),
    )
    .await;
    match guarded {
        Ok(Ok(Ok(data))) => TraceReport::Ran(data),
        Ok(Ok(Err(e))) => TraceReport::Failed(e.to_string()),
        Ok(Err(join_err)) => TraceReport::Failed(join_err.to_string()),
        Err(_) => TraceReport::Failed(crate::i18n::probe_trace_timeout(lang)),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_dest: IpAddr, _lang: crate::i18n::Lang) -> crate::report::TraceReport {
    crate::report::TraceReport::Unsupported
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::report::TraceData;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::{Duration, Instant};

    /// UDP traceroute の慣習ポート (TTL ごとに +1 して送信を識別する)
    const BASE_PORT: u16 = 33434;
    const MAX_HOPS: u8 = 30;
    const PROBES_PER_HOP: u32 = 2;
    const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
    const MTU_FEEDBACK_TIMEOUT: Duration = Duration::from_millis(700);
    /// 連続無応答がこの数に達したら打ち切る (完全に ICMP が
    /// フィルタされた経路で 60 秒待たないため)
    const MAX_CONSECUTIVE_SILENT: u32 = 8;
    /// DF 付き MTU プローブのパケットサイズ (大→小)
    const MTU_PROBE_SIZES: [u16; 5] = [1500, 1472, 1400, 1280, 1024];

    // Linux ABI の安定した定数 (musl / glibc 両対応のためローカル定義)
    const IP_RECVERR: libc::c_int = 11;
    const IPV6_RECVERR: libc::c_int = 25;
    const IP_MTU_DISCOVER: libc::c_int = 10;
    const IPV6_MTU_DISCOVER: libc::c_int = 23;
    const IP_MTU: libc::c_int = 14;
    const IPV6_MTU: libc::c_int = 24;
    /// IP_PMTUDISC_PROBE: DF を立てつつ経路 MTU キャッシュを無視して送る
    const PMTUDISC_PROBE: libc::c_int = 3;
    const SO_EE_ORIGIN_ICMP: u8 = 2;
    const SO_EE_ORIGIN_ICMP6: u8 = 3;
    const SO_EE_ORIGIN_LOCAL: u8 = 1;
    // ICMPv4
    const ICMP_DEST_UNREACH: u8 = 3;
    const ICMP_TIME_EXCEEDED: u8 = 11;
    const ICMP_CODE_PORT_UNREACH: u8 = 3;
    const ICMP_CODE_FRAG_NEEDED: u8 = 4;
    // ICMPv6
    const ICMP6_DEST_UNREACH: u8 = 1;
    const ICMP6_PACKET_TOO_BIG: u8 = 2;
    const ICMP6_TIME_EXCEEDED: u8 = 3;
    const ICMP6_CODE_PORT_UNREACH: u8 = 4;

    /// エラーキューから取り出した 1 イベントの分類
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum ErrKind {
        /// TTL 超過 (中間ルータからの応答)
        TimeExceeded,
        /// port-unreachable (宛先に到達した)
        PortUnreachable,
        /// その他の unreachable (経路上で拒否された — 終端扱い)
        Unreachable,
        /// fragmentation needed / packet too big
        FragNeeded,
        /// ローカル起源の EMSGSIZE
        LocalEmsgsize,
        Other,
    }

    /// MSG_ERRQUEUE から取り出した 1 イベント
    struct ErrEvent {
        kind: ErrKind,
        /// ICMP を送ってきたルータ/ホストのアドレス (SO_EE_OFFENDER)
        offender: Option<IpAddr>,
        /// 元パケットの宛先ポート (どの TTL の送信に対する応答かの識別用)
        dest_port: Option<u16>,
        /// ee_info (FragNeeded なら経路 MTU ヒント)
        info: u32,
    }

    fn setsockopt_int(
        fd: RawFd,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn getsockopt_int(fd: RawFd, level: libc::c_int, name: libc::c_int) -> io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                &mut value as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// sockaddr_storage から (IpAddr, port) を読む
    fn parse_sockaddr(storage: &libc::sockaddr_storage) -> Option<(IpAddr, u16)> {
        match libc::c_int::from(storage.ss_family) {
            f if f == libc::AF_INET => {
                let sa = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)));
                Some((ip, u16::from_be(sa.sin_port)))
            }
            f if f == libc::AF_INET6 => {
                let sa = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                let ip = IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr));
                Some((ip, u16::from_be(sa.sin6_port)))
            }
            _ => None,
        }
    }

    /// sock_extended_err の直後に置かれた offender アドレスを読む
    /// (SO_EE_OFFENDER 相当)。cmsg のデータ長を検証してから読む。
    unsafe fn read_offender(
        err: *const libc::sock_extended_err,
        cmsg_len: usize,
        v6: bool,
    ) -> Option<IpAddr> {
        let base = mem::size_of::<libc::sock_extended_err>();
        let need = base
            + if v6 {
                mem::size_of::<libc::sockaddr_in6>()
            } else {
                mem::size_of::<libc::sockaddr_in>()
            };
        // cmsg_len はヘッダ込みなので CMSG_LEN で比較する
        if cmsg_len < libc::CMSG_LEN(need as u32) as usize {
            return None;
        }
        let sa = err.add(1) as *const libc::sockaddr;
        match libc::c_int::from((*sa).sa_family) {
            f if f == libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            f if f == libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    /// sock_extended_err を ErrKind に分類する
    fn classify(err: &libc::sock_extended_err) -> ErrKind {
        match err.ee_origin {
            SO_EE_ORIGIN_ICMP => match err.ee_type {
                ICMP_TIME_EXCEEDED => ErrKind::TimeExceeded,
                ICMP_DEST_UNREACH => match err.ee_code {
                    ICMP_CODE_PORT_UNREACH => ErrKind::PortUnreachable,
                    ICMP_CODE_FRAG_NEEDED => ErrKind::FragNeeded,
                    _ => ErrKind::Unreachable,
                },
                _ => ErrKind::Other,
            },
            SO_EE_ORIGIN_ICMP6 => match err.ee_type {
                ICMP6_TIME_EXCEEDED => ErrKind::TimeExceeded,
                ICMP6_PACKET_TOO_BIG => ErrKind::FragNeeded,
                ICMP6_DEST_UNREACH => match err.ee_code {
                    ICMP6_CODE_PORT_UNREACH => ErrKind::PortUnreachable,
                    _ => ErrKind::Unreachable,
                },
                _ => ErrKind::Other,
            },
            SO_EE_ORIGIN_LOCAL if err.ee_errno == libc::EMSGSIZE as u32 => ErrKind::LocalEmsgsize,
            _ => ErrKind::Other,
        }
    }

    /// エラーキューから 1 イベント取り出す (なければ None、ブロックしない)
    fn recv_err(fd: RawFd, v6: bool) -> Option<ErrEvent> {
        let mut data_buf = [0u8; 2048];
        let mut ctrl_buf = [0u8; 512];
        let mut name: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: data_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: data_buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = ctrl_buf.len() as _;

        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE) };
        if n < 0 {
            return None;
        }
        // msg_name には元パケットの宛先が入る → ポートで TTL を識別できる
        let dest_port = parse_sockaddr(&name).map(|(_, p)| p);

        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let c = unsafe { &*cmsg };
            let is_recverr = (c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == IP_RECVERR)
                || (c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == IPV6_RECVERR);
            if is_recverr {
                let err_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sock_extended_err;
                let err = unsafe { &*err_ptr };
                let kind = classify(err);
                let offender =
                    if err.ee_origin == SO_EE_ORIGIN_ICMP || err.ee_origin == SO_EE_ORIGIN_ICMP6 {
                        unsafe { read_offender(err_ptr, c.cmsg_len as usize, v6) }
                    } else {
                        None
                    };
                return Some(ErrEvent {
                    kind,
                    offender,
                    dest_port,
                    info: err.ee_info,
                });
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        None
    }

    /// deadline までエラーキューを待ち、イベントと受信時刻を返す
    fn wait_err(fd: RawFd, v6: bool, deadline: Instant) -> Option<(ErrEvent, Instant)> {
        loop {
            if let Some(ev) = recv_err(fd, v6) {
                return Some((ev, Instant::now()));
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining_ms = (deadline - now).as_millis().max(1) as libc::c_int;
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
            if rc < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return None;
            }
            if rc == 0 {
                return None;
            }
            // 通常データ (万一の UDP 応答) が来ていたら捨てる。捨てないと
            // POLLIN が立ち続けてビジーループになる。
            if pfd.revents & libc::POLLIN != 0 && pfd.revents & libc::POLLERR == 0 {
                let mut sink = [0u8; 512];
                unsafe {
                    libc::recv(
                        fd,
                        sink.as_mut_ptr() as *mut libc::c_void,
                        sink.len(),
                        libc::MSG_DONTWAIT,
                    );
                }
            }
        }
    }

    fn new_udp_socket(v6: bool) -> io::Result<Socket> {
        let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        let fd = socket.as_raw_fd();
        if v6 {
            setsockopt_int(fd, libc::IPPROTO_IPV6, IPV6_RECVERR, 1)?;
        } else {
            setsockopt_int(fd, libc::IPPROTO_IP, IP_RECVERR, 1)?;
        }
        Ok(socket)
    }

    /// ステージ本体 (ブロッキング実行、spawn_blocking から呼ぶ)
    pub fn trace(dest: IpAddr) -> io::Result<TraceData> {
        let mut data = TraceData::default();
        trace_hops(dest, &mut data)?;
        // MTU 検出はベストエフォート: 失敗してもホップ結果は返す
        let _ = probe_mtu(dest, &mut data);
        Ok(data)
    }

    /// TTL 1..=30 のホップ探索
    fn trace_hops(dest: IpAddr, data: &mut TraceData) -> io::Result<()> {
        let v6 = dest.is_ipv6();
        let socket = new_udp_socket(v6)?;
        let fd = socket.as_raw_fd();

        // TTL ごとの送信時刻 (遅れて届いた応答の RTT 計算用)
        let mut send_times: [Option<Instant>; MAX_HOPS as usize + 1] =
            [None; MAX_HOPS as usize + 1];
        let mut consecutive_silent = 0u32;

        'ttl: for ttl in 1..=MAX_HOPS {
            if v6 {
                socket.set_unicast_hops_v6(u32::from(ttl))?;
            } else {
                socket.set_ttl_v4(u32::from(ttl))?;
            }
            let mut hop = TraceHop {
                index: ttl,
                addr: None,
                rtt_ms: None,
            };
            let mut terminal = false;

            'probe: for _ in 0..PROBES_PER_HOP {
                let target = SockAddr::from(SocketAddr::new(dest, BASE_PORT + u16::from(ttl)));
                send_times[ttl as usize] = Some(Instant::now());
                if socket.send_to(&[0u8; 32], &target).is_err() {
                    continue 'probe;
                }
                let deadline = Instant::now() + PROBE_TIMEOUT;
                while let Some((ev, at)) = wait_err(fd, v6, deadline) {
                    // どの TTL の送信に対する応答かをポートで識別する
                    let ev_ttl = ev
                        .dest_port
                        .and_then(|p| p.checked_sub(BASE_PORT))
                        .filter(|d| (1..=u16::from(MAX_HOPS)).contains(d))
                        .map(|d| d as u8);
                    let Some(ev_ttl) = ev_ttl else { continue };
                    let rtt_ms = send_times[ev_ttl as usize]
                        .map(|s| at.duration_since(s).as_secs_f64() * 1000.0);

                    if ev_ttl == ttl {
                        hop.addr = ev.offender;
                        hop.rtt_ms = rtt_ms;
                        match ev.kind {
                            ErrKind::TimeExceeded => {}
                            ErrKind::PortUnreachable => {
                                data.dest_reached = true;
                                terminal = true;
                            }
                            ErrKind::Unreachable => {
                                // 経路上で administratively prohibited 等 —
                                // ここから先には進めないので打ち切る
                                data.dest_reached = ev.offender == Some(dest);
                                terminal = true;
                            }
                            _ => continue,
                        }
                        break 'probe;
                    }
                    // 遅れて届いた前のホップの応答: 空欄なら埋める
                    if let Some(h) = data
                        .hops
                        .iter_mut()
                        .find(|h| h.index == ev_ttl && h.addr.is_none())
                    {
                        h.addr = ev.offender;
                        h.rtt_ms = rtt_ms;
                    }
                }
            }

            let silent = hop.addr.is_none();
            data.hops.push(hop);
            if terminal {
                break 'ttl;
            }
            if silent {
                consecutive_silent += 1;
                if consecutive_silent >= MAX_CONSECUTIVE_SILENT {
                    break 'ttl;
                }
            } else {
                consecutive_silent = 0;
            }
        }
        Ok(())
    }

    /// DF 付き MTU プローブ: 経路 MTU と ICMP 通知の有無を観測する
    fn probe_mtu(dest: IpAddr, data: &mut TraceData) -> io::Result<()> {
        let v6 = dest.is_ipv6();
        let socket = new_udp_socket(v6)?;
        let fd = socket.as_raw_fd();
        socket.connect(&SockAddr::from(SocketAddr::new(dest, BASE_PORT)))?;

        let (level, opt_mtu, opt_disc) = if v6 {
            (libc::IPPROTO_IPV6, IPV6_MTU, IPV6_MTU_DISCOVER)
        } else {
            (libc::IPPROTO_IP, IP_MTU, IP_MTU_DISCOVER)
        };
        let initial_mtu = getsockopt_int(fd, level, opt_mtu).ok();
        // PROBE モード: DF を立てつつ、カーネルの経路 MTU キャッシュを無視して
        // 実際に大きなパケットを送る (これで ICMP が返るかを観測できる)
        setsockopt_int(fd, level, opt_disc, PMTUDISC_PROBE)?;

        // IP+UDP ヘッダぶんを引いてペイロードサイズを決める
        let header = if v6 { 48u16 } else { 28u16 };
        for size in MTU_PROBE_SIZES {
            let Some(payload_len) = size.checked_sub(header) else {
                continue;
            };
            let payload = vec![0u8; usize::from(payload_len)];
            let outcome = match socket.send(&payload) {
                Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => MtuProbeOutcome::LocalError,
                Err(_) => MtuProbeOutcome::LocalError,
                Ok(_) => {
                    let deadline = Instant::now() + MTU_FEEDBACK_TIMEOUT;
                    let mut out = MtuProbeOutcome::Silent;
                    while let Some((ev, _)) = wait_err(fd, v6, deadline) {
                        match ev.kind {
                            ErrKind::FragNeeded => {
                                out = MtuProbeOutcome::FragNeeded {
                                    mtu: (ev.info > 0).then_some(ev.info),
                                };
                                break;
                            }
                            ErrKind::PortUnreachable => {
                                out = MtuProbeOutcome::Delivered;
                                break;
                            }
                            ErrKind::LocalEmsgsize => {
                                out = MtuProbeOutcome::LocalError;
                                break;
                            }
                            _ => continue,
                        }
                    }
                    out
                }
            };
            data.mtu_probes.push(MtuProbe { size, outcome });
        }

        // ICMP frag-needed を受けていればカーネルの経路 MTU が更新されている
        let final_mtu = getsockopt_int(fd, level, opt_mtu).ok().or(initial_mtu);
        data.kernel_mtu = final_mtu.and_then(|v| u16::try_from(v).ok());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(size: u16, outcome: MtuProbeOutcome) -> MtuProbe {
        MtuProbe { size, outcome }
    }

    fn hop(index: u8, addr: Option<&str>, rtt: Option<f64>) -> TraceHop {
        TraceHop {
            index,
            addr: addr.map(|a| a.parse().unwrap()),
            rtt_ms: rtt,
        }
    }

    // ── analyze_mtu ─────────────────────────────────────────────

    #[test]
    fn mtu_healthy_1500() {
        // 1500 バイトが宛先まで届く → 経路 MTU 1500、ブラックホールなし
        let probes = vec![
            probe(1500, MtuProbeOutcome::Delivered),
            probe(1472, MtuProbeOutcome::Delivered),
        ];
        let a = analyze_mtu(Some(1500), &probes);
        assert_eq!(a.path_mtu, Some(1500));
        assert!(!a.blackhole);
    }

    #[test]
    fn mtu_blackhole_silent_oversize() {
        // 1280 は届くが、それ超は ICMP 通知なしで消える → ブラックホール
        let probes = vec![
            probe(1500, MtuProbeOutcome::Silent),
            probe(1472, MtuProbeOutcome::Silent),
            probe(1400, MtuProbeOutcome::Silent),
            probe(1280, MtuProbeOutcome::Delivered),
            probe(1024, MtuProbeOutcome::Delivered),
        ];
        let a = analyze_mtu(Some(1500), &probes);
        assert_eq!(a.path_mtu, Some(1280));
        assert!(a.blackhole);
    }

    #[test]
    fn mtu_pmtud_working_is_not_blackhole() {
        // ICMP frag-needed が返る = PMTUD は機能している → ブラックホールではない
        let probes = vec![
            probe(1500, MtuProbeOutcome::FragNeeded { mtu: Some(1400) }),
            probe(1400, MtuProbeOutcome::Delivered),
        ];
        let a = analyze_mtu(Some(1500), &probes);
        assert_eq!(a.path_mtu, Some(1400));
        assert!(!a.blackhole);
    }

    #[test]
    fn mtu_kernel_route_narrow_and_silent() {
        // カーネルは経路 MTU 1400 と把握、1500/1472 は黙って消える
        let probes = vec![
            probe(1500, MtuProbeOutcome::Silent),
            probe(1472, MtuProbeOutcome::Silent),
        ];
        let a = analyze_mtu(Some(1400), &probes);
        assert_eq!(a.path_mtu, Some(1400));
        assert!(a.blackhole);
    }

    #[test]
    fn mtu_rate_limited_replies_not_blackhole() {
        // 1280 だけ無応答で 1400 は届いている (非単調) → ICMP レート制限の
        // 取りこぼしの可能性が高く、ブラックホールとは判定しない
        let probes = vec![
            probe(1400, MtuProbeOutcome::Delivered),
            probe(1280, MtuProbeOutcome::Silent),
        ];
        let a = analyze_mtu(Some(1500), &probes);
        assert_eq!(a.path_mtu, Some(1400));
        assert!(!a.blackhole);
    }

    #[test]
    fn mtu_no_data() {
        let a = analyze_mtu(None, &[]);
        assert_eq!(a.path_mtu, None);
        assert!(!a.blackhole);
    }

    // ── localize_failure ────────────────────────────────────────

    #[test]
    fn localize_early_failure_is_home() {
        // ホップ 1 で止まる → 宅内側
        let hops = vec![
            hop(1, Some("192.168.1.1"), Some(1.2)),
            hop(2, None, None),
            hop(3, None, None),
        ];
        let l = localize_failure(&hops, false).unwrap();
        assert_eq!(l.last_index, 1);
        assert_eq!(l.zone, HopZone::Home);
        assert_eq!(l.path_len_estimate, 3);
    }

    #[test]
    fn localize_mid_failure_is_isp() {
        // ホップ 4 で止まる → ISP 網内
        let hops = vec![
            hop(1, Some("192.168.1.1"), Some(1.0)),
            hop(2, Some("10.0.0.1"), Some(5.0)),
            hop(3, Some("100.64.0.1"), Some(8.0)),
            hop(4, Some("203.0.113.1"), Some(9.0)),
            hop(5, None, None),
            hop(6, None, None),
        ];
        let l = localize_failure(&hops, false).unwrap();
        assert_eq!(l.last_index, 4);
        assert_eq!(l.last_hop, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(l.zone, HopZone::Isp);
    }

    #[test]
    fn localize_late_failure_is_far_side() {
        // 奥のホップ 12 まで応答している → 対岸側
        let mut hops: Vec<TraceHop> = (1..=12)
            .map(|i| hop(i, Some("198.51.100.7"), Some(20.0)))
            .collect();
        hops.push(hop(13, None, None));
        hops.push(hop(14, None, None));
        let l = localize_failure(&hops, false).unwrap();
        assert_eq!(l.last_index, 12);
        assert_eq!(l.zone, HopZone::FarSide);
        assert_eq!(l.path_len_estimate, 14);
    }

    #[test]
    fn localize_dest_reached_uses_dest_index() {
        let hops = vec![
            hop(1, Some("192.168.1.1"), Some(1.0)),
            hop(2, Some("10.0.0.1"), Some(5.0)),
            hop(3, Some("93.184.216.34"), Some(12.0)),
        ];
        let l = localize_failure(&hops, true).unwrap();
        assert_eq!(l.last_index, 3);
        assert_eq!(l.path_len_estimate, 3);
    }

    #[test]
    fn localize_no_replies_is_none() {
        let hops = vec![hop(1, None, None), hop(2, None, None)];
        assert!(localize_failure(&hops, false).is_none());
    }
}
