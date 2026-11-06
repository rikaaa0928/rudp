use rand::Rng;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;
use std::thread;
use std::time::Duration;

pub const STATE_IDLE: u32 = 0;
pub const STATE_SYN_SENT: u32 = 1;
pub const STATE_SYN_RECEIVED: u32 = 2;
pub const STATE_ESTABLISHED: u32 = 3;

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RudpConfig {
    pub mode: u32,
    pub local_ip: u32,
    pub remote_ip: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub padding_enabled: u8,
    pub padding_max_len: u8,
    pub obfuscate_enabled: u8,
    pub tcp_extensions: u8,
    pub obfuscate_prob_bp: u32,
    pub obfuscate_max_len: u8,
    pub transparent: u8,
    pub internal_udp_port: u16,
    pub local_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
}

unsafe impl aya::Pod for RudpConfig {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PeerKey {
    pub ip: u32,
    pub port: u16,
    pub _pad: u16,
}

unsafe impl aya::Pod for PeerKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ConnState {
    pub client_ip: u32,
    pub client_port: u16,
    pub local_tcp_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub state: u32,
    pub orig_dst_ip: u32,
    pub last_seen_ns: u64,
    pub peer_mac: [u8; 6],
    pub local_mac: [u8; 6],
    pub _pad1: u32,
}

unsafe impl aya::Pod for ConnState {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RudpStats {
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub handshakes: u64,
    pub rx_obfuscate_pkts: u64,
    pub tx_obfuscate_pkts: u64,
    pub drops: u64,
}

unsafe impl aya::Pod for RudpStats {}

/// Loads the embedded eBPF ELF object compiled by `build.rs`.
pub fn load_ebpf() -> Result<aya::Ebpf, aya::EbpfError> {
    let data = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rudp_ebpf.o"));
    aya::Ebpf::load(data)
}

/// Removes any orphaned TC filter at the given priority on the interface.
pub fn reset_clsact(if_name: &str, priority: u16) {
    let pref = priority.to_string();
    let _ = Command::new("tc")
        .args(["filter", "del", "dev", if_name, "ingress", "pref", &pref])
        .output();
    let _ = Command::new("tc")
        .args(["filter", "del", "dev", if_name, "egress", "pref", &pref])
        .output();
}

/// Enables `accept_local` and `route_localnet` sysctls required for local/transparent eBPF packet redirection.
pub fn enable_local_routing_sysctls(if_name: &str) {
    let paths = [
        "/proc/sys/net/ipv4/conf/all/accept_local".to_string(),
        "/proc/sys/net/ipv4/conf/lo/accept_local".to_string(),
        format!("/proc/sys/net/ipv4/conf/{if_name}/accept_local"),
        "/proc/sys/net/ipv4/conf/all/route_localnet".to_string(),
        format!("/proc/sys/net/ipv4/conf/{if_name}/route_localnet"),
    ];
    for p in paths {
        let _ = fs::write(p, b"1\n");
    }
}

/// Monotonic clock in nanoseconds matching `bpf_ktime_get_ns()`.
pub fn ktime_get_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[derive(Clone, Debug)]
pub struct NetIfInfo {
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub mac: [u8; 6],
    pub gateway_mac: [u8; 6],
}

/// Auto-detects the outgoing interface, its IPv4 address, MAC, and gateway MAC.
pub fn detect_interface(override_name: Option<&str>, probe_target: Ipv4Addr) -> io::Result<NetIfInfo> {
    let local_ip = {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(SocketAddrV4::new(probe_target, 80))?;
        match sock.local_addr()? {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => return Err(io::Error::new(io::ErrorKind::Other, "expected IPv4 local addr")),
        }
    };

    let if_name = if let Some(name) = override_name.filter(|s| !s.is_empty()) {
        name.to_string()
    } else {
        find_interface_by_ipv4(local_ip)?
    };

    let mac = read_iface_mac(&if_name).unwrap_or([0; 6]);
    let gateway_mac = read_gateway_mac(&if_name, probe_target).unwrap_or([0; 6]);

    Ok(NetIfInfo {
        name: if_name,
        ipv4: local_ip,
        mac,
        gateway_mac,
    })
}

fn find_interface_by_ipv4(target_ip: Ipv4Addr) -> io::Result<String> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut cur = ifap;
        let mut found = None;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if ip == target_ip {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .into_owned();
                    found = Some(name);
                    break;
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no interface found with IPv4 {target_ip}"),
            )
        })
    }
}

fn read_iface_mac(if_name: &str) -> Option<[u8; 6]> {
    let path = format!("/sys/class/net/{if_name}/address");
    let s = fs::read_to_string(path).ok()?;
    parse_mac(s.trim())
}

/// Resolves the next-hop IPv4 address for `probe_target` on `if_name` from `/proc/net/route`.
fn find_next_hop_ipv4(if_name: &str, probe_target: Ipv4Addr) -> Option<Ipv4Addr> {
    const RTF_UP: u32 = 0x0001;
    const RTF_GATEWAY: u32 = 0x0002;

    let routes = fs::read_to_string("/proc/net/route").ok()?;
    let target_u32 = u32::from(probe_target);

    let mut best_match: Option<(u32, u32, Ipv4Addr)> = None; // (prefix_len, metric, next_hop)
    let mut fallback_gw: Option<Ipv4Addr> = None;

    for line in routes.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 || cols[0] != if_name {
            continue;
        }
        let dest_ne = u32::from_str_radix(cols[1], 16).ok()?;
        let gw_ne = u32::from_str_radix(cols[2], 16).ok()?;
        let flags = u32::from_str_radix(cols[3], 16).ok()?;
        let metric = cols[6].parse::<u32>().unwrap_or(0);
        let mask_ne = u32::from_str_radix(cols[7], 16).ok()?;

        if (flags & RTF_UP) == 0 {
            continue;
        }

        let dest = Ipv4Addr::from(dest_ne.to_ne_bytes());
        let gw = Ipv4Addr::from(gw_ne.to_ne_bytes());
        let mask = Ipv4Addr::from(mask_ne.to_ne_bytes());

        if (flags & RTF_GATEWAY) != 0 && !gw.is_unspecified() && fallback_gw.is_none() {
            fallback_gw = Some(gw);
        }

        let dest_u32 = u32::from(dest);
        let mask_u32 = u32::from(mask);
        if (target_u32 & mask_u32) == (dest_u32 & mask_u32) {
            let prefix_len = mask_u32.count_ones();
            let next_hop = if (flags & RTF_GATEWAY) != 0 && !gw.is_unspecified() {
                gw
            } else {
                probe_target
            };
            let replace = match best_match {
                None => true,
                Some((best_plen, best_metric, _)) => {
                    prefix_len > best_plen || (prefix_len == best_plen && metric < best_metric)
                }
            };
            if replace {
                best_match = Some((prefix_len, metric, next_hop));
            }
        }
    }

    best_match.map(|(_, _, nh)| nh).or(fallback_gw)
}

fn lookup_arp_mac(if_name: &str, target_ip: Option<Ipv4Addr>) -> Option<[u8; 6]> {
    let arp = fs::read_to_string("/proc/net/arp").ok()?;
    let target_str = target_ip.map(|ip| ip.to_string());

    for line in arp.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 || cols[5] != if_name || cols[3] == "00:00:00:00:00:00" {
            continue;
        }
        if let Some(ref ip_str) = target_str {
            if cols[0] != ip_str {
                continue;
            }
        }
        if let Some(mac) = parse_mac(cols[3]) {
            return Some(mac);
        }
    }
    None
}

fn read_gateway_mac(if_name: &str, probe_target: Ipv4Addr) -> Option<[u8; 6]> {
    let next_hop = find_next_hop_ipv4(if_name, probe_target);

    if let Some(nh_ip) = next_hop {
        if let Some(mac) = lookup_arp_mac(if_name, Some(nh_ip)) {
            return Some(mac);
        }
        // Trigger kernel ARP resolution for the next-hop gateway IP
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            let _ = sock.set_ttl(1);
            let _ = sock.send_to(&[0u8], SocketAddrV4::new(nh_ip, 33434));
            thread::sleep(Duration::from_millis(25));
        }
        if let Some(mac) = lookup_arp_mac(if_name, Some(nh_ip)) {
            return Some(mac);
        }
    }

    lookup_arp_mac(if_name, None)
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Encodes payload with optional 2-byte sum header + random even padding bytes (2..=max_len).
pub fn encode_payload(payload: &[u8], padding_enabled: bool, max_len: u8) -> Vec<u8> {
    if !padding_enabled {
        return payload.to_vec();
    }
    let mut rng = rand::thread_rng();
    let max_pad = max_len.clamp(2, 254);
    let num_even = (max_pad / 2).max(1);
    let pad_len = rng.gen_range(1..=num_even) * 2;
    let b0 = rng.gen_range(1..=127u8);
    let b1 = pad_len.wrapping_sub(b0);

    let mut out = Vec::with_capacity(2 + pad_len as usize + payload.len());
    out.push(b0);
    out.push(b1);
    for _ in 0..pad_len {
        out.push(rng.gen());
    }
    out.extend_from_slice(payload);
    out
}

/// Builds a complete IPv4 + TCP packet (with optional realistic SYN options) for raw socket transmission.
pub fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    tcp_extensions: bool,
    payload: &[u8],
) -> Vec<u8> {
    let is_syn = (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0;
    let tcp_opts: &[u8] = if is_syn {
        if tcp_extensions {
            // MSS(1460) + SACK_PERM + NOP + WScale(7) + NOP + NOP = 12 bytes
            &[0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x01, 0x03, 0x03, 0x07, 0x01, 0x01]
        } else {
            // NOP + WScale(14) = 4 bytes
            &[0x01, 0x03, 0x03, 0x0e]
        }
    } else {
        &[]
    };

    let actual_flags = if is_syn && tcp_extensions {
        flags | TCP_FLAG_ECE | TCP_FLAG_CWR
    } else if flags == TCP_FLAG_ACK && !payload.is_empty() && tcp_extensions {
        flags | TCP_FLAG_PSH
    } else {
        flags
    };

    let tcp_hdr_len = 20 + tcp_opts.len();
    let tcp_total_len = tcp_hdr_len + payload.len();
    let ip_total_len = 20 + tcp_total_len;

    let mut pkt = vec![0u8; ip_total_len];

    // IPv4 Header (20B)
    pkt[0] = (4 << 4) | 5;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    let ip_id: u16 = rand::thread_rng().gen();
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    pkt[8] = 64; // TTL
    pkt[9] = 6; // IPPROTO_TCP
    pkt[10..12].copy_from_slice(&[0, 0]);
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ip_csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP Header
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[33] = actual_flags;
    pkt[34..36].copy_from_slice(&0xffffu16.to_be_bytes());
    pkt[36..38].copy_from_slice(&[0, 0]); // checksum placeholder
    pkt[38..40].copy_from_slice(&[0, 0]); // urgent ptr

    if !tcp_opts.is_empty() {
        pkt[40..40 + tcp_opts.len()].copy_from_slice(tcp_opts);
    }
    if !payload.is_empty() {
        pkt[20 + tcp_hdr_len..].copy_from_slice(payload);
    }

    let tcp_csum = tcp_v4_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

    pkt
}

pub fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in hdr.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn tcp_v4_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src_ip.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 6u32; // IPPROTO_TCP
    sum += tcp_segment.len() as u32;

    for chunk in tcp_segment.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Raw IPv4 TCP socket with `IP_HDRINCL` enabled for sending SYN and initial flushed payload.
pub struct RawTcpSocket {
    fd: RawFd,
}

impl RawTcpSocket {
    pub fn new() -> io::Result<Self> {
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let one: libc::c_int = 1;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            ) < 0
            {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            Ok(Self { fd })
        }
    }

    pub fn send_to(&self, packet: &[u8], dst_ip: Ipv4Addr, dst_port: u16) -> io::Result<usize> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: dst_port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst_ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            let ret = libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            );
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }
    }
}

impl AsRawFd for RawTcpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawTcpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// NIC TX checksum offload control mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum TxOffloadMode {
    /// Keep TX offload ON by default; auto-sniff NIC capabilities and traffic to disable only when needed
    Auto,
    /// Always keep NIC TX checksum offload ON
    On,
    /// Always disable NIC TX checksum offload (`ethtool -K <iface> tx off`) on startup and restore on exit
    Off,
}

impl std::fmt::Display for TxOffloadMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxOffloadMode::Auto => write!(f, "auto"),
            TxOffloadMode::On => write!(f, "on"),
            TxOffloadMode::Off => write!(f, "off"),
        }
    }
}

/// Manages NIC TX checksum offload state with startup capability sniffing, runtime fallback sniffing, and exit restoration.
pub struct TxOffloadManager {
    iface: String,
    mode: TxOffloadMode,
    uses_tc_egress: bool,
    disabled_by_us: bool,
}

impl TxOffloadManager {
    pub fn new(iface: &str, mode: TxOffloadMode, uses_tc_egress: bool) -> Self {
        let mut mgr = Self {
            iface: iface.to_string(),
            mode,
            uses_tc_egress,
            disabled_by_us: false,
        };

        if !uses_tc_egress {
            return mgr;
        }

        match mode {
            TxOffloadMode::On => {
                log::info!("TX checksum offload on {}: kept ON (--tx-offload=on)", iface);
            }
            TxOffloadMode::Off => {
                mgr.disable_offload("forced by --tx-offload=off");
            }
            TxOffloadMode::Auto => {
                if let Some(reason) = Self::sniff_nic_requires_tx_off(iface) {
                    mgr.disable_offload(reason);
                } else {
                    log::info!(
                        "TX checksum offload on {}: kept ON (auto-sniffed generic csum support; runtime fallback active)",
                        iface
                    );
                }
            }
        }

        mgr
    }

    pub fn status_str(&self) -> &'static str {
        if self.disabled_by_us {
            "off (managed)"
        } else {
            "on"
        }
    }

    /// Static startup probe: returns `Some(reason)` only if the NIC or hypervisor cannot handle
    /// `CHECKSUM_PARTIAL` with a shifted `csum_start`.
    fn sniff_nic_requires_tx_off(iface: &str) -> Option<&'static str> {
        // 1. Check DMI for Google Compute Engine (Andromeda vSwitch drops VIRTIO_NET_HDR_F_NEEDS_CSUM
        //    packets when csum_start != 34 even though guest virtio_net reports tx-checksum-ip-generic).
        for path in [
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/board_vendor",
        ] {
            if let Ok(content) = fs::read_to_string(path) {
                if content.contains("Google") {
                    return Some("auto-sniffed Google Compute Engine vSwitch");
                }
            }
        }

        // 2. Check ethtool -k <iface> feature flags:
        //    NICs like AWS ENA or Intel ixgbe/i40e have `tx-checksum-ip-generic: off [fixed]` and only
        //    support protocol-specific `tx-checksum-ipv4` (which hardcodes L4 TCP checksum at offset 50).
        if let Ok(out) = std::process::Command::new("ethtool")
            .args(["-k", iface])
            .output()
        {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut generic_fixed_off = false;
                let mut generic_on = false;
                let mut ipv4_on = false;

                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("tx-checksum-ip-generic:") {
                        let val = rest.trim();
                        if val.starts_with("on") {
                            generic_on = true;
                        } else if val.contains("[fixed]") {
                            generic_fixed_off = true;
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("tx-checksum-ipv4:") {
                        let val = rest.trim();
                        if val.starts_with("on") {
                            ipv4_on = true;
                        }
                    }
                }

                if generic_fixed_off || (ipv4_on && !generic_on) {
                    return Some("auto-sniffed protocol-specific NIC without tx-checksum-ip-generic");
                }
            }
        }

        None
    }

    fn disable_offload(&mut self, reason: &str) {
        if self.disabled_by_us {
            return;
        }
        match std::process::Command::new("ethtool")
            .args(["-K", &self.iface, "tx", "off"])
            .output()
        {
            Ok(out) if out.status.success() => {
                self.disabled_by_us = true;
                log::info!(
                    "Disabled TX checksum offload on {} ({}; will restore on exit)",
                    self.iface,
                    reason
                );
            }
            Ok(out) => {
                log::warn!(
                    "ethtool -K {} tx off exited with {}: {}",
                    self.iface,
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => {
                log::warn!("Failed to run ethtool -K {} tx off: {}", self.iface, e);
            }
        }
    }

    /// Runtime traffic anomaly sniffer: if `Auto` kept TX offload ON at startup, monitors eBPF
    /// counters and automatically disables TX offload if egress packets are being dropped by the
    /// underlying hypervisor/NIC.
    pub fn observe_stats(&mut self, prev: &RudpStats, curr: &RudpStats, is_server: bool) {
        if !self.uses_tc_egress || self.mode != TxOffloadMode::Auto || self.disabled_by_us {
            return;
        }

        if is_server {
            // On server: if TC Egress has transmitted >= 3 replies, but the peer only keeps
            // retransmitting 148-byte handshake initiations without advancing to data packets,
            // our TC Egress replies are being dropped by the NIC/hypervisor.
            let delta_tx = curr.tx_pkts.saturating_sub(prev.tx_pkts);
            let delta_rx = curr.rx_pkts.saturating_sub(prev.rx_pkts);
            if curr.tx_pkts >= 3
                && delta_tx >= 1
                && delta_rx >= 1
                && curr.rx_pkts > 0
                && (curr.rx_bytes / curr.rx_pkts) == 148
                && (curr.tx_bytes / curr.tx_pkts) == 92
            {
                self.disable_offload("runtime auto-sniffed TC Egress response drop");
            }
        } else {
            // On transparent client: if TC Egress has encapsulated and sent >= 3 packets after
            // handshake completion, but 0 data packets have been received back from the server.
            if curr.tx_pkts >= 3 && curr.rx_pkts == 0 {
                self.disable_offload("runtime auto-sniffed TC Egress blackhole (tx_pkts>=3, rx_pkts=0)");
            }
        }
    }

    pub fn restore(&mut self) {
        if self.disabled_by_us {
            let _ = std::process::Command::new("ethtool")
                .args(["-K", &self.iface, "tx", "on", "tso", "on"])
                .output();
            log::info!("Restored TX checksum offload and TSO on {}", self.iface);
            self.disabled_by_us = false;
        }
    }
}

impl Drop for TxOffloadManager {
    fn drop(&mut self) {
        self.restore();
    }
}
