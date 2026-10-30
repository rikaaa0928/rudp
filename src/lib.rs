use rand::Rng;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;

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
    pub local_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub _pad: [u8; 3],
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
    pub _pad0: u32,
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
    let gateway_mac = read_gateway_mac(&if_name).unwrap_or([0; 6]);

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

fn read_gateway_mac(if_name: &str) -> Option<[u8; 6]> {
    let arp = fs::read_to_string("/proc/net/arp").ok()?;
    for line in arp.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 6 && cols[5] == if_name && cols[3] != "00:00:00:00:00:00" {
            if let Some(mac) = parse_mac(cols[3]) {
                return Some(mac);
            }
        }
    }
    None
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

/// Encodes payload with optional 2-byte sum header + random padding bytes.
pub fn encode_payload(payload: &[u8], padding_enabled: bool, max_len: u8) -> Vec<u8> {
    if !padding_enabled {
        return payload.to_vec();
    }
    let mut rng = rand::thread_rng();
    let max_pad = max_len.clamp(1, 5);
    let pad_len = rng.gen_range(1..=max_pad);
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
