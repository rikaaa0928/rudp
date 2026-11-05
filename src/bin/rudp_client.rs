use aya::maps::{Array, HashMap as BpfHashMap};
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use clap::Parser;
use log::{error, info, warn};
use rand::Rng;
use rudp::{
    build_ipv4_tcp_packet, detect_interface, enable_local_routing_sysctls, encode_payload,
    ktime_get_ns, load_ebpf, reset_clsact, ConnState, PeerKey, RawTcpSocket, RudpConfig,
    RudpStats, STATE_ESTABLISHED, STATE_SYN_RECEIVED, STATE_SYN_SENT, TCP_FLAG_ACK, TCP_FLAG_RST,
    TCP_FLAG_SYN,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};

const CONN_TIMEOUT_NS: u64 = 180_000_000_000;
const SYN_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_SYN_RETRIES: u32 = 6;

struct PendingHandshake {
    peer_addr: SocketAddr,
    local_tcp_port: u16,
    port_be32: u32,
    initial_seq: u32,
    attempts: u32,
    last_sent: Instant,
    pending_payloads: Vec<Vec<u8>>,
}

#[derive(Parser, Debug)]
#[command(name = "rudp_client", version, about = "eBPF-accelerated UDP-to-FakeTCP Client")]
struct Args {
    /// Local UDP listen address:port or port (optional in --transparent mode; defaults to remote port)
    #[arg(short = 'l', long = "local")]
    local: Option<String>,

    /// Remote Fake-TCP server host:port (e.g. server.example.com:12345)
    #[arg(short = 'r', long = "remote")]
    remote: String,

    /// Transparent mode: automatically hijack UDP packets to <remote_ip>:<local_port> without modifying client Endpoint
    #[arg(short = 't', long = "transparent", env = "RUDP_TRANSPARENT", default_value_t = false)]
    transparent: bool,

    /// Network interface to attach TC eBPF programs to (auto-detected if omitted)
    #[arg(short = 'i', long = "interface", default_value = "")]
    interface: String,

    /// Prefix outgoing payload with random padding header
    #[arg(long = "payload-padding", default_value_t = false)]
    payload_padding: bool,

    /// Maximum random even padding length (2..=254, rounded down to even)
    #[arg(long = "payload-padding-max-len", default_value_t = 4)]
    payload_padding_max_len: u8,

    /// Occasionally send dummy obfuscation packets
    #[arg(long = "obfuscate", env = "RUDP_OBFUSCATE", default_value_t = false)]
    obfuscate: bool,

    /// Probability (in percent) to send an obfuscation packet
    #[arg(long = "obfuscate-prob", env = "RUDP_OBFUSCATE_PROB", default_value_t = 5.0)]
    obfuscate_prob: f64,

    /// Maximum random padding length for an obfuscation packet (4..=255)
    #[arg(long = "obfuscate-max-len", env = "RUDP_OBFUSCATE_MAX_LEN", default_value_t = 255)]
    obfuscate_max_len: u8,

    /// Use realistic TCP options and PSH|ACK flags
    #[arg(long = "tcp-extensions", default_value_t = false)]
    tcp_extensions: bool,

    /// Optionally disable NIC TX checksum offload (`ethtool -K <iface> tx off`) in transparent mode and restore on exit
    #[arg(
        long = "disable-tx-offload",
        env = "RUDP_DISABLE_TX_OFFLOAD",
        default_value_t = true,
        num_args = 0..=1,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    disable_tx_offload: bool,

    /// Shorthand to keep NIC TX checksum offload and TSO enabled (equivalent to --disable-tx-offload=false)
    #[arg(long = "keep-tx-offload", default_value_t = false)]
    keep_tx_offload: bool,
}

fn parse_local_addr(s: &str) -> Result<SocketAddr, String> {
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)));
    }
    s.parse::<SocketAddr>()
        .map_err(|e| format!("invalid --local address or port '{s}': {e}"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let remote_addr = lookup_host(&args.remote)
        .await?
        .find(|a| a.is_ipv4())
        .ok_or("failed to resolve remote IPv4 address")?;
    let remote_ipv4 = match remote_addr.ip() {
        IpAddr::V4(ip) => ip,
        _ => unreachable!(),
    };
    let remote_port = remote_addr.port();

    let parsed_local = match args.local.as_deref() {
        Some(s) if !s.is_empty() => Some(parse_local_addr(s)?),
        _ => None,
    };

    let (bind_addr, local_port) = if args.transparent {
        let target_port = parsed_local.map(|a| a.port()).unwrap_or(remote_port);
        (
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            target_port,
        )
    } else {
        let addr = parsed_local
            .ok_or("--local <ADDR:PORT|PORT> is required unless --transparent is enabled")?;
        (addr, addr.port())
    };

    info!("Resolved remote server: {}:{}", remote_ipv4, remote_port);

    let net_if = detect_interface(Some(&args.interface), remote_ipv4)?;
    info!(
        "Detected interface {} (IPv4={}, MAC={:02x?}, GW_MAC={:02x?})",
        net_if.name, net_if.ipv4, net_if.mac, net_if.gateway_mac
    );

    let udp_sock = UdpSocket::bind(bind_addr).await?;
    let internal_udp_port = udp_sock.local_addr()?.port();
    let raw_sock = RawTcpSocket::new()?;

    let mut ebpf = load_ebpf()?;

    let cfg = RudpConfig {
        mode: 0,
        local_ip: u32::from(net_if.ipv4).to_be(),
        remote_ip: u32::from(remote_ipv4).to_be(),
        local_port,
        remote_port,
        padding_enabled: u8::from(args.payload_padding),
        padding_max_len: args.payload_padding_max_len.clamp(2, 254),
        obfuscate_enabled: u8::from(args.obfuscate),
        tcp_extensions: u8::from(args.tcp_extensions),
        obfuscate_prob_bp: ((args.obfuscate_prob.clamp(0.0, 100.0)) * 100.0) as u32,
        obfuscate_max_len: args.obfuscate_max_len.max(4),
        transparent: u8::from(args.transparent),
        internal_udp_port,
        local_mac: net_if.mac,
        gateway_mac: net_if.gateway_mac,
    };

    {
        let mut cfg_map: Array<_, RudpConfig> = Array::try_from(ebpf.map_mut("RUDP_CFG").unwrap())?;
        cfg_map.set(0, cfg, 0)?;
    }

    enable_local_routing_sysctls(&net_if.name);

    if let Err(e) = tc::qdisc_add_clsact(&net_if.name) {
        warn!("qdisc_add_clsact on {}: {} (continuing)", net_if.name, e);
    }
    reset_clsact(&net_if.name, local_port);

    let manage_tx_offload = args.transparent && args.disable_tx_offload && !args.keep_tx_offload;
    if manage_tx_offload {
        match std::process::Command::new("ethtool")
            .args(["-K", &net_if.name, "tx", "off"])
            .output()
        {
            Ok(_) => info!("Disabled TX checksum offload on {} (will restore on exit)", net_if.name),
            Err(e) => warn!("Failed to run ethtool -K {} tx off: {}", net_if.name, e),
        }
    }

    let ingress_prog: &mut SchedClassifier = ebpf
        .program_mut("rudp_client_ingress")
        .unwrap()
        .try_into()?;
    ingress_prog.load()?;
    let _ingress_link = ingress_prog.attach_with_options(
        &net_if.name,
        TcAttachType::Ingress,
        TcAttachOptions::Netlink(NlOptions {
            priority: local_port,
            handle: 1,
        }),
    )?;

    let _egress_link = if args.transparent {
        let egress_prog: &mut SchedClassifier = ebpf
            .program_mut("rudp_client_egress")
            .unwrap()
            .try_into()?;
        egress_prog.load()?;
        Some(egress_prog.attach_with_options(
            &net_if.name,
            TcAttachType::Egress,
            TcAttachOptions::Netlink(NlOptions {
                priority: local_port,
                handle: 1,
            }),
        )?)
    } else {
        None
    };

    if args.transparent {
        info!(
            "rudp_client eBPF attached to {} [TRANSPARENT MODE] (hijacking UDP {} -> FakeTCP {}:{}, internal_udp_port={}, padding={}, tcp_ext={}, obfuscate={}, disable_tx_offload={})",
            net_if.name,
            SocketAddrV4::new(remote_ipv4, local_port),
            remote_ipv4,
            remote_port,
            internal_udp_port,
            args.payload_padding,
            args.tcp_extensions,
            args.obfuscate,
            manage_tx_offload
        );
    } else {
        info!(
            "rudp_client eBPF attached to {} (UDP listen={} -> FakeTCP remote={}:{}, padding={}, tcp_ext={}, obfuscate={})",
            net_if.name,
            bind_addr,
            remote_ipv4,
            remote_port,
            args.payload_padding,
            args.tcp_extensions,
            args.obfuscate
        );
    }

    let mut buf = [0u8; 2048];
    let mut pending_handshakes: HashMap<PeerKey, PendingHandshake> = HashMap::new();
    let mut last_stats = RudpStats::default();
    let mut handshake_ticker = tokio::time::interval(Duration::from_millis(15));
    let mut stats_ticker = tokio::time::interval(Duration::from_secs(5));
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            res = udp_sock.recv_from(&mut buf) => {
                let (size, peer_addr) = res?;
                let peer_ipv4 = match peer_addr.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => continue,
                };
                let ukey = PeerKey {
                    ip: u32::from(peer_ipv4).to_be(),
                    port: peer_addr.port().to_be(),
                    _pad: 0,
                };

                // If handshake is already in progress for this UDP client, buffer the packet
                if let Some(ph) = pending_handshakes.get_mut(&ukey) {
                    if ph.pending_payloads.len() < 16 {
                        ph.pending_payloads.push(buf[..size].to_vec());
                    }
                    continue;
                }

                let now = ktime_get_ns();

                // Check if an established connection already exists in BPF map
                let existing_port = {
                    let client_by_udp: BpfHashMap<_, PeerKey, u32> =
                        BpfHashMap::try_from(ebpf.map("CLIENT_BY_UDP").unwrap())?;
                    client_by_udp.get(&ukey, 0).ok()
                };

                if let Some(port_be32) = existing_port {
                    let mut client_conns: BpfHashMap<_, u32, ConnState> =
                        BpfHashMap::try_from(ebpf.map_mut("CLIENT_CONNS").unwrap())?;
                    if let Ok(mut conn) = client_conns.get(&port_be32, 0) {
                        if conn.state == STATE_ESTABLISHED && now.saturating_sub(conn.last_seen_ns) <= CONN_TIMEOUT_NS {
                            let encoded = encode_payload(&buf[..size], args.payload_padding, args.payload_padding_max_len);
                            let local_tcp_port = u16::from_be(conn.local_tcp_port);
                            let pkt = build_ipv4_tcp_packet(
                                net_if.ipv4,
                                remote_ipv4,
                                local_tcp_port,
                                remote_port,
                                conn.seq,
                                conn.ack,
                                TCP_FLAG_ACK,
                                args.tcp_extensions,
                                &encoded,
                            );
                            let _ = raw_sock.send_to(&pkt, remote_ipv4, remote_port);
                            conn.seq = conn.seq.wrapping_add(encoded.len() as u32);
                            conn.last_seen_ns = now;
                            let _ = client_conns.insert(port_be32, conn, 0);
                            continue;
                        }
                    }
                }

                // Allocate a non-conflicting ephemeral TCP port and initiate non-blocking SYN handshake
                let mut local_tcp_port: u16 = rand::thread_rng().gen_range(32768..=60999);
                {
                    let client_conns: BpfHashMap<_, u32, ConnState> =
                        BpfHashMap::try_from(ebpf.map("CLIENT_CONNS").unwrap())?;
                    for _ in 0..1024 {
                        let candidate_be32 = (local_tcp_port.to_be()) as u32;
                        if client_conns.get(&candidate_be32, 0).is_err() {
                            break;
                        }
                        local_tcp_port = if local_tcp_port == 60999 {
                            32768
                        } else {
                            local_tcp_port + 1
                        };
                    }
                }
                let port_be16 = local_tcp_port.to_be();
                let port_be32 = port_be16 as u32;
                let initial_seq: u32 = rand::thread_rng().gen();

                let orig_dst_ip = if args.transparent {
                    u32::from(remote_ipv4).to_be()
                } else if peer_ipv4.is_loopback() {
                    u32::from(Ipv4Addr::LOCALHOST).to_be()
                } else {
                    u32::from(net_if.ipv4).to_be()
                };

                info!(
                    "New UDP client {}, initiating Fake-TCP handshake (local_port={} -> {}:{})",
                    peer_addr, local_tcp_port, remote_ipv4, remote_port
                );

                let init_conn = ConnState {
                    client_ip: ukey.ip,
                    client_port: ukey.port,
                    local_tcp_port: port_be16,
                    seq: initial_seq,
                    ack: 0,
                    state: STATE_SYN_SENT,
                    orig_dst_ip,
                    last_seen_ns: now,
                    peer_mac: net_if.gateway_mac,
                    local_mac: net_if.mac,
                    _pad1: 0,
                };

                {
                    let mut client_conns: BpfHashMap<_, u32, ConnState> =
                        BpfHashMap::try_from(ebpf.map_mut("CLIENT_CONNS").unwrap())?;
                    client_conns.insert(port_be32, init_conn, 0)?;
                }
                {
                    let mut client_by_udp: BpfHashMap<_, PeerKey, u32> =
                        BpfHashMap::try_from(ebpf.map_mut("CLIENT_BY_UDP").unwrap())?;
                    client_by_udp.insert(ukey, port_be32, 0)?;
                }

                let syn_pkt = build_ipv4_tcp_packet(
                    net_if.ipv4,
                    remote_ipv4,
                    local_tcp_port,
                    remote_port,
                    initial_seq,
                    0,
                    TCP_FLAG_SYN,
                    args.tcp_extensions,
                    &[],
                );
                if let Err(e) = raw_sock.send_to(&syn_pkt, remote_ipv4, remote_port) {
                    error!("Failed to send SYN for {}: {}", peer_addr, e);
                } else {
                    info!("Sent SYN to {}:{} for {} (attempt 1)", remote_ipv4, remote_port, peer_addr);
                }

                pending_handshakes.insert(
                    ukey,
                    PendingHandshake {
                        peer_addr,
                        local_tcp_port,
                        port_be32,
                        initial_seq,
                        attempts: 1,
                        last_sent: Instant::now(),
                        pending_payloads: vec![buf[..size].to_vec()],
                    },
                );
            }
            _ = handshake_ticker.tick() => {
                if pending_handshakes.is_empty() {
                    continue;
                }
                let mut completed_or_failed = Vec::new();
                for (&ukey, ph) in pending_handshakes.iter_mut() {
                    let conn_opt = {
                        let client_conns: BpfHashMap<_, u32, ConnState> =
                            BpfHashMap::try_from(ebpf.map("CLIENT_CONNS").unwrap())?;
                        client_conns.get(&ph.port_be32, 0).ok()
                    };

                    let Some(mut conn) = conn_opt else {
                        // Entry was removed (e.g. by incoming RST)
                        completed_or_failed.push((ukey, ph.port_be32, false));
                        continue;
                    };

                    if conn.state == STATE_SYN_RECEIVED || conn.state == STATE_ESTABLISHED {
                        for payload in &ph.pending_payloads {
                            let encoded = encode_payload(
                                payload,
                                args.payload_padding,
                                args.payload_padding_max_len,
                            );
                            let data_pkt = build_ipv4_tcp_packet(
                                net_if.ipv4,
                                remote_ipv4,
                                ph.local_tcp_port,
                                remote_port,
                                conn.seq,
                                conn.ack,
                                TCP_FLAG_ACK,
                                args.tcp_extensions,
                                &encoded,
                            );
                            let _ = raw_sock.send_to(&data_pkt, remote_ipv4, remote_port);
                            conn.seq = conn.seq.wrapping_add(encoded.len() as u32);
                        }
                        conn.last_seen_ns = ktime_get_ns();
                        conn.state = STATE_ESTABLISHED;
                        {
                            let mut client_conns: BpfHashMap<_, u32, ConnState> =
                                BpfHashMap::try_from(ebpf.map_mut("CLIENT_CONNS").unwrap())?;
                            let _ = client_conns.insert(ph.port_be32, conn, 0);
                        }
                        info!(
                            "Connection to {}:{} established for {} (local_tcp_port={}) — eBPF fastpath active!",
                            remote_ipv4, remote_port, ph.peer_addr, ph.local_tcp_port
                        );
                        completed_or_failed.push((ukey, ph.port_be32, true));
                    } else if ph.last_sent.elapsed() >= SYN_RETRY_INTERVAL {
                        if ph.attempts >= MAX_SYN_RETRIES {
                            error!(
                                "Handshake with {}:{} timed out for {}",
                                remote_ipv4, remote_port, ph.peer_addr
                            );
                            completed_or_failed.push((ukey, ph.port_be32, false));
                        } else {
                            ph.attempts += 1;
                            ph.last_sent = Instant::now();
                            let syn_pkt = build_ipv4_tcp_packet(
                                net_if.ipv4,
                                remote_ipv4,
                                ph.local_tcp_port,
                                remote_port,
                                ph.initial_seq,
                                0,
                                TCP_FLAG_SYN,
                                args.tcp_extensions,
                                &[],
                            );
                            let _ = raw_sock.send_to(&syn_pkt, remote_ipv4, remote_port);
                            info!(
                                "Sent SYN to {}:{} for {} (attempt {})",
                                remote_ipv4, remote_port, ph.peer_addr, ph.attempts
                            );
                        }
                    }
                }

                for (ukey, port_be32, ok) in completed_or_failed {
                    pending_handshakes.remove(&ukey);
                    if !ok {
                        let mut client_by_udp: BpfHashMap<_, PeerKey, u32> =
                            BpfHashMap::try_from(ebpf.map_mut("CLIENT_BY_UDP").unwrap())?;
                        let _ = client_by_udp.remove(&ukey);
                        let mut client_conns: BpfHashMap<_, u32, ConnState> =
                            BpfHashMap::try_from(ebpf.map_mut("CLIENT_CONNS").unwrap())?;
                        let _ = client_conns.remove(&port_be32);
                    }
                }
            }
            _ = stats_ticker.tick() => {
                // 1. Log eBPF dataplane counters
                {
                    let stats_map: Array<_, RudpStats> = Array::try_from(ebpf.map("RUDP_STATS").unwrap())?;
                    if let Ok(s) = stats_map.get(&0, 0) {
                        if s.rx_pkts != last_stats.rx_pkts || s.tx_pkts != last_stats.tx_pkts || s.handshakes != last_stats.handshakes {
                            info!(
                                "eBPF stats: handshakes={} tx_pkts={} ({} B) rx_pkts={} ({} B) obf_tx={} obf_rx={} drops={}",
                                s.handshakes, s.tx_pkts, s.tx_bytes, s.rx_pkts, s.rx_bytes, s.tx_obfuscate_pkts, s.rx_obfuscate_pkts, s.drops
                            );
                            last_stats = s;
                        }
                    }
                }

                // 2. Sweep idle connections (> 180s) and send TCP RST to server
                let now = ktime_get_ns();
                let mut expired = Vec::new();
                {
                    let client_conns: BpfHashMap<_, u32, ConnState> =
                        BpfHashMap::try_from(ebpf.map("CLIENT_CONNS").unwrap())?;
                    for item in client_conns.iter() {
                        if let Ok((port_be32, conn)) = item {
                            if now.saturating_sub(conn.last_seen_ns) > CONN_TIMEOUT_NS {
                                expired.push((port_be32, conn));
                            }
                        }
                    }
                }
                if !expired.is_empty() {
                    for (port_be32, conn) in expired {
                        let ukey = PeerKey {
                            ip: conn.client_ip,
                            port: conn.client_port,
                            _pad: 0,
                        };
                        let local_tcp_port = u16::from_be(conn.local_tcp_port);
                        let rst_pkt = build_ipv4_tcp_packet(
                            net_if.ipv4,
                            remote_ipv4,
                            local_tcp_port,
                            remote_port,
                            conn.seq,
                            conn.ack,
                            TCP_FLAG_RST | TCP_FLAG_ACK,
                            false,
                            &[],
                        );
                        let _ = raw_sock.send_to(&rst_pkt, remote_ipv4, remote_port);
                        {
                            let mut client_by_udp: BpfHashMap<_, PeerKey, u32> =
                                BpfHashMap::try_from(ebpf.map_mut("CLIENT_BY_UDP").unwrap())?;
                            let _ = client_by_udp.remove(&ukey);
                        }
                        {
                            let mut client_conns: BpfHashMap<_, u32, ConnState> =
                                BpfHashMap::try_from(ebpf.map_mut("CLIENT_CONNS").unwrap())?;
                            let _ = client_conns.remove(&port_be32);
                        }
                        info!(
                            "Recycled idle Fake-TCP connection (local_tcp_port={}, client={}:{})",
                            local_tcp_port,
                            Ipv4Addr::from(u32::from_be(conn.client_ip)),
                            u16::from_be(conn.client_port)
                        );
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, sending RST to active connections and detaching TC eBPF...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, sending RST to active connections and detaching TC eBPF...");
                break;
            }
        }
    }

    // Send TCP RST for all active connections on shutdown
    if let Ok(client_conns) = BpfHashMap::<_, u32, ConnState>::try_from(ebpf.map("CLIENT_CONNS").unwrap()) {
        for item in client_conns.iter() {
            if let Ok((_port_be32, conn)) = item {
                let local_tcp_port = u16::from_be(conn.local_tcp_port);
                let rst_pkt = build_ipv4_tcp_packet(
                    net_if.ipv4,
                    remote_ipv4,
                    local_tcp_port,
                    remote_port,
                    conn.seq,
                    conn.ack,
                    TCP_FLAG_RST | TCP_FLAG_ACK,
                    false,
                    &[],
                );
                let _ = raw_sock.send_to(&rst_pkt, remote_ipv4, remote_port);
            }
        }
    }

    if manage_tx_offload {
        let _ = std::process::Command::new("ethtool")
            .args(["-K", &net_if.name, "tx", "on", "tso", "on"])
            .output();
        info!("Restored TX checksum offload and TSO on {}", net_if.name);
    }

    Ok(())
}
