use aya::maps::{Array, HashMap as BpfHashMap};
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use clap::Parser;
use log::{info, warn};
use rudp::{
    build_ipv4_tcp_packet, detect_interface, ktime_get_ns, load_ebpf, reset_clsact, ConnState,
    PeerKey, RawTcpSocket, RudpConfig, RudpStats, TCP_FLAG_ACK, TCP_FLAG_RST,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::lookup_host;
use tokio::signal::unix::{signal, SignalKind};

const CONN_TIMEOUT_NS: u64 = 180_000_000_000;

#[derive(Parser, Debug)]
#[command(name = "rudp_server", version, about = "eBPF-accelerated FakeTCP-to-UDP Server")]
struct Args {
    /// Local TCP port to listen on
    #[arg(short = 'l', long = "local")]
    local: u16,

    /// Remote UDP address:port to forward decapsulated packets to (e.g. 127.0.0.1:22809)
    #[arg(short = 'r', long = "remote")]
    remote: String,

    /// Network interface to attach TC eBPF programs to (auto-detected if omitted)
    #[arg(short = 'i', long = "interface", default_value = "")]
    interface: String,

    /// Prefix outgoing payload with random padding header
    #[arg(long = "payload-padding", default_value_t = false)]
    payload_padding: bool,

    /// Maximum random padding length (1..=5)
    #[arg(long = "payload-padding-max-len", default_value_t = 5)]
    payload_padding_max_len: u8,

    /// Occasionally send dummy obfuscation packets
    #[arg(long = "obfuscate", env = "PHANTUN_OBFUSCATE", default_value_t = false)]
    obfuscate: bool,

    /// Probability (in percent) to send an obfuscation packet
    #[arg(long = "obfuscate-prob", env = "PHANTUN_OBFUSCATE_PROB", default_value_t = 5.0)]
    obfuscate_prob: f64,

    /// Maximum random padding length for an obfuscation packet
    #[arg(long = "obfuscate-max-len", env = "PHANTUN_OBFUSCATE_MAX_LEN", default_value_t = 255)]
    obfuscate_max_len: u8,

    /// Use realistic TCP options and PSH|ACK flags
    #[arg(long = "tcp-extensions", default_value_t = false)]
    tcp_extensions: bool,

    /// Disable NIC TX checksum offload (`ethtool -K <iface> tx off`) on startup and restore `tx on tso on` on exit
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

    /// Compatibility flags with phantun CLI (ignored in eBPF mode)
    #[arg(long = "accept-nonzero-syn-seq", default_value_t = false)]
    accept_nonzero_syn_seq: bool,
    #[arg(long = "tun", default_value = "")]
    tun: String,
    #[arg(long = "tun-local", default_value = "")]
    tun_local: String,
    #[arg(long = "tun-peer", default_value = "")]
    tun_peer: String,
    #[arg(short = '4', long = "ipv4-only", default_value_t = false)]
    ipv4_only: bool,
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

    let net_if = detect_interface(Some(&args.interface), Ipv4Addr::new(8, 8, 8, 8))?;
    info!(
        "Detected interface {} (IPv4={}, MAC={:02x?}, GW_MAC={:02x?})",
        net_if.name, net_if.ipv4, net_if.mac, net_if.gateway_mac
    );

    let mut ebpf = load_ebpf()?;

    let cfg = RudpConfig {
        mode: 1,
        local_ip: u32::from(net_if.ipv4).to_be(),
        remote_ip: u32::from(remote_ipv4).to_be(),
        local_port: args.local,
        remote_port: remote_addr.port(),
        padding_enabled: u8::from(args.payload_padding),
        padding_max_len: args.payload_padding_max_len.clamp(1, 5),
        obfuscate_enabled: u8::from(args.obfuscate),
        tcp_extensions: u8::from(args.tcp_extensions),
        obfuscate_prob_bp: ((args.obfuscate_prob.clamp(0.0, 100.0)) * 100.0) as u32,
        obfuscate_max_len: args.obfuscate_max_len,
        local_mac: net_if.mac,
        gateway_mac: net_if.gateway_mac,
        _pad: [0; 3],
    };

    {
        let mut cfg_map: Array<_, RudpConfig> = Array::try_from(ebpf.map_mut("RUDP_CFG").unwrap())?;
        cfg_map.set(0, cfg, 0)?;
    }

    if let Err(e) = tc::qdisc_add_clsact(&net_if.name) {
        warn!("qdisc_add_clsact on {}: {} (continuing)", net_if.name, e);
    }
    reset_clsact(&net_if.name, args.local);

    let manage_tx_offload = args.disable_tx_offload && !args.keep_tx_offload;
    if manage_tx_offload {
        // Disable TX checksum offload on the interface so locally-originated UDP packets
        // enter TC Egress with CHECKSUM_NONE instead of CHECKSUM_PARTIAL (csum_offset=6).
        match std::process::Command::new("ethtool")
            .args(["-K", &net_if.name, "tx", "off"])
            .output()
        {
            Ok(_) => info!("Disabled TX checksum offload on {} (will restore on exit)", net_if.name),
            Err(e) => warn!("Failed to run ethtool -K {} tx off: {}", net_if.name, e),
        }
    }

    let ingress_prog: &mut SchedClassifier = ebpf
        .program_mut("rudp_server_ingress")
        .unwrap()
        .try_into()?;
    ingress_prog.load()?;
    let _ingress_link = ingress_prog.attach_with_options(
        &net_if.name,
        TcAttachType::Ingress,
        TcAttachOptions::Netlink(NlOptions {
            priority: args.local,
            handle: 1,
        }),
    )?;

    let egress_prog: &mut SchedClassifier = ebpf
        .program_mut("rudp_server_egress")
        .unwrap()
        .try_into()?;
    egress_prog.load()?;
    let _egress_link = egress_prog.attach_with_options(
        &net_if.name,
        TcAttachType::Egress,
        TcAttachOptions::Netlink(NlOptions {
            priority: args.local,
            handle: 1,
        }),
    )?;

    info!(
        "rudp_server eBPF attached to {} (TCP listen={} -> UDP target={}:{}, padding={}, tcp_ext={}, obfuscate={}, disable_tx_offload={})",
        net_if.name,
        args.local,
        remote_ipv4,
        remote_addr.port(),
        args.payload_padding,
        args.tcp_extensions,
        args.obfuscate,
        manage_tx_offload
    );

    let raw_sock = RawTcpSocket::new()?;
    let mut last_stats = RudpStats::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                {
                    let stats_map: Array<_, RudpStats> = Array::try_from(ebpf.map("RUDP_STATS").unwrap())?;
                    if let Ok(s) = stats_map.get(&0, 0) {
                        if s.rx_pkts != last_stats.rx_pkts || s.tx_pkts != last_stats.tx_pkts || s.handshakes != last_stats.handshakes {
                            info!(
                                "eBPF stats: handshakes={} rx_pkts={} ({} B) tx_pkts={} ({} B) obf_rx={} drops={}",
                                s.handshakes, s.rx_pkts, s.rx_bytes, s.tx_pkts, s.tx_bytes, s.rx_obfuscate_pkts, s.drops
                            );
                            last_stats = s;
                        }
                    }
                }

                // Sweep idle connections (> 180s) and send TCP RST to peer
                let now = ktime_get_ns();
                let mut expired = Vec::new();
                {
                    let server_conns: BpfHashMap<_, PeerKey, ConnState> =
                        BpfHashMap::try_from(ebpf.map("SERVER_CONNS").unwrap())?;
                    for item in server_conns.iter() {
                        if let Ok((key, conn)) = item {
                            if now.saturating_sub(conn.last_seen_ns) > CONN_TIMEOUT_NS {
                                expired.push((key, conn));
                            }
                        }
                    }
                }
                if !expired.is_empty() {
                    let mut server_conns: BpfHashMap<_, PeerKey, ConnState> =
                        BpfHashMap::try_from(ebpf.map_mut("SERVER_CONNS").unwrap())?;
                    for (key, conn) in expired {
                        let peer_ip = Ipv4Addr::from(u32::from_be(key.ip));
                        let peer_port = u16::from_be(key.port);
                        let rst_pkt = build_ipv4_tcp_packet(
                            net_if.ipv4,
                            peer_ip,
                            args.local,
                            peer_port,
                            conn.seq,
                            conn.ack,
                            TCP_FLAG_RST | TCP_FLAG_ACK,
                            false,
                            &[],
                        );
                        let _ = raw_sock.send_to(&rst_pkt, peer_ip, peer_port);
                        let _ = server_conns.remove(&key);
                        info!("Recycled idle Fake-TCP peer {}:{} (sent RST)", peer_ip, peer_port);
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, sending RST to peers and detaching TC eBPF programs...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, sending RST to peers and detaching TC eBPF programs...");
                break;
            }
        }
    }

    if let Ok(server_conns) = BpfHashMap::<_, PeerKey, ConnState>::try_from(ebpf.map("SERVER_CONNS").unwrap()) {
        for item in server_conns.iter() {
            if let Ok((key, conn)) = item {
                let peer_ip = Ipv4Addr::from(u32::from_be(key.ip));
                let peer_port = u16::from_be(key.port);
                let rst_pkt = build_ipv4_tcp_packet(
                    net_if.ipv4,
                    peer_ip,
                    args.local,
                    peer_port,
                    conn.seq,
                    conn.ack,
                    TCP_FLAG_RST | TCP_FLAG_ACK,
                    false,
                    &[],
                );
                let _ = raw_sock.send_to(&rst_pkt, peer_ip, peer_port);
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
