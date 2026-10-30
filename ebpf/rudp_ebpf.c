// SPDX-License-Identifier: GPL-2.0 OR MIT
// Self-contained TC eBPF dataplane for rudp (UDP <-> FakeTCP obfuscator)

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

/* TC actions */
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_UNSPEC  -1

/* Protocols & Constants */
#define ETH_ALEN        6
#define ETH_HLEN        14
#define ETH_P_IP        0x0800
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/* TCP flags */
#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80

/* BPF map types & flags */
#define BPF_MAP_TYPE_HASH       1
#define BPF_MAP_TYPE_ARRAY      2
#define BPF_MAP_TYPE_LRU_HASH   9

#define BPF_ANY         0
#define BPF_ADJ_ROOM_NET 0
#define BPF_ADJ_ROOM_MAC 1

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Connection states */
#define STATE_IDLE         0
#define STATE_SYN_SENT     1
#define STATE_SYN_RECEIVED 2
#define STATE_ESTABLISHED  3

/* Idle timeout in nanoseconds (180 seconds) */
#define CONN_TIMEOUT_NS    180000000000ULL
/* SYN retry interval in nanoseconds (1 second) */
#define SYN_RETRY_NS       1000000000ULL

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
};

struct ethhdr {
    __u8  h_dest[ETH_ALEN];
    __u8  h_source[ETH_ALEN];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8  ihl:4,
          version:4;
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8  res1:4,
          doff:4;
    __u8  flags;
    __be16 window;
    __u16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __u16 check;
} __attribute__((packed));

/* BPF Helper Declarations */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)9;
static long (*bpf_clone_redirect)(struct __sk_buff *skb, __u32 ifindex, __u64 flags) = (void *)13;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static long (*bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *)38;
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *)39;
static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *)50;

/* Shared Structs with Userspace */
struct rudp_config {
    __u32 mode;              /* 0 = client, 1 = server */
    __u32 local_ip;          /* Network byte order */
    __u32 remote_ip;         /* Network byte order */
    __u16 local_port;        /* Host byte order */
    __u16 remote_port;       /* Host byte order */
    __u8  padding_enabled;
    __u8  padding_max_len;   /* 1..=5 */
    __u8  obfuscate_enabled;
    __u8  tcp_extensions;
    __u32 obfuscate_prob_bp; /* 0..10000 (5.0% = 500) */
    __u8  obfuscate_max_len;
    __u8  local_mac[6];
    __u8  gateway_mac[6];
    __u8  _pad[3];
};

struct peer_key {
    __u32 ip;   /* Network byte order */
    __u16 port; /* Network byte order */
    __u16 _pad;
};

struct conn_state {
    __u32 client_ip;      /* Network byte order */
    __u16 client_port;    /* Network byte order */
    __u16 local_tcp_port; /* Network byte order */
    __u32 seq;            /* Host byte order */
    __u32 ack;            /* Host byte order */
    __u32 state;          /* STATE_* */
    __u32 _pad0;
    __u64 last_seen_ns;
    __u8  peer_mac[6];
    __u8  local_mac[6];
    __u32 _pad1;
};

struct rudp_stats {
    __u64 rx_pkts;
    __u64 rx_bytes;
    __u64 tx_pkts;
    __u64 tx_bytes;
    __u64 handshakes;
    __u64 rx_obfuscate_pkts;
    __u64 tx_obfuscate_pkts;
    __u64 drops;
};

/* BPF Maps */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rudp_config);
} RUDP_CFG SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rudp_stats);
} RUDP_STATS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct peer_key);
    __type(value, struct conn_state);
} SERVER_CONNS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct peer_key);
    __type(value, __u32); /* local_tcp_port in network byte order */
} CLIENT_BY_UDP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); /* local_tcp_port in network byte order */
    __type(value, struct conn_state);
} CLIENT_CONNS SEC(".maps");

/* Checksum Helpers */
static __always_inline __u16 compute_ip_csum(struct iphdr *ip) {
    ip->check = 0;
    __u16 *p = (__u16 *)ip;
    __u32 sum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        sum += p[i];
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~(__u16)sum;
}

static __always_inline __u16 compute_l4_csum(
    struct __sk_buff *skb,
    __u32 l4_len,
    __be32 saddr,
    __be32 daddr,
    __u8 proto
) {
    if (l4_len > 1500) {
        l4_len = 1500;
    }
    __u32 total_len = 34 + l4_len;
    if (total_len <= skb->len) {
        bpf_skb_pull_data(skb, total_len);
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u64 sum = 0;
    sum += (__u32)saddr & 0xffff;
    sum += (__u32)saddr >> 16;
    sum += (__u32)daddr & 0xffff;
    sum += (__u32)daddr >> 16;
    sum += (__u32)bpf_htons((__u16)proto);
    sum += (__u32)bpf_htons((__u16)l4_len);

    for (__u32 i = 0; i < 750; i++) {
        __u32 off = 34 + i * 2;
        if (i * 2 + 2 > l4_len)
            break;
        if (data + off + 2 > data_end)
            break;
        sum += *(__u16 *)(data + off);
    }

    if (l4_len & 1) {
        __u32 odd_off = 34 + (l4_len & 0xfffe);
        if (odd_off < 1560 && data + odd_off + 1 <= data_end) {
            sum += *(__u8 *)(data + odd_off);
        }
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~(__u16)sum;
}

static __always_inline void swap_eth_mac(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }
}

static __always_inline void copy_mac(__u8 dst[ETH_ALEN], const __u8 src[ETH_ALEN]) {
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        dst[i] = src[i];
    }
}

static __always_inline int store_padding(struct __sk_buff *skb, __u32 pad_len, __u32 rand_val) {
    __u8 pad_buf[8];
    __u8 b0 = 1 + ((rand_val >> 8) % 127);
    __u8 b1 = (__u8)pad_len - b0;
    pad_buf[0] = b0;
    pad_buf[1] = b1;

    __u32 r2 = bpf_get_prandom_u32();
    pad_buf[2] = (__u8)(r2 & 0xff);
    pad_buf[3] = (__u8)((r2 >> 8) & 0xff);
    pad_buf[4] = (__u8)((r2 >> 16) & 0xff);
    pad_buf[5] = (__u8)((r2 >> 24) & 0xff);
    pad_buf[6] = (__u8)((rand_val >> 16) & 0xff);
    pad_buf[7] = (__u8)((rand_val >> 24) & 0xff);

    switch (pad_len) {
    case 1:
        return bpf_skb_store_bytes(skb, 54, pad_buf, 3, 0);
    case 2:
        return bpf_skb_store_bytes(skb, 54, pad_buf, 4, 0);
    case 3:
        return bpf_skb_store_bytes(skb, 54, pad_buf, 5, 0);
    case 4:
        return bpf_skb_store_bytes(skb, 54, pad_buf, 6, 0);
    default:
        return bpf_skb_store_bytes(skb, 54, pad_buf, 7, 0);
    }
}

/* ============================================================================
 * SERVER TC INGRESS:
 * 1. Responds to incoming TCP SYN with SYN+ACK directly in kernel (0-RTT to userspace)
 * 2. Converts incoming Fake-TCP data packets into plain UDP for local backend (e.g. wg0)
 * 3. Absorbs handshake ACKs and dummy obfuscation packets
 * ============================================================================ */
SEC("classifier")
int rudp_server_ingress(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct rudp_config *cfg = bpf_map_lookup_elem(&RUDP_CFG, &zero);
    struct rudp_stats *stats = bpf_map_lookup_elem(&RUDP_STATS, &zero);
    if (!cfg || !stats)
        return TC_ACT_UNSPEC;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_UNSPEC;

    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60)
        return TC_ACT_UNSPEC;

    if (data + ETH_HLEN + ip_hdr_len + sizeof(struct tcphdr) > data_end) {
        if (bpf_skb_pull_data(skb, ETH_HLEN + ip_hdr_len + sizeof(struct tcphdr)) < 0)
            return TC_ACT_UNSPEC;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return TC_ACT_UNSPEC;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_UNSPEC;
    }

    struct tcphdr *tcp = data + ETH_HLEN + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (bpf_ntohs(tcp->dest) != cfg->local_port)
        return TC_ACT_UNSPEC;

    struct peer_key key = {
        .ip = ip->saddr,
        .port = tcp->source,
        ._pad = 0,
    };

    __u8 flags = tcp->flags;

    /* Handle RST */
    if (flags & TCP_FLAG_RST) {
        bpf_map_delete_elem(&SERVER_CONNS, &key);
        return TC_ACT_SHOT;
    }

    /* Handle SYN -> Reply with SYN+ACK in-place and redirect out */
    if ((flags & TCP_FLAG_SYN) && !(flags & (TCP_FLAG_ACK | TCP_FLAG_FIN))) {
        __u32 client_isn = bpf_ntohl(tcp->seq);
        __u32 server_isn = bpf_get_prandom_u32();

        struct conn_state new_conn = {};
        new_conn.client_ip = ip->saddr;
        new_conn.client_port = tcp->source;
        new_conn.local_tcp_port = tcp->dest;
        new_conn.seq = server_isn + 1;
        new_conn.ack = client_isn + 1;
        new_conn.state = STATE_ESTABLISHED;
        new_conn.last_seen_ns = bpf_ktime_get_ns();
        copy_mac(new_conn.peer_mac, eth->h_source);
        copy_mac(new_conn.local_mac, eth->h_dest);

        bpf_map_update_elem(&SERVER_CONNS, &key, &new_conn, BPF_ANY);
        __sync_fetch_and_add(&stats->handshakes, 1);

        struct ethhdr reply_eth = *eth;
        swap_eth_mac(&reply_eth);

        /* 20B IP + 28B TCP (20B header + 8B options: MSS 1460, NOP, WScale 14) */
        __u32 synack_tcp_len = 28;
        __u32 synack_total_len = ETH_HLEN + 20 + synack_tcp_len;

        struct iphdr reply_ip = {};
        reply_ip.version = 4;
        reply_ip.ihl = 5;
        reply_ip.tos = 0;
        reply_ip.tot_len = bpf_htons(20 + synack_tcp_len);
        reply_ip.id = (__be16)bpf_get_prandom_u32();
        reply_ip.frag_off = bpf_htons(0x4000);
        reply_ip.ttl = 64;
        reply_ip.protocol = IPPROTO_TCP;
        reply_ip.saddr = ip->daddr;
        reply_ip.daddr = ip->saddr;
        reply_ip.check = compute_ip_csum(&reply_ip);

        struct tcphdr reply_tcp = {};
        reply_tcp.source = tcp->dest;
        reply_tcp.dest = tcp->source;
        reply_tcp.seq = bpf_htonl(server_isn);
        reply_tcp.ack_seq = bpf_htonl(client_isn + 1);
        reply_tcp.doff = 7; /* 28 bytes */
        reply_tcp.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
        reply_tcp.window = bpf_htons(0xffff);
        reply_tcp.check = 0;
        reply_tcp.urg_ptr = 0;

        /* TCP Options: MSS(1460) + NOP + WScale(14) */
        __u8 tcp_opts[8] = { 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x0e };

        if (bpf_skb_change_tail(skb, synack_total_len, 0) < 0)
            return TC_ACT_SHOT;

        bpf_skb_store_bytes(skb, 0, &reply_eth, sizeof(reply_eth), 0);
        bpf_skb_store_bytes(skb, 14, &reply_ip, sizeof(reply_ip), 0);
        bpf_skb_store_bytes(skb, 34, &reply_tcp, sizeof(reply_tcp), 0);
        bpf_skb_store_bytes(skb, 54, tcp_opts, sizeof(tcp_opts), 0);

        __u16 csum = compute_l4_csum(skb, synack_tcp_len, reply_ip.saddr, reply_ip.daddr, IPPROTO_TCP);
        bpf_skb_store_bytes(skb, 34 + 16, &csum, sizeof(csum), 0);

        return bpf_redirect(skb->ifindex, 0);
    }

    /* Lookup existing connection */
    struct conn_state *conn = bpf_map_lookup_elem(&SERVER_CONNS, &key);
    __u64 now = bpf_ktime_get_ns();
    if (!conn || (now - conn->last_seen_ns) > CONN_TIMEOUT_NS) {
        if (conn) {
            bpf_map_delete_elem(&SERVER_CONNS, &key);
        }
        __sync_fetch_and_add(&stats->drops, 1);

        /* Send RST+ACK back so client immediately re-handshakes */
        struct ethhdr rst_eth = *eth;
        swap_eth_mac(&rst_eth);

        struct iphdr rst_ip = {};
        rst_ip.version = 4;
        rst_ip.ihl = 5;
        rst_ip.tos = 0;
        rst_ip.tot_len = bpf_htons(40);
        rst_ip.id = (__be16)bpf_get_prandom_u32();
        rst_ip.frag_off = bpf_htons(0x4000);
        rst_ip.ttl = 64;
        rst_ip.protocol = IPPROTO_TCP;
        rst_ip.saddr = ip->daddr;
        rst_ip.daddr = ip->saddr;
        rst_ip.check = compute_ip_csum(&rst_ip);

        struct tcphdr rst_tcp = {};
        rst_tcp.source = tcp->dest;
        rst_tcp.dest = tcp->source;
        rst_tcp.seq = tcp->ack_seq;
        rst_tcp.ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
        rst_tcp.doff = 5;
        rst_tcp.flags = TCP_FLAG_RST | TCP_FLAG_ACK;
        rst_tcp.window = 0;
        rst_tcp.check = 0;
        rst_tcp.urg_ptr = 0;

        if (bpf_skb_change_tail(skb, ETH_HLEN + 40, 0) < 0)
            return TC_ACT_SHOT;

        bpf_skb_store_bytes(skb, 0, &rst_eth, sizeof(rst_eth), 0);
        bpf_skb_store_bytes(skb, 14, &rst_ip, sizeof(rst_ip), 0);
        bpf_skb_store_bytes(skb, 34, &rst_tcp, sizeof(rst_tcp), 0);

        __u16 csum = compute_l4_csum(skb, 20, rst_ip.saddr, rst_ip.daddr, IPPROTO_TCP);
        bpf_skb_store_bytes(skb, 34 + 16, &csum, sizeof(csum), 0);

        return bpf_redirect(skb->ifindex, 0);
    }

    __u32 tcp_hdr_len = (__u32)tcp->doff * 4;
    __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
    if (tcp_hdr_len < 20 || ip_tot_len < ip_hdr_len + tcp_hdr_len)
        return TC_ACT_SHOT;

    __u32 tcp_payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
    conn->last_seen_ns = now;

    /* Pure ACK (e.g. handshake completion ACK or keepalive ACK) */
    if (tcp_payload_len == 0) {
        return TC_ACT_SHOT;
    }

    __u32 seq = bpf_ntohl(tcp->seq);
    conn->ack = seq + tcp_payload_len;

    /* Decode optional payload padding */
    __u32 pad_total = 0;
    if (cfg->padding_enabled) {
        if (tcp_payload_len < 2)
            return TC_ACT_SHOT;
        __u8 hdr[2] = {0, 0};
        if (bpf_skb_load_bytes(skb, ETH_HLEN + ip_hdr_len + tcp_hdr_len, hdr, 2) < 0)
            return TC_ACT_SHOT;
        __u32 pad_len = (__u8)(hdr[0] + hdr[1]);
        if (pad_len == 0 || tcp_payload_len < 2 + pad_len)
            return TC_ACT_SHOT;
        pad_total = 2 + pad_len;
    }

    __u32 udp_payload_len = tcp_payload_len - pad_total;
    if (udp_payload_len == 0) {
        /* Dummy obfuscation packet: absorb in kernel */
        __sync_fetch_and_add(&stats->rx_obfuscate_pkts, 1);
        return TC_ACT_SHOT;
    }

    __be32 saddr = ip->saddr;
    __be32 daddr = ip->daddr;
    __u8 tos = ip->tos;
    __be16 ip_id = ip->id;
    __u8 ttl = ip->ttl;

    /* Shrink from (ip_hdr_len + tcp_hdr_len + pad_total) to (20B IP + 8B UDP) */
    __s32 shrink_len = (__s32)(ip_hdr_len + tcp_hdr_len + pad_total) - 28;
    if (bpf_skb_adjust_room(skb, -shrink_len, BPF_ADJ_ROOM_NET, 0) < 0) {
        __sync_fetch_and_add(&stats->drops, 1);
        return TC_ACT_SHOT;
    }

    struct iphdr new_ip = {};
    new_ip.version = 4;
    new_ip.ihl = 5;
    new_ip.tos = tos;
    new_ip.tot_len = bpf_htons(28 + udp_payload_len);
    new_ip.id = ip_id;
    new_ip.frag_off = bpf_htons(0x4000);
    new_ip.ttl = ttl;
    new_ip.protocol = IPPROTO_UDP;
    new_ip.saddr = saddr;
    new_ip.daddr = daddr;
    new_ip.check = compute_ip_csum(&new_ip);

    struct udphdr new_udp = {};
    new_udp.source = key.port;
    new_udp.dest = bpf_htons(cfg->remote_port);
    new_udp.len = bpf_htons(8 + udp_payload_len);
    new_udp.check = 0; /* Valid for IPv4 UDP local delivery */

    bpf_skb_store_bytes(skb, 14, &new_ip, sizeof(new_ip), 0);
    bpf_skb_store_bytes(skb, 34, &new_udp, sizeof(new_udp), 0);

    __sync_fetch_and_add(&stats->rx_pkts, 1);
    __sync_fetch_and_add(&stats->rx_bytes, udp_payload_len);

    return TC_ACT_OK;
}

/* ============================================================================
 * SERVER TC EGRESS:
 * Intercepts outgoing UDP packets from local backend (e.g. wg0 port 22809)
 * destined to known Fake-TCP peers and converts them in-place to Fake-TCP.
 * ============================================================================ */
SEC("classifier")
int rudp_server_egress(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct rudp_config *cfg = bpf_map_lookup_elem(&RUDP_CFG, &zero);
    struct rudp_stats *stats = bpf_map_lookup_elem(&RUDP_STATS, &zero);
    if (!cfg || !stats)
        return TC_ACT_UNSPEC;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_UNSPEC;

    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len != 20)
        return TC_ACT_UNSPEC;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (bpf_ntohs(udp->source) != cfg->remote_port)
        return TC_ACT_UNSPEC;

    struct peer_key key = {
        .ip = ip->daddr,
        .port = udp->dest,
        ._pad = 0,
    };

    struct conn_state *conn = bpf_map_lookup_elem(&SERVER_CONNS, &key);
    if (!conn || conn->state != STATE_ESTABLISHED)
        return TC_ACT_UNSPEC;

    __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
    if (ip_tot_len <= 28)
        return TC_ACT_UNSPEC;
    __u32 udp_payload_len = ip_tot_len - 28;

    __be32 saddr = ip->saddr;
    __be32 daddr = ip->daddr;
    __u8 tos = ip->tos;

    __u32 rand_val = bpf_get_prandom_u32();
    __u32 pad_len = 0;
    __u32 pad_total = 0;
    if (cfg->padding_enabled) {
        __u32 max_pad = cfg->padding_max_len;
        if (max_pad < 1) max_pad = 1;
        if (max_pad > 5) max_pad = 5;
        pad_len = 1 + (rand_val % max_pad);
        pad_total = 2 + pad_len;
    }

    __u32 tcp_payload_len = pad_total + udp_payload_len;
    __u32 tcp_total_len = 20 + tcp_payload_len;
    __s32 grow_len = (__s32)(12 + pad_total);

    __u32 seq = __sync_fetch_and_add(&conn->seq, tcp_payload_len);
    __u32 ack = conn->ack;
    conn->last_seen_ns = bpf_ktime_get_ns();

    if (bpf_skb_adjust_room(skb, grow_len, BPF_ADJ_ROOM_NET, 0) < 0) {
        __sync_fetch_and_add(&stats->drops, 1);
        return TC_ACT_SHOT;
    }

    struct iphdr new_ip = {};
    new_ip.version = 4;
    new_ip.ihl = 5;
    new_ip.tos = tos;
    new_ip.tot_len = bpf_htons(20 + tcp_total_len);
    new_ip.id = (__be16)(rand_val >> 16);
    new_ip.frag_off = bpf_htons(0x4000);
    new_ip.ttl = 64;
    new_ip.protocol = IPPROTO_TCP;
    new_ip.saddr = saddr;
    new_ip.daddr = daddr;
    new_ip.check = compute_ip_csum(&new_ip);

    struct tcphdr new_tcp = {};
    new_tcp.source = bpf_htons(cfg->local_port);
    new_tcp.dest = key.port;
    new_tcp.seq = bpf_htonl(seq);
    new_tcp.ack_seq = bpf_htonl(ack);
    new_tcp.doff = 5;
    new_tcp.flags = cfg->tcp_extensions ? (TCP_FLAG_ACK | TCP_FLAG_PSH) : TCP_FLAG_ACK;
    new_tcp.window = bpf_htons(0xffff);
    new_tcp.check = 0;
    new_tcp.urg_ptr = 0;

    bpf_skb_store_bytes(skb, 14, &new_ip, sizeof(new_ip), 0);
    bpf_skb_store_bytes(skb, 34, &new_tcp, sizeof(new_tcp), 0);

    if (cfg->padding_enabled) {
        store_padding(skb, pad_len, rand_val);
    }

    __u16 csum = compute_l4_csum(skb, tcp_total_len, saddr, daddr, IPPROTO_TCP);
    bpf_skb_store_bytes(skb, 34 + 16, &csum, sizeof(csum), 0);

    __sync_fetch_and_add(&stats->tx_pkts, 1);
    __sync_fetch_and_add(&stats->tx_bytes, udp_payload_len);

    return TC_ACT_OK;
}

/* ============================================================================
 * CLIENT TC INGRESS:
 * 1. Path A (UDP from WireGuard Client -> Fake-TCP to Server):
 *    - If connection is ESTABLISHED: zero-copy rewrites UDP to Fake-TCP and
 *      hairpin redirects out eth0 Egress.
 *    - If new connection: passes first UDP packet to userspace UdpSocket to
 *      initiate SYN handshake.
 * 2. Path B (Fake-TCP from Server -> UDP to WireGuard Client):
 *    - If SYN+ACK in SYN_SENT state: replies with TCP ACK in-place and marks
 *      connection as SYN_RECEIVED for userspace to flush first packet.
 *    - If data packet: strips Fake-TCP + padding, writes UDP header, and
 *      hairpin redirects out eth0 Egress to WireGuard Client.
 * ============================================================================ */
SEC("classifier")
int rudp_client_ingress(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct rudp_config *cfg = bpf_map_lookup_elem(&RUDP_CFG, &zero);
    struct rudp_stats *stats = bpf_map_lookup_elem(&RUDP_STATS, &zero);
    if (!cfg || !stats)
        return TC_ACT_UNSPEC;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;

    __u32 ip_hdr_len = (__u32)ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60)
        return TC_ACT_UNSPEC;

    /* ------------------------------------------------------------------------
     * PATH A: Incoming UDP packet to local_port (e.g. 9283)
     * ------------------------------------------------------------------------ */
    if (ip->protocol == IPPROTO_UDP && ip_hdr_len == 20) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_UNSPEC;

        if (bpf_ntohs(udp->dest) != cfg->local_port)
            return TC_ACT_UNSPEC;

        struct peer_key ukey = {
            .ip = ip->saddr,
            .port = udp->source,
            ._pad = 0,
        };

        __u32 *p_tcp_port = bpf_map_lookup_elem(&CLIENT_BY_UDP, &ukey);
        if (!p_tcp_port)
            return TC_ACT_UNSPEC; /* Pass to userspace UdpSocket to start handshake */

        struct conn_state *conn = bpf_map_lookup_elem(&CLIENT_CONNS, p_tcp_port);
        if (!conn)
            return TC_ACT_UNSPEC;

        __u64 now = bpf_ktime_get_ns();
        if (conn->state != STATE_ESTABLISHED || (now - conn->last_seen_ns) > CONN_TIMEOUT_NS) {
            return TC_ACT_UNSPEC;
        }

        __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
        if (ip_tot_len <= 28)
            return TC_ACT_SHOT;
        __u32 udp_payload_len = ip_tot_len - 28;

        struct ethhdr new_eth = *eth;
        swap_eth_mac(&new_eth);

        __u32 rand_val = bpf_get_prandom_u32();
        __u32 pad_len = 0;
        __u32 pad_total = 0;
        if (cfg->padding_enabled) {
            __u32 max_pad = cfg->padding_max_len;
            if (max_pad < 1) max_pad = 1;
            if (max_pad > 5) max_pad = 5;
            pad_len = 1 + (rand_val % max_pad);
            pad_total = 2 + pad_len;
        }

        __u32 tcp_payload_len = pad_total + udp_payload_len;
        __u32 tcp_total_len = 20 + tcp_payload_len;
        __s32 grow_len = (__s32)(12 + pad_total);

        __u32 seq = __sync_fetch_and_add(&conn->seq, tcp_payload_len);
        __u32 ack = conn->ack;
        conn->last_seen_ns = now;

        if (bpf_skb_adjust_room(skb, grow_len, BPF_ADJ_ROOM_NET, 0) < 0) {
            __sync_fetch_and_add(&stats->drops, 1);
            return TC_ACT_SHOT;
        }

        struct iphdr new_ip = {};
        new_ip.version = 4;
        new_ip.ihl = 5;
        new_ip.tos = 0;
        new_ip.tot_len = bpf_htons(20 + tcp_total_len);
        new_ip.id = (__be16)(rand_val >> 16);
        new_ip.frag_off = bpf_htons(0x4000);
        new_ip.ttl = 64;
        new_ip.protocol = IPPROTO_TCP;
        new_ip.saddr = cfg->local_ip;
        new_ip.daddr = cfg->remote_ip;
        new_ip.check = compute_ip_csum(&new_ip);

        struct tcphdr new_tcp = {};
        new_tcp.source = conn->local_tcp_port;
        new_tcp.dest = bpf_htons(cfg->remote_port);
        new_tcp.seq = bpf_htonl(seq);
        new_tcp.ack_seq = bpf_htonl(ack);
        new_tcp.doff = 5;
        new_tcp.flags = cfg->tcp_extensions ? (TCP_FLAG_ACK | TCP_FLAG_PSH) : TCP_FLAG_ACK;
        new_tcp.window = bpf_htons(0xffff);
        new_tcp.check = 0;
        new_tcp.urg_ptr = 0;

        bpf_skb_store_bytes(skb, 0, &new_eth, sizeof(new_eth), 0);
        bpf_skb_store_bytes(skb, 14, &new_ip, sizeof(new_ip), 0);
        bpf_skb_store_bytes(skb, 34, &new_tcp, sizeof(new_tcp), 0);

        if (cfg->padding_enabled) {
            store_padding(skb, pad_len, rand_val);
        }

        __u16 csum = compute_l4_csum(skb, tcp_total_len, new_ip.saddr, new_ip.daddr, IPPROTO_TCP);
        bpf_skb_store_bytes(skb, 34 + 16, &csum, sizeof(csum), 0);

        __sync_fetch_and_add(&stats->tx_pkts, 1);
        __sync_fetch_and_add(&stats->tx_bytes, udp_payload_len);

        if (cfg->padding_enabled && cfg->obfuscate_enabled &&
            (rand_val % 10000) < cfg->obfuscate_prob_bp) {
            /* Send the real packet first via clone_redirect */
            bpf_clone_redirect(skb, skb->ifindex, 0);

            /* Turn current skb into a dummy padding-only packet (4B pad -> 6B payload) */
            __u32 dummy_pad_len = 4;
            __u32 dummy_payload_len = 2 + dummy_pad_len;
            __u32 dummy_tcp_len = 20 + dummy_payload_len;
            __u32 dummy_seq = __sync_fetch_and_add(&conn->seq, dummy_payload_len);

            if (bpf_skb_change_tail(skb, ETH_HLEN + 20 + dummy_tcp_len, 0) < 0)
                return TC_ACT_SHOT;

            new_ip.tot_len = bpf_htons(20 + dummy_tcp_len);
            new_ip.id = (__be16)bpf_get_prandom_u32();
            new_ip.check = compute_ip_csum(&new_ip);

            new_tcp.seq = bpf_htonl(dummy_seq);
            new_tcp.check = 0;

            bpf_skb_store_bytes(skb, 0, &new_eth, sizeof(new_eth), 0);
            bpf_skb_store_bytes(skb, 14, &new_ip, sizeof(new_ip), 0);
            bpf_skb_store_bytes(skb, 34, &new_tcp, sizeof(new_tcp), 0);
            store_padding(skb, dummy_pad_len, bpf_get_prandom_u32());

            __u16 dummy_csum = compute_l4_csum(skb, dummy_tcp_len, new_ip.saddr, new_ip.daddr, IPPROTO_TCP);
            bpf_skb_store_bytes(skb, 34 + 16, &dummy_csum, sizeof(dummy_csum), 0);

            __sync_fetch_and_add(&stats->tx_obfuscate_pkts, 1);
        }

        return bpf_redirect(skb->ifindex, 0);
    }

    /* ------------------------------------------------------------------------
     * PATH B: Incoming Fake-TCP packet from remote_ip:remote_port
     * ------------------------------------------------------------------------ */
    if (ip->protocol == IPPROTO_TCP && ip->saddr == cfg->remote_ip) {
        if (data + ETH_HLEN + ip_hdr_len + sizeof(struct tcphdr) > data_end) {
            if (bpf_skb_pull_data(skb, ETH_HLEN + ip_hdr_len + sizeof(struct tcphdr)) < 0)
                return TC_ACT_UNSPEC;
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return TC_ACT_UNSPEC;
            ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end)
                return TC_ACT_UNSPEC;
        }

        struct tcphdr *tcp = data + ETH_HLEN + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_UNSPEC;

        if (bpf_ntohs(tcp->source) != cfg->remote_port)
            return TC_ACT_UNSPEC;

        __u32 port_key = (__u32)tcp->dest;
        struct conn_state *conn = bpf_map_lookup_elem(&CLIENT_CONNS, &port_key);
        if (!conn)
            return TC_ACT_UNSPEC;

        __u8 flags = tcp->flags;

        if (flags & TCP_FLAG_RST) {
            struct peer_key ukey = {
                .ip = conn->client_ip,
                .port = conn->client_port,
                ._pad = 0,
            };
            bpf_map_delete_elem(&CLIENT_BY_UDP, &ukey);
            bpf_map_delete_elem(&CLIENT_CONNS, &port_key);
            return TC_ACT_SHOT;
        }

        /* Handle SYN+ACK from server -> send ACK in-place */
        if (conn->state == STATE_SYN_SENT &&
            (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
            __u32 expected_ack = conn->seq + 1;
            if (bpf_ntohl(tcp->ack_seq) != expected_ack)
                return TC_ACT_SHOT;

            __u32 server_seq = bpf_ntohl(tcp->seq);
            conn->seq = expected_ack;
            conn->ack = server_seq + 1;
            conn->last_seen_ns = bpf_ktime_get_ns();
            conn->state = STATE_SYN_RECEIVED;
            __sync_fetch_and_add(&stats->handshakes, 1);

            struct ethhdr ack_eth = *eth;
            swap_eth_mac(&ack_eth);

            struct iphdr ack_ip = {};
            ack_ip.version = 4;
            ack_ip.ihl = 5;
            ack_ip.tos = 0;
            ack_ip.tot_len = bpf_htons(40);
            ack_ip.id = (__be16)bpf_get_prandom_u32();
            ack_ip.frag_off = bpf_htons(0x4000);
            ack_ip.ttl = 64;
            ack_ip.protocol = IPPROTO_TCP;
            ack_ip.saddr = cfg->local_ip;
            ack_ip.daddr = cfg->remote_ip;
            ack_ip.check = compute_ip_csum(&ack_ip);

            struct tcphdr ack_tcp = {};
            ack_tcp.source = conn->local_tcp_port;
            ack_tcp.dest = bpf_htons(cfg->remote_port);
            ack_tcp.seq = bpf_htonl(conn->seq);
            ack_tcp.ack_seq = bpf_htonl(conn->ack);
            ack_tcp.doff = 5;
            ack_tcp.flags = TCP_FLAG_ACK;
            ack_tcp.window = bpf_htons(0xffff);
            ack_tcp.check = 0;
            ack_tcp.urg_ptr = 0;

            if (bpf_skb_change_tail(skb, ETH_HLEN + 40, 0) < 0)
                return TC_ACT_SHOT;

            bpf_skb_store_bytes(skb, 0, &ack_eth, sizeof(ack_eth), 0);
            bpf_skb_store_bytes(skb, 14, &ack_ip, sizeof(ack_ip), 0);
            bpf_skb_store_bytes(skb, 34, &ack_tcp, sizeof(ack_tcp), 0);

            __u16 csum = compute_l4_csum(skb, 20, ack_ip.saddr, ack_ip.daddr, IPPROTO_TCP);
            bpf_skb_store_bytes(skb, 34 + 16, &csum, sizeof(csum), 0);

            return bpf_redirect(skb->ifindex, 0);
        }

        if (conn->state != STATE_ESTABLISHED && conn->state != STATE_SYN_RECEIVED)
            return TC_ACT_SHOT;

        __u32 tcp_hdr_len = (__u32)tcp->doff * 4;
        __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
        if (tcp_hdr_len < 20 || ip_tot_len < ip_hdr_len + tcp_hdr_len)
            return TC_ACT_SHOT;

        __u32 tcp_payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
        conn->last_seen_ns = bpf_ktime_get_ns();

        if (tcp_payload_len == 0)
            return TC_ACT_SHOT;

        __u32 seq = bpf_ntohl(tcp->seq);
        conn->ack = seq + tcp_payload_len;

        __u32 pad_total = 0;
        if (cfg->padding_enabled) {
            if (tcp_payload_len < 2)
                return TC_ACT_SHOT;
            __u8 hdr[2] = {0, 0};
            if (bpf_skb_load_bytes(skb, ETH_HLEN + ip_hdr_len + tcp_hdr_len, hdr, 2) < 0)
                return TC_ACT_SHOT;
            __u32 pad_len = (__u8)(hdr[0] + hdr[1]);
            if (pad_len == 0 || tcp_payload_len < 2 + pad_len)
                return TC_ACT_SHOT;
            pad_total = 2 + pad_len;
        }

        __u32 udp_payload_len = tcp_payload_len - pad_total;
        if (udp_payload_len == 0) {
            __sync_fetch_and_add(&stats->rx_obfuscate_pkts, 1);
            return TC_ACT_SHOT;
        }

        struct ethhdr out_eth = *eth;
        swap_eth_mac(&out_eth);

        __be32 client_ip = conn->client_ip;
        __be16 client_port = conn->client_port;

        __s32 shrink_len = (__s32)(ip_hdr_len + tcp_hdr_len + pad_total) - 28;
        if (bpf_skb_adjust_room(skb, -shrink_len, BPF_ADJ_ROOM_NET, 0) < 0) {
            __sync_fetch_and_add(&stats->drops, 1);
            return TC_ACT_SHOT;
        }

        struct iphdr new_ip = {};
        new_ip.version = 4;
        new_ip.ihl = 5;
        new_ip.tos = 0;
        new_ip.tot_len = bpf_htons(28 + udp_payload_len);
        new_ip.id = (__be16)bpf_get_prandom_u32();
        new_ip.frag_off = bpf_htons(0x4000);
        new_ip.ttl = 64;
        new_ip.protocol = IPPROTO_UDP;
        new_ip.saddr = cfg->local_ip;
        new_ip.daddr = client_ip;
        new_ip.check = compute_ip_csum(&new_ip);

        struct udphdr new_udp = {};
        new_udp.source = bpf_htons(cfg->local_port);
        new_udp.dest = client_port;
        new_udp.len = bpf_htons(8 + udp_payload_len);
        new_udp.check = 0;

        bpf_skb_store_bytes(skb, 0, &out_eth, sizeof(out_eth), 0);
        bpf_skb_store_bytes(skb, 14, &new_ip, sizeof(new_ip), 0);
        bpf_skb_store_bytes(skb, 34, &new_udp, sizeof(new_udp), 0);

        __u16 udp_csum = compute_l4_csum(skb, 8 + udp_payload_len, new_ip.saddr, new_ip.daddr, IPPROTO_UDP);
        if (udp_csum == 0)
            udp_csum = 0xffff;
        bpf_skb_store_bytes(skb, 34 + 6, &udp_csum, sizeof(udp_csum), 0);

        __sync_fetch_and_add(&stats->rx_pkts, 1);
        __sync_fetch_and_add(&stats->rx_bytes, udp_payload_len);

        return bpf_redirect(skb->ifindex, 0);
    }

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "Dual MIT/GPL";
