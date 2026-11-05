# rudp

`rudp` 是一个基于 **Linux TC (Traffic Control) eBPF** 实现的高性能、零拷贝 **UDP-to-FakeTCP** 隧道与混淆工具（支持 `x86_64` 与 `aarch64`）。

它专为突破运营商对 UDP 流量的 QoS 限速或阻断而设计（例如加速 WireGuard 等 UDP 协议）。与传统的基于用户态 `TUN` 虚拟网卡 + `iptables/nftables` NAT 的方案不同，`rudp` 直接在 Linux 内核网卡驱动层与协议栈交界处（TC Ingress / Egress）对 `sk_buff` 进行**原地（In-Place）协议头改写**，无需创建虚拟网卡、无需配置任何防火墙规则、且数据面零用户态拷贝。

---

## 核心特性

- **全内核态零拷贝数据面（Zero-Copy TC eBPF）**：
  - 使用 `bpf_skb_adjust_room(..., BPF_ADJ_ROOM_NET, 0)` 直接在内核 `sk_buff` 中将 8 字节 UDP 头原地替换为 `20B TCP 头 + 随机 Padding`（反之亦然）。
  - 消除 `TUN` 虚拟网卡上下文切换（内核 $\leftrightarrow$ 用户态来回拷贝），CPU 开销与转发延迟显著降低。
- **透明接管模式（`--transparent`，零配置改动接管现有 WireGuard）**：
  - 客户端支持挂载 `TC Egress` + `TC Ingress` 直接拦截发往远端 `<server_ip>:<port>` 的 UDP 流量并原地改写为 Fake-TCP。
  - **无需修改现有 WireGuard 客户端的 `Endpoint` 配置，无需重启 WireGuard**，随时启动 `rudp_client -r <server_ip>:<port> --transparent` 即可无缝接管，停止进程后自动恢复原生 UDP 通信。
- **支持本机代理、局域网网关与公网中转全场景**：
  - 自动解析 `/proc/net/route` 最长前缀匹配下一跳网关 IP，并通过 `/proc/net/arp`（冷缓存时自动发送 TTL=1 探测触发 ARP）精确获取网关 MAC。
  - 在 `conn_state` 中记录客户端真实二层源 MAC 与原始目标 IP（`orig_dst_ip`），下行回包自动判断目标为本机协议栈（`TC_ACT_OK` / `lo`）或外部局域网设备（Hairpin Redirect）。
- **内核级 0-RTT 握手响应与即时 `RST` 自愈**：
  - `rudp_server` 在 `TC Ingress` 内核态直接拦截 TCP `SYN` 并原地翻转为 `SYN+ACK`（通过 `bpf_redirect` 直接从网卡发回），无需唤醒用户态。
  - 当服务端重启或连接过期后收到旧连接的未知数据包时，内核直接在 `TC Ingress` 原地回发 `TCP RST|ACK`，客户端在 `TC Ingress` 收到 `RST` 后立即清除旧状态并自动发起重新握手，无需苦等超时。
- **完整的多客户端支持与单网卡多实例共存**：
  - **1 `rudp_server` $\leftrightarrow$ 多 `rudp_client`**：服务端基于客户端 `(ip, tcp_port)` 维护连接表，解封装为 UDP 交给后端服务时将客户端 TCP 源端口映射为 UDP 源端口，回包时按目的 `(ip, udp_port)` 自动还原对应的 Fake-TCP 会话。
  - **1 `rudp_client` $\leftrightarrow$ 多 UDP 客户端**：每个上游 UDP 客户端 `(ip, udp_port)` 自动分配独立的本地 Fake-TCP 源端口（`32768..=60999`），支持多客户端并发非阻塞握手。
  - **单网卡多 `rudp_client` 实例共存**：非匹配流量返回 `TC_ACT_UNSPEC` 配合不同 Netlink 优先级（`priority = local_port`），同一张网卡（如中转机 `eth0`）可同时运行任意多个指向不同后端的 `rudp_client` 实例。
- **四重连接状态回收机制**：
  - 内核 `BPF_MAP_TYPE_LRU_HASH`（容量 4096）自动淘汰最久未活跃连接 + 用户态每 5 秒巡检清理超 180 秒空闲连接并主动发送 `TCP RST|ACK` + 内核快路径超时拦截 + 进程退出（`SIGTERM`/`SIGINT`）优雅发送 `RST` 并卸载 TC 钩子。
- **抗 DPI 深度包检测与流量混淆**：
  - 支持随机长度载荷填充（`--payload-padding`）、真实 TCP 扩展头与标志位（`--tcp-extensions`）、以及内核态 `bpf_clone_redirect` 概率性注入自定义最大长度（`1..=255` 字节）的纯随机混淆包（`--obfuscate`）。

---

## 架构与数据流设计

### 1. 拓扑模式

#### 模式 A：透明接管模式（`--transparent`，推荐用于客户端本机或局域网软路由）
WireGuard 客户端保持原有配置 `Endpoint = server.example:12345` 完全不变：
```text
[Client Host]                                                      [Server Host]
+-------------------+   UDP (dst=server:12345)   +--------------+         Fake-TCP         +---------------+   UDP (12345)
|  wg0 (:12345)     | -------------------------> | rudp_client  | <======================> |  rudp_server  | <-------------> [ wg0 (:12345) ]
| (Endpoint Untouched)| <------------------------- | (TC Egress / |    server.example:12345  | (TC In/Egress)|
+-------------------+   UDP (src=server:12345)   |  TC Ingress) |                          +---------------+
```

#### 模式 B：传统端口代理 / 中转模式
在中转机或本机监听指定 UDP 端口（如 `0.0.0.0:9283`），上游客户端将 `Endpoint` 指向中转端口：
```text
+-------------------+         UDP          +-------------------+        Fake-TCP        +-------------------+    UDP (0.0.0.0:22809)
|  WireGuard Client | <------------------> |    rudp_client    | <====================> |    rudp_server    | <--------------------> [ wg0 ]
|  (Any OS / NAT)   |   relay.example:9283 | (TC Ingress Hairpin)|   server.example:928  | (TC Ingress/Egress)|
+-------------------+                      +-------------------+                        +-------------------+
```

### 2. 客户端 (`rudp_client`) 数据路径

1. **首个 UDP 包（非阻塞握手慢路径）**：
   - 当某 `(udp_client_ip, udp_client_port)` 的首个 UDP 包到达时，`CLIENT_BY_UDP` BPF Map 中尚无记录：
     - 在传统代理模式下，数据包交由绑定在 `local_port` 的用户态 `UdpSocket`；
     - 在 `--transparent` 透明模式下，`rudp_client` 自动绑定不与本机 WireGuard 冲突的空闲端口 `internal_udp_port`，eBPF 将未建立连接的首包重定向至 `internal_udp_port`。
   - 用户态分配未占用的本地 TCP 端口 `local_tcp_port`（`32768..=60999`），记录原始目标 IP `orig_dst_ip` 写入 `CLIENT_CONNS`（状态为 `STATE_SYN_SENT`），并通过 `RawTcpSocket` 发送 `TCP SYN`（支持 1s 间隔自动重传，最多 6 次，握手期间缓存待发 UDP 包确保首包零丢失）。
   - 当服务端回发的 `SYN+ACK` 到达 `rudp_client_ingress` 时，**eBPF 在内核态直接将其原地翻转为 `TCP ACK` 发回服务端**，并将状态更新为 `STATE_SYN_RECEIVED`。
   - 用户态轮询发现状态变为 `STATE_SYN_RECEIVED` 后，立即将握手期间缓存的首批 UDP 包通过 Raw Socket 发出，并将状态切换为 `STATE_ESTABLISHED`。
2. **后续双向数据包（eBPF 零拷贝快路径）**：
   - **上行（UDP $\to$ Fake-TCP）**：
     - 本机透明模式（`rudp_client_egress`）：在 `TC Egress` 拦截发往 `remote_ip:local_port` 的 UDP 包，直接通过 `bpf_skb_adjust_room` 原地将 UDP 头替换为 `TCP 头 + Padding` 后返回 `TC_ACT_OK` 发往网卡驱动。
     - 局域网网关 / 中转模式（`rudp_client_ingress`）：在 `TC Ingress` 拦截入站 UDP 包，记录客户端源 MAC 至 `conn->peer_mac`，将二层目的 MAC 设为网关 MAC（`cfg->gateway_mac`），原地替换为 Fake-TCP 后调用 `bpf_redirect(skb->ifindex, 0)` 从网卡发出。
   - **下行（Fake-TCP $\to$ UDP）**：
     - `rudp_client_ingress` 收到来自 `remote_ip:remote_port` 的 TCP 数据包，校验并剥离 Padding（若是纯 Padding 混淆包则直接 `TC_ACT_SHOT` 丢弃），将 TCP 头缩减为 8 字节 UDP 头，源 IP 还原为 `conn->orig_dst_ip`：
       - 若客户端位于本机（透明模式），直接返回 `TC_ACT_OK` 上送本机内核协议栈；
       - 若客户端位于本机（本地 `127.0.0.1` 代理模式），通过 `bpf_redirect(1, BPF_F_INGRESS)` 送入 `lo`；
       - 若客户端位于外部网络/局域网，目的 MAC 设为 `conn->peer_mac`，通过 `bpf_redirect(skb->ifindex, 0)` 转发回客户端。

### 3. 服务端 (`rudp_server`) 数据路径

`rudp_server` 在网卡上同时挂载 **`TC Ingress`**（`rudp_server_ingress`）与 **`TC Egress`**（`rudp_server_egress`）：

1. **握手包（0-RTT 内核响应）**：
   - `rudp_server_ingress` 收到发往 `local_port` 的 `TCP SYN` 包时，直接生成初始序列号写入 `SERVER_CONNS`（状态立即设为 `STATE_ESTABLISHED`），并将原包原地改写为 `SYN+ACK`（附带 `MSS 1460`、`NOP`、`WScale 14` 选项），通过 `bpf_redirect(skb->ifindex, 0)` 直接从网卡发回。
2. **上行解封装（`TC Ingress`：Fake-TCP $\to$ 本机 UDP）**：
   - 收到已建立连接的 TCP 数据包后，更新 `conn->ack` 与 `conn->last_seen_ns`，解析并剥离随机 Padding。
   - 使用 `bpf_skb_adjust_room(skb, -shrink_len, BPF_ADJ_ROOM_NET, 0)` 将 `TCP 头 + Padding` 缩减为 8 字节 UDP 头：
     - **保留客户端原始源 IP**；
     - **UDP 源端口设为客户端的 TCP 源端口 `key.port`**；
     - **UDP 目的端口设为后端服务端口 `remote_port`（如 WireGuard `22809` 或 `12345`）**；
     - UDP 校验和置 `0`（IPv4 本地递交合法免校验），返回 `TC_ACT_OK` 交由本机协议栈直接送入 `wg0`。
3. **下行封装（`TC Egress`：本机 UDP $\to$ Fake-TCP）**：
   - 当本机 `wg0` 向客户端 `(ip, port)` 发送 UDP 回包时，`rudp_server_egress` 在 `TC Egress` 拦截该包。
   - 以目的 `(ip->daddr, udp->dest)` 为 Key 查询 `SERVER_CONNS`，使用 `bpf_skb_adjust_room(skb, grow_len, BPF_ADJ_ROOM_NET, 0)` 将 8 字节 UDP 头扩充为 `20B TCP 头 + 随机 Padding`，计算 IPv4 与 TCP 校验和后返回 `TC_ACT_OK` 发往网卡驱动。

---

## 协议格式与混淆机制

### 1. 随机载荷填充（`--payload-padding`）

开启 `--payload-padding` 后，每个 Fake-TCP 数据段在 TCP 头部之后、真实 UDP 载荷之前会插入一段变长头部：

```text
+---------------+---------------+-----------------------+--------------------------+
|   Byte 0 (b0) |   Byte 1 (b1) |  Random Padding Bytes |    Original UDP Payload  |
|   (1 byte)    |   (1 byte)    |  (pad_len: 1..=255 B) |      (0..=MTU bytes)     |
+---------------+---------------+-----------------------+--------------------------+
```

- **长度编码规则**：前两个字节 `b0` 与 `b1` 均为随机生成的字节，但满足：
  $$\texttt{pad\_len} = (\texttt{b0} + \texttt{b1}) \bmod 256$$
- **正常数据包**：`pad_len` 在 `2..=padding_max_len`（默认 `4`，取偶数，最大支持 `254`）之间随机选取，随后紧跟 `pad_len` 个随机字节，再紧跟原始 UDP 载荷。接收端验证 `tcp_payload_len > 2 + pad_len` 后剥离前 `2 + pad_len` 字节即可还原 UDP 载荷。
- **纯混淆包（`--obfuscate`）**：当触发混淆（默认概率 `5%`）时，eBPF 先通过 `bpf_clone_redirect` 发送真实数据包，随后在 `max(4, pad_len)..=obfuscate_max_len`（默认上限 `255`）范围内随机选取 `dummy_pad_len`，将当前 `skb` 截断并填充为 `tcp_payload_len == 2 + dummy_pad_len`（无 UDP 载荷）的纯随机包。接收端在内核发现 `tcp_payload_len == 2 + pad_len` 时，仅递增 `stats->rx_obfuscate_pkts` 计数并直接 `TC_ACT_SHOT` 丢弃，不产生任何上层开销。

### 2. TCP 扩展伪装（`--tcp-extensions`）

开启 `--tcp-extensions` 后：
- 客户端发出的 `SYN` 包携带 `ECN + CWR` 标志位，并附带 12 字节标准 Linux TCP Options（`MSS 1460`、`SACK Permitted`、`NOP`、`WScale 7`、`NOP`、`NOP`）。
- 服务端回发的 `SYN+ACK` 附带 8 字节 TCP Options（`MSS 1460`、`NOP`、`WScale 14`）。
- 所有 Fake-TCP 数据包携带 `PSH | ACK` (`0x18`) 标志位，纯混淆包仅携带 `ACK` (`0x10`) 标志位。

---

## 注意事项与云厂商网卡兼容性

### 1. 后端 UDP 服务需监听 `0.0.0.0`
`rudp_server` 在 `TC Ingress` 将 Fake-TCP 原地改写为 UDP 时，为了保持零拷贝且无需 DNAT，保留了数据包原本的目的 IP（即服务器网卡自身的 IP），仅将目的端口改为 `--remote` 指定的端口。
因此，后端的 UDP 服务（例如 WireGuard `wg0`）应绑定在 `0.0.0.0:<port>`（WireGuard 默认行为）。如果后端 UDP 程序仅绑定在 `127.0.0.1:<port>`，内核会因目的 IP 是网卡 IP 而拒绝投递到 `127.0.0.1` Socket。

### 2. AWS (`ena`) / GCP (`gve`) 网卡 TX 校验和卸载处理
在 Linux 内核中，本机发出的 UDP 包默认带有 `skb->ip_summed = CHECKSUM_PARTIAL`（`csum_offset = 6`）。当 `TC Egress` 将 UDP 改写为 TCP（`csum_offset = 16`）时，内核的 `bpf_skb_adjust_room` 不会清除 `CHECKSUM_PARTIAL` 标记，这会导致 AWS `ena` 和 GCP `gve` 网卡驱动因硬件校验和偏移量不匹配而丢包。
为此，`rudp` 做了两项处理：
1. 所有包头扩缩均使用 `BPF_ADJ_ROOM_NET` 模式，确保 `skb_network_offset(skb) == 14` 与 `skb_transport_offset(skb) == 34` 始终正确。
2. `rudp_server` 以及开启 `--transparent` 的 `rudp_client` 默认在启动时自动调用 `ethtool -K <iface> tx off` 关闭出口网卡的 TX 硬件校验和卸载（并在进程退出时自动执行 `ethtool -K <iface> tx on tso on` 还原网卡卸载状态），从而兼容 AWS `ena`、GCP `gve` 等严格校验硬件卸载描述符的云厂商网卡驱动。
   - 在不校验 `csum_offset` 的 `virtio_net` 网卡环境（如 Oracle Cloud）中，若希望保留网卡硬件 TSO 加速，可通过 `--keep-tx-offload`（或 `--disable-tx-offload=false`）关闭该行为。

---

## 编译与安装

### 依赖要求
- **Linux 内核**：$\ge 5.10$（需支持 TC `clsact` BPF 与 `BPF_MAP_TYPE_LRU_HASH`）
- **编译环境**：Rust 工具链、`clang`（用于编译 `ebpf/rudp_ebpf.c` 为 `bpf` 字节码，构建时由 `build.rs` 自动调用并内嵌至二进制文件中）
- **运行环境**：`ethtool`、`iproute2` (`tc`)，需要 `root` 或 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_NET_RAW` 权限

### 本地编译
```bash
# 编译当前架构 release 二进制
cargo build --release

# 交叉编译静态链接 musl 二进制（x86_64 / aarch64）
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```
编译产物位于 `target/release/rudp_client` 与 `target/release/rudp_server`（eBPF 字节码已静态内嵌，单文件即可直接部署运行）。

---

## 命令行参数

> **注意**：`--payload-padding`、`--payload-padding-max-len` 与 `--tcp-extensions` 参数在 `rudp_client` 和 `rudp_server` 两端必须保持一致。

### `rudp_server`
```text
Usage: rudp_server [OPTIONS] --local <LOCAL> --remote <REMOTE>

Options:
  -l, --local <LOCAL>
          监听的本地 Fake-TCP 端口（例如: 12345 或 928）
  -r, --remote <REMOTE>
          转发解封装后 UDP 包的目标地址:端口（例如: 127.0.0.1:12345）
  -i, --interface <INTERFACE>
          挂载 TC eBPF 程序的网卡名称（省略则自动根据默认路由探测）
      --payload-padding
          开启随机长度载荷填充头
      --payload-padding-max-len <PAYLOAD_PADDING_MAX_LEN>
          数据包最大随机偶数填充长度（2..=16）[默认: 4]
      --obfuscate
          开启内核态随机混淆包注入 [环境变量: RUDP_OBFUSCATE]
      --obfuscate-prob <OBFUSCATE_PROB>
          每个数据包触发额外混淆包的百分比概率 [环境变量: RUDP_OBFUSCATE_PROB] [默认: 5.0]
      --obfuscate-max-len <OBFUSCATE_MAX_LEN>
          混淆包最大随机填充长度（4..=255）[环境变量: RUDP_OBFUSCATE_MAX_LEN] [默认: 255]
      --tcp-extensions
          开启真实 TCP Options 与 PSH|ACK 标志位伪装
      --disable-tx-offload [<DISABLE_TX_OFFLOAD>]
          启动时自动执行 `ethtool -K <iface> tx off`，退出时自动还原 `tx on tso on` [环境变量: RUDP_DISABLE_TX_OFFLOAD] [默认: true]
      --keep-tx-offload
          保持网卡 TX 校验和卸载与 TSO 开启（等价于 `--disable-tx-offload=false`）
  -h, --help
          打印帮助信息
  -V, --version
          打印版本信息
```

### `rudp_client`
```text
Usage: rudp_client [OPTIONS] --remote <REMOTE>

Options:
  -l, --local <LOCAL>
          普通模式下为本地监听的 UDP 地址:端口或端口（如 0.0.0.0:9283 或 9283）；
          --transparent 模式下为要透明劫持的远端目标 UDP 端口（可省略，默认等于 --remote 的端口）
  -r, --remote <REMOTE>
          远端 rudp_server 的域名或 IP:端口（例如: example.com:12345）
  -t, --transparent
          开启透明接管模式：自动劫持发往 <remote_ip>:<local_port> 的 UDP 包，无需修改客户端 Endpoint [环境变量: RUDP_TRANSPARENT]
  -i, --interface <INTERFACE>
          挂载 TC eBPF 程序的网卡名称（省略则自动根据默认路由探测）
      --payload-padding
          开启随机长度载荷填充头
      --payload-padding-max-len <PAYLOAD_PADDING_MAX_LEN>
          数据包最大随机偶数填充长度（2..=16）[默认: 4]
      --obfuscate
          开启内核态随机混淆包注入 [环境变量: RUDP_OBFUSCATE]
      --obfuscate-prob <OBFUSCATE_PROB>
          每个数据包触发额外混淆包的百分比概率 [环境变量: RUDP_OBFUSCATE_PROB] [默认: 5.0]
      --obfuscate-max-len <OBFUSCATE_MAX_LEN>
          混淆包最大随机填充长度（4..=255）[环境变量: RUDP_OBFUSCATE_MAX_LEN] [默认: 255]
      --tcp-extensions
          开启真实 TCP Options 与 PSH|ACK 标志位伪装
      --disable-tx-offload [<DISABLE_TX_OFFLOAD>]
          透明模式下启动时自动执行 `ethtool -K <iface> tx off`，退出时自动还原 `tx on tso on` [环境变量: RUDP_DISABLE_TX_OFFLOAD] [默认: true]
      --keep-tx-offload
          保持网卡 TX 校验和卸载与 TSO 开启（等价于 `--disable-tx-offload=false`）
  -h, --help
          打印帮助信息
  -V, --version
          打印版本信息
```

---

## Systemd 部署示例

### 1. 服务端 (`/etc/systemd/system/rudp-server.service`)

假设服务端 WireGuard 监听在 UDP `12345` 端口，启动 `rudp_server` 在 TCP `12345` 端口接收 Fake-TCP 并解封装至本机 UDP `12345`：

```ini
[Unit]
Description=rudp eBPF server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="RUST_LOG=info"
Environment="RUDP_OBFUSCATE_PROB=5"
Environment="RUDP_OBFUSCATE_MAX_LEN=32"
ExecStart=/usr/local/bin/rudp_server --local 12345 --remote 127.0.0.1:12345 --payload-padding --tcp-extensions --obfuscate
Restart=always
RestartSec=2
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

### 2. 客户端：透明接管模式 (`/etc/systemd/system/rudp-client.service`)

客户端 WireGuard 配置保持 `Endpoint = jp.example.com:12345` 不变，`rudp_client` 使用 `--transparent` 自动接管所有发往 `jp.example.com:12345` 的 UDP 包：

```ini
[Unit]
Description=rudp eBPF transparent client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="RUST_LOG=info"
Environment="RUDP_OBFUSCATE_PROB=5"
Environment="RUDP_OBFUSCATE_MAX_LEN=32"
ExecStart=/usr/local/bin/rudp_client --remote jp.example.com:12345 --transparent --payload-padding --tcp-extensions --obfuscate
Restart=always
RestartSec=2
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

### 3. 客户端：传统中转代理模式 (`/etc/systemd/system/rudp-relay.service`)

在中转机上监听本地 UDP `0.0.0.0:9283`，封装为 Fake-TCP 发往远端 `jp.example.com:928`：

```ini
[Unit]
Description=rudp eBPF relay client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="RUST_LOG=info"
Environment="RUDP_OBFUSCATE_PROB=5"
Environment="RUDP_OBFUSCATE_MAX_LEN=32"
ExecStart=/usr/local/bin/rudp_client --local 0.0.0.0:9283 --remote jp.example.com:928 --payload-padding --tcp-extensions --obfuscate
Restart=always
RestartSec=2
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

---

## TODO

- [ ] **大包（>1500B MTU / GRO / GSO）L4 校验和支持**：当前 `ebpf/rudp_ebpf.c` 中的 `compute_l4_csum` 循环上限为 `750` 次（对应 L4 最大长度 `1500` 字节）。在开启 Jumbo Frame 或 GRO/GSO 聚合大包场景下，超过 1500B 的 L4 载荷校验和会被截断，后续可改为基于 `bpf_csum_diff` / `bpf_l4_csum_replace` 的增量校验和更新以彻底解除帧长限制。
- [ ] **IPv6 支持**：扩展 `ETH_P_IPV6` 与 IPv6 头部原地改写支持。
