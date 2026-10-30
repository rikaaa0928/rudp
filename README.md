# rudp

`rudp` 是一个基于 **Linux TC (Traffic Control) eBPF** 实现的高性能、零拷贝 **UDP-to-FakeTCP** 隧道工具（支持 `x86_64` 与 `aarch64`）。

它专为突破运营商对 UDP 流量的 QoS 限速或阻断而设计（例如加速 WireGuard 等 UDP 协议）。与传统的基于用户态 `TUN` 虚拟网卡 + `iptables/nftables` NAT 的方案（如 `phantun`）不同，`rudp` 直接在 Linux 内核网卡驱动层与协议栈交界处（TC Ingress / Egress）对 `sk_buff` 进行**原地（In-Place）协议头改写**，无需创建虚拟网卡、无需配置任何防火墙规则、且数据面零用户态拷贝。

---

## 核心特性

- **全内核态零拷贝数据面（Zero-Copy TC eBPF）**：
  - 使用 `bpf_skb_adjust_room(..., BPF_ADJ_ROOM_NET, 0)` 直接在内核 `sk_buff` 中将 8 字节 UDP 头原地替换为 `20B TCP 头 + 随机 Padding`（反之亦然）。
  - 消除 `TUN` 虚拟网卡上下文切换（内核 $\leftrightarrow$ 用户态来回拷贝），CPU 开销与转发延迟显著降低。
- **免 `TUN` 网卡、免 `iptables`/`nftables`**：
  - 自动探测出口网卡 IPv4 地址、本机 MAC 与默认网关 MAC（读取 `/proc/net/route` 与 `/proc/net/arp`，必要时自动触发 UDP 探测解析 ARP）。
  - 通过 TC filter 优先级（`priority = local_port`）自动挂载与精确卸载，不污染宿主机路由表或防火墙规则。
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
  - 支持随机长度载荷填充（`--payload-padding`）、真实 TCP 扩展头与标志位（`--tcp-extensions`）、以及内核态 `bpf_clone_redirect` 概率性注入纯随机混淆包（`--obfuscate`）。

---

## 架构与数据流设计

### 1. 整体拓扑

```text
+-------------------+         UDP          +-------------------+        Fake-TCP        +-------------------+    UDP (0.0.0.0:22809)
|  WireGuard Client | <------------------> |    rudp_client    | <====================> |    rudp_server    | <--------------------> [ wg0 ]
|  (Any OS / NAT)   |   ali.example:9283   | (TC Ingress Hairpin)|   server.example:928  | (TC Ingress/Egress)|
+-------------------+                      +-------------------+                        +-------------------+
```

### 2. 客户端 (`rudp_client`) 数据路径

`rudp_client` 仅需在网卡挂载 **`TC Ingress`** 钩子（`rudp_client_ingress`），利用内核 Hairpin Redirect（`bpf_redirect(skb->ifindex, 0)`）直接在单张网卡上完成入站拦截与改写转发：

1. **首个 UDP 包（握手慢路径）**：
   - 当某 `(udp_client_ip, udp_client_port)` 的第一个 UDP 包到达 `eth0` 时，`CLIENT_BY_UDP` BPF Map 中尚无记录，eBPF 返回 `TC_ACT_UNSPEC` 将该包交给用户态 `UdpSocket`。
   - 用户态分配一个未占用的本地 TCP 端口 `local_tcp_port`（`32768..=60999`），写入 `CLIENT_CONNS`（状态为 `STATE_SYN_SENT`），并通过 `AF_INET, SOCK_RAW, IPPROTO_RAW` 发送 `TCP SYN`（支持 1s 间隔自动重传，最多 6 次）。
   - 当服务端回发的 `SYN+ACK` 到达 `rudp_client_ingress` 时，**eBPF 在内核态直接将其原地翻转为 `TCP ACK` 发回服务端**，并将状态更新为 `STATE_SYN_RECEIVED`。
   - 用户态轮询发现状态变为 `STATE_SYN_RECEIVED` 后，将握手期间缓存的首批 UDP 包通过 Raw Socket 发出，并将状态切换为 `STATE_ESTABLISHED`。
2. **后续双向数据包（eBPF 零拷贝快路径）**：
   - **上行（UDP $\to$ Fake-TCP）**：`rudp_client_ingress` 匹配到目的端口等于 `local_port` 且 `CLIENT_BY_UDP` 已处于 `STATE_ESTABLISHED` 时，直接通过 `bpf_skb_adjust_room` 将 UDP 头替换为 `TCP 头 + Padding`，翻转二层 MAC（本机 MAC $\to$ 网关 MAC），调用 `bpf_redirect(skb->ifindex, 0)` 直接从 `eth0` Egress 发出。
   - **下行（Fake-TCP $\to$ UDP）**：`rudp_client_ingress` 收到来自 `remote_ip:remote_port` 的 TCP 数据包，校验并剥离 Padding（若是纯 Padding 混淆包则直接 `TC_ACT_SHOT` 丢弃），将 TCP 头缩减为 8 字节 UDP 头，目的地址改写为对应的 `(udp_client_ip, udp_client_port)`，直接从 `eth0` Hairpin 转发回客户端。

### 3. 服务端 (`rudp_server`) 数据路径

`rudp_server` 在网卡上同时挂载 **`TC Ingress`**（`rudp_server_ingress`）与 **`TC Egress`**（`rudp_server_egress`）：

1. **握手包（0-RTT 内核响应）**：
   - `rudp_server_ingress` 收到发往 `local_port` 的 `TCP SYN` 包时，直接生成初始序列号写入 `SERVER_CONNS`（状态立即设为 `STATE_ESTABLISHED`），并将原包原地改写为 `SYN+ACK`（附带 `MSS 1460`、`NOP`、`WScale 14` 选项），通过 `bpf_redirect(skb->ifindex, 0)` 直接从网卡发回。
2. **上行解封装（`TC Ingress`：Fake-TCP $\to$ 本机 UDP）**：
   - 收到已建立连接的 TCP 数据包后，更新 `conn->ack` 与 `conn->last_seen_ns`，解析并剥离随机 Padding。
   - 使用 `bpf_skb_adjust_room(skb, -shrink_len, BPF_ADJ_ROOM_NET, 0)` 将 `TCP 头 + Padding` 缩减为 8 字节 UDP 头：
     - **保留客户端原始源 IP**；
     - **UDP 源端口设为客户端的 TCP 源端口 `key.port`**；
     - **UDP 目的端口设为后端服务端口 `remote_port`（如 WireGuard `22809`）**；
     - UDP 校验和置 `0`（IPv4 本地递交合法免校验），返回 `TC_ACT_OK` 交由本机协议栈直接送入 `wg0`。
3. **下行封装（`TC Egress`：本机 UDP $\to$ Fake-TCP）**：
   - 当本机 `wg0`（源端口 `22809`）向客户端 `(ip, port)` 发送 UDP 回包时，`rudp_server_egress` 在 `TC Egress` 拦截该包。
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
- **正常数据包**：`pad_len` 在 `1..=padding_max_len`（默认 `1..=5`）之间随机选取，随后紧跟 `pad_len` 个随机字节，再紧跟原始 UDP 载荷。接收端验证 `tcp_payload_len > 2 + pad_len` 后剥离前 `2 + pad_len` 字节即可还原 UDP 载荷。
- **纯混淆包（`--obfuscate`）**：当触发混淆（默认概率 `5%`）时，eBPF 先通过 `bpf_clone_redirect` 发送真实数据包，随后将当前 `skb` 截断并填充为 `tcp_payload_len == 2 + pad_len`（无 UDP 载荷）的纯随机包。接收端在内核发现 `tcp_payload_len <= 2 + pad_len` 时，仅递增 `stats->obf_rx` 计数并直接 `TC_ACT_SHOT` 丢弃，不产生任何上层开销。

### 2. TCP 扩展伪装（`--tcp-extensions`）

开启 `--tcp-extensions` 后：
- 客户端发出的 `SYN` 包携带 `ECN + CWR` 标志位，并附带 12 字节标准 Linux TCP Options（`MSS 1460`、`SACK Permitted`、`NOP`、`WScale 7`、`NOP`、`NOP`）。
- 服务端回发的 `SYN+ACK` 附带 8 字节 TCP Options（`MSS 1460`、`NOP`、`WScale 14`）。
- 所有 Fake-TCP 数据包携带 `PSH | ACK` (`0x18`) 标志位，纯混淆包仅携带 `ACK` (`0x10`) 标志位。

---

## 连接状态回收机制

Fake-TCP 是无状态底层上的有状态伪装，当客户端网络切换（Wi-Fi/蜂窝切换）、NAT 端口漂移或一端重启时，必须回收残留连接状态。`rudp` 实现了四层保护：

1. **内核 LRU 自动淘汰**：`CLIENT_CONNS`、`CLIENT_BY_UDP` 与 `SERVER_CONNS` 均采用 `BPF_MAP_TYPE_LRU_HASH`（最大 4096 条目），极端高并发下内核自动按 LRU 淘汰最老条目。
2. **用户态定时巡检（每 5 秒）**：扫描所有连接，若 `ktime_get_ns() - last_seen_ns > 180s`，主动通过 Raw Socket 向对端发送 3 个 `TCP RST|ACK` 包，并从 BPF Map 中删除该条目。
3. **内核态即时 `RST` 自愈**：
   - 若 `rudp_server` 收到不在 `SERVER_CONNS` 中（例如服务端刚重启）或已超过 180 秒未活跃的 TCP 数据包，`rudp_server_ingress` 直接在内核原地构造 `TCP RST|ACK`（`seq = incoming_ack`, `ack = incoming_seq + len`）发回客户端。
   - `rudp_client_ingress` 收到 `RST` 后立即将 `conn->state` 置为 `0`，下一个到达的 UDP 包会自动走慢路径触发重新握手，实现毫秒级断线自愈。
4. **优雅退出清理**：收到 `SIGTERM` 或 `SIGINT` 时，遍历当前所有活跃连接发送 `TCP RST|ACK`，并仅卸载当前实例对应优先级（`priority = local_port`）的 TC filter。

---

## 注意事项与云厂商网卡兼容性

### 1. 后端 UDP 服务需监听 `0.0.0.0`
`rudp_server` 在 `TC Ingress` 将 Fake-TCP 原地改写为 UDP 时，为了保持零拷贝且无需 DNAT，保留了数据包原本的目的 IP（即服务器网卡自身的 IP），仅将目的端口改为 `--remote` 指定的端口。
因此，后端的 UDP 服务（例如 WireGuard `wg0`）应绑定在 `0.0.0.0:<port>`（WireGuard 默认行为）。如果后端 UDP 程序仅绑定在 `127.0.0.1:<port>`，内核会因目的 IP 是网卡 IP 而拒绝投递到 `127.0.0.1` Socket。

### 2. AWS (`ena`) / GCP (`gve`) 网卡 TX 校验和卸载处理
在 Linux 内核中，本机发出的 UDP 包默认带有 `skb->ip_summed = CHECKSUM_PARTIAL`（`csum_offset = 6`）。当 `TC Egress` 将 UDP 改写为 TCP（`csum_offset = 16`）时，内核的 `bpf_skb_adjust_room` 不会清除 `CHECKSUM_PARTIAL` 标记，这会导致 AWS `ena` 和 GCP `gve` 网卡驱动因硬件校验和偏移量不匹配而丢包。
为此，`rudp` 做了两项处理：
1. 所有包头扩缩均使用 `BPF_ADJ_ROOM_NET` 模式，确保 `skb_network_offset(skb) == 14` 与 `skb_transport_offset(skb) == 34` 始终正确。
2. `rudp_server` 默认在启动时自动调用 `ethtool -K <iface> tx off` 关闭出口网卡的 TX 硬件校验和卸载（使所有本机发出的 UDP 包以 `CHECKSUM_NONE` 进入 `TC Egress`，并在进程退出时自动执行 `ethtool -K <iface> tx on tso on` 还原网卡卸载状态），从而兼容 AWS `ena`、GCP `gve` 等严格校验硬件卸载描述符的云厂商网卡驱动。
   - 在不校验 `csum_offset` 的 `virtio_net` 网卡环境（如 Oracle Cloud）中，若希望保留网卡硬件 TSO 加速，可通过 `--disable-tx-offload=false`（或 `--keep-tx-offload`）关闭该行为。

---

## 编译与安装

### 依赖要求
- **Linux 内核**：$\ge 5.10$（需支持 TC `clsact` BPF 与 `BPF_MAP_TYPE_LRU_HASH`）
- **编译环境**：Rust 工具链、`clang`（用于编译 `ebpf/rudp_ebpf.c` 为 `bpfel-unknown-none` 字节码，构建时由 `build.rs` 自动调用并内嵌至二进制文件中）
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
          监听的本地 Fake-TCP 端口（例如: 928）
  -r, --remote <REMOTE>
          转发解封装后 UDP 包的目标地址:端口（例如: 127.0.0.1:22809）
  -i, --interface <INTERFACE>
          挂载 TC eBPF 程序的网卡名称（省略则自动根据默认路由探测）
      --payload-padding
          开启随机长度载荷填充头
      --payload-padding-max-len <PAYLOAD_PADDING_MAX_LEN>
          数据包最大随机填充长度（1..=5）[默认: 5]
      --obfuscate
          开启内核态随机混淆包注入 [环境变量: PHANTUN_OBFUSCATE]
      --obfuscate-prob <OBFUSCATE_PROB>
          每个数据包触发额外混淆包的百分比概率 [环境变量: PHANTUN_OBFUSCATE_PROB] [默认: 5.0]
      --obfuscate-max-len <OBFUSCATE_MAX_LEN>
          混淆包最大随机填充长度（1..=255）[环境变量: PHANTUN_OBFUSCATE_MAX_LEN] [默认: 255]
      --tcp-extensions
          开启真实 TCP Options 与 PSH|ACK 标志位伪装
      --disable-tx-offload [<DISABLE_TX_OFFLOAD>]
          启动时自动执行 `ethtool -K <iface> tx off`，退出时自动还原 `tx on tso on` [环境变量: RUDP_DISABLE_TX_OFFLOAD] [默认: true]
      --keep-tx-offload
          保持网卡 TX 校验和卸载与 TSO 开启（等价于 `--disable-tx-offload=false`，适用于 virtio_net 等不校验 csum_offset 的网卡）
  -h, --help
          打印帮助信息
  -V, --version
          打印版本信息
```

### `rudp_client`
```text
Usage: rudp_client [OPTIONS] --local <LOCAL> --remote <REMOTE>

Options:
  -l, --local <LOCAL>
          监听的本地 UDP 地址:端口（例如: 0.0.0.0:9283）
  -r, --remote <REMOTE>
          远端 rudp_server 的域名或 IP:端口（例如: example.com:928）
  -i, --interface <INTERFACE>
          挂载 TC eBPF 程序的网卡名称（省略则自动根据默认路由探测）
      --payload-padding
          开启随机长度载荷填充头
      --payload-padding-max-len <PAYLOAD_PADDING_MAX_LEN>
          数据包最大随机填充长度（1..=5）[默认: 5]
      --obfuscate
          开启内核态随机混淆包注入 [环境变量: PHANTUN_OBFUSCATE]
      --obfuscate-prob <OBFUSCATE_PROB>
          每个数据包触发额外混淆包的百分比概率 [环境变量: PHANTUN_OBFUSCATE_PROB] [默认: 5.0]
      --obfuscate-max-len <OBFUSCATE_MAX_LEN>
          混淆包最大随机填充长度（1..=255）[环境变量: PHANTUN_OBFUSCATE_MAX_LEN] [默认: 255]
      --tcp-extensions
          开启真实 TCP Options 与 PSH|ACK 标志位伪装
  -h, --help
          打印帮助信息
  -V, --version
          打印版本信息
```

---

## Systemd 部署示例

### 1. 服务端 (`/etc/systemd/system/rudp.service`)

将公网 TCP `928` 端口收到的 Fake-TCP 流量解封装转发至本机 WireGuard `22809` 端口：

```ini
[Unit]
Description=rudp eBPF server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="RUST_LOG=info"
Environment="PHANTUN_OBFUSCATE_PROB=5"
Environment="PHANTUN_OBFUSCATE_MAX_LEN=32"
ExecStart=/usr/local/bin/rudp_server --local 928 --remote 127.0.0.1:22809 --payload-padding --tcp-extensions --obfuscate
Restart=always
RestartSec=2
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

### 2. 客户端 / 中转端 (`/etc/systemd/system/rudp-jp.service`)

在中转机或客户端监听 UDP `0.0.0.0:9283`，封装为 Fake-TCP 发往远端 `rudp_server`（同一台机器可按不同本地端口部署多个服务，如 `9281`、`9282`、`9283`）：

```ini
[Unit]
Description=rudp eBPF client (JP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="RUST_LOG=info"
Environment="PHANTUN_OBFUSCATE_PROB=5"
Environment="PHANTUN_OBFUSCATE_MAX_LEN=32"
ExecStart=/usr/local/bin/rudp_client --local 0.0.0.0:9283 --remote jp.example.com:928 --payload-padding --tcp-extensions --obfuscate
Restart=always
RestartSec=2
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

启用并查看运行状态与 eBPF 统计日志：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rudp.service
sudo journalctl -u rudp.service -f
```
