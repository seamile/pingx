# PingX

[🇬🇧 English](#pingx) ⇌ [🇨🇳 中文](#pingx-中文)

PingX is a practical network diagnostic CLI for **ICMP**, **half-open TCP SYN**, **UDP**, and **HTTP** probing. It supports IPv4 and IPv6 Ping, GeoIP, JSON output, interface binding on Unix, and ICMP/UDP/TCP traceroute on Linux, macOS, and x86_64 Windows.

## Features

1. **Multi-Protocol**: ICMP, TCP, UDP, and HTTP probing.
2. **Dual Stack**: Full support for IPv4, IPv6, and domain resolution.
3. **Concurrency**: Probe multiple targets simultaneously.
4. **GeoIP**: Retrieve geographical location (country, region, city, coordinates) for IP addresses.
5. **JSON Output**: Export results to JSON for machine readability.
6. **Interface Binding**: Bind all probes to a specific network interface (e.g., `en0`, `eth0`, `utun1`).
7. **Traceroute**: Trace ICMP, UDP, or half-open TCP paths with per-hop RTTs and multiple responding nodes.
8. **macOS Helper**: Run privileged probes through a root-owned launchd helper without starting PingX as root.

## Installation

### Install with Cargo

```shell
cargo install pingx
```

### Linux Permissions

On Linux systems, `pingx` attempts to use unprivileged **DGRAM sockets** first, which work without root privileges if `net.ipv4.ping_group_range` covers the user's group.

If that fails, it falls back to **RAW sockets**, which require `CAP_NET_RAW` capability. To enable this:

```shell
sudo setcap cap_net_raw+ep $(which pingx)
```

**Note**: The permissions will be lost if you reinstall or recompile pingx. You'll need to run the command again.

### macOS Privileged Helper

`cargo install pingx` does not elevate the program. On the first interactive privileged probe, PingX offers to install or update a root-owned helper. You can also manage it directly:

```shell
pingx helper install
pingx helper status
pingx helper uninstall
```

The helper runs on demand through launchd and is authorized for the UID that installed it. Other processes with the same UID can use its network-probe interface. Only installation, update, and removal ask for administrator approval. Running PingX as root uses the local probe implementation directly. HTTP requests, GeoIP downloads, and helper installation remain in the normal user process. A protocol mismatch or a helper installed for another UID prompts you to reinstall it.

On macOS, HTTP targets and targets that require the privileged helper must be run in separate commands because HTTP requests never run inside the helper.

### Windows Requirements

The Windows release ZIP already includes the required WinDivert 2.2.2 x64 runtime. For a `cargo install` build, follow [docs/WINDIVERT.md](docs/WINDIVERT.md): download the pinned official archive, verify its SHA-256, and place `WinDivert.dll` and `WinDivert64.sys` beside `pingx.exe`.

Windows UDP/TCP Ping and all traceroute modes require an Administrator terminal. ICMP Ping uses the Windows IP Helper API and does not load WinDivert. Interface binding with `-I` is not supported on Windows.

## Usage

### Basic Usage (ICMP)

```shell
# IPv4
pingx 1.1.1.1

# IPv6
pingx 2400:3200::1

# Domain (IPv6 preferred)
pingx example.com
```

### Protocol Modes

#### Auto-Detection Mode

PingX automatically selects the protocol based on the target format:
- Starts with `http://` or `https://`: Uses HTTP protocol.
- Format `<host>:<port>`: Uses TCP by default.
- Others: Uses ICMP by default.

For host targets, an explicit `-T` or `-U` overrides auto-detection. With `-U`, `<host>:<port>` uses UDP and the port is interpreted as a UDP port. When the port is omitted, `-T` uses 80 and `-U` uses 33434.

```shell
# Auto-detected as HTTP
pingx https://www.google.com

# Auto-detected as TCP (port 80)
pingx 1.1.1.1:80
```

#### Forced Mode

Use flags to force specific protocols (target must match required format):

- `-4`: Restrict address resolution to IPv4.
- `-6`: Restrict address resolution to IPv6.
- `-T` / `--tcp`: Force TCP protocol (default port 80).
- `-U` / `--udp`: Force UDP protocol (default port 33434).
- `-H` / `--http`: Force HTTP protocol.

```shell
# Force IPv4
pingx -4 example.com

# Force TCP
pingx -T example.com:443
```

### Interface Binding

Specify which network interface to send probes through (e.g., `en0`, `eth0`, `utun1`):

```shell
# ICMP via en0
pingx -I en0 223.5.5.5

# TCP via utun1
pingx --interface utun1 223.5.5.5:443
```

**Note**: Interface binding is implemented on Unix. On Linux, ICMP/TCP binding uses `SO_BINDTODEVICE`; HTTP uses source-address binding as a best-effort fallback. On macOS, privileged probes pass the selected interface to the helper. Windows does not support `-I` in this release.

### Concurrent Probing

Supports probing multiple targets simultaneously. Results are displayed interleaved unless quiet mode (`-q`) is enabled.

```shell
pingx 1.1.1.1 www.github.com
```

### Traceroute Mode

Use `-R` to trace the route to one IPv4, IPv6, or domain target. `-s` sets the total IP packet size:

```shell
pingx -R 1.1.1.1
pingx -R 2400:3200::1
pingx -R example.com
pingx -R -4 --max-hops 24 example.com
pingx -R example.com -s 64
pingx -R -I en0 example.com
pingx -R -U 1.1.1.1
pingx -R 1.1.1.1:443
pingx -R -T 1.1.1.1:443
pingx -R -6 -T '[2001:db8::1]:443'
pingx -R -U 1.1.1.1:33434
```

Minimum total packet lengths: ICMP 28/48 bytes (IPv4/IPv6), UDP 32/52 bytes, TCP 40/60 bytes. TCP traceroute packet length is fixed at those values; passing a different `-s` value is an error.

`pingx -R HOST` uses ICMP by default; `pingx -R HOST:PORT` uses TCP when no protocol flag is given. `-T` forces TCP and defaults to port 80; `-U` forces UDP and defaults to base port 33434. `-s` defaults to 40 bytes for IPv4 and 60 bytes for IPv6. `-4` and `-6` only restrict the resolved address family. Use `[IPv6]:PORT` for IPv6 ports. UDP probes use successive destination ports; TCP probes reserve a distinct local source port for each active probe. There is no separate port option.

Unlike some system `traceroute` builds that default to UDP, PingX defaults `-R HOST` to ICMP. An explicit `-U` changes both `HOST` and `HOST:PORT` to UDP; with `-U HOST:PORT`, the port is the UDP destination port.

Each hop is probed three times. The probe stream runs concurrently across hops and stops sending higher TTLs after the target replies. Each displayed RTT is the average of matching replies, and a fully unanswered hop shows `*` in both the IP and RTT columns. A hop answered by multiple nodes gets one row per node, each with its own location. Private, loopback, link-local, and IPv6 unique-local addresses show `Internal node` in the Location column. Long values are truncated to keep the table aligned. The default probe packet is 40 bytes for IPv4 and 60 bytes for IPv6; `-s` overrides the total IP packet size for ICMP and UDP.

On Linux, ICMP and TCP traceroute require `CAP_NET_RAW`; UDP traceroute reads ICMP errors from the socket error queue and does not require RAW privileges. On macOS, traceroute modes use a privileged RAW socket; a normal user reaches it through the installed helper. On Windows, all traceroute modes require an Administrator terminal and the WinDivert runtime beside `pingx.exe`. GeoIP lookup uses the existing IP2Location database and shows `-` when no location is available; it does not download a database automatically.

### Response Semantics

TCP Ping and TCP traceroute send a SYN without completing the TCP handshake. A SYN-ACK is reported as `status=open`; an RST is reported as `status=closed` and still counts as a received response with its RTT. UDP application replies are `status=reply`; target Port Unreachable errors are `status=port_unreachable`; both count as received. Other outcomes use `status=timeout`, `status=network_error`, or `status=local_error` as appropriate. A timeout means no usable response was observed and does not prove that the host is offline. Other ICMP errors identify the responding node and reason but do not contribute a target RTT.

JSON results include `target_port`, `response_counts`, `local_failures`, and `network_errors`. `response_counts` keeps open, closed, UDP reply, UDP Port Unreachable, ICMP, and HTTP outcomes separate instead of collapsing them into one final state.

### GeoIP Lookup

Retrieve geographical information for IP addresses. The first run will guide you through downloading the IP2Location database.

```shell
# Lookup physical location
pingx -g 1.1.1.1 8.8.8.8

# Manually fetch/update database
pingx --fetch-geo
```

### JSON Output

Export results in structured JSON format. If one target, outputs an object; if multiple targets, outputs an array.

```shell
# Print JSON to stdout
pingx 1.1.1.1 --json

# Write JSON to file
pingx 1.1.1.1 8.8.8.8 -c 5 --json result.json

# JSON for GeoIP
pingx -g 8.8.8.8 --json

# JSON for a successful traceroute
pingx -R example.com --json
pingx -R example.com --json route.json
```

Traceroute JSON contains `target_name`, `target`, `max_hops`, `size`, and `rows`. Each row contains `ttl` and `nodes`; each node contains `ip`, the average `rtt_ns`, and an optional `error`. JSON is emitted only after the target is reached. If it is not reached, PingX prints only the error and does not create or replace the output file.

### Common Options

- `-c <COUNT>`: Stop after sending count packets.
- `-i <INTERVAL>`: Wait interval seconds between sending each packet (default 1.0s).
- `-w <DEADLINE>`: Stop running after deadline seconds.
- `-W <TIMEOUT>`: Time to wait for a response, in seconds (default 1.0s).
- `-t <TTL>`: Set the IP Time to Live (default 64).
- `-s <SIZE>`: Ping payload size (default 56); in traceroute, total IP packet size (default 40/60 for IPv4/IPv6).
- `--max-hops <N>`: Traceroute hop limit (default 32; `-R` only).
- `-T` / `--tcp`: Use half-open TCP SYN probing (default port 80).
- `-U` / `--udp`: Use UDP (default port 33434).
- `HOST:PORT`: TCP target port, or UDP port when `-U` is set; use `[IPv6]:PORT` for IPv6.
- `-I <IFACE>`: Specify a Unix network interface to bind to (e.g., `en0`, `eth0`, `utun1`); unavailable on Windows.
- `-q`: Quiet output. Only displays summary statistics.

---

# PingX (中文)

[🇨🇳 中文](#pingx-中文) ⇌ [🇬🇧 English](#pingx)

PingX 是一款实用的网络诊断命令行工具，支持 **ICMP**、**半开 TCP SYN**、**UDP** 和 **HTTP** 探测，覆盖 IPv4/IPv6 Ping、GeoIP、JSON 输出，以及 Linux、macOS 和 x86_64 Windows 上的 ICMP/UDP/TCP 路由追踪。

## 特性

1. **多协议支持**: 支持 ICMP、TCP、UDP 和 HTTP 协议探测。
2. **双栈支持**: 完美支持 IPv4、IPv6 地址及域名解析。
3. **并发探测**: 支持同时对多个目标发起探测。
4. **GeoIP 信息**: 获取 IP 地址的物理地理位置（国家、地区、城市、经纬度）。
5. **JSON 输出**: 支持将探测或定位结果以 JSON 格式输出，方便集成。
6. **网卡绑定**: 将探测流量绑定到指定网络接口（如 `en0`、`eth0`、`utun1`）。
7. **路由追踪**: 追踪 ICMP、UDP 或半开 TCP 路径，并按跳显示 RTT 和多个响应节点。
8. **macOS Helper**：通过 root 所有的 launchd helper 执行特权探测，无需以 root 启动 PingX。

## 安装

### 使用 Cargo 安装

```shell
cargo install pingx
```

### Linux 权限设置

在 Linux 系统上，PingX 会优先尝试使用非特权 **DGRAM socket**。如果系统配置了 `net.ipv4.ping_group_range`，则无需 root 权限即可运行。

如果 DGRAM 模式不可用，程序会回退到 **RAW socket** 模式，此时需要 `CAP_NET_RAW` 权限：

```shell
sudo setcap cap_net_raw+ep $(which pingx)
```

**注意**：如果重新安装或重新编译 pingx，权限将会丢失，需要重新运行上述命令。

### macOS 特权 Helper

`cargo install pingx` 不会提权。首次在交互终端执行需要特权的探测时，PingX 会提示安装或更新 root 所有的 helper。也可以直接管理：

```shell
pingx helper install
pingx helper status
pingx helper uninstall
```

helper 由 launchd 按需启动，仅授权安装它的 UID 使用；同一 UID 的其他进程也可以调用其网络探测接口。只有安装、更新和卸载会请求管理员授权。以 root 运行 PingX 时直接使用本地探测实现。HTTP 请求、GeoIP 下载和 helper 安装仍由普通用户进程处理。协议版本不兼容或 helper 属于其他 UID 时，会提示重新安装。

在 macOS 上，HTTP 目标与需要特权 helper 的目标必须分开执行，因为 HTTP 请求不会在 helper 中运行。

### Windows 运行依赖

Windows 发布 ZIP 已包含所需的 WinDivert 2.2.2 x64 运行文件。使用 `cargo install` 安装时，请按 [docs/WINDIVERT.md](docs/WINDIVERT.md) 下载固定版本的官方压缩包、校验 SHA-256，并将 `WinDivert.dll` 与 `WinDivert64.sys` 放到 `pingx.exe` 同目录。

Windows 的 UDP/TCP Ping 和所有路由追踪模式需要管理员终端。ICMP Ping 使用 Windows IP Helper API，不加载 WinDivert。Windows 暂不支持 `-I` 网卡绑定。

## 用法

### 基础用法 (ICMP)

```shell
# IPv4
pingx 1.1.1.1

# IPv6
pingx 2400:3200::1

# 域名 (优先使用 IPv6)
pingx example.com
```

### 指定协议模式

#### 自动识别模式

PingX 会根据目标格式自动选择协议：

- `http://` 或 `https://` 开头：使用 HTTP 协议。
- `<host>:<port>` 格式：默认使用 TCP。
- 其他：默认使用 ICMP。

对于主机目标，显式指定 `-T` 或 `-U` 会覆盖自动识别。配合 `-U` 时，`<host>:<port>` 使用 UDP，端口按 UDP 目标端口解释；省略端口时，`-T` 默认使用 80，`-U` 默认使用 33434。

```shell
# 自动识别为 HTTP
pingx https://www.google.com

# 自动识别为 TCP (端口 80)
pingx 1.1.1.1:80
```

#### 强制模式

使用参数强制指定协议（此时参数必须符合特定格式）：

- `-4`: 仅解析 IPv4 地址。
- `-6`: 仅解析 IPv6 地址。
- `-T` / `--tcp`: 强制使用 TCP 协议（默认端口 80）。
- `-U` / `--udp`: 强制使用 UDP 协议（默认端口 33434）。
- `-H` / `--http`: 强制使用 HTTP 协议。

```shell
# 检测 IPv4
pingx -4 example.com

# 强制使用 TCP 协议
pingx -T example.com:443
```

### 网卡绑定

指定探测流量从哪个网络接口发送（如 `en0`、`eth0`、`utun1`）：

```shell
# ICMP 通过 en0
pingx -I en0 223.5.5.5

# TCP 通过 utun1
pingx --interface utun1 223.5.5.5:443
```

**注意**：网卡绑定目前实现于 Unix。Linux 的 ICMP/TCP 通过 `SO_BINDTODEVICE` 绑定，HTTP 通过源地址绑定作为尽力而为的回退方案。macOS 的特权探测会把指定网卡传给 helper。Windows 当前版本不支持 `-I`。

### 并发探测

pingx 可以并发对多个目标以不同协议进行检测。结果将交替显示，除非开启安静模式 (`-q`)。

```shell
pingx 1.1.1.1 www.github.com
```

### 路由追踪模式

使用 `-R` 追踪一个 IPv4、IPv6 或域名目标；通过 `-s` 设置 IP 报文总长度：

```shell
pingx -R 1.1.1.1
pingx -R 2400:3200::1
pingx -R example.com
pingx -R -4 --max-hops 24 example.com
pingx -R example.com -s 64
pingx -R -I en0 example.com
pingx -R -U 1.1.1.1
pingx -R 1.1.1.1:443
pingx -R -T 1.1.1.1:443
pingx -R -6 -T '[2001:db8::1]:443'
pingx -R -U 1.1.1.1:33434
```

`pingx -R HOST` 默认使用 ICMP；未指定协议参数时，`pingx -R HOST:PORT` 使用 TCP。`-T` 强制 TCP 且省略端口时默认 80，`-U` 强制 UDP 且省略端口时默认基础端口 33434。`-s` 设置路由追踪的 IP 报文总长度，IPv4/IPv6 默认分别为 40/60 字节。`-4` 和 `-6` 只限制地址族。IPv6 带端口使用 `[IPv6]:PORT`。UDP 使用递增的目的端口，TCP 会为每个活动探测预留一个独立的本地源端口。不提供独立端口参数。

部分系统的 `traceroute` 默认使用 UDP，而 PingX 的 `-R HOST` 默认使用 ICMP。显式指定 `-U` 后，`HOST` 和 `HOST:PORT` 都改用 UDP；`-U HOST:PORT` 中的端口即 UDP 目标端口。

每一跳发送三次探测。不同 TTL 使用流水线并发发送，收到目标回复后不再发送更高 TTL。每个显示值是对应响应的平均 RTT；整跳无响应时在 IP 和 RTT 列显示 `*`。同一跳若收到多个节点的回复，每个节点单独一行，并分别显示位置。私有地址、回环地址、链路本地地址和 IPv6 唯一本地地址在 Location 列显示 `Internal node`。过长内容会截断以保持表格对齐。默认探测包为 40 字节 IPv4 或 60 字节 IPv6；`-s`可覆盖 ICMP/UDP 的 IP 报文总长度。最小总长度：ICMP 为 28/48 字节（IPv4/IPv6），UDP 为 32/52 字节，TCP 为 40/60 字节。TCP 路由追踪包长固定，显式传入其他值会报错。

Linux 的 ICMP/TCP 路由追踪需要 `CAP_NET_RAW`；UDP 路径从 socket 错误队列读取 ICMP 错误，不需要 RAW 权限。macOS 的路由追踪使用特权 RAW socket，普通用户通过已安装的 helper 使用。Windows 的所有路由追踪模式需要管理员终端，并将 WinDivert 运行文件放在 `pingx.exe` 同目录。位置复用现有 IP2Location 数据库，查询不到时显示 `-`，不会自动下载数据库。

### 响应语义

TCP Ping 和 TCP 路由追踪只发送 SYN，不完成 TCP 握手。收到 SYN-ACK 显示 `status=open`；收到 RST 显示 `status=closed`，仍计为成功响应并记录 RTT。UDP 应用响应为 `status=reply`，目标返回的 Port Unreachable 为 `status=port_unreachable`，两者都计入成功响应。其他结果使用 `status=timeout`、`status=network_error` 或 `status=local_error`。超时表示没有观察到可用响应，不能据此判定主机离线；其他 ICMP 错误会显示响应节点和原因，但不计入目标 RTT。

JSON 结果包含 `target_port`、`response_counts`、`local_failures` 和 `network_errors`。`response_counts` 会分别保留开放端口、关闭端口、UDP 应用响应、UDP Port Unreachable、ICMP 和 HTTP 等响应类型，不用一个最终状态掩盖运行期间的差异。

### GeoIP 位置查询

获取 IP 地址的物理地理位置信息。第一次运行会引导你下载 IP2Location 数据库。

```shell
# 查询物理位置
pingx -g 1.1.1.1 8.8.8.8

# 手动更新/下载数据库
pingx --fetch-geo
```

### JSON 格式输出

将结果以结构化的 JSON 格式输出。单个目标输出对象 `{...}`，多个目标输出列表 `[{...}, ...]`。

```shell
# 打印 JSON 到屏幕
pingx 1.1.1.1 --json

# 保存 JSON 到文件
pingx 1.1.1.1 8.8.8.8 -c 5 --json result.json

# GeoIP 模式输出 JSON
pingx -g 8.8.8.8 --json

# 成功完成路由追踪后输出 JSON
pingx -R example.com --json
pingx -R example.com --json route.json
```

路由追踪 JSON 包含 `target_name`、`target`、`max_hops`、`size` 和 `rows`。每个 `row` 包含 `ttl` 和 `nodes`；每个 `node` 包含 `ip`、平均 `rtt_ns` 和可选的 `error`。只有到达目标后才会输出 JSON；未到达目标时仅输出错误，不会创建或覆盖结果文件。

### 常用参数

- `-c <COUNT>`: 发送数据包的数量。
- `-i <INTERVAL>`: 发包间隔（秒），默认 1.0 秒。
- `-w <DEADLINE>`: 持续运行的时间限制（秒）。
- `-W <TIMEOUT>`: 等待响应的超时时间（秒），默认 1.0 秒。
- `-t <TTL>`: 设置 IP 生存时间 (TTL)，默认 64。
- `-s <SIZE>`: Ping 的载荷大小（默认 56 字节）；路由追踪使用 IP 报文总长度（IPv4/IPv6 默认 40/60 字节）。
- `--max-hops <N>`: 路由追踪最大跳数（默认 32，仅用于 `-R`）。
- `-T` / `--tcp`: 使用半开 TCP SYN 探测（默认端口 80）。
- `-U` / `--udp`: 使用 UDP（默认端口 33434）。
- `HOST:PORT`：TCP 目标端口，或配合 `-U` 设置 UDP 端口；IPv6 使用 `[IPv6]:PORT`。
- `-I <IFACE>`: 指定 Unix 网卡接口（如 `en0`、`eth0`、`utun1`）；Windows 不可用。
- `-q`: 安静模式，不显示逐个包的详细信息，仅显示统计结果。
