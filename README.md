# PingX

[🇬🇧 English](#pingx) ⇌ [🇨🇳 中文](#pingx-中文)

PingX is a simple and practical network diagnostic tool designed to replace system `ping` and `ping6` commands. It supports **ICMP Ping**, **TCP Ping** (via SYN handshake), and **HTTP Ping** (via HEAD requests), allowing for comprehensive connectivity testing across IPv4 and IPv6.

## Features

1. **Multi-Protocol**: ICMP, TCP, and HTTP probing.
2. **Dual Stack**: Full support for IPv4, IPv6, and domain resolution.
3. **Concurrency**: Probe multiple targets simultaneously.
4. **GeoIP**: Retrieve geographical location (country, region, city, coordinates) for IP addresses.
5. **JSON Output**: Export results to JSON for machine readability.
6. **Interface Binding**: Bind all probes to a specific network interface (e.g., `en0`, `eth0`, `utun1`).

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
- Format `<host>:<port>`: Uses TCP protocol.
- Others: Defaults to ICMP protocol.

```shell
# Auto-detected as HTTP
pingx https://www.google.com

# Auto-detected as TCP (port 80)
pingx 1.1.1.1:80
```

#### Forced Mode

Use flags to force specific protocols (target must match required format):

- `-4`: Force IPv4 ICMP.
- `-6`: Force IPv6 ICMP.
- `-T` / `--tcp`: Force TCP protocol (Target must include port, e.g., `ip:port`).
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

**Note**: On macOS, all protocol modes (ICMP/TCP/HTTP) support interface binding. On Linux, ICMP/TCP binding is fully supported via `SO_BINDTODEVICE`; HTTP is supported with `local_address()` (source IP binding, best-effort). Windows is not supported.

### Concurrent Probing

Supports probing multiple targets simultaneously. Results are displayed interleaved unless quiet mode (`-q`) is enabled.

```shell
pingx 1.1.1.1 www.github.com
```

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
```

### Common Options

- `-c <COUNT>`: Stop after sending count packets.
- `-i <INTERVAL>`: Wait interval seconds between sending each packet (default 1.0s).
- `-w <DEADLINE>`: Stop running after deadline seconds.
- `-W <TIMEOUT>`: Time to wait for a response, in seconds (default 1.0s).
- `-t <TTL>`: Set the IP Time to Live (default 64).
- `-s <SIZE>`: Size of ICMP payload in bytes (default 56).
- `-I <IFACE>`: Specify network interface to bind to (e.g., `en0`, `eth0`, `utun1`).
- `-q`: Quiet output. Only displays summary statistics.

---

# PingX (中文)

[🇨🇳 中文](#pingx-中文) ⇌ [🇬🇧 English](#pingx)

PingX 是一款简单实用的网络诊断工具，旨在替代系统的 `ping` 和 `ping6` 命令。它不仅支持标准的 **ICMP Ping**，还支持 **TCP Ping**（发送 SYN 握手报文）和 **HTTP Ping**（发送 HEAD 请求），可对 IPv4 和 IPv6 目标进行全面的连通性测试。

## 特性

1. **多协议支持**: 支持 ICMP、TCP 和 HTTP 协议探测。
2. **双栈支持**: 完美支持 IPv4、IPv6 地址及域名解析。
3. **并发探测**: 支持同时对多个目标发起探测。
4. **GeoIP 信息**: 获取 IP 地址的物理地理位置（国家、地区、城市、经纬度）。
5. **JSON 输出**: 支持将探测或定位结果以 JSON 格式输出，方便集成。
6. **网卡绑定**: 将探测流量绑定到指定网络接口（如 `en0`、`eth0`、`utun1`）。

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
- `<host>:<port>` 格式：使用 TCP 协议。
- 其他：默认为 ICMP 协议。

```shell
# 自动识别为 HTTP
pingx https://www.google.com

# 自动识别为 TCP (端口 80)
pingx 1.1.1.1:80
```

#### 强制模式

使用参数强制指定协议（此时参数必须符合特定格式）：

- `-4`: 强制使用 ICMP 协议检测 IPv4 目标。
- `-6`: 强制使用 ICMP 协议检测 IPv6 目标。
- `-T` / `--tcp`: 强制使用 TCP 协议 (目标必须包含端口，如 `ip:port`)。
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

**注意**：macOS 下所有协议模式（ICMP/TCP/HTTP）均支持网卡绑定。Linux 下 ICMP/TCP 通过 `SO_BINDTODEVICE` 完整支持，HTTP 通过 `local_address()` 绑定源 IP（尽力而为）。Windows 暂不支持。

### 并发探测

pingx 可以并发对多个目标以不同协议进行检测。结果将交替显示，除非开启安静模式 (`-q`)。

```shell
pingx 1.1.1.1 www.github.com
```

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
```

### 常用参数

- `-c <COUNT>`: 发送数据包的数量。
- `-i <INTERVAL>`: 发包间隔（秒），默认 1.0 秒。
- `-w <DEADLINE>`: 持续运行的时间限制（秒）。
- `-W <TIMEOUT>`: 等待响应的超时时间（秒），默认 1.0 秒。
- `-t <TTL>`: 设置 IP 生存时间 (TTL)，默认 64。
- `-s <SIZE>`: ICMP 数据包大小（默认 56 字节）。
- `-I <IFACE>`: 指定探测流量从哪个网卡接口发送（如 `en0`、`eth0`、`utun1`）。
- `-q`: 安静模式，不显示逐个包的详细信息，仅显示统计结果。
