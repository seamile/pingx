# PingX

[🇬🇧 English](#pingx) ⇌ [🇨🇳 中文](#pingx-中文)

PingX is a simple and practical network diagnostic tool designed to replace system `ping` and `ping6` commands. It supports **ICMP Ping**, **TCP Ping** (via SYN handshake), and **HTTP Ping** (via HEAD requests), allowing for comprehensive connectivity testing across IPv4 and IPv6.

## Features

1. **Multi-Protocol**: ICMP, TCP, and HTTP probing.
2. **Dual Stack**: Full support for IPv4, IPv6, and domain resolution.
3. **Concurrency**: Probe multiple targets simultaneously.

## Installation

### Install with Cargo

```shell
cargo install pingx
```

### Linux ICMP Permission Setup

On Linux systems, ICMP ping requires special permissions. After installation, run:

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
- `-t` / `--tcp`: Force TCP protocol (Target must include port, e.g., `ip:port`).
- `-H` / `--http`: Force HTTP protocol.

```shell
# Force IPv4
pingx -4 example.com

# Force TCP
pingx -t example.com:443
```

### Concurrent Probing

Supports probing multiple targets simultaneously. In multi-target mode, quiet mode (`-q`) is automatically enabled, showing only statistics at the end.

```shell
pingx 1.1.1.1 www.github.com
```

### Common Options

- `-c <COUNT>`: Stop after sending count packets.
- `-i <INTERVAL>`: Wait interval seconds between sending each packet (default 1.0s).
- `-w <DEADLINE>`: Stop running after deadline seconds.
- `-W <TIMEOUT>`: Time to wait for a response, in seconds (default 1.0s).
- `-s <SIZE>`: Size of ICMP payload in bytes (default 56).
- `-q`: Quiet output. Only displays summary statistics.

---

# PingX (中文)

[🇨🇳 中文](#pingx-中文) ⇌ [🇬🇧 English](#pingx)

PingX 是一款简单实用的网络诊断工具，旨在替代系统的 `ping` 和 `ping6` 命令。它不仅支持标准的 **ICMP Ping**，还支持 **TCP Ping**（发送 SYN 握手报文）和 **HTTP Ping**（发送 HEAD 请求），可对 IPv4 和 IPv6 目标进行全面的连通性测试。

## 特性

1. **多协议支持**: 支持 ICMP、TCP 和 HTTP 协议探测。
2. **双栈支持**: 完美支持 IPv4、IPv6 地址及域名解析。
3. **并发探测**: 支持同时对多个目标发起探测。

## 安装

### 使用 Cargo 安装

```shell
cargo install pingx
```

### Linux ICMP 权限设置

在 Linux 系统上，ICMP ping 需要特殊权限。安装完成后，请运行：

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
- `-t` / `--tcp`: 强制使用 TCP 协议 (目标必须包含端口，如 `ip:port`)。
- `-H` / `--http`: 强制使用 HTTP 协议。

```shell
# 检测 IPv4
pingx -4 example.com

# 强制使用 TCP 协议
pingx -t example.com:443
```

### 并发探测

pingx 可以并发对多个目标以不同协议进行检测。多目标模式下会自动开启安静模式 (`-q`)，仅在结束时输出统计信息。

```shell
pingx 1.1.1.1 www.github.com
```

### 常用参数

- `-c <COUNT>`: 发送数据包的数量。
- `-i <INTERVAL>`: 发包间隔（秒），默认 1.0 秒。
- `-w <DEADLINE>`: 持续运行的时间限制（秒）。
- `-W <TIMEOUT>`: 等待响应的超时时间（秒），默认 1.0 秒。
- `-s <SIZE>`: ICMP 数据包大小（默认 56 字节）。
- `-q`: 安静模式，不显示逐个包的详细信息，仅显示统计结果。
