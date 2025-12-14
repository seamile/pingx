# PingX

PingX 是一个通用的网络诊断工具，可用于代替系统的 ping 和 ping6 命令。

## 特性

1. pingx 可以对 ipv4、ipv6 地址，以及域名进行诊断测试。
2. 支持 ICMP、HTTP、TCP、UDP 协议。
3. 可以并发对多个目标同时发起 ping。

## 用法

### 直接 ping 一个目标

```shell
# ipv4
pingx 1.1.1.1

# ipv6
pingx 2400:3200::1

# domain
pingx example.com
```

ping 的结果与系统的 ping 命令保持一致：

```shell
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=59 time=0.864 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=59 time=0.791 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=59 time=0.921 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=59 time=0.787 ms
64 bytes from 1.1.1.1: icmp_seq=5 ttl=59 time=0.801 ms
64 bytes from 1.1.1.1: icmp_seq=6 ttl=59 time=0.853 ms
64 bytes from 1.1.1.1: icmp_seq=7 ttl=59 time=0.803 ms
64 bytes from 1.1.1.1: icmp_seq=8 ttl=59 time=0.791 ms
64 bytes from 1.1.1.1: icmp_seq=9 ttl=59 time=0.795 ms
64 bytes from 1.1.1.1: icmp_seq=10 ttl=59 time=0.960 ms

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 1863ms
rtt min/avg/max/mdev = 0.787/0.836/0.960/0.058 ms
```

### 多协议支持

pingx 默认使用 ICMP 协议, 也可通过以下参数指定协议。

```shell
# TCP
pingx -t 8.8.8.8

# UDP
pingx -u 8.8.4.4

# HTTP (通过协议头来识别，无需特殊参数)
pingx http://example.com/
```

### 并发探测多个目标

对多个目标发起探测时，自动转为安静模式，只展示对每一个目标最终的探测结果，而不再动态显示每次的探测状态。

```shell
pingx 8.8.8.8 2001:4860:4860::8888

--- 8.8.8.8 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 1868ms
rtt min/avg/max/mdev = 0.352/0.391/0.426/0.024 ms

--- 2001:4860:4860::8888 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 1855ms
rtt min/avg/max/mdev = 0.399/0.846/2.575/0.711 ms
```


### 其他参数

- `-i INTERVAL`: 发包间隔，默认1秒。
- `-c COUNT`: 发包数量
- `-t DEADLINE`: 持续运行时间
- `-W TIMEOUT`: 等待响应的超时时间
- `-q`: 安静模式。只显示最终统计结果，不会动态显示每个包的状态

未指定 `-c` 或 `-t` 参数时，会持续对目标进行探测，直至收到 INT (interrupt) 信号。如果 `-t` 与 `-c` 同时使用，任何一个目标达成，ping 就会停止。
