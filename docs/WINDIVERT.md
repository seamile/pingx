# WinDivert runtime for PingX

PingX dynamically loads WinDivert from the directory containing `pingx.exe`.
Windows UDP/TCP Ping and all Windows traceroute modes require an Administrator
terminal and these two unmodified x64 files from WinDivert 2.2.2:

```text
WinDivert.dll
WinDivert64.sys
```

Official release archive:

<https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip>

Archive SHA-256:

```text
63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
```

Upstream source:

<https://github.com/basil00/Divert>

WinDivert is dual-licensed under LGPLv3 or GPLv2. Its complete license text is
included in the official archive and in the PingX Windows release package as
`WinDivert-LICENSE.txt`. The version and upstream README are included as
`WinDivert-VERSION.txt` and `WinDivert-README.txt`.

For a `cargo install` build, download the official archive, verify the hash,
and copy `x64/WinDivert.dll` and `x64/WinDivert64.sys` beside `pingx.exe`,
normally under `%USERPROFILE%\.cargo\bin`.
