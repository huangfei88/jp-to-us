# jp-to-us — 企业级全流量 VPN 配置

> **目标**：将大阪 Windows 机器的 **所有** 网络流量路由到圣何塞 Linux 服务器出口，
> 完全伪装为美国 IP，保证低延迟、高吞吐量，零泄露。

---

## 架构概览

```
[大阪 Windows 客户端]
        │
        │  WireGuard 全加密隧道（UDP 51820）
        │  AllowedIPs = 0.0.0.0/0, ::/0（全流量）
        │
        ▼
[圣何塞 Linux 服务端]
        │
        │  NAT MASQUERADE（源 IP 替换为服务器公网 IP）
        │
        ▼
    [互联网]  ← 外部看到的是圣何塞美国 IP
```

## 技术选型

| 方案 | 选型 | 理由 |
|---|---|---|
| 隧道协议 | **WireGuard** | 最低延迟、最高性能、内核原生、现代加密 |
| 加密 | ChaCha20-Poly1305 + Curve25519 + PSK | 企业级双重加密 |
| 拥塞控制 | **BBR** | Google 研发，跨洲际链路延迟低、带宽利用率高 |
| DNS | Cloudflare 1.1.1.1（隧道内） | 防 DNS 泄露，全走 VPN 出口 |
| IPv6 | 全隧道（::/0）| 防 IPv6 泄露 |

---

## 目录结构

```
jp-to-us/
├── server/
│   ├── setup-server.sh          # 圣何塞 Linux 一键安装脚本
│   └── wg0.conf.template        # 服务端配置模板（参考）
├── client/
│   ├── setup-client.ps1         # 大阪 Windows 一键安装脚本
│   └── wg-client.conf.template  # 客户端配置模板（参考）
└── verify/
    ├── check-leak.sh            # Linux 服务端泄露检测
    └── check-leak.ps1           # Windows 客户端泄露检测
```

---

## 快速部署

### 步骤 1：配置 Linux 服务端（圣何塞）

```bash
# 以 root 权限运行
sudo bash server/setup-server.sh
```

脚本将自动完成：
- 安装 WireGuard
- 优化内核参数（BBR + 大缓冲区）
- 生成服务端 + 客户端密钥对（含 Pre-Shared Key）
- 配置 NAT MASQUERADE（IPv4 + IPv6）
- 开放防火墙 UDP 51820
- 启动服务并设为开机自启
- **生成客户端配置文件** `/etc/wireguard/client-wg0.conf`

脚本完成后，将 `/etc/wireguard/client-wg0.conf` 复制到 Windows 机器。

---

### 步骤 2：配置 Windows 客户端（大阪）

1. 将 `client-wg0.conf`（从服务端复制过来的）重命名为 `wg-client.conf`，
   放到解压目录下的 `client\` 子目录中（即与 `setup-client.ps1` 同级）。

2. 以**管理员身份**运行 PowerShell，**先 `cd` 到解压根目录**，再执行：

```powershell
cd C:\jp-to-us-main
Set-ExecutionPolicy Bypass -Scope Process -Force
.\client\setup-client.ps1
```

> **注意**：必须从 `jp-to-us-main`（根目录）运行，而非从 `client\` 子目录内运行。
> 若已在 `client\` 目录内，请改用 `.\setup-client.ps1`。

脚本将自动完成：
- 下载并安装 WireGuard for Windows
- 导入并保护配置文件
- 注册并启动隧道服务（开机自启）
- 禁用其他网卡 IPv6（防泄露）
- 锁定所有网卡 DNS 到 1.1.1.1
- 禁用 Smart Multi-Homed Name Resolution
- 验证出口 IP

---

### 步骤 3：验证无泄露

**Linux 服务端验证：**
```bash
sudo bash verify/check-leak.sh
```

**Windows 客户端验证：**
```powershell
.\verify\check-leak.ps1
```

**在线验证（浏览器）：**

| 网站 | 检测内容 |
|---|---|
| https://ipleak.net | IP + DNS + WebRTC 综合检测 |
| https://dnsleaktest.com | DNS 泄露（点 Extended Test）|
| https://ipv6leak.com | IPv6 泄露 |
| https://browserleaks.com/webrtc | WebRTC 泄露 |

---

## 泄露防护矩阵

| 泄露向量 | 防护措施 |
|---|---|
| IP 泄露 | AllowedIPs = 0.0.0.0/0（全流量隧道） |
| IPv6 泄露 | AllowedIPs = ::/0 + 禁用其他网卡 IPv6 |
| DNS 泄露 | DNS 锁定为 1.1.1.1（走隧道）+ 禁用多宿主 DNS |
| WebRTC 泄露 | 使用 uBlock Origin 并启用 WebRTC 保护策略 |
| 分片/MTU 问题 | MTU = 1420（适合跨太平洋链路） |

---

## 性能优化细节

| 参数 | 值 | 说明 |
|---|---|---|
| 拥塞控制 | BBR | 低延迟高带宽，适合高延迟跨洋链路 |
| TCP 发送/接收缓冲 | 64 MB | 满足高带宽延迟积（BDP）需求 |
| MTU | 1420 | WireGuard 推荐值，避免分片 |
| PersistentKeepalive | 25 秒 | 穿越 NAT，保持连接稳定 |
| qdisc | fq（BBR）/ fq_codel（降级） | 配合 BBR 使用公平队列；BBR 不可用时自动降级为 fq_codel（含 AQM，减少 bufferbloat）|
| tcp_fin_timeout | 30 秒 | 默认 60s，加速 TIME_WAIT 回收，减少 conntrack 占用 |
| tcp_max_tw_buckets | 262144 | 默认约 8192，防止高并发 NAT 下桶溢出强制销毁 TIME_WAIT 条目 |
| conntrack 表大小 | 524288 条 | 防止全流量 NAT 下 conntrack 表溢出丢包（hashsize=131072）|
| conntrack established 超时 | 3600 秒 | 默认 432000s（5天），缩短为 1 小时，加速失活连接回收 |
| optmem_max | 524288 字节 | 与 64MB 套接字缓冲区匹配，防止辅助数据内存不足 |

---

## 管理命令

### Linux 服务端

```bash
# 查看状态
sudo wg show wg0

# 重启
sudo systemctl restart wg-quick@wg0

# 查看日志
sudo journalctl -u wg-quick@wg0 -f
```

### Windows 客户端

```powershell
# 停止 VPN
Stop-Service  "WireGuardTunnel`$jp-to-us-vpn"

# 启动 VPN
Start-Service "WireGuardTunnel`$jp-to-us-vpn"

# 卸载（从解压根目录 jp-to-us-main 运行）
.\client\setup-client.ps1 -Uninstall
```

---

## 注意事项

1. **端口开放**：确保圣何塞服务器的安全组 / 防火墙开放了 UDP 51820 入站。
2. **iptables-persistent**（仅限 Debian 11/12 + UFW **未激活**时）：若服务器重启后 NAT 规则丢失，运行
   `apt install iptables-persistent && netfilter-persistent save`。
   Debian 13 (Trixie) 使用 UFW 时无需此操作——UFW 自动持久化所有规则；wg-quick PostUp/PostDown 动态管理 NAT/FORWARD，重启后随 `wg-quick@wg0` 服务自动重建。
3. **WebRTC**：浏览器 WebRTC 可能泄露本地 IP，建议安装 uBlock Origin 并在设置中勾选「防止 WebRTC 泄露本地 IP」。
4. **VPN 断线保护（Kill Switch）**：`setup-client.ps1` 已自动配置 Windows 防火墙 Kill Switch——VPN 断线时所有出站流量将被立即阻断，防止流量暴露真实日本 IP。以下流量已豁免：DHCP 更新（UDP 67，防止租约到期后失去 IP 导致 VPN 无法恢复）、NTP 时间同步（UDP 123，防止时钟漂移超过 180s 导致 WireGuard 握手失败）、链路本地地址（169.254.0.0/16、fe80::/10，保障邻居发现和 APIPA 正常工作）。卸载时运行 `.\setup-client.ps1 -Uninstall` 会自动清除相关规则。
