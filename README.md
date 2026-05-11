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
   放到与 `setup-client.ps1` 相同目录。

2. 以**管理员身份**运行 PowerShell，执行：

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\client\setup-client.ps1
```

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
bash verify/check-leak.sh
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

# 卸载
.\client\setup-client.ps1 -Uninstall
```

---

## 注意事项

1. **端口开放**：确保圣何塞服务器的安全组 / 防火墙开放了 UDP 51820 入站。
2. **iptables-persistent**：若服务器重启后 NAT 规则丢失，运行
   `apt install iptables-persistent && netfilter-persistent save`
3. **WebRTC**：浏览器 WebRTC 可能泄露本地 IP，建议安装 uBlock Origin 并在设置中勾选「防止 WebRTC 泄露本地 IP」。
4. **VPN 断线保护（Kill Switch）**：`setup-client.ps1` 已自动配置 Windows 防火墙 Kill Switch——VPN 断线时所有出站流量将被立即阻断，防止流量暴露真实日本 IP。卸载时运行 `.\setup-client.ps1 -Uninstall` 会自动清除相关规则。
