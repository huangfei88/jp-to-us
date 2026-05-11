#!/usr/bin/env bash
# =============================================================================
# WireGuard VPN Server Setup — San Jose Linux (Ubuntu 20.04 / 22.04 / Debian 11+)
# 用途：将大阪 Windows 机器的所有流量通过本服务器出口，完全伪装为美国 IP
# 运行方式：sudo bash setup-server.sh
# =============================================================================
set -euo pipefail

# ── 颜色输出 ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "请以 root 权限运行：sudo bash $0"

# ── 配置变量（按需修改）────────────────────────────────────────────────────────
WG_IFACE="wg0"
WG_PORT=51820                       # WireGuard 监听端口
WG_SUBNET_V4="10.10.0.0/24"        # 隧道 IPv4 子网
WG_SERVER_V4="10.10.0.1"           # 服务端隧道 IP
WG_CLIENT_V4="10.10.0.2"           # 客户端隧道 IP
WG_SUBNET_V6="fd10:cafe::/64"      # 隧道 IPv6 子网
WG_SERVER_V6="fd10:cafe::1"        # 服务端隧道 IPv6
WG_CLIENT_V6="fd10:cafe::2"        # 客户端隧道 IPv6
KEY_DIR="/etc/wireguard/keys"
# conntrack 哈希桶数 = nf_conntrack_max / 4（建议比例，平衡内存与查找性能）
# 若修改 sysctl 中的 nf_conntrack_max，请同步调整此值
CONNTRACK_HASHSIZE=131072

# 自动检测出口网卡（排除 lo / wg*）
PUB_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
[[ -z "$PUB_IF" ]] && error "无法自动检测出口网卡，请手动设置 PUB_IF"
info "检测到出口网卡：$PUB_IF"

# ── 1. 安装依赖 ────────────────────────────────────────────────────────────────
info "安装 WireGuard 及相关工具..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    wireguard wireguard-tools iptables iptables-persistent iproute2 \
    openssl curl

# ── 2. 内核参数优化（低延迟 + 高吞吐量） ────────────────────────────────────────
info "优化内核网络参数..."
cat > /etc/sysctl.d/99-vpn-perf.conf << 'SYSCTL'
# ── 转发 ──
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ── BBR 拥塞控制（低延迟高带宽）──
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# ── 套接字缓冲区（企业级大缓冲）──
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 67108864
net.ipv4.tcp_wmem = 4096 1048576 67108864
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536

# ── 连接队列 ──
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# ── 其他性能 ──
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65535
# TCP MTU 探测：防止跨太平洋链路上 PMTUD 黑洞导致 TCP 连接卡死（企业级必须）
net.ipv4.tcp_mtu_probing = 1
# socket 选项内存上限：辅助数据（ancillary data / cmsg）的每个套接字内存上限。
# 512 KB（524288 B）确保大缓冲区场景下 IP_PKTINFO、SO_TIMESTAMPING 等辅助选项
# 不会因默认 20480 B 上限而被截断，与 64 MB rmem_max/wmem_max 配套使用。
net.core.optmem_max = 524288
# TCP Keepalive：加速检测死连接，避免NAT表和conntrack资源被僵尸连接占用
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
# TIME_WAIT 状态超时（默认 60s），减少 conntrack 条目长期占用
net.ipv4.tcp_fin_timeout = 30

# ── conntrack（NAT VPN 连接跟踪表，防止满表丢包）──
# 默认值通常为 65536–131072，全流量 NAT VPN 高并发时极易耗尽
# 每条 conntrack 约占 300–400 字节；524288 条约需 ~200 MB
net.netfilter.nf_conntrack_max = 524288
# TCP established 超时：默认 432000s（5天），改为 3600s（1小时）
# NAT 表中失活的长连接将在 1 小时内被回收，避免表溢出
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
# TIME_WAIT/CLOSE_WAIT 加速回收
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
# UDP 跟踪超时（默认 30s/180s）
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60

# ── 路由安全 / 防 ICMP 劫持 ──
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# 作为 NAT/转发服务器禁止发送 ICMP 重定向，防止干扰客户端路由表
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# 不接受 ICMP 重定向，防止路由被劫持（all + default 覆盖动态新建接口如 wg0）
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# 禁止源路由（Source Routing）——防止攻击者操纵数据包路径绕过防火墙和 NAT 规则
# 默认在转发主机上应为 0，但显式设置保证安全基线不受其他配置覆盖
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ── 软中断数据包预算（提升高负载吞吐量）──
# 每次 NAPI poll 处理的最大数据包数（默认 300）——对高速 VPN 转发场景可提升吞吐量
# 防止网卡在大流量时因配额不足被频繁打断，减少 CPU 上下文切换
net.core.netdev_budget = 600
SYSCTL
# 预加载 BBR 模块（如果可用）——必须在 sysctl -p 之前，否则在以模块形式编译 BBR 的内核上
# sysctl -p 对 tcp_congestion_control = bbr 报 "Invalid argument"，set -e 会中断整个脚本
modprobe tcp_bbr 2>/dev/null || true
# 预加载 nf_conntrack 模块，确保 sysctl 中的 nf_conntrack_max 等参数可写
modprobe nf_conntrack 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-vpn-perf.conf > /dev/null

# 设置 conntrack 哈希桶数（建议值 = nf_conntrack_max / 4）
# hashsize 仅可在模块加载后通过 sysfs 写入，不走 sysctl
if [[ -f /sys/module/nf_conntrack/parameters/hashsize ]]; then
    echo "${CONNTRACK_HASHSIZE}" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi
# 持久化：模块加载时自动设置 hashsize（重启后仍生效）
echo "options nf_conntrack hashsize=${CONNTRACK_HASHSIZE}" > /etc/modprobe.d/nf-conntrack.conf

# 检查 BBR 是否真正生效
if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    info "BBR 拥塞控制已加载 ✓"
else
    warn "BBR 模块不可用（内核版本可能过低），降级为 cubic"
    sed -i 's/net.ipv4.tcp_congestion_control = bbr/net.ipv4.tcp_congestion_control = cubic/' \
        /etc/sysctl.d/99-vpn-perf.conf
    sed -i 's/net.core.default_qdisc = fq$/net.core.default_qdisc = fq_codel/' \
        /etc/sysctl.d/99-vpn-perf.conf
    sysctl -p /etc/sysctl.d/99-vpn-perf.conf > /dev/null
fi

# ── 3. 生成密钥对 ──────────────────────────────────────────────────────────────
info "生成服务端 / 客户端密钥对..."
# 保存当前 umask 并设置严格权限（仅影响本段密钥生成，之后立即恢复）
OLD_UMASK=$(umask)
umask 077
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

# 服务端
if [[ ! -f "$KEY_DIR/server.key" ]]; then
    wg genkey | tee "$KEY_DIR/server.key" | wg pubkey > "$KEY_DIR/server.pub"
    chmod 600 "$KEY_DIR/server.key"
fi
# 客户端
if [[ ! -f "$KEY_DIR/client.key" ]]; then
    wg genkey | tee "$KEY_DIR/client.key" | wg pubkey > "$KEY_DIR/client.pub"
    chmod 600 "$KEY_DIR/client.key"
fi
# Pre-shared key（额外一层加密）
if [[ ! -f "$KEY_DIR/psk.key" ]]; then
    wg genpsk > "$KEY_DIR/psk.key"
    chmod 600 "$KEY_DIR/psk.key"
fi

SERVER_PRIV=$(cat "$KEY_DIR/server.key")
SERVER_PUB=$(cat  "$KEY_DIR/server.pub")
CLIENT_PRIV=$(cat "$KEY_DIR/client.key")
CLIENT_PUB=$(cat  "$KEY_DIR/client.pub")
PSK=$(cat         "$KEY_DIR/psk.key")

# 恢复原始 umask（密钥生成完毕）
umask "$OLD_UMASK"

# ── 4. 写入服务端 wg0.conf ──────────────────────────────────────────────────────
info "生成 /etc/wireguard/wg0.conf ..."
cat > /etc/wireguard/wg0.conf << EOF
# ============================================================
# WireGuard Server — San Jose Linux
# ============================================================
[Interface]
Address    = ${WG_SERVER_V4}/24, ${WG_SERVER_V6}/64
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}

# ── NAT：所有客户端流量从 ${PUB_IF} 出口 ──────────────────
PostUp   = iptables  -t nat -A POSTROUTING -s ${WG_SUBNET_V4} -o ${PUB_IF} -j MASQUERADE
PostUp   = ip6tables -t nat -A POSTROUTING -s ${WG_SUBNET_V6} -o ${PUB_IF} -j MASQUERADE
PostDown = iptables  -t nat -D POSTROUTING -s ${WG_SUBNET_V4} -o ${PUB_IF} -j MASQUERADE
PostDown = ip6tables -t nat -D POSTROUTING -s ${WG_SUBNET_V6} -o ${PUB_IF} -j MASQUERADE

# ── 转发规则（入→出 / 出→入） ─────────────────────────────
PostUp   = iptables  -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostUp   = iptables  -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables  -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostDown = iptables  -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── IPv6 转发规则（与 IPv4 对称，保证 ::/0 客户端流量正常转发）──
PostUp   = ip6tables -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostUp   = ip6tables -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── MSS 钳制：防止跨 MTU 边界导致 TCP 连接卡住（企业级必须）──
# 双向精确匹配：避免宽泛规则影响非 VPN FORWARD 流量
# 入方向（客户端→互联网）：出口为 ${PUB_IF}，clamping 使用其 MTU（无害但保持对称）
# 出方向（互联网→客户端）：出口为 ${WG_IFACE}（MTU 1420），防止大包进隧道时被分片
PostUp   = iptables  -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp   = iptables  -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables  -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables  -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp   = ip6tables -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp   = ip6tables -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip6tables -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ip6tables -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# ── MTU：避免分片，适合日本到美国的太平洋链路 ────────────────
MTU = 1420

# ── 客户端 Peer ─────────────────────────────────────────────
[Peer]
# Windows 大阪客户端
PublicKey    = ${CLIENT_PUB}
PresharedKey = ${PSK}
AllowedIPs   = ${WG_CLIENT_V4}/32, ${WG_CLIENT_V6}/128
EOF
chmod 600 /etc/wireguard/wg0.conf

# ── 5. 开放防火墙端口 ──────────────────────────────────────────────────────────
info "开放 UDP ${WG_PORT}..."
if command -v ufw &>/dev/null; then
    ufw allow "${WG_PORT}/udp" > /dev/null
    ufw allow OpenSSH        > /dev/null
    # 允许转发
    sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw 2>/dev/null || true
    ufw --force reload       > /dev/null
fi
# 使用 -C 先检查规则是否存在，避免重复执行脚本时在 INPUT 链中叠加重复条目
iptables  -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || \
    iptables  -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true
ip6tables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || \
    ip6tables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true

# 持久化防火墙规则（仅保存 INPUT 规则；FORWARD/NAT 由 PostUp/PostDown 动态管理）
# 必须先停止 wg0：若 wg0 已在运行（二次安装），其 PostUp 规则已写入 iptables；
# 若此时直接 save，这些规则会被持久化，重启后 netfilter-persistent 恢复一次，
# wg-quick PostUp 再添加一次，造成 FORWARD/NAT 规则双重叠加，破坏 conntrack 和 NAT 正确性。
wg-quick down "${WG_IFACE}" 2>/dev/null || true
netfilter-persistent save > /dev/null 2>&1 || warn "netfilter-persistent save 失败，规则可能在重启后丢失"

# ── 6. 启动并设置开机自启 ──────────────────────────────────────────────────────
info "启动 WireGuard..."
systemctl enable  "wg-quick@${WG_IFACE}"
systemctl restart "wg-quick@${WG_IFACE}"

# ── 7. 生成客户端配置文件 ──────────────────────────────────────────────────────
SERVER_PUBLIC_IP=$(curl -s4 --max-time 10 https://api.ipify.org 2>/dev/null)
if [[ -z "$SERVER_PUBLIC_IP" ]]; then
    warn "无法从 api.ipify.org 获取公网 IP，将使用本机 IP 作为 Endpoint"
    warn "请手动核对客户端配置文件中的 Endpoint 地址是否正确"
    SERVER_PUBLIC_IP=$(hostname -I | awk '{print $1}')
fi
CLIENT_CONF="/etc/wireguard/client-wg0.conf"

info "生成客户端配置 ${CLIENT_CONF}..."
cat > "$CLIENT_CONF" << EOF
# ============================================================
# WireGuard Client — Osaka Windows
# 将此文件导入 Windows WireGuard 客户端
# ============================================================
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address    = ${WG_CLIENT_V4}/32, ${WG_CLIENT_V6}/128
DNS        = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU        = 1420

# ── 全隧道：所有流量（IPv4 + IPv6）走 VPN ──────────────────
# DNS 也通过隧道，防止 DNS 泄露

[Peer]
PublicKey    = ${SERVER_PUB}
PresharedKey = ${PSK}
Endpoint     = ${SERVER_PUBLIC_IP}:${WG_PORT}
AllowedIPs   = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
chmod 600 "$CLIENT_CONF"

# ── 8. 完成，打印摘要 ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} WireGuard 服务端配置完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  服务端公钥   : ${SERVER_PUB}"
echo -e "  服务端 IP    : ${SERVER_PUBLIC_IP}:${WG_PORT}"
echo -e "  客户端配置   : ${CLIENT_CONF}"
echo ""
echo -e "${YELLOW}下一步：${NC}"
echo -e "  1. 将 ${CLIENT_CONF} 复制到 Windows 机器"
echo -e "  2. 在 Windows 上运行 client/setup-client.ps1"
echo -e "  3. 运行 verify/ 目录下的验证脚本确认无泄露"
echo ""
wg show "${WG_IFACE}"
