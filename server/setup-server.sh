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

# 自动检测出口网卡（排除 lo / wg*）
PUB_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
[[ -z "$PUB_IF" ]] && error "无法自动检测出口网卡，请手动设置 PUB_IF"
info "检测到出口网卡：$PUB_IF"

# ── 1. 安装依赖 ────────────────────────────────────────────────────────────────
info "安装 WireGuard 及相关工具..."
apt-get update -qq
apt-get install -y wireguard wireguard-tools iptables iproute2 \
    openssl curl resolvconf 2>/dev/null || true

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
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# ── 连接队列 ──
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# ── 其他性能 ──
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65535

# ── 防 IP 欺骗 ──
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-vpn-perf.conf > /dev/null

# ── 3. 生成密钥对 ──────────────────────────────────────────────────────────────
info "生成服务端 / 客户端密钥对..."
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
PostUp   = iptables -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostUp   = iptables -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostDown = iptables -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT

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
iptables  -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true
ip6tables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true

# ── 6. 启动并设置开机自启 ──────────────────────────────────────────────────────
info "启动 WireGuard..."
systemctl enable  "wg-quick@${WG_IFACE}"
systemctl restart "wg-quick@${WG_IFACE}"

# ── 7. 生成客户端配置文件 ──────────────────────────────────────────────────────
SERVER_PUBLIC_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
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
