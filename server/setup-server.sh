#!/usr/bin/env bash
# =============================================================================
# WireGuard VPN Server Setup — San Jose Debian Linux
# 适用系统：Debian 13 (Trixie) / Debian 11 (Bullseye) / Debian 12 (Bookworm)
# 用途：将大阪 Windows 机器的所有流量通过本服务器出口，完全伪装为美国 IP
# 防火墙：UFW（Debian 默认激活）或 iptables-persistent（无 UFW 时）
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
WG_PORT=51820                       # WireGuard 监听端口（默认 51820）
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

# ── 1.5 iptables 后端选择（版本感知：Debian 13+ 用 nft；Debian 11/12 视 UFW 状态选择）──
#
# 架构说明：
#   Debian 13 (Trixie)+：内核 nftables 为唯一 netfilter 框架。UFW 通过 iptables-nft
#   shim 写规则到 nftables compat 表。wg-quick PostUp 也必须用 iptables（→ iptables-nft）
#   写到同一 nftables 框架，否则 iptables-legacy 写到老 xtables 子系统，与 nftables 互相
#   隔离——UFW 的 DEFAULT_FORWARD_POLICY=ACCEPT 在 nftables，iptables-legacy 的
#   MASQUERADE/FORWARD 在 xtables，二者对同一数据包的处理互不感知，导致 NAT 静默失效。
#
#   Debian 11/12 (Bullseye/Bookworm)：iptables-nft 为默认后端，legacy 仍可用。
#   - UFW 激活时：UFW 用 iptables-nft，wg-quick 也用 iptables-nft → 一致，无需 legacy。
#   - UFW 未激活时：netfilter-persistent 用 iptables-save/restore；若 nft 和 legacy 混用
#     会在重启后规则不一致，切换到 legacy 确保统一。
#
# 结论：Debian 13+ 永远不切 legacy；Debian 11/12 仅在 UFW 未激活时切 legacy。

info "检测 Debian 版本，选择 iptables 后端..."
_DEB_MAJOR_VER=$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_ID:-0}" | cut -d. -f1)
_DEB_MAJOR_VER_INT=0
[[ "$_DEB_MAJOR_VER" =~ ^[0-9]+$ ]] && _DEB_MAJOR_VER_INT="$_DEB_MAJOR_VER"

# 初始化：默认使用 iptables（→ iptables-nft，Debian 默认）
_IPTABLES="iptables"
_IP6TABLES="ip6tables"

if [[ "$_DEB_MAJOR_VER_INT" -ge 13 ]]; then
    # ── Debian 13+ (Trixie)：强制 iptables → iptables-nft，禁止切换 legacy ──
    # 理由：Debian 13 的 nftables 是唯一 netfilter 框架；iptables-legacy 写入独立的
    # xtables 子系统，与 UFW/nftables 的 FORWARD/NAT 规则完全隔离，导致 VPN 流量无法被 NAT。
    info "Debian 13 (Trixie) 检测到：确保 iptables → iptables-nft（不切换 legacy）..."
    if command -v update-alternatives &>/dev/null && [[ -f /usr/sbin/iptables-nft ]]; then
        update-alternatives --set iptables          /usr/sbin/iptables-nft          2>/dev/null || true
        update-alternatives --set ip6tables         /usr/sbin/ip6tables-nft         2>/dev/null || true
        update-alternatives --set iptables-save     /usr/sbin/iptables-nft-save     2>/dev/null || true
        update-alternatives --set ip6tables-save    /usr/sbin/ip6tables-nft-save    2>/dev/null || true
        update-alternatives --set iptables-restore  /usr/sbin/iptables-nft-restore  2>/dev/null || true
        update-alternatives --set ip6tables-restore /usr/sbin/ip6tables-nft-restore 2>/dev/null || true
    fi
    # _IPTABLES 保持 "iptables"（→ iptables-nft）
elif command -v update-alternatives &>/dev/null && [[ -f /usr/sbin/iptables-legacy ]]; then
    # ── Debian 11/12：根据 UFW 状态决定后端 ──
    _UFW_ACTIVE_NOW=false
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        _UFW_ACTIVE_NOW=true
    fi
    if ! $_UFW_ACTIVE_NOW; then
        # UFW 未激活：切换到 legacy，确保 netfilter-persistent 用同一后端持久化规则
        # 切换前无需禁用 UFW（UFW 当前未激活，无 nft 规则残留风险）
        info "Debian 11/12 + UFW 未激活：切换 iptables → legacy（netfilter-persistent 兼容）..."
        update-alternatives --set iptables          /usr/sbin/iptables-legacy          2>/dev/null || true
        update-alternatives --set ip6tables         /usr/sbin/ip6tables-legacy         2>/dev/null || true
        update-alternatives --set iptables-save     /usr/sbin/iptables-legacy-save     2>/dev/null || true
        update-alternatives --set ip6tables-save    /usr/sbin/ip6tables-legacy-save    2>/dev/null || true
        update-alternatives --set iptables-restore  /usr/sbin/iptables-legacy-restore  2>/dev/null || true
        update-alternatives --set ip6tables-restore /usr/sbin/ip6tables-legacy-restore 2>/dev/null || true
        _IPTABLES="iptables-legacy"
        _IP6TABLES="ip6tables-legacy"
    else
        # UFW 激活：UFW 用 iptables-nft，wg-quick 也用 iptables-nft → 一致
        # 无需切换 legacy；netfilter-persistent save 在 UFW 激活时不会被调用
        info "Debian 11/12 + UFW 已激活：保持 iptables → iptables-nft（与 UFW 一致）..."
        # _IPTABLES 保持 "iptables"（→ iptables-nft）
    fi
else
    warn "无法检测 Debian 版本或 update-alternatives 不可用，使用当前默认 iptables 后端"
fi
info "iptables 后端：$(iptables --version 2>/dev/null | head -1)"

# ── 2. 内核参数优化（低延迟 + 高吞吐量） ────────────────────────────────────────
info "优化内核网络参数..."
cat > /etc/sysctl.d/99-vpn-perf.conf << 'SYSCTL'
# ── 转发 ──
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

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
# 禁止内核缓存 TCP 连接度量（RTT/MSS/cwnd）——对 NAT 网关尤为重要：
# 跨太平洋链路上一次失败/超时连接的坏度量会被重用于后续同目的 IP 的新连接，
# 导致新连接初始窗口异常小或 MSS 被错误压低，降低所有用户的吞吐量
net.ipv4.tcp_no_metrics_save = 1
# SYN-ACK 重传次数：默认 5（约 63 s 后放弃）→ 2（约 7 s 后放弃）
# 未完成 TCP 握手的半开连接占用 conntrack 表；缩短重试次数可加速僵尸连接清理，
# 减轻 NAT 网关在高并发下的 conntrack 压力（对 VPN 隧道的 UDP 流量无影响）
net.ipv4.tcp_synack_retries = 2
# 孤立（orphaned）套接字最大数量：FIN 阶段已被应用层关闭但 TCP 尚未完成 4 次挥手
# 的连接。NAT 网关高并发下默认上限（约 4096–16384）可能不够用，设为 32768 避免
# "TCP: too many of orphaned sockets" 导致的新连接被静默拒绝
net.ipv4.tcp_max_orphans = 32768
# 孤立连接 FIN 重传次数：默认 7（约 112 s 后关闭）→ 2（约 1 s 后关闭）
# 跨太平洋链路 RTT ~180 ms，初始 RTO 约 360 ms；两次重传 360 + 720 ms ≈ 1 s；
# 加速释放孤立连接占用的 conntrack/内存资源，同时保留足够时间处理高延迟 ACK
net.ipv4.tcp_orphan_retries = 2
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
# TIME_WAIT 桶上限：防止高并发 NAT 下桶溢出后内核强制销毁 TIME_WAIT 条目
# 默认约 8192，高并发时极易耗尽；溢出时内核直接销毁 TIME_WAIT 套接字，
# 可能导致新连接复用同一四元组时收到残留 RST（"TCP: time wait bucket table overflow"）
net.ipv4.tcp_max_tw_buckets = 262144

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
# WireGuard UDP 流超时：PersistentKeepalive=25s；需 ≥ 3× keepalive（75s）确保即使两个连续
# keepalive 包在跨太平洋链路上丢失（t=25 和 t=50），第三个 keepalive（t=75）仍能在超时前到达。
# 设为 120s（4.8×）提供充足冗余，防止 NAT 映射消失后返回包被单方向丢弃
net.netfilter.nf_conntrack_udp_timeout_stream = 120

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
# netdev_budget_usecs：Linux 5.0+ 中 NAPI poll 的最大时间预算（默认 2000 μs = 2 ms）
# 2 ms 在高速链路上会在数据包配额耗尽前提前退出，降低吞吐量；
# 8000 μs（8 ms）配合 netdev_budget=600，让每轮 softirq 有充足时间处理批量 UDP 包，
# 降低 WireGuard 数据包处理的上下文切换开销，提升跨太平洋隧道吞吐量
net.core.netdev_budget_usecs = 8000
SYSCTL
# 预加载 BBR 模块（如果可用）——必须在 sysctl -p 之前，否则在以模块形式编译 BBR 的内核上
# sysctl -p 对 tcp_congestion_control = bbr 报 "Invalid argument"，set -e 会中断整个脚本
modprobe tcp_bbr 2>/dev/null || true
# 预加载 nf_conntrack 模块，确保 sysctl 中的 nf_conntrack_max 等参数可写
modprobe nf_conntrack 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-vpn-perf.conf > /dev/null

# IPv6 send_redirects 在部分内核/容器环境中不存在（IPv6 转发开启时内核已隐式禁用）。
# 条件写入：路径存在才设置并追加到持久化配置，避免 sysctl -p 在重启时因路径缺失而报错退出。
# 注意：上方 heredoc 每次运行都完整覆写配置文件，此处的追加在同一次运行中最多执行一次，不会产生重复条目。
for _P6SR in net.ipv6.conf.all.send_redirects net.ipv6.conf.default.send_redirects; do
    if [[ -f "/proc/sys/$(printf '%s' "$_P6SR" | tr '.' '/')" ]]; then
        sysctl -w "${_P6SR}=0" > /dev/null 2>&1 || true
        echo "${_P6SR} = 0" >> /etc/sysctl.d/99-vpn-perf.conf
    fi
done

# 设置 conntrack 哈希桶数（建议值 = nf_conntrack_max / 4）
# hashsize 仅可在模块加载后通过 sysfs 写入，不走 sysctl
if [[ -f /sys/module/nf_conntrack/parameters/hashsize ]]; then
    echo "${CONNTRACK_HASHSIZE}" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
fi
# 持久化：模块加载时自动设置 hashsize（重启后仍生效）
echo "options nf_conntrack hashsize=${CONNTRACK_HASHSIZE}" > /etc/modprobe.d/nf-conntrack.conf
# 开机自动加载：systemd-sysctl.service 的 unit 文件中有 After=systemd-modules-load.service，
# 确保 sysctl 在模块加载完成后才运行。若缺少此配置，nf_conntrack 可能未加载，
# nf_conntrack_max=524288 等参数静默失效，conntrack 表回退到内核默认值（约 65536），高并发 NAT 下将触发丢包
echo "nf_conntrack" > /etc/modules-load.d/nf-conntrack.conf
# tcp_bbr 同理：仅在模块可用时写入，内核不支持时跳过（脚本已有 cubic 降级逻辑）
if modinfo tcp_bbr &>/dev/null; then
    echo "tcp_bbr" > /etc/modules-load.d/tcp-bbr.conf
fi

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
PostUp   = ${_IPTABLES}  -t nat -A POSTROUTING -s ${WG_SUBNET_V4} -o ${PUB_IF} -j MASQUERADE
PostUp   = ${_IP6TABLES} -t nat -A POSTROUTING -s ${WG_SUBNET_V6} -o ${PUB_IF} -j MASQUERADE
PostDown = ${_IPTABLES}  -t nat -D POSTROUTING -s ${WG_SUBNET_V4} -o ${PUB_IF} -j MASQUERADE
PostDown = ${_IP6TABLES} -t nat -D POSTROUTING -s ${WG_SUBNET_V6} -o ${PUB_IF} -j MASQUERADE

# ── 转发规则（入→出 / 出→入） ─────────────────────────────
PostUp   = ${_IPTABLES}  -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostUp   = ${_IPTABLES}  -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ${_IPTABLES}  -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostDown = ${_IPTABLES}  -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── IPv6 转发规则（与 IPv4 对称，保证 ::/0 客户端流量正常转发）──
PostUp   = ${_IP6TABLES} -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostUp   = ${_IP6TABLES} -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = ${_IP6TABLES} -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -j ACCEPT
PostDown = ${_IP6TABLES} -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# ── MSS 钳制：防止跨 MTU 边界导致 TCP 连接卡住（企业级必须）──
# 双向精确匹配：避免宽泛规则影响非 VPN FORWARD 流量
# 入方向（客户端→互联网）：出口为 ${PUB_IF}，clamping 使用其 MTU（无害但保持对称）
# 出方向（互联网→客户端）：出口为 ${WG_IFACE}（MTU 1420），防止大包进隧道时被分片
PostUp   = ${_IPTABLES}  -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp   = ${_IPTABLES}  -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ${_IPTABLES}  -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ${_IPTABLES}  -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp   = ${_IP6TABLES} -A FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp   = ${_IP6TABLES} -A FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ${_IP6TABLES} -D FORWARD -i ${WG_IFACE} -o ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = ${_IP6TABLES} -D FORWARD -i ${PUB_IF} -o ${WG_IFACE} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

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

# 检测 UFW 是否激活
# UFW 激活时：仅通过 ufw 命令管理所有规则（UFW 自身处理规则持久化）。
# 不得额外操作 iptables INPUT 链，也不可运行 netfilter-persistent save：
# 二者同时存在会在重启后互相叠加规则（UFW 重载 + netfilter-persistent restore），
# 导致 INPUT/FORWARD/NAT 规则翻倍，破坏防火墙和 conntrack 正确性。
_UFW_ACTIVE=false
if command -v ufw &>/dev/null; then
    ufw allow "${WG_PORT}/udp" > /dev/null
    ufw allow OpenSSH         > /dev/null
    # DEFAULT_FORWARD_POLICY=ACCEPT 是 UFW 允许内核 FORWARD 链生效的前提（wg-quick PostUp 依赖此策略）
    # 使用通配替换而非仅匹配 "DROP"：若当前值为 "REJECT" 或行不存在，原 sed 静默失效，
    # UFW 的 ufw-after-forward 链 catchall DROP/REJECT 落在 wg-quick PostUp 追加的 FORWARD
    # ACCEPT 规则之前，所有 VPN 流量被静默丢弃——此为跨太平洋链路常见静默故障根因之一
    if [[ -f /etc/default/ufw ]]; then
        if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
            sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' \
                /etc/default/ufw 2>/dev/null || true
        else
            echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
        fi
    fi
    ufw --force enable  > /dev/null
    # 必须显式 reload：若 UFW 在 enable 时已处于激活状态（常见情况），
    # enable 是空操作，不会重新读取 /etc/default/ufw 中的 DEFAULT_FORWARD_POLICY。
    # reload 确保新的 FORWARD 策略（ACCEPT）被加载到内核 FORWARD 链，
    # 否则 wg-quick PostUp 追加（-A）的 FORWARD ACCEPT 规则会落在 UFW 的 DROP catchall
    # 之后，VPN 流量转发被静默丢弃。
    ufw --force reload  > /dev/null
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        _UFW_ACTIVE=true
        info "UFW 已启用并重载，WireGuard 端口 ${WG_PORT}/udp 已开放 ✓"
    fi
fi

if ! $_UFW_ACTIVE; then
    # UFW 未激活（或未安装）：直接管理 iptables INPUT，并用 netfilter-persistent 持久化
    # 使用 -C 先检查规则是否存在，避免重复执行脚本时在 INPUT 链叠加重复条目
    ${_IPTABLES}  -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || \
        ${_IPTABLES}  -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true
    ${_IP6TABLES} -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || \
        ${_IP6TABLES} -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true

    # 持久化 INPUT 规则（FORWARD/NAT 由 PostUp/PostDown 动态管理，不在此保存以防重复叠加）
    # 必须先停止 wg0：若已在运行，PostUp 已写入 FORWARD/NAT 规则；
    # 停止后 PostDown 自动清除，save 时不会持久化这些动态规则。
    wg-quick down "${WG_IFACE}" 2>/dev/null || true
    netfilter-persistent save > /dev/null 2>&1 || \
        warn "netfilter-persistent save 失败，规则可能在重启后丢失"
fi

# ── 6. 生成客户端配置文件（在启动 WireGuard 之前完成）──────────────────────────
# 必须先于 systemctl restart：若 wg-quick PostUp 失败（set -euo pipefail 触发），
# 脚本立即退出，客户端配置将永远无法生成，管理员无法调试。
# 客户端配置只依赖公网 IP 和已生成的密钥，与 WireGuard 是否运行无关。
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

# ── 7. 启动并设置开机自启 ──────────────────────────────────────────────────────
info "启动 WireGuard..."
systemctl enable  "wg-quick@${WG_IFACE}"
systemctl restart "wg-quick@${WG_IFACE}"

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
