#!/usr/bin/env bash
# =============================================================================
# 泄露检测脚本 — Linux 服务端
# 检查：WireGuard 服务状态、NAT/转发规则、IPv4/IPv6 出口
# 运行方式：bash verify/check-leak.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }

FAILED=0
WG_IFACE="wg0"
# WG_PORT：从实际运行的 wg0.conf 动态读取，消除与 setup-server.sh 的手动同步风险；
# 若配置文件不存在（WireGuard 未安装），则沿用默认值 51820 使其他检测项仍可运行。
WG_PORT=51820
if [[ -f "/etc/wireguard/${WG_IFACE}.conf" ]]; then
    _CFG_PORT=$(grep -m1 '^ListenPort' "/etc/wireguard/${WG_IFACE}.conf" 2>/dev/null | awk '{print $NF}')
    [[ "$_CFG_PORT" =~ ^[0-9]+$ ]] && WG_PORT="$_CFG_PORT"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  WireGuard 服务端泄露检测"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── 1. WireGuard 接口状态 ────────────────────────────────────────────────────
info "检查 WireGuard 服务..."
if systemctl is-active --quiet "wg-quick@${WG_IFACE}"; then
    pass "wg-quick@${WG_IFACE} 服务运行正常"
else
    fail "wg-quick@${WG_IFACE} 服务未运行"
fi

# ── 2. 接口 IP ────────────────────────────────────────────────────────────────
info "检查 ${WG_IFACE} 接口 IP..."
WG_IP=$(ip addr show "$WG_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}' || true)
WG_IP6=$(ip addr show "$WG_IFACE" 2>/dev/null | grep "inet6 " | awk '{print $2}' | head -1 || true)
if [[ -n "$WG_IP" ]]; then
    pass "IPv4 隧道地址：${WG_IP}"
else
    fail "未检测到 IPv4 隧道地址"
fi
if [[ -n "$WG_IP6" ]]; then
    pass "IPv6 隧道地址：${WG_IP6}"
else
    fail "未检测到 IPv6 隧道地址"
fi

# ── 3. IPv4 转发 ──────────────────────────────────────────────────────────────
info "检查 IPv4 转发..."
FWD4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
[[ "$FWD4" == "1" ]] && pass "IPv4 转发已启用" || fail "IPv4 转发未启用（当前值：${FWD4}）"

# ── 4. IPv6 转发 ──────────────────────────────────────────────────────────────
info "检查 IPv6 转发..."
FWD6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)
[[ "$FWD6" == "1" ]] && pass "IPv6 转发已启用" || fail "IPv6 转发未启用（当前值：${FWD6}）"

# ── 5. NAT MASQUERADE 规则 ────────────────────────────────────────────────────
info "检查 iptables NAT 规则..."
if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
    pass "IPv4 NAT MASQUERADE 规则存在"
else
    fail "IPv4 NAT MASQUERADE 规则缺失"
fi
if ip6tables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
    pass "IPv6 NAT MASQUERADE 规则存在"
else
    fail "IPv6 NAT MASQUERADE 规则缺失（IPv6 可能泄露）"
fi

# ── 6. FORWARD 规则 ────────────────────────────────────────────────────────────
info "检查 IPv4 FORWARD 规则..."
if iptables -L FORWARD -n -v 2>/dev/null | grep -q "${WG_IFACE}"; then
    pass "IPv4 FORWARD 链规则存在"
else
    fail "IPv4 FORWARD 链未找到 ${WG_IFACE} 相关规则"
fi

info "检查 IPv6 FORWARD 规则..."
if ip6tables -L FORWARD -n -v 2>/dev/null | grep -q "${WG_IFACE}"; then
    pass "IPv6 FORWARD 链规则存在（::/0 隧道流量可正常转发）"
else
    fail "IPv6 FORWARD 链未找到 ${WG_IFACE} 相关规则（客户端 IPv6 流量可能被静默丢弃）"
fi

info "检查 TCP MSS 钳制规则（TCPMSS）..."
if iptables -L FORWARD -n -v 2>/dev/null | grep -q "TCPMSS"; then
    pass "IPv4 TCPMSS 钳制规则存在（防跨 MTU 边界 TCP 连接卡死）"
else
    fail "IPv4 TCPMSS 钳制规则缺失（跨 MTU 边界的 TCP 连接可能随机卡住）"
fi
if ip6tables -L FORWARD -n -v 2>/dev/null | grep -q "TCPMSS"; then
    pass "IPv6 TCPMSS 钳制规则存在"
else
    fail "IPv6 TCPMSS 钳制规则缺失"
fi

# ── 7. BBR 拥塞控制 ────────────────────────────────────────────────────────────
info "检查 BBR 拥塞控制..."
CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
if [[ "$CC" == "bbr" ]]; then
    pass "BBR 已启用（高性能）"
else
    warn "BBR 未启用（当前：${CC}）——建议升级内核以启用 BBR；cubic 为有效降级方案"
fi

# ── 8. TCP MTU 探测 ────────────────────────────────────────────────────────────
info "检查 TCP MTU 探测..."
MTP=$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo 0)
[[ "$MTP" == "1" ]] && pass "TCP MTU 探测已启用（防跨太平洋 PMTUD 黑洞）" \
                     || fail "TCP MTU 探测未启用（可能导致隧道内 TCP 连接随机卡死）"

# ── 9. ICMP 重定向 ─────────────────────────────────────────────────────────────
info "检查 ICMP redirect 设置..."
SR=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo 1)
[[ "$SR" == "0" ]] && pass "ICMP 重定向发送已禁用（路由表安全）" \
                   || fail "ICMP 重定向发送未禁用（可能干扰客户端路由）"

AR=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 1)
[[ "$AR" == "0" ]] && pass "ICMP 重定向接受已禁用（防路由表被远程劫持）" \
                   || fail "ICMP 重定向接受未禁用（路由可能被远程重定向攻击劫持）"

# ── 10. 反向路径过滤（rp_filter）──────────────────────────────────────────────
info "检查反向路径过滤（rp_filter）..."
RP=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 0)
[[ "$RP" == "1" ]] && pass "rp_filter 已启用（防 IP 源地址欺骗 / 洪水攻击）" \
                   || fail "rp_filter 未启用（当前值：${RP}），IP 源地址欺骗风险增加"

# ── 11. 源路由防护（accept_source_route）──────────────────────────────────────
info "检查源路由防护..."
SR4=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo 1)
[[ "$SR4" == "0" ]] && pass "IPv4 源路由已禁用（防源路由绕过防火墙 / NAT 攻击）" \
                    || fail "IPv4 源路由未禁用（当前值：${SR4}），可能被用于绕过防火墙/NAT 规则"
SR6=$(sysctl -n net.ipv6.conf.all.accept_source_route 2>/dev/null || echo 1)
[[ "$SR6" == "0" ]] && pass "IPv6 源路由已禁用" \
                    || fail "IPv6 源路由未禁用（当前值：${SR6}）"

# ── 12. TCP Keepalive ──────────────────────────────────────────────────────────
info "检查 TCP Keepalive 参数..."
KA_TIME=$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo 7200)
KA_INTVL=$(sysctl -n net.ipv4.tcp_keepalive_intvl 2>/dev/null || echo 75)
KA_PROBES=$(sysctl -n net.ipv4.tcp_keepalive_probes 2>/dev/null || echo 9)
if [[ "$KA_TIME" -le 300 && "$KA_INTVL" -le 30 && "$KA_PROBES" -le 5 ]]; then
    pass "TCP Keepalive 已调优（time=${KA_TIME}s intvl=${KA_INTVL}s probes=${KA_PROBES}）"
else
    fail "TCP Keepalive 未调优（time=${KA_TIME} intvl=${KA_INTVL} probes=${KA_PROBES}）——僵尸连接最多占用 $((KA_TIME + KA_INTVL * KA_PROBES))s"
fi

# ── 13. TCP FIN 超时 ────────────────────────────────────────────────────────────
info "检查 TCP FIN 超时..."
FIN_TO=$(sysctl -n net.ipv4.tcp_fin_timeout 2>/dev/null || echo 60)
if [[ "$FIN_TO" -le 30 ]]; then
    pass "TCP FIN 超时已调优（${FIN_TO}s，加速 TIME_WAIT 回收，减少 conntrack 压力）"
else
    fail "TCP FIN 超时未调优（当前 ${FIN_TO}s，建议 ≤ 30s）——TIME_WAIT 条目长期堆积，conntrack 表更快耗尽"
fi

# ── 14. 服务端公网 IP ─────────────────────────────────────────────────────────
info "检查服务端出口 IP..."
# 并行获取 IPv4/IPv6（各自最多等 5 秒），减少总等待时间
# 先初始化变量再设 trap：防止第二个 mktemp 失败时 trap 引用未定义变量（set -u）
_TMP4=""; _TMP6=""
trap 'rm -f "$_TMP4" "$_TMP6" 2>/dev/null' EXIT INT TERM
_TMP4=$(mktemp); _TMP6=$(mktemp)
curl -s4 --max-time 5 https://api.ipify.org    > "$_TMP4" 2>/dev/null & _PID4=$!
curl -s6 --max-time 5 https://api6.ipify.org   > "$_TMP6" 2>/dev/null & _PID6=$!
wait "$_PID4" || true; wait "$_PID6" || true
PUB_IP4=$(cat "$_TMP4" 2>/dev/null); [[ -z "$PUB_IP4" ]] && PUB_IP4="获取失败"
PUB_IP6=$(cat "$_TMP6" 2>/dev/null); [[ -z "$PUB_IP6" ]] && PUB_IP6="无 IPv6"
rm -f "$_TMP4" "$_TMP6"
echo -e "  服务端 IPv4：${CYAN}${PUB_IP4}${NC}"
echo -e "  服务端 IPv6：${CYAN}${PUB_IP6}${NC}"

# ── 15. conntrack 连接跟踪表 ──────────────────────────────────────────────────
info "检查 conntrack 连接跟踪表..."
CT_MAX=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)
CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "N/A")
if [[ "$CT_MAX" -ge 524288 ]]; then
    pass "conntrack 表容量充足（max=${CT_MAX}，当前=${CT_COUNT}）"
elif [[ "$CT_MAX" -gt 0 ]]; then
    fail "conntrack 表容量不足（max=${CT_MAX}，当前=${CT_COUNT}）——高并发 NAT 下可能丢包"
else
    warn "无法读取 nf_conntrack_max（模块未加载或内核不支持）"
fi

# conntrack established 超时（默认 432000s = 5天，必须缩短否则失活连接长期占表）
CT_EST=$(sysctl -n net.netfilter.nf_conntrack_tcp_timeout_established 2>/dev/null || echo 432000)
if [[ "$CT_EST" -le 3600 ]]; then
    pass "conntrack established 超时已调优（${CT_EST}s，失活连接 1 小时内回收）"
else
    fail "conntrack established 超时过长（当前 ${CT_EST}s，默认 432000s/5天）——失活 TCP 连接长期占据 conntrack 表，高并发下快速耗尽"
fi

# ── 16. WireGuard peer 状态 ───────────────────────────────────────────────────
info "WireGuard 连接状态："
wg show "$WG_IFACE" 2>/dev/null || fail "无法读取 wg show 输出"

# ── 17. 软中断数据包预算（netdev_budget）─────────────────────────────────────
info "检查软中断数据包预算（netdev_budget）..."
BUDGET=$(sysctl -n net.core.netdev_budget 2>/dev/null || echo 0)
if [[ "$BUDGET" -ge 600 ]]; then
    pass "netdev_budget 已调优（${BUDGET}，高负载下吞吐量提升）"
elif [[ "$BUDGET" -gt 0 ]]; then
    warn "netdev_budget 较低（当前 ${BUDGET}，建议 ≥ 600 以提升高负载下吞吐量，运行 setup-server.sh 可自动调优）"
else
    warn "无法读取 netdev_budget"
fi

# ── 18. iptables 后端一致性（Debian 版本感知）──────────────────────────────────
# Debian 13+（Trixie）：正确后端是 iptables-nft（native nftables 框架）
# Debian 11/12（Bullseye/Bookworm）：正确后端视 UFW 激活状态而定
#   UFW 激活 → iptables-nft（与 UFW 一致）
#   UFW 未激活 → iptables-legacy（与 netfilter-persistent 一致）
if command -v update-alternatives &>/dev/null && \
   update-alternatives --list iptables &>/dev/null 2>&1; then
    info "检查 iptables 后端一致性（Debian 专项）..."
    _CK_DEB_MAJOR_VER=$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_ID:-0}" | cut -d. -f1)
    _CK_DEB_MAJOR_VER_INT=0
    [[ "$_CK_DEB_MAJOR_VER" =~ ^[0-9]+$ ]] && _CK_DEB_MAJOR_VER_INT="$_CK_DEB_MAJOR_VER"
    IPTR=$(update-alternatives --query iptables 2>/dev/null | awk '/^Value:/{print $2}')
    if [[ "$_CK_DEB_MAJOR_VER_INT" -ge 13 ]]; then
        # Debian 13+：必须是 nft，legacy 会与 UFW/nftables 产生规则隔离，NAT 静默失效
        if [[ "$IPTR" == *"nft"* ]]; then
            pass "iptables 后端为 nft（Debian 13 正确：与 UFW/nftables 共用同一框架，无规则隔离）"
        else
            fail "iptables 后端为 legacy（${IPTR}）——Debian 13 上 legacy 写入独立 xtables 子系统，" \
                 "与 UFW/nftables 的 FORWARD/NAT 规则完全隔离，VPN 流量 NAT 可能静默失效；" \
                 "请重新运行 setup-server.sh 修复"
        fi
    else
        # Debian 11/12：看 UFW 是否激活
        _CK_UFW_ACTIVE=false
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            _CK_UFW_ACTIVE=true
        fi
        if $_CK_UFW_ACTIVE; then
            # UFW 激活：nft 正确，legacy 会与 UFW 不一致
            if [[ "$IPTR" == *"nft"* ]]; then
                pass "iptables 后端为 nft（Debian 11/12 + UFW 激活：与 UFW 一致）"
            else
                warn "iptables 后端为 legacy（${IPTR}）——UFW 激活时 Debian 11/12 也应使用 nft 后端；" \
                     "建议重新运行 setup-server.sh"
            fi
        else
            # UFW 未激活：legacy 正确，nft 与 netfilter-persistent 可能不一致
            if [[ "$IPTR" == *"legacy"* ]]; then
                pass "iptables 后端为 legacy（Debian 11/12 + UFW 未激活：与 netfilter-persistent 兼容）"
            else
                warn "iptables 后端为 nft（${IPTR}）——UFW 未激活时若与 netfilter-persistent 同用，" \
                     "重启后可能出现规则不一致；建议重新运行 setup-server.sh"
            fi
        fi
    fi
fi

# ── 19. UFW 防火墙状态（Debian 专项）──────────────────────────────────────────
if command -v ufw &>/dev/null; then
    info "检查 UFW 状态（Debian 专项）..."
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        pass "UFW 已激活"
        if ufw status 2>/dev/null | grep -qE "${WG_PORT}/udp"; then
            pass "UFW 已开放 WireGuard 端口 ${WG_PORT}/udp"
        else
            fail "UFW 未开放 WireGuard 端口 ${WG_PORT}/udp（握手包将被丢弃，隧道无法建立）"
        fi
    else
        warn "UFW 已安装但未激活（当前由 iptables/netfilter-persistent 直接管理规则）"
    fi
fi

# ── 结果汇总 ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}  所有检测通过 ✓  服务端配置正确${NC}"
else
    echo -e "${RED}  检测失败项：${FAILED}  请根据 [FAIL] 提示修复${NC}"
fi
echo "═══════════════════════════════════════════════════════"
echo ""
