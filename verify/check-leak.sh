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
info "检查 FORWARD 规则..."
if iptables -L FORWARD -n -v 2>/dev/null | grep -q "${WG_IFACE}"; then
    pass "FORWARD 链规则存在"
else
    fail "FORWARD 链未找到 ${WG_IFACE} 相关规则"
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

# ── 10. 服务端公网 IP ─────────────────────────────────────────────────────────
info "检查服务端出口 IP..."
# 并行获取 IPv4/IPv6（各自最多等 5 秒），减少总等待时间
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

# ── 11. WireGuard peer 状态 ───────────────────────────────────────────────────
info "WireGuard 连接状态："
wg show "$WG_IFACE" 2>/dev/null || fail "无法读取 wg show 输出"

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
