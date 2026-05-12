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
[[ "$FWD6" == "1" ]] && pass "IPv6 转发已启用（all.forwarding）" || fail "IPv6 转发未启用（当前值：${FWD6}）"
# default.forwarding 为新建接口的基线值（wg0 每次 wg-quick up 新建，继承 default 而非 all）
FWD6DEF=$(sysctl -n net.ipv6.conf.default.forwarding 2>/dev/null || echo 0)
[[ "$FWD6DEF" == "1" ]] && pass "IPv6 default.forwarding 已启用（新建接口继承转发能力）" \
                         || fail "IPv6 default.forwarding 未启用（当前值：${FWD6DEF}，期望值 1）——wg0 等动态接口创建后可能无法转发 IPv6 流量"

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
# default.send_redirects：wg0 等动态接口继承 default；虽 all=0 已足够（内核需 all AND per-iface 均为 1 才发送），
# 但显式验证 default 确认配置完整性
SR_DEF=$(sysctl -n net.ipv4.conf.default.send_redirects 2>/dev/null || echo 1)
[[ "$SR_DEF" == "0" ]] && pass "IPv4 default.send_redirects 已禁用（新建接口如 wg0 继承安全基线）" \
                        || fail "IPv4 default.send_redirects 未禁用（当前值：${SR_DEF}，期望值 0）——新建接口将发送 ICMP 重定向，可能干扰客户端路由"

AR=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 1)
[[ "$AR" == "0" ]] && pass "ICMP 重定向接受已禁用（防路由表被远程劫持）" \
                   || fail "ICMP 重定向接受未禁用（路由可能被远程重定向攻击劫持）"
# default.accept_redirects：wg0 每次由 wg-quick 动态创建，继承 default 而非 all；
# 若 default 未被设为 0，wg0 创建后将接受 ICMP 重定向，路由表可被远程篡改
AR_DEF=$(sysctl -n net.ipv4.conf.default.accept_redirects 2>/dev/null || echo 1)
[[ "$AR_DEF" == "0" ]] && pass "IPv4 default.accept_redirects 已禁用（新建接口如 wg0 继承安全基线）" \
                        || fail "IPv4 default.accept_redirects 未禁用（当前值：${AR_DEF}，期望值 0）——wg0 等动态接口创建后将接受 ICMP 重定向，路由表可被远程篡改"

# IPv6 accept_redirects：与 IPv4 同等重要，防止 ICMPv6 重定向修改路由表
AR6=$(sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null || echo 1)
[[ "$AR6" == "0" ]] && pass "IPv6 ICMP 重定向接受已禁用（防 ICMPv6 重定向路由劫持）" \
                    || fail "IPv6 ICMP 重定向接受未禁用（当前值：${AR6}，期望值 0）——攻击者可通过 ICMPv6 重定向修改服务器路由表"
AR6DEF=$(sysctl -n net.ipv6.conf.default.accept_redirects 2>/dev/null || echo 1)
[[ "$AR6DEF" == "0" ]] && pass "IPv6 default.accept_redirects 已禁用（新建接口继承安全基线）" \
                        || fail "IPv6 default.accept_redirects 未禁用（当前值：${AR6DEF}，期望值 0）——wg0 等动态接口创建后将接受 ICMPv6 重定向"

# IPv6 发送重定向（send_redirects）：转发开启时内核隐式禁止，但显式设置确保安全基线
SR6_ALL=$(sysctl -n net.ipv6.conf.all.send_redirects 2>/dev/null || echo 1)
[[ "$SR6_ALL" == "0" ]] && pass "IPv6 ICMP 重定向发送已禁用（all.send_redirects=0）" \
                         || fail "IPv6 ICMP 重定向发送未禁用（当前值：${SR6_ALL}，期望值 0）——虽启用 IPv6 转发时内核隐式禁用，但显式配置可防止安全基线被其他工具覆盖"
SR6_DEF=$(sysctl -n net.ipv6.conf.default.send_redirects 2>/dev/null || echo 1)
[[ "$SR6_DEF" == "0" ]] && pass "IPv6 default.send_redirects 已禁用（新建接口如 wg0 继承安全基线）" \
                         || fail "IPv6 default.send_redirects 未禁用（当前值：${SR6_DEF}，期望值 0）——新建接口可能发送 ICMPv6 重定向"

# ── 10. 反向路径过滤（rp_filter）──────────────────────────────────────────────
info "检查反向路径过滤（rp_filter）..."
RP=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 0)
[[ "$RP" == "1" ]] && pass "rp_filter 已启用（防 IP 源地址欺骗 / 洪水攻击）" \
                   || fail "rp_filter 未启用（当前值：${RP}），IP 源地址欺骗风险增加"
# default.rp_filter：wg0 动态创建时继承 default；若 default 为 0，wg0 无源地址欺骗防护
RP_DEF=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo 0)
[[ "$RP_DEF" == "1" ]] && pass "net.ipv4.conf.default.rp_filter 已启用（新建接口如 wg0 继承反向路径过滤）" \
                        || fail "net.ipv4.conf.default.rp_filter 未启用（当前值：${RP_DEF}）——新建接口（含 wg0）无 IP 源地址欺骗防护"

# ── 11. 源路由防护（accept_source_route）──────────────────────────────────────
info "检查源路由防护..."
SR4=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo 1)
[[ "$SR4" == "0" ]] && pass "IPv4 源路由已禁用（防源路由绕过防火墙 / NAT 攻击）" \
                    || fail "IPv4 源路由未禁用（当前值：${SR4}），可能被用于绕过防火墙/NAT 规则"
SR6=$(sysctl -n net.ipv6.conf.all.accept_source_route 2>/dev/null || echo 1)
[[ "$SR6" == "0" ]] && pass "IPv6 源路由已禁用" \
                    || fail "IPv6 源路由未禁用（当前值：${SR6}）"
# default.accept_source_route：wg0 动态创建时继承 default；
# 若 default 未被设为 0，攻击者可通过源路由选项操纵进入 wg0 的数据包路径，绕过防火墙 / NAT
SR4DEF=$(sysctl -n net.ipv4.conf.default.accept_source_route 2>/dev/null || echo 1)
[[ "$SR4DEF" == "0" ]] && pass "IPv4 default.accept_source_route 已禁用（新建接口继承安全基线）" \
                        || fail "IPv4 default.accept_source_route 未禁用（当前值：${SR4DEF}，期望值 0）——新建接口（含 wg0）可接受源路由，攻击者可操纵包路径绕过防火墙/NAT"
SR6DEF=$(sysctl -n net.ipv6.conf.default.accept_source_route 2>/dev/null || echo 1)
[[ "$SR6DEF" == "0" ]] && pass "IPv6 default.accept_source_route 已禁用（新建接口继承安全基线）" \
                        || fail "IPv6 default.accept_source_route 未禁用（当前值：${SR6DEF}，期望值 0）——新建接口（含 wg0）可接受 IPv6 源路由"

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

# ── 13b. TCP 半开连接 / 孤立连接参数 ─────────────────────────────────────────
info "检查 TCP SYN-ACK 重传次数（tcp_synack_retries）..."
SYNACK_R=$(sysctl -n net.ipv4.tcp_synack_retries 2>/dev/null || echo 5)
if [[ "$SYNACK_R" -le 2 ]]; then
    pass "tcp_synack_retries 已调优（${SYNACK_R}，半开连接约 7s 后清理，减轻 conntrack 压力）"
else
    fail "tcp_synack_retries 未调优（当前 ${SYNACK_R}，建议 ≤ 2）——默认 5 次约 63s 后才放弃，高并发时半开连接长期占据 conntrack 表"
fi

info "检查 TCP 孤立连接参数（tcp_orphan_retries / tcp_max_orphans）..."
ORPHAN_R=$(sysctl -n net.ipv4.tcp_orphan_retries 2>/dev/null || echo 7)
if [[ "$ORPHAN_R" -le 2 ]]; then
    pass "tcp_orphan_retries 已调优（${ORPHAN_R}，孤立连接约 1s 后释放）"
else
    fail "tcp_orphan_retries 未调优（当前 ${ORPHAN_R}，建议 ≤ 2）——默认 7 次约 112s 后关闭，孤立连接长期占用 conntrack/内存资源"
fi
ORPHAN_MAX=$(sysctl -n net.ipv4.tcp_max_orphans 2>/dev/null || echo 4096)
if [[ "$ORPHAN_MAX" -ge 32768 ]]; then
    pass "tcp_max_orphans 已调优（${ORPHAN_MAX}，NAT 网关高并发下不触发孤立连接丢弃）"
else
    fail "tcp_max_orphans 过低（当前 ${ORPHAN_MAX}，建议 ≥ 32768）——触发 'TCP: too many orphaned sockets' 时新连接被静默拒绝"
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

# conntrack TIME_WAIT / CLOSE_WAIT 加速回收
CT_TW=$(sysctl -n net.netfilter.nf_conntrack_tcp_timeout_time_wait 2>/dev/null || echo 120)
if [[ "$CT_TW" -le 30 ]]; then
    pass "conntrack tcp_timeout_time_wait 已调优（${CT_TW}s，TIME_WAIT 条目快速回收）"
else
    fail "conntrack tcp_timeout_time_wait 过长（当前 ${CT_TW}s，建议 ≤ 30s）——TIME_WAIT 条目回收慢，conntrack 表加速耗尽"
fi
CT_CW=$(sysctl -n net.netfilter.nf_conntrack_tcp_timeout_close_wait 2>/dev/null || echo 60)
if [[ "$CT_CW" -le 30 ]]; then
    pass "conntrack tcp_timeout_close_wait 已调优（${CT_CW}s，CLOSE_WAIT 条目快速回收）"
else
    fail "conntrack tcp_timeout_close_wait 过长（当前 ${CT_CW}s，建议 ≤ 30s）——CLOSE_WAIT 条目回收慢"
fi

# WireGuard UDP 流超时（udp_timeout_stream）：需 ≥ 3× PersistentKeepalive（25s）= 75s
# 跨太平洋链路上 keepalive 包存在周期性丢包风险；若连续两个 keepalive（t=25, t=50）丢失，
# 第三个 keepalive（t=75）仍需在超时前到达以维持 NAT 映射。
# 推荐值 120s（4.8×）在充足安全边际与 conntrack 内存占用之间取得平衡。
CT_UDP_STREAM=$(sysctl -n net.netfilter.nf_conntrack_udp_timeout_stream 2>/dev/null || echo 30)
if [[ "$CT_UDP_STREAM" -ge 60 ]]; then
    pass "conntrack udp_timeout_stream 已调优（${CT_UDP_STREAM}s ≥ 60s，WireGuard keepalive=25s 的 2.4 倍以上安全边际；推荐值 120s）"
else
    fail "conntrack udp_timeout_stream 过短（当前 ${CT_UDP_STREAM}s，推荐 120s / 最低 60s）——跨太平洋链路 keepalive 丢包时 NAT 映射可能提前消失，隧道返回包被单方向丢弃"
fi

# ── 15b. conntrack 表使用率 ────────────────────────────────────────────────────
info "检查 conntrack 表使用率..."
if [[ "$CT_MAX" -gt 0 && "$CT_COUNT" != "N/A" ]]; then
    CT_PCT=$(( CT_COUNT * 100 / CT_MAX ))
    if [[ "$CT_PCT" -ge 80 ]]; then
        fail "conntrack 表使用率危险（当前 ${CT_COUNT}/${CT_MAX}，${CT_PCT}%）——即将触发 conntrack 满表丢包；请立即排查连接泄漏或增大 nf_conntrack_max"
    elif [[ "$CT_PCT" -ge 60 ]]; then
        warn "conntrack 表使用率较高（当前 ${CT_COUNT}/${CT_MAX}，${CT_PCT}%）——建议监控流量增长趋势，必要时提前扩容"
    else
        pass "conntrack 表使用率正常（当前 ${CT_COUNT}/${CT_MAX}，${CT_PCT}%）"
    fi
else
    warn "无法计算 conntrack 使用率（CT_MAX=${CT_MAX} CT_COUNT=${CT_COUNT}）"
fi

# ── 15c. conntrack hashsize（查找性能）────────────────────────────────────────
info "检查 conntrack hashsize（哈希桶数量）..."
CT_HASH=$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || echo 0)
if [[ "$CT_HASH" -ge 131072 ]]; then
    pass "conntrack hashsize 已调优（${CT_HASH} = nf_conntrack_max/4，O(1) 查找性能）"
elif [[ "$CT_HASH" -gt 0 ]]; then
    warn "conntrack hashsize 偏低（当前 ${CT_HASH}，建议 ≥ 131072 = nf_conntrack_max/4）——桶内链表过长，高负载下查找退化为 O(n)，引发延迟毛刺；请重新运行 setup-server.sh 修复"
else
    warn "无法读取 conntrack hashsize（/sys/module/nf_conntrack/parameters/hashsize 不可访问）"
fi

# ── 16. WireGuard peer 状态 ───────────────────────────────────────────────────
info "WireGuard 连接状态："
wg show "$WG_IFACE" 2>/dev/null || fail "无法读取 wg show 输出"

# ── 17. 软中断数据包预算（netdev_budget / netdev_budget_usecs）────────────────
info "检查软中断数据包预算（netdev_budget）..."
BUDGET=$(sysctl -n net.core.netdev_budget 2>/dev/null || echo 0)
if [[ "$BUDGET" -ge 600 ]]; then
    pass "netdev_budget 已调优（${BUDGET}，高负载下吞吐量提升）"
elif [[ "$BUDGET" -gt 0 ]]; then
    warn "netdev_budget 较低（当前 ${BUDGET}，建议 ≥ 600 以提升高负载下吞吐量，运行 setup-server.sh 可自动调优）"
else
    warn "无法读取 netdev_budget"
fi

info "检查 NAPI poll 时间预算（netdev_budget_usecs，Linux 5.0+）..."
BUDGET_USECS=$(sysctl -n net.core.netdev_budget_usecs 2>/dev/null || echo 0)
if [[ "$BUDGET_USECS" -ge 8000 ]]; then
    pass "netdev_budget_usecs 已调优（${BUDGET_USECS} μs，高速链路吞吐量提升）"
elif [[ "$BUDGET_USECS" -gt 0 ]]; then
    warn "netdev_budget_usecs 较低（当前 ${BUDGET_USECS} μs，建议 ≥ 8000 以避免高速链路上 NAPI poll 提前退出，运行 setup-server.sh 可自动调优）"
else
    warn "无法读取 netdev_budget_usecs（内核 < 5.0 或参数不可用，可忽略）"
fi

info "检查 TCP 度量缓存禁用（tcp_no_metrics_save）..."
NO_METRICS=$(sysctl -n net.ipv4.tcp_no_metrics_save 2>/dev/null || echo 0)
[[ "$NO_METRICS" == "1" ]] \
    && pass "tcp_no_metrics_save 已启用（NAT 网关不缓存连接度量，避免跨太平洋坏度量污染新连接）" \
    || fail "tcp_no_metrics_save 未启用（当前 ${NO_METRICS}，期望值 1）——坏 TCP 度量（RTT/MSS/cwnd）将被重用于后续同目的 IP 的新连接，影响吞吐量"

# ── 17b. NAT 出口端口范围（防端口耗尽）────────────────────────────────────────
info "检查 NAT 出口端口范围（ip_local_port_range）..."
PORT_RANGE=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo "32768 60999")
PORT_LOW=$(echo "$PORT_RANGE" | awk '{print $1}')
PORT_HIGH=$(echo "$PORT_RANGE" | awk '{print $2}')
PORT_COUNT=$(( PORT_HIGH - PORT_LOW + 1 ))
if [[ "$PORT_LOW" -le 10000 && "$PORT_COUNT" -ge 50000 ]]; then
    pass "NAT 出口端口范围已扩展（${PORT_LOW}-${PORT_HIGH}，共 ${PORT_COUNT} 个端口，防止高并发 NAT 端口耗尽）"
else
    fail "NAT 出口端口范围不足（当前 ${PORT_LOW}-${PORT_HIGH}，共 ${PORT_COUNT} 个端口）——默认范围仅约 28000 个端口，高并发 NAT 下易耗尽，导致新出站连接失败（EADDRINUSE）；请重新运行 setup-server.sh 修复"
fi

# ── 17c. TCP 慢启动恢复（空闲后性能）─────────────────────────────────────────
info "检查 TCP 空闲慢启动（tcp_slow_start_after_idle）..."
SLOW_START=$(sysctl -n net.ipv4.tcp_slow_start_after_idle 2>/dev/null || echo 1)
[[ "$SLOW_START" == "0" ]] \
    && pass "tcp_slow_start_after_idle 已禁用（跨太平洋链路空闲后恢复流量无降速惩罚）" \
    || fail "tcp_slow_start_after_idle 未禁用（当前 ${SLOW_START}，期望值 0）——高延迟链路上 TCP 空闲后重启慢启动，流量恢复初始窗口极小，吞吐量骤降；对 VPN 隧道内周期性突发流量影响显著"

# ── 17d. TIME_WAIT 端口复用 ────────────────────────────────────────────────────
info "检查 TCP TIME_WAIT 端口复用（tcp_tw_reuse）..."
TW_REUSE=$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null || echo 0)
[[ "$TW_REUSE" == "1" ]] \
    && pass "tcp_tw_reuse 已启用（TIME_WAIT 端口可复用，减少 NAT 高并发下端口耗尽风险）" \
    || fail "tcp_tw_reuse 未启用（当前 ${TW_REUSE}，期望值 1）——NAT 网关高并发下 TIME_WAIT 端口不可复用，出口端口耗尽风险增加；请重新运行 setup-server.sh 修复"

# ── 17e. 套接字缓冲区（高 BDP 跨太平洋吞吐量）────────────────────────────────
info "检查套接字缓冲区大小（rmem_max / wmem_max）..."
RMEM_MAX=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
WMEM_MAX=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)
if [[ "$RMEM_MAX" -ge 67108864 && "$WMEM_MAX" -ge 67108864 ]]; then
    pass "套接字缓冲区已调优（rmem_max=${RMEM_MAX} wmem_max=${WMEM_MAX}，64 MB，适配高 BDP 跨太平洋链路）"
else
    fail "套接字缓冲区不足（rmem_max=${RMEM_MAX} wmem_max=${WMEM_MAX}）——默认 ~200 KB 无法充分利用跨太平洋链路的带宽延迟积（BDP），吞吐量受限；请重新运行 setup-server.sh 修复"
fi

# ── 18. 内核模块开机自动加载持久化（企业级稳定性：重启后 sysctl 参数必须仍然生效）────────
# systemd-sysctl.service 的 unit 文件中有 After=systemd-modules-load.service，
# 确保 sysctl 在模块加载完成后才运行，所以只要模块在 /etc/modules-load.d/ 中配置，重启后参数即可生效
info "检查内核模块开机自动加载配置..."
if [[ -f /etc/modules-load.d/nf-conntrack.conf ]] && \
   grep -q 'nf_conntrack' /etc/modules-load.d/nf-conntrack.conf 2>/dev/null; then
    pass "nf_conntrack 已配置开机自动加载（/etc/modules-load.d/nf-conntrack.conf 存在）"
else
    fail "nf_conntrack 未配置开机自动加载——重启后 systemd-sysctl 在模块加载前运行，nf_conntrack_max 等 conntrack 参数静默失效，conntrack 表回退到默认值（约 65536），高并发 NAT 下将触发丢包；请重新运行 setup-server.sh 修复"
fi

if modinfo tcp_bbr &>/dev/null; then
    if [[ -f /etc/modules-load.d/tcp-bbr.conf ]] && \
       grep -q 'tcp_bbr' /etc/modules-load.d/tcp-bbr.conf 2>/dev/null; then
        pass "tcp_bbr 已配置开机自动加载（/etc/modules-load.d/tcp-bbr.conf 存在）"
    else
        fail "tcp_bbr 已安装但未配置开机自动加载——重启后 BBR 拥塞控制将失效（退回 cubic），影响跨太平洋链路吞吐量；请重新运行 setup-server.sh 修复"
    fi
else
    warn "tcp_bbr 模块不可用（内核版本过低），BBR 开机加载检测跳过（cubic 降级已生效）"
fi

# ── 19. iptables 后端一致性（Debian 版本感知）──────────────────────────────────
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

# ── 20. UFW 防火墙状态（Debian 专项）──────────────────────────────────────────
if command -v ufw &>/dev/null; then
    info "检查 UFW 状态（Debian 专项）..."
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        pass "UFW 已激活"
        if ufw status 2>/dev/null | grep -qE "${WG_PORT}/udp"; then
            pass "UFW 已开放 WireGuard 端口 ${WG_PORT}/udp"
        else
            fail "UFW 未开放 WireGuard 端口 ${WG_PORT}/udp（握手包将被丢弃，隧道无法建立）"
        fi
        # DEFAULT_FORWARD_POLICY 必须为 ACCEPT：UFW 激活时在 ufw-after-forward 链插入 catchall
        # DROP/REJECT 规则；wg-quick PostUp 使用 -A（追加）将 FORWARD ACCEPT 规则写到 FORWARD
        # 链末尾，在 UFW 的 catchall 之后——VPN 流量在到达 ACCEPT 规则前就被 UFW 丢弃。
        # FORWARD 链的默认策略（-P FORWARD ACCEPT）只作用于通过所有链规则后仍未匹配的流量，
        # 但 UFW 的 ufw-after-forward 链内有显式 DROP 规则，所以仅改默认策略不够，
        # 必须将 DEFAULT_FORWARD_POLICY 设为 ACCEPT 使 UFW 不生成该 catchall DROP。
        FWD_POL=$(grep '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw 2>/dev/null \
                  | cut -d= -f2 | tr -d '"')
        if [[ "$FWD_POL" == "ACCEPT" ]]; then
            pass "UFW DEFAULT_FORWARD_POLICY=ACCEPT（VPN 流量可正常转发）"
        else
            fail "UFW DEFAULT_FORWARD_POLICY=${FWD_POL:-未设置}（期望 ACCEPT）——UFW 的 ufw-after-forward 链 catchall DROP 在 wg-quick FORWARD ACCEPT 规则之前执行，VPN 流量被静默丢弃；请重新运行 setup-server.sh 修复"
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
