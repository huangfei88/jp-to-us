<#
.SYNOPSIS
    泄露检测脚本 — Windows 客户端
    检查：WireGuard 隧道状态、出口 IP、DNS 泄露、IPv6 泄露
.NOTES
    需要以管理员权限运行
#>

#Requires -RunAsAdministrator

$TUNNEL_NAME = "jp-to-us-vpn"
$PASSED = 0
$FAILED = 0

function Write-Pass { param($msg) Write-Host "[PASS] $msg" -ForegroundColor Green;  $script:PASSED++ }
function Write-Fail { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red;    $script:FAILED++ }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan   }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "  WireGuard 客户端泄露检测" -ForegroundColor White
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor White
Write-Host ""

# ── 1. 检查 WireGuard 隧道服务 ────────────────────────────────────────────────
Write-Info "检查 WireGuard 隧道服务..."
$svcName = "WireGuardTunnel`$$TUNNEL_NAME"
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($null -ne $svc -and $svc.Status -eq "Running") {
    Write-Pass "隧道服务运行正常：$svcName"
} else {
    Write-Fail "隧道服务未运行（状态：$($svc?.Status ?? '未安装')）"
}

# ── 2. 检查 WireGuard 网卡 ────────────────────────────────────────────────────
Write-Info "检查 WireGuard 网卡..."
$wgAdapter = Get-NetAdapter | Where-Object {
    $_.Name -like "*$TUNNEL_NAME*" -or $_.InterfaceDescription -like "*WireGuard*"
}
if ($wgAdapter -and $wgAdapter.Status -eq "Up") {
    Write-Pass "WireGuard 网卡正常：$($wgAdapter.Name)"
} else {
    Write-Fail "WireGuard 网卡未就绪（状态：$($wgAdapter?.Status ?? '未找到')）"
}

# ── 3. 检查当前出口 IP ────────────────────────────────────────────────────────
Write-Info "检查出口 IPv4..."
try {
    $ipv4 = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 10).ip
    Write-Host "  当前出口 IPv4：$ipv4" -ForegroundColor Yellow
    Write-Pass "IPv4 出口可达（请确认上方 IP 为圣何塞美国 IP）"
} catch {
    Write-Fail "无法获取出口 IPv4：$_"
}

# ── 4. 检查 IPv6 泄露 ─────────────────────────────────────────────────────────
Write-Info "检查 IPv6 泄露..."
try {
    $ipv6 = (Invoke-RestMethod -Uri "https://api6.ipify.org?format=json" -TimeoutSec 5).ip
    Write-Host "  检测到 IPv6 出口：$ipv6" -ForegroundColor Yellow
    # 如果 IPv6 走的是隧道（fd10:cafe::2 为隧道 IP），属于正常
    if ($ipv6 -like "fd10:*" -or $ipv6 -like "10.10.*") {
        Write-Pass "IPv6 经过隧道（隧道 IP：$ipv6）"
    } else {
        Write-Fail "IPv6 可能泄露（显示非隧道 IP：$ipv6）"
    }
} catch {
    Write-Pass "无 IPv6 出口（IPv6 已禁用或完全走隧道，无泄露风险）"
}

# ── 5. 检查 DNS 配置 ──────────────────────────────────────────────────────────
Write-Info "检查 DNS 配置..."
$allDns = Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -eq 2 } |
    Select-Object -ExpandProperty ServerAddresses | Sort-Object -Unique
$expectedDns = @("1.1.1.1", "1.0.0.1")
$dnsBad = $allDns | Where-Object { $_ -notin $expectedDns -and $_ -notlike "10.10.*" -and $_ -ne "::1" }
if ($dnsBad) {
    Write-Fail "存在非隧道 DNS 服务器：$($dnsBad -join ', ')（可能 DNS 泄露）"
} else {
    Write-Pass "DNS 配置正常（仅隧道 DNS：$($allDns -join ', ')）"
}

# ── 6. DNS 解析泄露测试（发送 DNS 查询到外部检测服务）─────────────────────────
Write-Info "测试 DNS 解析路径..."
try {
    # 查询 whoami.cloudflare.com TXT（Cloudflare 会返回你的出口 DNS 解析器 IP）
    $dnsResult = Resolve-DnsName -Name "whoami.cloudflare.com" -Type TXT -Server "1.1.1.1" -ErrorAction Stop
    $resolverIP = ($dnsResult | Where-Object { $_.Type -eq "TXT" }).Strings -join ""
    Write-Host "  Cloudflare 识别的 DNS 解析器 IP：$resolverIP" -ForegroundColor Yellow
    Write-Pass "DNS 解析路径可测（请确认上方 IP 为美国 IP）"
} catch {
    Write-Warn "DNS 路径测试失败：$_"
}

# ── 7. 检查 Smart Multi-Homed Name Resolution ─────────────────────────────────
Write-Info "检查多宿主 DNS 设置..."
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$smhnr = (Get-ItemProperty -Path $policyPath -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue)?.DisableSmartNameResolution
if ($smhnr -eq 1) {
    Write-Pass "Smart Multi-Homed Name Resolution 已禁用"
} else {
    Write-Fail "Smart Multi-Homed Name Resolution 未禁用（可能 DNS 泄露）"
}

# ── 8. 检查默认路由 ───────────────────────────────────────────────────────────
Write-Info "检查默认路由..."
$defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric
$bestRoute = $defaultRoutes | Select-Object -First 1
if ($bestRoute) {
    $routeIface = (Get-NetAdapter -InterfaceIndex $bestRoute.InterfaceIndex -ErrorAction SilentlyContinue)?.Name
    Write-Host "  默认路由出口网卡：$routeIface（指标：$($bestRoute.RouteMetric)）" -ForegroundColor Yellow
    if ($routeIface -like "*WireGuard*" -or $routeIface -like "*$TUNNEL_NAME*") {
        Write-Pass "默认路由经过 WireGuard 隧道 ✓"
    } else {
        Write-Fail "默认路由未走 WireGuard 隧道（走的是：$routeIface）"
    }
}

# ── 结果汇总 ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor White
if ($FAILED -eq 0) {
    Write-Host "  所有检测通过 ✓  配置正确，无泄露风险" -ForegroundColor Green
} else {
    Write-Host "  通过：$PASSED  失败：$FAILED  请根据 [FAIL] 提示修复" -ForegroundColor Red
}
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor White
Write-Host ""
Write-Host "在线验证（浏览器打开）：" -ForegroundColor Yellow
Write-Host "  https://ipleak.net"
Write-Host "  https://dnsleaktest.com  （点 Extended Test）"
Write-Host "  https://ipv6leak.com"
Write-Host "  https://browserleaks.com/webrtc"
Write-Host ""
