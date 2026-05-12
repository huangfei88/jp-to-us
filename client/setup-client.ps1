<#
.SYNOPSIS
    WireGuard 全流量 VPN 客户端安装脚本 — Osaka Windows Server 2022 Datacenter
    将 Windows 所有网络流量路由通过圣何塞 Linux 服务器出口
.DESCRIPTION
    - 自动下载并安装 WireGuard for Windows
    - 导入客户端配置（全隧道 + DNS 防泄露）
    - 调整 Windows 网络设置防止各类泄露（WebRTC / IPv6 / DNS）
    - 适配 Windows Server 2022 Datacenter（IE 增强安全配置、Hyper-V vNIC 排除）
    - 需要以管理员权限运行
.NOTES
    使用前请先将 wg-client.conf 放到与本脚本相同目录，
    或通过 -ConfigFile 参数指定路径
#>

#Requires -RunAsAdministrator

param(
    [string]$ConfigFile = "$PSScriptRoot\wg-client.conf",
    [switch]$Uninstall
)

# ── 颜色输出 ──────────────────────────────────────────────────────────────────
function Write-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Green  }
function Write-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

$WG_TUNNEL_NAME = "jp-to-us-vpn"
$WG_INSTALL_DIR = "$env:ProgramFiles\WireGuard"
$WG_EXE         = "$WG_INSTALL_DIR\wireguard.exe"
$WG_CONF_DIR    = "$env:ProgramData\WireGuard"

# ── 提前捕获物理网关和管理 IP（WireGuard 修改路由表之前快照）────────────────────
# 物理网关在 WireGuard 接管后仍留在路由表（只是 metric 较高），但此处提前捕获更可靠
$_physGW    = $null   # 物理默认网关 IP
$_physIfIdx = $null   # 物理网卡接口序号

foreach ($_adp in (Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notlike "*WireGuard*" -and
        $_.InterfaceDescription -notlike "*Hyper-V*" -and
        $_.Name -notlike "*$WG_TUNNEL_NAME*" })) {
    $_rt = Get-NetRoute -InterfaceIndex $_adp.InterfaceIndex -DestinationPrefix "0.0.0.0/0" `
               -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric | Select-Object -First 1
    if ($_rt -and $_rt.NextHop -and $_rt.NextHop -ne "0.0.0.0") {
        $_physGW    = $_rt.NextHop
        $_physIfIdx = $_adp.InterfaceIndex
        break
    }
}

# 抓取所有已建立（或近期）的 RDP 入站连接的客户端 IP，并转为 /24 网段
# （包含 Established/TimeWait/CloseWait，覆盖正在使用及刚断开的管理连接）
$_rdpMgmtNets = @(
    (Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue |
     Where-Object {
         # 使用局部变量一次解析，避免重复调用 TryParse；解析结果存入 $_parsed
         $addr = $_.RemoteAddress
         $_parsed = $null
         $addr -ne "0.0.0.0" -and $addr -ne "127.0.0.1" -and
         [System.Net.IPAddress]::TryParse($addr, [ref]$_parsed) -and
         $_parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
     } |
     Select-Object -ExpandProperty RemoteAddress -Unique) |
    ForEach-Object { ($_ -replace '\.\d{1,3}$', '.0') }   # /24 网络地址
) | Sort-Object -Unique

# ── 卸载模式 ──────────────────────────────────────────────────────────────────
if ($Uninstall) {
    # 先读取安装时保存的旁路路由记录（必须在停止服务前读取，防止目录被清理）
    # Test-Path 在目录不存在时返回 $false，无需额外处理
    $_stateFile = "$WG_CONF_DIR\rdp-bypass-routes.txt"
    $_savedNets = @()
    if (Test-Path $_stateFile) {
        $_savedNets = @(Get-Content $_stateFile -ErrorAction SilentlyContinue |
                        Where-Object { $_ -match '\S' })
    }

    Write-Info "停止并移除 WireGuard 隧道..."
    if (Test-Path $WG_EXE) {
        & $WG_EXE /uninstalltunnelservice $WG_TUNNEL_NAME 2>$null
        Start-Sleep 2
        & $WG_EXE /uninstallmanagerservice 2>$null
    }
    # 移除 Kill Switch 防火墙规则
    Remove-NetFirewallRule -Name "WG-KS-*" -ErrorAction SilentlyContinue | Out-Null
    Write-Info "Kill Switch 规则已清除。"
    # 移除安装时写入的 RDP 管理直通路由（从状态文件读取，与安装时完全一致）
    if ($_savedNets.Count -gt 0) {
        foreach ($_net in $_savedNets) {
            $null = & route delete "$_net" mask 255.255.255.0 2>&1
        }
        Remove-Item $_stateFile -Force -ErrorAction SilentlyContinue
        Write-Info "RDP 直通路由已清除。"
    }
    Write-Info "卸载完成。"
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
# 1. 安装 WireGuard for Windows
# ═════════════════════════════════════════════════════════════════════════════
Write-Info "检查 WireGuard 安装状态..."

if (-not (Test-Path $WG_EXE)) {
    Write-Info "下载 WireGuard for Windows..."
    $wgInstaller = "$env:TEMP\wireguard-installer.exe"
    $wgUrl = "https://download.wireguard.com/windows-client/wireguard-installer.exe"

    try {
        # 启用 TLS 1.2 + TLS 1.3（TLS 1.3 在 .NET 4.8 / PowerShell 7+ 上可用）
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        Invoke-WebRequest -Uri $wgUrl -OutFile $wgInstaller -UseBasicParsing -TimeoutSec 60
    } catch {
        Write-Err "下载失败：$_"
    }

    Write-Info "安装 WireGuard（静默模式）..."
    Start-Process -FilePath $wgInstaller -ArgumentList "/S" -Wait
    Remove-Item $wgInstaller -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $WG_EXE)) {
        Write-Err "WireGuard 安装失败，请手动安装：https://www.wireguard.com/install/"
    }
}
Write-Info "WireGuard 已安装：$WG_EXE"

# ═════════════════════════════════════════════════════════════════════════════
# 2. 检查并复制配置文件
# ═════════════════════════════════════════════════════════════════════════════
if (-not (Test-Path $ConfigFile)) {
    Write-Err "未找到配置文件：$ConfigFile`n请先将服务端生成的 wg-client.conf 放到同目录"
}

New-Item -ItemType Directory -Force -Path $WG_CONF_DIR | Out-Null
$destConf = "$WG_CONF_DIR\$WG_TUNNEL_NAME.conf"
Copy-Item -Path $ConfigFile -Destination $destConf -Force
# 保护配置文件权限（仅 SYSTEM 和 Administrators 可读）
$acl = Get-Acl $destConf
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
foreach ($id in @("SYSTEM","Administrators")) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $id, "FullControl", "Allow")
    $acl.AddAccessRule($rule)
}
Set-Acl -Path $destConf -AclObject $acl
Write-Info "配置文件已复制到 $destConf"

# ═════════════════════════════════════════════════════════════════════════════
# 3. 安装并启动 WireGuard 隧道服务
# ═════════════════════════════════════════════════════════════════════════════
Write-Info "安装 WireGuard 隧道服务：$WG_TUNNEL_NAME"

# 先停止旧实例（如果存在）
& $WG_EXE /uninstalltunnelservice $WG_TUNNEL_NAME 2>$null
Start-Sleep 1

# ── RDP 管理直通路由（在 VPN 路由写入前持久化，确保管理连接不受影响）───────────
# 根本原因：WireGuard 全隧道向路由表注入 0.0.0.0/1 + 128.0.0.0/1，所有出站包含
# RDP 响应包均经 VPN 隧道转发，源 IP 变为 VPN 出口 IP；客户端收到源 IP 不符的
# SYN-ACK，TCP 握手失败，RDP 连接立即断开。
# 修复：为管理网段写入持久 /24 路由（最长前缀匹配，/24 > /1，无条件优先），
# 响应包走物理网卡发出，源 IP 保持本机真实 IP，RDP 握手正常。
if ($_physGW) {
    # 重新运行前清理上次写入的旁路路由，防止管理 IP 变化时旧持久路由积累无法清理
    # （仅删除已写入的路由条目，不触碰路由表中其他条目；route delete 在路由不存在时返回非零，属正常情况）
    $_stateFile = "$WG_CONF_DIR\rdp-bypass-routes.txt"
    if (Test-Path $_stateFile) {
        @(Get-Content $_stateFile -ErrorAction SilentlyContinue |
          Where-Object { $_ -match '\S' }) | ForEach-Object {
            $null = & route delete "$_" mask 255.255.255.0 2>&1
        }
    }

    if ($_rdpMgmtNets.Count -gt 0) {
        Write-Info "写入 RDP 管理网段直通路由（物理网关：$_physGW）..."
        $_writtenNets = @()
        foreach ($_net in $_rdpMgmtNets) {
            # 先删除同条路由（幂等）。route delete 在路由不存在时返回非零，属正常情况，静默丢弃
            $null = & route delete "$_net" mask 255.255.255.0 2>&1
            $_routeOut = & route add "$_net" mask 255.255.255.0 $_physGW metric 1 -p 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Info "  ✓ $_net/24 → $_physGW（已持久化，重启后有效）"
                $_writtenNets += $_net
            } else {
                Write-Warn "  持久化失败（$_net）：$_routeOut"
                Write-Warn "  尝试写入临时路由..."
                $_tmpErr = $null
                New-NetRoute -DestinationPrefix "$_net/24" -NextHop $_physGW `
                    -InterfaceIndex $_physIfIdx -RouteMetric 1 `
                    -ErrorAction SilentlyContinue -ErrorVariable _tmpErr | Out-Null
                if ($_tmpErr) {
                    Write-Warn "  临时路由也写入失败：$_tmpErr — RDP 响应包可能仍经隧道转发，请检查权限。"
                } else {
                    Write-Warn "  ✓ 临时路由已写入（重启后失效，请排查持久化问题后重新运行脚本）"
                    $_writtenNets += $_net
                }
            }
        }
        # 保存已写入的旁路路由到状态文件，供 -Uninstall 精确清理使用
        # $WG_CONF_DIR 已在步骤 2 由 New-Item -Force 创建，此处直接写入
        if ($_writtenNets.Count -gt 0) {
            $_writtenNets | Out-File "$WG_CONF_DIR\rdp-bypass-routes.txt" -Encoding ASCII -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Warn @"
未检测到活动 RDP 连接。VPN 启动后如需从新 IP 远程桌面，请在确认管理 IP 后
以管理员 PowerShell 运行（将 1.2.3.0 替换为管理机 IP 所属 /24 网段地址；
若路由已存在可先运行 route delete 1.2.3.0 mask 255.255.255.0 再添加）：
  route add 1.2.3.0 mask 255.255.255.0 $_physGW metric 1 -p
"@
    }
} else {
    Write-Warn "无法获取物理网关，跳过 RDP 直通路由写入。RDP 可能因 VPN 路由变化而断开。"
}

& $WG_EXE /installtunnelservice $destConf
Start-Sleep 3

$svcName = "WireGuardTunnel`$$WG_TUNNEL_NAME"
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Err "隧道服务未注册，请检查配置文件格式"
}

# 设置服务自动启动
Set-Service -Name $svcName -StartupType Automatic

# 启动服务
if ($svc.Status -ne "Running") {
    Start-Service -Name $svcName
    Start-Sleep 3
}
$svc = Get-Service -Name $svcName
if ($svc.Status -ne "Running") {
    Write-Err "隧道服务启动失败：$($svc.Status)"
}
Write-Info "隧道服务运行中 ✓"

# ═════════════════════════════════════════════════════════════════════════════
# 4. 防泄露强化
# ═════════════════════════════════════════════════════════════════════════════

# 4-a. 禁用其他网卡的 IPv6（防止 IPv6 绕过隧道）
# 排除：隧道接口本身、WireGuard 描述的适配器、Hyper-V 虚拟交换机适配器
# （Server 2022 Datacenter 上 Hyper-V vNIC 若被禁用 IPv6 会破坏 VM 网络）
Write-Info "禁用非 WireGuard 网卡的 IPv6..."
Get-NetAdapter | Where-Object {
    $_.Name -notlike "*$WG_TUNNEL_NAME*" -and
    $_.InterfaceDescription -notlike "*WireGuard*" -and
    $_.InterfaceDescription -notlike "*Hyper-V*" -and
    $_.Status -eq "Up"
} | ForEach-Object {
    Disable-NetAdapterBinding -Name $_.Name -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue
    Write-Warn "  已禁用 $($_.Name) 的 IPv6"
}

# 4-b. 强制 DNS 设置（覆盖所有非 VPN / 非 Hyper-V 网卡，防止 DNS 泄露）
# 排除 WireGuard 隧道接口（WireGuard 自身管理该接口的 DNS）和 Hyper-V vNIC
# （修改 Hyper-V 虚拟适配器 DNS 会影响 VM 内部 DNS 解析，Server 2022 必须排除）
Write-Info "锁定物理网卡 DNS 到隧道 DNS..."
$vpnDns = @("1.1.1.1", "1.0.0.1")
Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and
    $_.Name -notlike "*$WG_TUNNEL_NAME*" -and
    $_.InterfaceDescription -notlike "*WireGuard*" -and
    $_.InterfaceDescription -notlike "*Hyper-V*"
} | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses $vpnDns -ErrorAction SilentlyContinue
}

# 4-c. 禁用 DNS 多播（防止 mDNS 泄露本地 IP）
Write-Info "禁用 DNS 多播..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" `
    -Name "EnableMulticast" -Value 0 -Type DWord -Force

# 4-d. 禁用 Windows Smart Multi-Homed Name Resolution（防止 DNS 走多网卡）
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
Set-ItemProperty -Path $policyPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force

# 4-e. 等待 WireGuard 适配器就绪（Windows Server 2022 上驱动注册可能需要最多 30 秒）
# Kill Switch 规则的 -InterfaceAlias 需要适配器处于 Up 状态才能正确绑定
$maxRetries = 15          # 每次等待 2 秒，共最多 $maxRetries × 2 = 30 秒
Write-Info "等待 WireGuard 网卡就绪..."
$wgAdapter = $null
for ($i = 0; $i -lt $maxRetries; $i++) {
    $wgAdapter = Get-NetAdapter | Where-Object {
        ($_.Name -like "*$WG_TUNNEL_NAME*" -or $_.InterfaceDescription -like "*WireGuard*") -and
        $_.Status -eq "Up"
    } | Select-Object -First 1
    if ($wgAdapter) { break }
    Start-Sleep 2
}
if ($wgAdapter) {
    Write-Info "WireGuard 网卡就绪：$($wgAdapter.Name) ✓"
} else {
    Write-Warn "WireGuard 网卡在 30 秒内未进入 Up 状态，Kill Switch InterfaceAlias 规则可能未立即生效（规则已写入，适配器上线后自动应用）"
}

# 4-f. Kill Switch — VPN 断线时阻断所有流量（企业级安全）
Write-Info "配置 Kill Switch（VPN 断线保护）..."

# 解析服务端 Endpoint（用于允许建立/保持隧道的防火墙规则）
# 支持格式：IPv4:port、hostname:port、[IPv6]:port
$configRaw = Get-Content $destConf -Raw
$epMatch = [regex]::Match($configRaw, 'Endpoint\s*=\s*(\[.*?\]|[^\s:]+):(\d+)')
$serverEndpointIP   = if ($epMatch.Success) {
    # 去除 IPv6 地址的方括号（如 [2001:db8::1] → 2001:db8::1）
    $raw = $epMatch.Groups[1].Value.Trim().Trim('[', ']')
    # 若 Endpoint 是主机名而非 IP，解析为 IPv4 地址（防火墙规则不支持主机名）
    if ($raw -match '^[\d.]+$' -or $raw -match '^[0-9a-fA-F:]+$') {
        $raw
    } else {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($raw) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                Select-Object -ExpandProperty IPAddressToString -First 1
            if ($resolved) { $resolved } else { $raw }
        } catch {
            Write-Warn "无法解析 Endpoint 主机名 '$raw' 为 IP 地址。Windows 防火墙不支持主机名作为 RemoteAddress，Kill Switch 将无法正确阻止 VPN 断线时的流量，真实 IP 可能泄露。请将配置文件中 Endpoint 改为 IP 地址后重新运行安装脚本。"
            $raw
        }
    }
} else { $null }
$serverEndpointPort = if ($epMatch.Success) { [int]$epMatch.Groups[2].Value }    else { 51820 }

# 清除旧 Kill Switch 规则
Remove-NetFirewallRule -Name "WG-KS-*" -ErrorAction SilentlyContinue | Out-Null

# 阻断所有出站流量（默认拒绝策略）
New-NetFirewallRule -Name "WG-KS-BlockOut" `
    -DisplayName "WireGuard KS: Block All Outbound" `
    -Direction Outbound -Action Block -Profile Any -Enabled True | Out-Null

# 允许通过 VPN 隧道接口出站（所有隧道内流量）
New-NetFirewallRule -Name "WG-KS-AllowTunnel" `
    -DisplayName "WireGuard KS: Allow VPN Tunnel Interface" `
    -Direction Outbound -Action Allow `
    -InterfaceAlias $WG_TUNNEL_NAME -Profile Any -Enabled True | Out-Null

# 允许 UDP 到服务端 Endpoint（建立 / 保持 WireGuard 握手）
if ($serverEndpointIP) {
    New-NetFirewallRule -Name "WG-KS-AllowEndpoint" `
        -DisplayName "WireGuard KS: Allow VPN Endpoint UDP" `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemoteAddress $serverEndpointIP -RemotePort $serverEndpointPort `
        -Profile Any -Enabled True | Out-Null
}

# 允许本地回环 + 链路本地（防止 APIPA 和邻居发现失败）
# 127.0.0.0/8：IPv4 回环；::1/128：IPv6 回环
# 169.254.0.0/16：IPv4 链路本地（APIPA / DHCP 失败后备地址 + 部分云元数据）
# fe80::/10：IPv6 链路本地（邻居发现 / NDP 必须）
New-NetFirewallRule -Name "WG-KS-AllowLoopbackAndLinkLocal" `
    -DisplayName "WireGuard KS: Allow Loopback and Link-Local" `
    -Direction Outbound -Action Allow `
    -RemoteAddress @("127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10") `
    -Profile Any -Enabled True | Out-Null

# 允许 DHCP 更新（UDP dst 67 → 路由器/DHCP 服务器）
# Kill Switch 若阻断 DHCP，租约到期后客户端丢失 IP，WireGuard 握手无法发送，VPN 无法恢复
New-NetFirewallRule -Name "WG-KS-AllowDHCP" `
    -DisplayName "WireGuard KS: Allow DHCP Renewal" `
    -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePort 67 `
    -Profile Any -Enabled True | Out-Null

# 允许 NTP 时间同步（UDP dst 123）
# WireGuard 握手的 replay protection 要求双端时钟偏差 < 180s；
# 长期运行时若 NTP 被阻断，时钟漂移将导致握手失败，VPN 永久断线
New-NetFirewallRule -Name "WG-KS-AllowNTP" `
    -DisplayName "WireGuard KS: Allow NTP Time Sync" `
    -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePort 123 `
    -Profile Any -Enabled True | Out-Null

# 允许 RDP 远程管理（防止 Kill Switch 阻断远程桌面响应流量，导致管理会话断开）
# 本机作为被管理的 Windows Server，RDP（TCP 3389）是唯一管理通道。
# 出站方向 LocalPort 3389 = 服务端向 RDP 客户端发回的响应包；必须无条件放行，
# 否则 Kill Switch 生效后 RDP 会话立即断开，无法再远程登录修复。
New-NetFirewallRule -Name "WG-KS-AllowRDP" `
    -DisplayName "WireGuard KS: Allow RDP Remote Management" `
    -Direction Outbound -Action Allow `
    -Protocol TCP -LocalPort 3389 `
    -Profile Any -Enabled True | Out-Null

Write-Info "Kill Switch 已启用 ✓ （VPN 断线时所有出站流量将被自动阻断；DHCP/NTP/RDP/链路本地已豁免）"

# ═════════════════════════════════════════════════════════════════════════════
# 5. 验证连接
# ═════════════════════════════════════════════════════════════════════════════
Write-Info "等待隧道就绪..."
Start-Sleep 5

Write-Info "检查当前出口 IP..."
try {
    # -UseBasicParsing：Server 2022 默认启用 IE 增强安全配置（IE ESC），
    # 不加此参数 Invoke-RestMethod 会因 IE COM 引擎不可用而抛出异常
    $currentIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 10 -UseBasicParsing).ip
    Write-Host ""
    Write-Host "  当前出口 IP：$currentIP" -ForegroundColor Cyan
    Write-Host "  请访问 https://ipleak.net 确认显示为美国（圣何塞）IP" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Warn "无法检测出口 IP（可能隧道还未完全就绪），请手动访问 https://ip.me"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════" -ForegroundColor Green
Write-Host " WireGuard 全流量 VPN 配置完成！        " -ForegroundColor Green
Write-Host "════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "验证步骤：" -ForegroundColor Yellow
Write-Host "  1. 访问 https://ipleak.net      — 确认 IP/DNS 均显示美国"
Write-Host "  2. 访问 https://dnsleaktest.com  — 点击 Extended Test"
Write-Host "  3. 访问 https://ipv6leak.com     — 确认无 IPv6 泄露"
Write-Host "  4. 运行 verify\check-leak.ps1    — 自动化检测"
Write-Host ""
Write-Host "管理命令：" -ForegroundColor Yellow
Write-Host "  停止 VPN：Stop-Service  'WireGuardTunnel`$$WG_TUNNEL_NAME'"
Write-Host "  启动 VPN：Start-Service 'WireGuardTunnel`$$WG_TUNNEL_NAME'"
Write-Host "  卸载 VPN：.\setup-client.ps1 -Uninstall"
