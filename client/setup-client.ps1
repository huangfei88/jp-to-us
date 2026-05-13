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
.PARAMETER ManagementCIDR
    【重要】管理机 IP 或 /24 网段，格式：
      单个 IP：   -ManagementCIDR "203.0.113.10"
      单个 /24：  -ManagementCIDR "203.0.113.0"
      多个网段：  -ManagementCIDR "203.0.113.0","198.51.100.0"
    若未指定，脚本自动检测当前 RDP/TCP 连接；检测失败时强制要求输入。
.NOTES
    使用前请先将 wg-client.conf 放到与本脚本相同目录，
    或通过 -ConfigFile 参数指定路径
.EXAMPLE
    # 推荐：明确指定管理机网段，最安全
    .\setup-client.ps1 -ManagementCIDR "203.0.113.0"

    # 自动检测（须在 RDP 会话中运行）
    .\setup-client.ps1

    # 卸载
    .\setup-client.ps1 -Uninstall
#>

#Requires -RunAsAdministrator

param(
    [string]$ConfigFile = "$PSScriptRoot\wg-client.conf",

    # ★ 新增：显式指定管理机 IP 或 /24 网段，作为旁路路由兜底
    # 接受字符串数组，支持 "1.2.3.10"（自动转为 1.2.3.0/24）或 "1.2.3.0"
    [string[]]$ManagementCIDR = @(),

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

# ── 将任意 IP 字符串标准化为 /24 网络地址（末位改为 0）───────────────────────
# 输入 "1.2.3.45" 或 "1.2.3.0" 均输出 "1.2.3.0"
function ConvertTo-NetworkAddress {
    param([string]$ip)
    # 去除可能携带的 CIDR 后缀（如 /24 /32）
    $bare = $ip -replace '/\d+$', ''
    if ($bare -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$') {
        return "$($Matches[1]).$($Matches[2]).$($Matches[3]).0"
    }
    return $null   # 无效 IP，调用方负责过滤
}

# ── 提前捕获物理网关和管理 IP（WireGuard 修改路由表之前快照）────────────────────
$_physGW    = $null
$_physIfIdx = $null

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

# ════════════════════════════════════════════════════════════════════════════
# ★ 管理网段收集（三层兜底，任一层有结果即合并）
# 层级 1：-ManagementCIDR 参数（用户显式指定，最可靠）
# 层级 2：Get-NetTCPConnection 检测活跃 RDP 连接
# 层级 3：qwinsta 检测当前登录会话的客户端 IP
# 三层全部为空时强制要求用户输入，拒绝无保护地继续
# ════════════════════════════════════════════════════════════════════════════

$_mgmtNets = [System.Collections.Generic.HashSet[string]]::new()

# 层级 1：用户通过 -ManagementCIDR 参数指定
foreach ($_cidr in $ManagementCIDR) {
    $_net = ConvertTo-NetworkAddress $_cidr
    if ($_net) {
        [void]$_mgmtNets.Add($_net)
        Write-Info "管理网段（参数指定）：$_net/24"
    } else {
        Write-Warn "-ManagementCIDR 包含无效 IP：'$_cidr'，已跳过"
    }
}

# 层级 2：Get-NetTCPConnection 检测所有 RDP 相关状态的远端 IP
#   覆盖 Established（当前连接）/ TimeWait / CloseWait（近期断开的连接）
#   同时覆盖 Listen（端口监听）时 RemoteAddress 为 0.0.0.0 的情况（已过滤）
try {
    $null = Get-NetTCPConnection -LocalPort 3389 -ErrorAction Stop  # 先测试命令是否可用
    Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue |
    Where-Object {
        $addr = $_.RemoteAddress
        $parsed = $null
        $addr -ne "0.0.0.0" -and
        $addr -ne "::" -and
        $addr -ne "127.0.0.1" -and
        [System.Net.IPAddress]::TryParse($addr, [ref]$parsed) -and
        $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    } |
    Select-Object -ExpandProperty RemoteAddress -Unique |
    ForEach-Object {
        $_net = ConvertTo-NetworkAddress $_
        if ($_net -and $_mgmtNets.Add($_net)) {
            Write-Info "管理网段（TCP 连接检测）：$_net/24（来自 $_）"
        }
    }
} catch {
    Write-Warn "Get-NetTCPConnection 不可用：$_"
}

# 层级 3：qwinsta 解析当前已登录 RDP 会话的客户端 IP
#   qwinsta 输出示例（Server 2022）：
#   SESSIONNAME       USERNAME            ID  STATE   TYPE        DEVICE
#   rdp-tcp#0         Administrator        2  Active  rdpwd
#   qwinsta 本身不输出客户端 IP，需结合 netstat -n 匹配端口
#   补充策略：用 netstat -n 获取 ESTABLISHED 状态的 :3389 远端 IP
try {
    $netstatLines = & netstat.exe -n 2>$null
    $netstatLines |
    Where-Object { $_ -match '^\s+TCP\s+[\d.]+:3389\s+([\d.]+):\d+\s+ESTABLISHED' } |
    ForEach-Object {
        $remoteIP = $Matches[1]
        $_net = ConvertTo-NetworkAddress $remoteIP
        if ($_net -and $remoteIP -ne "127.0.0.1" -and $_mgmtNets.Add($_net)) {
            Write-Info "管理网段（netstat 检测）：$_net/24（来自 $remoteIP）"
        }
    }
} catch {
    Write-Warn "netstat 检测失败：$_"
}

# ★ 三层全部为空 → 强制要求用户输入，拒绝无保护地继续
if ($_mgmtNets.Count -eq 0) {
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host " [SAFETY BLOCK] 未检测到任何管理机 IP/网段" -ForegroundColor Red
    Write-Host ""
    Write-Host " 若不写入旁路路由，VPN 启动后 RDP 响应包将经隧道发出，" -ForegroundColor Red
    Write-Host " 源 IP 变为圣何塞出口 IP，客户端 TCP 握手失败，RDP 立即断开。" -ForegroundColor Red
    Write-Host ""
    Write-Host " 请输入您管理机的 IP 地址（如 203.0.113.10），或直接回车退出：" -ForegroundColor Yellow
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""

    $userInput = Read-Host "管理机 IP"
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        Write-Err "已取消：必须提供管理机 IP 才能安全继续。`n请重新运行并加参数：-ManagementCIDR `"您的管理机IP`""
    }

    $_net = ConvertTo-NetworkAddress $userInput.Trim()
    if (-not $_net) {
        Write-Err "输入的 IP 格式无效：'$userInput'"
    }
    [void]$_mgmtNets.Add($_net)
    Write-Info "管理网段（用户输入）：$_net/24"
}

$_rdpMgmtNets = @($_mgmtNets)

# ════════════════════════════════════════════════════════════════════════════
# ── 卸载模式 ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
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
    Remove-NetFirewallRule -Name "WG-KS-*" -ErrorAction SilentlyContinue | Out-Null
    Write-Info "Kill Switch 规则已清除。"
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

& $WG_EXE /uninstalltunnelservice $WG_TUNNEL_NAME 2>$null
Start-Sleep 1

# ── RDP 管理直通路由（必须在 installtunnelservice 之前写入）──────────────────
# 原理：WireGuard 全隧道向路由表注入 0.0.0.0/1 + 128.0.0.0/1，覆盖所有出站流量。
# 修复：为管理网段写入持久 /24 路由（/24 比 /1 更精确，最长前缀匹配无条件优先），
#       RDP 响应包走物理网卡，源 IP 保持本机真实 IP，TCP 握手正常。
if ($_physGW) {
    # 清理上次写入的旧旁路路由（防止 IP 变化导致旧路由残留）
    $_stateFile = "$WG_CONF_DIR\rdp-bypass-routes.txt"
    if (Test-Path $_stateFile) {
        @(Get-Content $_stateFile -ErrorAction SilentlyContinue |
          Where-Object { $_ -match '\S' }) | ForEach-Object {
            $null = & route delete "$_" mask 255.255.255.0 2>&1
        }
        Remove-Item $_stateFile -Force -ErrorAction SilentlyContinue
    }

    # $_rdpMgmtNets 此时已保证非空（前面三层检测 + 强制输入兜底）
    Write-Info "写入 RDP 管理网段直通路由（物理网关：$_physGW）..."
    $_writtenNets = @()
    foreach ($_net in $_rdpMgmtNets) {
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
                # ★ 路由写入失败时强制中止，防止 RDP 在 VPN 启动后断开
                Write-Err "路由写入彻底失败（$_net）：$_tmpErr`n请以管理员权限重新运行脚本。"
            } else {
                Write-Warn "  ✓ 临时路由已写入（重启后失效，建议排查持久化权限后重新运行）"
                $_writtenNets += $_net
            }
        }
    }

    if ($_writtenNets.Count -gt 0) {
        $_writtenNets | Out-File $_stateFile -Encoding ASCII -Force -ErrorAction SilentlyContinue
    }

} else {
    # 无法获取物理网关：这种情况下无论如何路由旁路都无法工作，必须中止
    Write-Err "无法获取物理网关 IP。路由旁路无法工作，为保护 RDP 连接已中止安装。`n请检查网络配置后重新运行。"
}

& $WG_EXE /installtunnelservice $destConf
Start-Sleep 3

$svcName = "WireGuardTunnel`$$WG_TUNNEL_NAME"
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Err "隧道服务未注册，请检查配置文件格式"
}

Set-Service -Name $svcName -StartupType Automatic

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

Write-Info "禁用 DNS 多播..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" `
    -Name "EnableMulticast" -Value 0 -Type DWord -Force

$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
Set-ItemProperty -Path $policyPath -Name "DisableSmartNameResolution" -Value 1 -Type DWord -Force

Write-Info "等待 WireGuard 网卡就绪..."
$maxRetries = 15
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
    Write-Warn "WireGuard 网卡在 30 秒内未进入 Up 状态，Kill Switch 规则写入后待适配器上线自动生效"
}

# ─── Kill Switch ────────────────────────────────────────────────────────────
Write-Info "配置 Kill Switch（VPN 断线保护）..."

$configRaw = Get-Content $destConf -Raw
$epMatch = [regex]::Match($configRaw, 'Endpoint\s*=\s*(\[.*?\]|[^\s:]+):(\d+)')
$serverEndpointIP = if ($epMatch.Success) {
    $raw = $epMatch.Groups[1].Value.Trim().Trim('[', ']')
    if ($raw -match '^[\d.]+$' -or $raw -match '^[0-9a-fA-F:]+$') {
        $raw
    } else {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($raw) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                Select-Object -ExpandProperty IPAddressToString -First 1
            if ($resolved) { $resolved } else { $raw }
        } catch {
            Write-Warn "无法解析 Endpoint 主机名 '$raw'，Kill Switch Endpoint 规则可能失效。建议将 Endpoint 改为 IP 地址。"
            $raw
        }
    }
} else { $null }
$serverEndpointPort = if ($epMatch.Success) { [int]$epMatch.Groups[2].Value } else { 51820 }

Remove-NetFirewallRule -Name "WG-KS-*" -ErrorAction SilentlyContinue | Out-Null

# 默认拒绝所有出站
New-NetFirewallRule -Name "WG-KS-BlockOut" `
    -DisplayName "WireGuard KS: Block All Outbound" `
    -Direction Outbound -Action Block -Profile Any -Enabled True | Out-Null

# 允许 VPN 隧道接口出站
New-NetFirewallRule -Name "WG-KS-AllowTunnel" `
    -DisplayName "WireGuard KS: Allow VPN Tunnel Interface" `
    -Direction Outbound -Action Allow `
    -InterfaceAlias $WG_TUNNEL_NAME -Profile Any -Enabled True | Out-Null

# 允许 WireGuard 握手包（UDP 到服务端 Endpoint）
if ($serverEndpointIP) {
    New-NetFirewallRule -Name "WG-KS-AllowEndpoint" `
        -DisplayName "WireGuard KS: Allow VPN Endpoint UDP" `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemoteAddress $serverEndpointIP -RemotePort $serverEndpointPort `
        -Profile Any -Enabled True | Out-Null
}

# 允许回环 + 链路本地
New-NetFirewallRule -Name "WG-KS-AllowLoopbackAndLinkLocal" `
    -DisplayName "WireGuard KS: Allow Loopback and Link-Local" `
    -Direction Outbound -Action Allow `
    -RemoteAddress @("127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10") `
    -Profile Any -Enabled True | Out-Null

# 允许 DHCP（UDP 67）
New-NetFirewallRule -Name "WG-KS-AllowDHCP" `
    -DisplayName "WireGuard KS: Allow DHCP Renewal" `
    -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePort 67 `
    -Profile Any -Enabled True | Out-Null

# 允许 NTP（UDP 123）
New-NetFirewallRule -Name "WG-KS-AllowNTP" `
    -DisplayName "WireGuard KS: Allow NTP Time Sync" `
    -Direction Outbound -Action Allow `
    -Protocol UDP -RemotePort 123 `
    -Profile Any -Enabled True | Out-Null

# ★ RDP 管理豁免规则（双重保护）
#
# 原则：Kill Switch 的 WG-KS-BlockOut 阻断全部出站流量。
#       Windows 防火墙规则评估：更精确的规则（更多匹配字段）优先于更宽泛的规则。
#       因此 Allow（精确匹配管理目标 IP + TCP 3389）> Block（匹配所有流量）。
#
# 规则 A：RDP 响应包出站（源端口 3389，目标 = 管理机 IP）
#   说明：本机作为 RDP 服务端，响应包的源端口 = 3389，目标 = 管理机 IP。
#         -LocalPort 3389 匹配源端口；-RemoteAddress 精确匹配管理机网段。
#
# 规则 B：管理网段全流量允许出站（兜底，覆盖 ICMP/WinRM 等非 TCP 3389 管理通道）
#   说明：旁路路由使管理响应包走物理网卡；此规则确保 Kill Switch 不在防火墙层拦截。

$_mgmtRemoteAddrs = @($_rdpMgmtNets | ForEach-Object { "$_/24" })

# 规则 A：精确放行 RDP 响应包
New-NetFirewallRule -Name "WG-KS-AllowRDP" `
    -DisplayName "WireGuard KS: Allow RDP Response to Management" `
    -Direction Outbound -Action Allow `
    -Protocol TCP -LocalPort 3389 `
    -RemoteAddress $_mgmtRemoteAddrs `
    -Profile Any -Enabled True | Out-Null

# 规则 B：放行管理网段全部出站（兜底）
New-NetFirewallRule -Name "WG-KS-AllowMgmtSubnet" `
    -DisplayName "WireGuard KS: Allow All Outbound to Management Subnet" `
    -Direction Outbound -Action Allow `
    -RemoteAddress $_mgmtRemoteAddrs `
    -Profile Any -Enabled True | Out-Null

Write-Info "Kill Switch 已启用 ✓"
Write-Info "管理网段豁免：$($_mgmtRemoteAddrs -join ', ')"
Write-Info "（VPN 断线时仅保留管理通道，其他出站流量全部阻断）"

# ═════════════════════════════════════════════════════════════════════════════
# 5. 验证连接
# ═════════════════════════════════════════════════════════════════════════════
Write-Info "等待隧道就绪..."
Start-Sleep 5

Write-Info "检查当前出口 IP..."
try {
    $currentIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 10 -UseBasicParsing).ip
    Write-Host ""
    Write-Host "  当前出口 IP：$currentIP" -ForegroundColor Cyan
    Write-Host "  请访问 https://ipleak.net 确认显示为美国（圣何塞）IP" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Warn "无法检测出口 IP（隧道可能还未完全就绪），请手动访问 https://ip.me"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host " WireGuard 全流量 VPN 配置完成！                           " -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "RDP 管理保护状态：" -ForegroundColor Yellow
foreach ($_net in $_rdpMgmtNets) {
    Write-Host "  ✓ $_net/24 已设置路由旁路 + Kill Switch 豁免" -ForegroundColor Green
}
Write-Host ""
Write-Host "验证步骤：" -ForegroundColor Yellow
Write-Host "  1. 访问 https://ipleak.net      — 确认 IP/DNS 均显示美国"
Write-Host "  2. 访问 https://dnsleaktest.com  — 点击 Extended Test"
Write-Host "  3. 访问 https://ipv6leak.com     — 确认无 IPv6 泄露"
Write-Host "  4. 从管理机重新建立 RDP 连接测试是否正常"
Write-Host ""
Write-Host "管理命令：" -ForegroundColor Yellow
Write-Host "  停止 VPN：Stop-Service  'WireGuardTunnel`$$WG_TUNNEL_NAME'"
Write-Host "  启动 VPN：Start-Service 'WireGuardTunnel`$$WG_TUNNEL_NAME'"
Write-Host "  添加新管理 IP：route add 新IP所属/24网络地址 mask 255.255.255.0 $($_physGW ?? '物理网关IP') metric 1 -p"
Write-Host "  卸载 VPN：.\setup-client.ps1 -Uninstall"
