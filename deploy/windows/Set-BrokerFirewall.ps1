<#
.SYNOPSIS
Program-scoped Windows Defender Firewall rules for the broker and its cloudflared.

.DESCRIPTION
The host default outbound action is a host-wide decision, so this script does not change
it. Instead it pins the two broker programs with allow rules plus block rules. Windows
Firewall evaluates block rules before allow rules, so each block rule lists the
complement of what is allowed (addresses and ports), never "any".

Broker interpreter (C:\Program Files\ProxmoxMCP\python\python.exe; the venv
Scripts\python.exe and the console-script .exe re-launch this file, so this is the
process that opens sockets):
  allow  TCP -> <Proxmox addresses>:<ProxmoxPort>
  allow  TCP -> Cloudflare ranges:443        (access mode only: Access JWKS)
  block  every other IPv4/IPv6 address, any protocol (loopback excluded)
  block  other TCP ports and all UDP to the allowed addresses
  block  all inbound
cloudflared (cloudflared.exe):
  allow  TCP 7844, UDP 7844, TCP 443 to public addresses. The edge hosts
         region1/region2.v2.argotunnel.com resolve to changing Cloudflare addresses,
         so the rule pins ports, not addresses.
  block  private, link-local, CGNAT and multicast ranges (IPv4 and IPv6), all ports:
         a remote-managed tunnel config that adds an ingress rule to a LAN service is
         stopped here, so the tunnel can only reach the broker on loopback
  block  other TCP/UDP ports to non-loopback addresses
  block  all inbound
Replacement is safe: the new rule set is added first (new generation), then the old
generation is removed. There is never a moment without block rules.
No inbound allow rule exists for the broker port: it binds 127.0.0.1 only.
Blocked packets are logged (pfirewall.log) on every profile.

.EXAMPLE
.\Set-BrokerFirewall.ps1 -ProxmoxAddress 192.0.2.10/32 -WhatIf
.\Set-BrokerFirewall.ps1 -ProxmoxAddress 192.0.2.10/32,192.0.2.11/32 -BrokerMode access -FetchCloudflareRanges
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # IPv4 addresses or CIDRs of the Proxmox API endpoint(s). Use the node addresses, not a
    # whole LAN.
    [Parameter(Mandatory)][string[]]$ProxmoxAddress,
    [ValidateRange(1, 65535)][int]$ProxmoxPort = 8006,
    [ValidateSet('vpc', 'access')][string]$BrokerMode = 'vpc',
    # access mode: Cloudflare IPv4 ranges for the Access JWKS fetch. Pass them, or use
    # -FetchCloudflareRanges to read https://api.cloudflare.com/client/v4/ips now.
    [string[]]$CloudflareRanges = @(),
    [switch]$FetchCloudflareRanges,
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator
Initialize-PmcTlsProtocol

$group = 'ProxmoxMCP'
$generation = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$existing = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
if ($Remove) {
    if ($existing.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($existing.Count) rules in group $group", 'Remove')) {
        $existing | Remove-NetFirewallRule
    }
    Write-Step 'Rules removed.'
    return
}

$cf = $null
foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if ($base -and (Test-Path -LiteralPath (Join-Path $base 'cloudflared\cloudflared.exe'))) { $cf = Join-Path $base 'cloudflared\cloudflared.exe' }
}
if (-not (Test-Path -LiteralPath $PmcPythonExe)) { throw "Broker interpreter not found: $PmcPythonExe. Run Install-ProxmoxMcpBroker.ps1 first." }
if (-not $cf) { throw 'cloudflared.exe not found. Run Install-Cloudflared.ps1 first.' }

foreach ($a in $ProxmoxAddress) { [void](ConvertTo-PmcIPv4Range $a) }
if ($BrokerMode -eq 'access') {
    if ($FetchCloudflareRanges) {
        $r = Invoke-RestMethod -UseBasicParsing -Uri 'https://api.cloudflare.com/client/v4/ips' -TimeoutSec 30
        if (-not $r.success) { throw 'Cloudflare IP list request failed.' }
        $CloudflareRanges = @($r.result.ipv4_cidrs)
    }
    if ($CloudflareRanges.Count -lt 5) { throw 'access mode needs the Cloudflare IPv4 ranges (-CloudflareRanges or -FetchCloudflareRanges).' }
    foreach ($a in $CloudflareRanges) { [void](ConvertTo-PmcIPv4Range $a) }
}

$loop4 = '127.0.0.0/8'
$v6NotLoopback = @('::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
$allowed4 = @($ProxmoxAddress) + @($CloudflareRanges)
$blockAddr = @(Get-PmcIPv4Complement -Cidr (@($allowed4) + $loop4)) + $v6NotLoopback
$notLoop = @(Get-PmcIPv4Complement -Cidr @($loop4)) + $v6NotLoopback
# Non-public destinations for cloudflared (its edge is always public).
$private = @('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
    '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4', 'fc00::/7', 'fe80::/10', 'ff00::/8')

function Add-PmcRule {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][hashtable]$Rule)
    $script:ruleIndex++
    $common = @{ Group = $group; Profile = 'Any'; Enabled = 'True'; Name = ('ProxmoxMCP-{0}-{1:D2}' -f $generation, $script:ruleIndex) }
    if ($PSCmdlet.ShouldProcess($Rule.DisplayName, 'New-NetFirewallRule')) {
        New-NetFirewallRule @common @Rule | Out-Null
    }
}

$script:ruleIndex = 0
Write-Step "Broker interpreter rules (generation $generation)"
Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker -> Proxmox API'; Direction = 'Outbound'; Action = 'Allow'
    Program = $PmcPythonExe; Protocol = 'TCP'; RemoteAddress = $ProxmoxAddress; RemotePort = "$ProxmoxPort" }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker block other ports to Proxmox'; Direction = 'Outbound'; Action = 'Block'
    Program = $PmcPythonExe; Protocol = 'TCP'; RemoteAddress = $ProxmoxAddress; RemotePort = (Get-PmcPortComplement @($ProxmoxPort)) }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker block UDP to Proxmox'; Direction = 'Outbound'; Action = 'Block'
    Program = $PmcPythonExe; Protocol = 'UDP'; RemoteAddress = $ProxmoxAddress }
if ($BrokerMode -eq 'access') {
    Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker -> Cloudflare Access JWKS'; Direction = 'Outbound'; Action = 'Allow'
        Program = $PmcPythonExe; Protocol = 'TCP'; RemoteAddress = $CloudflareRanges; RemotePort = '443' }
    Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker block other ports to Cloudflare'; Direction = 'Outbound'; Action = 'Block'
        Program = $PmcPythonExe; Protocol = 'TCP'; RemoteAddress = $CloudflareRanges; RemotePort = (Get-PmcPortComplement @(443)) }
    Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker block UDP to Cloudflare'; Direction = 'Outbound'; Action = 'Block'
        Program = $PmcPythonExe; Protocol = 'UDP'; RemoteAddress = $CloudflareRanges }
}
Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker block all other destinations'; Direction = 'Outbound'; Action = 'Block'
    Program = $PmcPythonExe; RemoteAddress = $blockAddr }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP broker block inbound'; Direction = 'Inbound'; Action = 'Block'
    Program = $PmcPythonExe; RemoteAddress = $notLoop }

Write-Step 'cloudflared rules'
Add-PmcRule @{ DisplayName = 'ProxmoxMCP cloudflared block private and link-local ranges'; Direction = 'Outbound'; Action = 'Block'
    Program = $cf; RemoteAddress = $private }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP cloudflared -> edge TCP 7844, 443'; Direction = 'Outbound'; Action = 'Allow'
    Program = $cf; Protocol = 'TCP'; RemotePort = @('7844', '443') }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP cloudflared -> edge UDP 7844 (QUIC)'; Direction = 'Outbound'; Action = 'Allow'
    Program = $cf; Protocol = 'UDP'; RemotePort = '7844' }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP cloudflared block other TCP ports'; Direction = 'Outbound'; Action = 'Block'
    Program = $cf; Protocol = 'TCP'; RemoteAddress = $notLoop; RemotePort = (Get-PmcPortComplement @(443, 7844)) }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP cloudflared block other UDP ports'; Direction = 'Outbound'; Action = 'Block'
    Program = $cf; Protocol = 'UDP'; RemoteAddress = $notLoop; RemotePort = (Get-PmcPortComplement @(7844)) }
Add-PmcRule @{ DisplayName = 'ProxmoxMCP cloudflared block inbound'; Direction = 'Inbound'; Action = 'Block'
    Program = $cf; RemoteAddress = $notLoop }

# The new generation is in place: remove the old one.
if ($existing.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($existing.Count) rules of the previous generation", 'Remove')) {
    $existing | Remove-NetFirewallRule
}

Write-Step 'Firewall profiles: on, inbound default block, log dropped packets'
if ($PSCmdlet.ShouldProcess('All profiles', 'Enable, DefaultInboundAction Block, LogBlocked True')) {
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -LogBlocked True `
        -LogMaxSizeKilobytes 32767 -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'
}

# There must be no inbound allow rule for the broker port.
$brokerPort = 8765
$envMap = Read-PmcEnvFile
if ($envMap.Contains('MCP_PORT')) { $brokerPort = [int]$envMap['MCP_PORT'] }
$bad = @(Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -contains "$brokerPort" } |
        Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' })
if ($bad.Count -gt 0) {
    Write-Warning ("Inbound allow rules for port {0} exist: {1}. Remove them." -f $brokerPort, (($bad | ForEach-Object DisplayName) -join '; '))
}
Write-Step 'Done.'
