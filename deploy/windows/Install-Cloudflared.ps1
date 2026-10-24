<#
.SYNOPSIS
Installs cloudflared from the signed MSI and runs a dedicated tunnel service for the broker.

.DESCRIPTION
- Copies the MSI into an Administrators-only staging folder, then verifies the SHA-256 of
  that copy (pinned by the operator) and its Authenticode signature (signer CN exactly
  "Cloudflare, Inc.", chain valid on this host). msiexec runs the verified copy. The
  installed cloudflared.exe signature is checked on every run.
- Does NOT use "cloudflared service install". That command creates service "Cloudflared"
  running as LocalSystem. Releases before 2026.7.3 also put the token in the service
  ImagePath (argv, registry, event log). Releases from 2026.7.3 write a token file that
  only SYSTEM and Administrators can read, but the service still runs as LocalSystem.
- Instead it creates service "cloudflared-proxmox-mcp" that runs as the virtual account
  NT SERVICE\cloudflared-proxmox-mcp with:
      cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:20241
                  --protocol <quic|auto> run --token-file <ProgramData>\ProxmoxMCP\cloudflared\tunnel-token
  The token is only in that file. ACL: Administrators + SYSTEM full, the service SID read.
  --token-file needs cloudflared 2025.4.0 or later; Workers VPC needs 2025.7.0 or later and QUIC.
- The tunnel token comes from stdin or a hidden prompt (-SetToken), never a parameter.
  Provisioning (deploy/cloudflare/provision.sh) can pipe it straight in over SSH.

.EXAMPLE
.\Install-Cloudflared.ps1 -MsiPath .\cloudflared-windows-amd64.msi -MsiSha256 <hex> -Version 2026.10.3 -WhatIf
.\Install-Cloudflared.ps1 -MsiPath .\cloudflared-windows-amd64.msi -MsiSha256 <hex> -Version 2026.10.3 -SetToken -Start
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$MsiPath,
    # From the GitHub release notes of that version. Check it from a second network.
    [Parameter(Mandatory, ParameterSetName = 'Install')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$MsiSha256,
    [Parameter(Mandatory, ParameterSetName = 'Install')][ValidatePattern('^\d{4}\.\d{1,2}\.\d{1,3}$')][string]$Version,
    # Only (re)write the token file and restart the service. Used by provision.sh over SSH
    # and for token rotation. Implies -SetToken -Start.
    [Parameter(Mandatory, ParameterSetName = 'Token')][switch]$TokenOnly,
    # QUIC is required for Workers VPC. "auto" falls back to HTTP/2 when UDP 7844 is blocked,
    # which hides a firewall problem until the Worker gets dns_error; keep quic unless told otherwise.
    [ValidateSet('quic', 'auto')][string]$Protocol = 'quic',
    [switch]$SetToken,
    [switch]$Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator
Initialize-PmcTlsProtocol

if ($TokenOnly) {
    $SetToken = [switch]$true
    $Start = [switch]$true
    if (-not (Get-Service -Name $PmcCfServiceName -ErrorAction SilentlyContinue)) { throw "Service $PmcCfServiceName does not exist. Run the install first." }
}

function Get-CloudflaredExe {
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $base) { continue }
        $p = Join-Path $base 'cloudflared\cloudflared.exe'
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

$tokenFile = Join-Path $PmcCfDir 'tunnel-token'
$cfLogDir = Join-Path $PmcCfDir 'logs'
if (-not $TokenOnly) {
    $minVersion = [version]'2025.7.0'
    if ([version]$Version -lt $minVersion) { throw "cloudflared $Version is too old. Need $minVersion or later (token file, Workers VPC)." }

    Write-Step 'Stage and verify MSI (SHA-256 of the staged copy, Authenticode)'
    $stage = $null
    if ($PSCmdlet.ShouldProcess($PmcStagingDir, 'Create private staging folder')) {
        New-PmcDirectory -Path $PmcProgramDir
        $stage = New-PmcStagingDir
        $MsiPath = Copy-PmcVerifiedArtifact -Source $MsiPath -Sha256 $MsiSha256 -StagingDir $stage
    } else {
        Assert-Sha256 -Path $MsiPath -Expected $MsiSha256
    }
    Assert-AuthenticodeSigner -Path $MsiPath -SignerCommonName 'Cloudflare, Inc.'

    $exe = Get-CloudflaredExe
    $installed = $null
    if ($exe) {
        $out = & $exe --version 2>&1 | Out-String
        if ($out -match 'version (\d{4}\.\d{1,2}\.\d{1,3})') { $installed = $Matches[1] }
    }
    if ($installed -ne $Version) {
        if ($PSCmdlet.ShouldProcess($MsiPath, "msiexec install cloudflared $Version (installed: $installed)")) {
            $svc = Get-Service -Name $PmcCfServiceName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name $PmcCfServiceName -Force }
            $log = Join-Path $stage 'cloudflared-msi.log'
            $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
                -ArgumentList @('/i', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
            if (@(0, 3010) -notcontains $p.ExitCode) { throw "msiexec failed with $($p.ExitCode). Log: $log" }
            $exe = Get-CloudflaredExe
            if (-not $exe) { throw 'cloudflared.exe not found after install.' }
        }
    } else {
        Write-Step "cloudflared $Version already installed at $exe"
    }
    # The binary the service runs: check its signature on every run, not only after install.
    if ($exe) { Assert-AuthenticodeSigner -Path $exe -SignerCommonName 'Cloudflare, Inc.' }
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }

    $stock = Get-Service -Name 'Cloudflared' -ErrorAction SilentlyContinue
    if ($stock) {
        Write-Warning 'A stock "Cloudflared" service exists (LocalSystem). This script does not use or change it. Remove it if it is not needed: cloudflared service uninstall'
    }

    # ---- Directories (parent locked first) -------------------------------------------------
    New-PmcDirectory -Path $PmcDataDir
    New-PmcDirectory -Path $PmcCfDir
    New-PmcDirectory -Path $cfLogDir
    Assert-PmcTrustedTree -Path $PmcCfDir

    # ---- Service (create or converge) ----------------------------------------------------
    if (-not $exe) { $exe = Join-Path $env:ProgramFiles 'cloudflared\cloudflared.exe' }
    # "tunnel --no-autoupdate": updates come only through this script (pinned hash + signer).
    $bin = ('"{0}" tunnel --no-autoupdate --metrics 127.0.0.1:20241 --protocol {1} ' +
        '--loglevel info --logfile "{2}" run --token-file "{3}"') -f $exe, $Protocol, (Join-Path $cfLogDir 'cloudflared.log'), $tokenFile
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$PmcCfServiceName"
    $svc = Get-Service -Name $PmcCfServiceName -ErrorAction SilentlyContinue
    if ($PSCmdlet.ShouldProcess($PmcCfServiceName, "Create or update service as $PmcCfServiceAccount")) {
        if (-not $svc) {
            New-Service -Name $PmcCfServiceName -BinaryPathName $bin -DisplayName 'Cloudflare Tunnel (Proxmox MCP broker)' `
                -Description 'Dedicated outbound tunnel for the Proxmox MCP broker. Token from file, not argv.' -StartupType Automatic | Out-Null
        } else {
            # Registry, not "sc.exe config binPath=": Windows PowerShell 5.1 does not escape the
            # embedded quotes of a native argument, which would corrupt the path.
            Set-ItemProperty -LiteralPath $svcKey -Name ImagePath -Value $bin -Type ExpandString
        }
        if ((Get-ItemProperty -LiteralPath $svcKey).ImagePath -ne $bin) { throw 'ImagePath was not written as expected.' }
        Invoke-Native $sc @('config', $PmcCfServiceName, 'obj=', $PmcCfServiceAccount, 'start=', 'auto')
        Invoke-Native $sc @('sidtype', $PmcCfServiceName, 'unrestricted')
        Invoke-Native $sc @('privs', $PmcCfServiceName, 'SeChangeNotifyPrivilege')
        Invoke-Native $sc @('failure', $PmcCfServiceName, 'reset=', '86400', 'actions=', 'restart/20000/restart/20000/restart/60000')
        Invoke-Native $sc @('failureflag', $PmcCfServiceName, '1')
    }

    # ACLs after the service exists (its SID resolves now). The token file keeps its own
    # explicit ACL; only the log folder is reset.
    Set-PmcAcl -Path $PmcCfDir -Grant @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "$($PmcCfServiceAccount):(OI)(CI)RX")
    Set-PmcAcl -Path $cfLogDir -Grant @("$($SidAdmins):(OI)(CI)RX", "$($SidSystem):(OI)(CI)F", "$($PmcCfServiceAccount):(OI)(CI)M", "$($SidOwnerRights):(OI)(CI)M") -ResetChildren
}  # end of install part

# ---- Token -----------------------------------------------------------------------------
if ($SetToken) {
    $token = Read-PmcSecret -Prompt 'Tunnel token'
    $json = $null
    $bytes = $null
    try {
        # A remote-managed tunnel token is base64 JSON {"a":account,"t":tunnel,"s":secret}.
        # Checked with operators and .NET calls only: no cmdlet sees the value, so module
        # logging (event 4103) cannot record it.
        if ($token -notmatch '^[A-Za-z0-9+/=_-]{40,4096}$') { throw 'The value is not a tunnel token (not base64).' }
        try {
            $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($token))
        } catch {
            throw 'The value is not a tunnel token (not base64).'
        }
        if ($json -notmatch '^\s*\{' -or $json -notmatch '"a"\s*:\s*"[0-9a-f]{32}"' -or $json -notmatch '"s"\s*:\s*"' -or
            $json -notmatch '"t"\s*:\s*"([0-9a-f-]{36})"') {
            throw 'The value is not a tunnel token (missing a/t/s).'
        }
        Write-Step "Token for tunnel $($Matches[1])"
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($token)
        Write-PmcFileAtomic -Path $tokenFile -Bytes $bytes -Grant @("$($SidAdmins):F", "$($SidSystem):F", "$($PmcCfServiceAccount):R")
    } finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        $token = $null
        $json = $null
    }
}

if ($Start) {
    if (-not (Test-Path -LiteralPath $tokenFile)) { throw "No token file. Run again with -SetToken." }
    if ($PSCmdlet.ShouldProcess($PmcCfServiceName, 'Restart service')) {
        Restart-Service -Name $PmcCfServiceName -Force
        Start-Sleep -Seconds 5
        try {
            $r = Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:20241/ready' -TimeoutSec 10
            Write-Step "cloudflared ready connections: $($r.readyConnections)"
        } catch {
            Write-Warning "cloudflared is not ready yet. Check $cfLogDir\cloudflared.log and the firewall (UDP/TCP 7844)."
        }
    }
}
Write-Step 'Done. Next: Set-BrokerFirewall.ps1'
