<#
.SYNOPSIS
Quarterly access review evidence: who can use the Proxmox MCP, in which mode, with which
Proxmox rights, and who the Cloudflare Access policies admit. Read-only.

.DESCRIPTION
Writes a dated folder (default C:\ProgramData\ProxmoxMCP\evidence\access-review-<yyyy-MM-dd>):
  enrollment.json            copy of the broker access list
  enrollment.csv             email, mode, Proxmox user, token credential, token stored
  proxmox-access.json        ACLs, users (enabled, expiry, tokens), roles, pools (API, GET only)
  cloudflare-access.json     Access apps and policies for the Worker (and broker) hostname
  crosscheck.csv             one row per person across the three sources, with findings
  SHA256SUMS.txt             hash of every file above
The reviewer signs off by recording the folder hash in the ticket (docs/COMPLIANCE.md).

Inputs: broker.env (Proxmox host + TLS pin), credential "pve-review-token" (store with
Protect-BrokerCredential.ps1 -Name pve-review-token -Reader Administrators; create with
setup-proxmox-access.sh review-token), and a Cloudflare API token with
"Access: Apps and Policies Read" only, read from stdin or a hidden prompt.

.EXAMPLE
.\Export-AccessReview.ps1 -AccountId <account id> -WorkerHostname mcp.example.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$AccountId,
    [Parameter(Mandatory)][string]$WorkerHostname,
    [string]$BrokerHostname,
    [string]$OutputRoot = (Join-Path $env:ProgramData 'ProxmoxMCP\evidence'),
    [switch]$SkipCloudflare,
    [switch]$SkipProxmox
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$day = Get-Date -Format 'yyyy-MM-dd'
$dir = Join-Path $OutputRoot "access-review-$day"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Set-PmcAcl -Path $OutputRoot -Grant @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F")

# ---- 1. Enrollment -------------------------------------------------------------------------
$enrPath = Join-Path $PmcCredDir 'enrollment.json'
Copy-Item -LiteralPath $enrPath -Destination (Join-Path $dir 'enrollment.json')
$enr = Get-Content -LiteralPath $enrPath -Raw | ConvertFrom-Json
$rows = @()
foreach ($p in $enr.users.PSObject.Properties) {
    $rows += [pscustomobject]@{ email = $p.Name; mode = $p.Value.mode; proxmox_userid = $p.Value.proxmox_userid
        token_credential = $p.Value.token_credential
        token_stored = (Test-Path -LiteralPath (Join-Path $PmcCredDir ($p.Value.token_credential + '.dpapi'))) }
}
$rows | Export-Csv -NoTypeInformation -LiteralPath (Join-Path $dir 'enrollment.csv')

# ---- 2. Proxmox (read-only API, pinned TLS, from the broker interpreter) -----------------
$pve = $null
if (-not $SkipProxmox) {
    $envMap = Read-PmcEnvFile
    $vpy = Join-Path $PmcVenvDir 'Scripts\python.exe'
    $dump = Join-Path $PmcScriptsDir 'pve_access_dump.py'
    $saved = @{}
    foreach ($k in @('PROXMOX_HOST', 'PROXMOX_PORT', 'PROXMOX_TLS_FINGERPRINT', 'PROXMOX_CA_BUNDLE')) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        $v = ''
        if ($envMap.Contains($k)) { $v = $envMap[$k] }
        [Environment]::SetEnvironmentVariable($k, $v, 'Process')
    }
    [Environment]::SetEnvironmentVariable('BROKER_CREDENTIALS_DIR', $PmcCredDir, 'Process')
    [Environment]::SetEnvironmentVariable('BROKER_DPAPI_ENTROPY_FILE', $PmcEntropyFile, 'Process')
    try {
        $json = & $vpy -I $dump
        if ($LASTEXITCODE -ne 0) { throw "pve_access_dump.py failed with exit code $LASTEXITCODE" }
        $text = ($json -join "`n")
        Set-Content -LiteralPath (Join-Path $dir 'proxmox-access.json') -Value $text -Encoding UTF8
        $pve = $text | ConvertFrom-Json
    } finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
}

# ---- 3. Cloudflare Access (read-only token from stdin / prompt) --------------------------
$cfDoc = [ordered]@{ apps = @() }
if (-not $SkipCloudflare) {
    $tok = Read-PmcSecret -Prompt 'Cloudflare API token (Access: Apps and Policies Read)'
    try {
        $h = @{ Authorization = "Bearer $tok" }
        foreach ($hn in @($WorkerHostname, $BrokerHostname)) {
            if (-not $hn) { continue }
            $u = "https://api.cloudflare.com/client/v4/accounts/$AccountId/access/apps?domain=$([uri]::EscapeDataString($hn))"
            $apps = Invoke-RestMethod -UseBasicParsing -Uri $u -Headers $h -TimeoutSec 30
            foreach ($a in @($apps.result | Where-Object { $_.domain -eq $hn })) {
                $pu = "https://api.cloudflare.com/client/v4/accounts/$AccountId/access/apps/$($a.id)/policies"
                $pol = Invoke-RestMethod -UseBasicParsing -Uri $pu -Headers $h -TimeoutSec 30
                $cfDoc.apps += [ordered]@{ id = $a.id; name = (Get-PmcProp $a 'name'); domain = $a.domain
                    session_duration = (Get-PmcProp $a 'session_duration'); allowed_idps = (Get-PmcProp $a 'allowed_idps')
                    oauth_configuration = (Get-PmcProp $a 'oauth_configuration'); policies = @($pol.result) }
            }
        }
    } finally { $tok = $null; $h = $null }
    ($cfDoc | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath (Join-Path $dir 'cloudflare-access.json') -Encoding UTF8
}

# ---- 4. Cross-check ----------------------------------------------------------------------
$accessEmails = @{}
foreach ($a in $cfDoc.apps) {
    if ($a.domain -ne $WorkerHostname) { continue }
    foreach ($p in $a.policies) {
        if ((Get-PmcProp $p 'decision') -ne 'allow') { continue }
        foreach ($inc in @(Get-PmcProp $p 'include')) {
            $em = Get-PmcProp (Get-PmcProp $inc 'email') 'email'
            if ($em) { $accessEmails[$em.ToLowerInvariant()] = $true }
        }
    }
}
$pveUsers = @{}
if ($pve -and (Get-PmcProp $pve 'users')) { foreach ($u in @($pve.users)) { $pveUsers[$u.userid] = $u } }
$all = @{}
foreach ($r in $rows) { $all[$r.email] = $true }
foreach ($e in $accessEmails.Keys) { $all[$e] = $true }
$cross = @()
foreach ($e in ($all.Keys | Sort-Object)) {
    $r = $rows | Where-Object email -eq $e | Select-Object -First 1
    $findings = @()
    if (-not $r) { $findings += 'admitted by Access but not enrolled (no broker access)' }
    if (-not $SkipCloudflare -and -not $accessEmails.ContainsKey($e)) { $findings += 'enrolled but not in the Access policy (cannot sign in)' }
    $pu = $null
    if ($r) {
        if (-not $r.token_stored) { $findings += 'token credential missing on broker' }
        if ($pve) {
            $pu = $pveUsers[$r.proxmox_userid]
            if (-not $pu) { $findings += 'Proxmox user missing' }
            elseif ((Get-PmcProp $pu 'enable') -ne 1) { $findings += 'Proxmox user disabled' }
        }
    }
    $tokExp = ''
    if ($pu -and (Get-PmcProp $pu 'tokens')) {
        $tokExp = (@($pu.tokens) | ForEach-Object { "$($_.tokenid):$(Get-PmcProp $_ 'expire')" }) -join ' '
        foreach ($t in @($pu.tokens)) {
            $exp = Get-PmcProp $t 'expire'
            if ($null -eq $exp -or [int64]$exp -eq 0) { $findings += "token $($t.tokenid) never expires" }
            elseif ([DateTimeOffset]::FromUnixTimeSeconds([int64]$exp) -lt [DateTimeOffset]::UtcNow.AddDays(14)) { $findings += "token $($t.tokenid) expires within 14 days" }
        }
    }
    $mode = ''; $uid = ''
    if ($r) { $mode = $r.mode; $uid = $r.proxmox_userid }
    $cross += [pscustomobject]@{ email = $e; mode = $mode; proxmox_userid = $uid; in_access_policy = $accessEmails.ContainsKey($e)
        token_expiry = $tokExp; findings = ($findings -join '; ') }
}
$cross | Export-Csv -NoTypeInformation -LiteralPath (Join-Path $dir 'crosscheck.csv')

# ---- 5. Hashes ------------------------------------------------------------------------------
$sums = Get-ChildItem -LiteralPath $dir -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $_.Name
}
Set-Content -LiteralPath (Join-Path $dir 'SHA256SUMS.txt') -Value $sums -Encoding ASCII
$folderHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir 'SHA256SUMS.txt')).Hash.ToLowerInvariant()
Write-Step "Evidence: $dir"
Write-Step "Record this value in the review ticket: SHA256(SHA256SUMS.txt) = $folderHash"
$cross | Where-Object findings | Format-Table -AutoSize -Wrap
