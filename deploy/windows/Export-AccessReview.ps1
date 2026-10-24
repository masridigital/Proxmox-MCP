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
  selfcheck-live.json        proxmox-mcp-selfcheck --live: each token's effective privileges
                             checked against its mode (SOC 2 CC6.3 evidence)
  crosscheck.csv             one row per person across the three sources, with findings
  SHA256SUMS.txt             hash of every file above
The reviewer signs off by recording the folder hash in the ticket (docs/COMPLIANCE.md).

Inputs: broker.env (Proxmox host + TLS pin), credential "pve-review-token" (store with
Protect-BrokerCredential.ps1 -Name pve-review-token -Reader Administrators; create with
setup-proxmox-access.sh review-token), and a Cloudflare API token with
"Access: Apps and Policies Read" only, read from stdin or a hidden prompt.

.EXAMPLE
.\Export-AccessReview.ps1 -AccountId <account id> -WorkerHostname <worker-hostname>
#>
[CmdletBinding(SupportsShouldProcess)]
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
Initialize-PmcTlsProtocol
if ($WorkerHostname -cnotmatch '^[a-z0-9.-]{1,253}$') { throw '-WorkerHostname must be a lower-case host name.' }
if ($BrokerHostname -and $BrokerHostname -cnotmatch '^[a-z0-9.-]{1,253}$') { throw '-BrokerHostname must be a lower-case host name.' }

$day = Get-Date -Format 'yyyy-MM-dd'
$dir = Join-Path $OutputRoot "access-review-$day"
if (-not $PSCmdlet.ShouldProcess($dir, 'Write access review evidence')) { return }
New-PmcDirectory -Path $OutputRoot -Confirm:$false
Set-PmcAcl -Path $OutputRoot -Grant @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F") -Confirm:$false
New-PmcDirectory -Path $dir -Confirm:$false
if (@(Get-ChildItem -LiteralPath $dir -Force).Count -gt 0) { throw "$dir is not empty. Move the earlier export away first (evidence is never overwritten)." }

function Invoke-CfGet {
    # GET with the read-only Cloudflare token from $script:CfToken. .NET only: the token is
    # never bound to a cmdlet parameter, so module logging cannot record it.
    param([Parameter(Mandatory)][string]$Url)
    $req = [Net.HttpWebRequest]::Create($Url)
    $req.Method = 'GET'; $req.Timeout = 30000; $req.AllowAutoRedirect = $false
    $req.Headers.Add('Authorization', "Bearer $($script:CfToken)")
    $resp = $req.GetResponse()
    try { $body = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } finally { $resp.Dispose() }
    $doc = $body | ConvertFrom-Json
    if (-not $doc.success) { throw "Cloudflare API call failed: $Url" }
    return $doc
}

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
    $vpy = Get-PmcTool -Name python
    $dump = Join-Path $PmcScriptsDir 'pve_access_dump.py'
    $saved = @{}
    foreach ($k in @('PROXMOX_HOST', 'PROXMOX_PORT', 'PROXMOX_TLS_FINGERPRINT', 'PROXMOX_CA_BUNDLE')) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        $v = $null
        if ($envMap.Contains($k)) { $v = $envMap[$k] }
        [Environment]::SetEnvironmentVariable($k, $v, 'Process')
    }
    foreach ($k in @('BROKER_CREDENTIALS_DIR', 'BROKER_DPAPI_ENTROPY_FILE')) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
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
    $script:CfToken = Read-PmcSecret -Prompt 'Cloudflare API token (Access: Apps and Policies Read)'
    try {
        foreach ($hn in @($WorkerHostname, $BrokerHostname)) {
            if (-not $hn) { continue }
            $apps = Invoke-CfGet -Url "https://api.cloudflare.com/client/v4/accounts/$AccountId/access/apps?domain=$([uri]::EscapeDataString($hn))"
            foreach ($a in @($apps.result | Where-Object { $_.domain -eq $hn })) {
                $pol = Invoke-CfGet -Url "https://api.cloudflare.com/client/v4/accounts/$AccountId/access/apps/$($a.id)/policies"
                $cfDoc.apps += [ordered]@{ id = $a.id; name = (Get-PmcProp $a 'name'); domain = $a.domain
                    session_duration = (Get-PmcProp $a 'session_duration'); allowed_idps = (Get-PmcProp $a 'allowed_idps')
                    oauth_configuration = (Get-PmcProp $a 'oauth_configuration'); policies = @($pol.result) }
            }
        }
    } finally { $script:CfToken = $null }
    ($cfDoc | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath (Join-Path $dir 'cloudflare-access.json') -Encoding UTF8
}

# ---- 3b. Least privilege, measured: proxmox-mcp-selfcheck --live ----------------------------
$live = $null
if (-not $SkipProxmox) {
    $sc = Invoke-PmcBrokerTool -Tool 'proxmox-mcp-selfcheck' -ArgumentList @('--live')
    Set-Content -LiteralPath (Join-Path $dir 'selfcheck-live.json') -Value $sc.Output -Encoding UTF8
    try { $live = $sc.Output | ConvertFrom-Json } catch { Write-Warning 'selfcheck output is not JSON.' }
    if ($sc.Code -ge 2) { Write-Warning "proxmox-mcp-selfcheck --live exit $($sc.Code): see selfcheck-live.json." }
}
$expiryMap = @{}
if (Test-Path -LiteralPath $PmcExpiryFile) {
    $ej = Get-Content -LiteralPath $PmcExpiryFile -Raw | ConvertFrom-Json
    foreach ($p in $ej.PSObject.Properties) { $expiryMap[$p.Name] = [string]$p.Value }
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
    if ($r -and $live) {
        foreach ($c in @($live.checks | Where-Object { $_.id -eq "live:$e" -or $_.id -eq "token:$e" -or $_.id -eq "token_expiry:$e" })) {
            if ($c.status -in @('fail', 'warn')) { $findings += "selfcheck $($c.id): $($c.message)" }
        }
    }
    $recorded = ''
    if ($r) {
        $enrEntry = Get-PmcProp $enr.users $e
        $recorded = [string](Get-PmcProp $enrEntry 'token_expires')
        if (-not $recorded -and $expiryMap.ContainsKey($e)) { $recorded = $expiryMap[$e] }
        if (-not $recorded) { $findings += 'token expiry not recorded (Set-BrokerEnrollment.ps1 -TokenExpires)' }
    }
    $mode = ''; $uid = ''
    if ($r) { $mode = $r.mode; $uid = $r.proxmox_userid }
    $cross += [pscustomobject]@{ email = $e; mode = $mode; proxmox_userid = $uid; in_access_policy = $accessEmails.ContainsKey($e)
        token_expiry = $tokExp; token_expires_recorded = $recorded; findings = ($findings -join '; ') }
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
