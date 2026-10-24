<#
.SYNOPSIS
Adds, changes, removes or lists enrolled users in credentials\enrollment.json.

.DESCRIPTION
enrollment.json is the access list: the only place that grants a person access through
the MCP broker, and in which mode (ro | operator | rw). It is plain JSON (it holds no
secret), readable by the broker service SID and writable by Administrators only.
The broker validates it strictly and grants nobody when it is invalid. This script
validates the new file with the broker's own parser (proxmox_mcp.enrollment) BEFORE it
replaces the old one, so a typo can never lock everybody out or grant the wrong mode.

One person, one key: no two subjects may share a proxmox_userid or a token_credential.
This script refuses that, and so does the broker.

Token expiry (-TokenExpires YYYY-MM-DD): the date chosen at "pveum user token add --expire"
(setup-proxmox-access.sh prints it). proxmox-mcp-selfcheck warns 14 days before and fails
on the day. The script writes it as "token_expires" in enrollment.json when the installed
broker accepts that key. When the broker parser refuses the key, the date goes to
config\token-expiry.json instead (read by Export-AccessReview.ps1) and a warning says so.

Every change is logged by script block logging (event 4104) and is visible in the
quarterly access review (Export-AccessReview.ps1).

.EXAMPLE
.\Set-BrokerEnrollment.ps1 -Email <email> -Mode ro -ProxmoxUserId mcp-<short>@pve -TokenExpires 2027-01-31
.\Set-BrokerEnrollment.ps1 -Email <email> -Remove
.\Set-BrokerEnrollment.ps1 -List
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Set')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Set')]
    [Parameter(Mandatory, ParameterSetName = 'Remove')]
    [string]$Email,
    [Parameter(Mandatory, ParameterSetName = 'Set')][ValidateSet('ro', 'operator', 'rw')][string]$Mode,
    [Parameter(Mandatory, ParameterSetName = 'Set')][string]$ProxmoxUserId,
    # Name of the DPAPI credential file (without .dpapi) that holds this user's token.
    # Written to enrollment.json as token_credential. Default: pve-token-<short>.
    [Parameter(ParameterSetName = 'Set')][string]$TokenStore,
    [Parameter(ParameterSetName = 'Set')][ValidatePattern('^\d{4}-\d{2}-\d{2}$')][string]$TokenExpires,
    [Parameter(Mandatory, ParameterSetName = 'Remove')][switch]$Remove,
    [Parameter(Mandatory, ParameterSetName = 'List')][switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator

$path = Join-Path $PmcCredDir 'enrollment.json'
Assert-PmcNotReparsePoint -Path $path
$users = [ordered]@{}
$services = [ordered]@{}
if (Test-Path -LiteralPath $path) {
    $doc = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $u = Get-PmcProp $doc 'users'
    if ($u) { foreach ($p in $u.PSObject.Properties) { $users[$p.Name] = $p.Value } }
    $sv = Get-PmcProp $doc 'services'
    if ($sv) { foreach ($p in $sv.PSObject.Properties) { $services[$p.Name] = $p.Value } }
}
$expiry = [ordered]@{}
if (Test-Path -LiteralPath $PmcExpiryFile) {
    $e = Get-Content -LiteralPath $PmcExpiryFile -Raw | ConvertFrom-Json
    foreach ($p in $e.PSObject.Properties) { $expiry[$p.Name] = [string]$p.Value }
}

if ($List) {
    foreach ($k in $users.Keys) {
        $exp = Get-PmcProp $users[$k] 'token_expires'
        if (-not $exp -and $expiry.Contains($k)) { $exp = $expiry[$k] }
        [pscustomobject]@{ Email = $k; Mode = $users[$k].mode; ProxmoxUserId = $users[$k].proxmox_userid
            TokenCredential = $users[$k].token_credential; TokenExpires = $exp
            TokenStored = (Test-Path -LiteralPath (Join-Path $PmcCredDir ($users[$k].token_credential + '.dpapi'))) }
    }
    return
}

$Email = $Email.Trim().ToLowerInvariant()
if ($Email -cnotmatch '^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$') { throw "Invalid email '$Email'." }

if ($Remove) {
    if (-not $users.Contains($Email)) { Write-Step "$Email is not enrolled. Nothing to do."; return }
    $users.Remove($Email)
    if ($expiry.Contains($Email)) { $expiry.Remove($Email) }
} else {
    if ($ProxmoxUserId -cnotmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$') { throw "Invalid Proxmox user id '$ProxmoxUserId'." }
    if ($ProxmoxUserId -match '^root@') { throw 'root is refused.' }
    if ($ProxmoxUserId -match '@pam$') { throw '@pam (Linux) accounts are refused. Use a dedicated mcp-<short>@pve user (setup-proxmox-access.sh).' }
    if ($ProxmoxUserId -cnotmatch '^mcp-[a-z0-9-]+@pve$') {
        Write-Warning 'Proxmox user id does not follow mcp-<short>@pve (setup-proxmox-access.sh convention).'
    }
    if (-not $TokenStore) {
        $short = ($ProxmoxUserId -split '@')[0] -replace '^mcp-', ''
        $TokenStore = "pve-token-$short"
    }
    Assert-PmcName -Name $TokenStore
    if ($TokenStore.Length -gt 64) { throw 'TokenCredential is longer than 64 characters.' }
    # One person, one key.
    foreach ($section in @($users, $services)) {
        foreach ($k in @($section.Keys)) {
            if ($k -eq $Email) { continue }
            if ($section[$k].proxmox_userid -ieq $ProxmoxUserId) { throw "$ProxmoxUserId is already enrolled for $k. One person, one Proxmox user." }
            if ($section[$k].token_credential -eq $TokenStore) { throw "$TokenStore is already used by $k. One person, one token." }
        }
    }
    if ($TokenExpires) {
        $d = [datetime]::ParseExact($TokenExpires, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        if ($d -le (Get-Date).Date) { throw '-TokenExpires is not in the future. Issue a new token first.' }
        if ($d -gt (Get-Date).AddDays(366)) { throw '-TokenExpires is more than one year away; tokens must expire within 365 days.' }
    } else {
        Write-Warning 'No -TokenExpires: proxmox-mcp-selfcheck will warn until the expiry date is recorded.'
    }
    $entry = [ordered]@{ mode = $Mode; proxmox_userid = $ProxmoxUserId; token_credential = $TokenStore }
    if ($TokenExpires) { $entry.token_expires = $TokenExpires; $expiry[$Email] = $TokenExpires }
    $users[$Email] = $entry
    if (-not (Test-Path -LiteralPath (Join-Path $PmcCredDir "$TokenStore.dpapi"))) {
        Write-Warning "Credential $TokenStore.dpapi does not exist yet. Store it with Protect-BrokerCredential.ps1."
    }
}

function ConvertTo-EnrollmentJson {
    param([switch]$WithoutExpiry)
    $u2 = [ordered]@{}
    foreach ($k in $users.Keys) {
        $src = $users[$k]
        $o = [ordered]@{ mode = $src.mode; proxmox_userid = $src.proxmox_userid; token_credential = $src.token_credential }
        $te = Get-PmcProp $src 'token_expires'
        if ($te -and -not $WithoutExpiry) { $o.token_expires = [string]$te }
        $u2[$k] = $o
    }
    $out = [ordered]@{ users = $u2 }
    if ($services.Count -gt 0) { $out.services = $services }
    return ($out | ConvertTo-Json -Depth 5)
}

function Test-WithBrokerParser {
    # Exit 0 = the broker accepts the file. Uses the broker's own strict parser.
    param([Parameter(Mandatory)][string]$File)
    $vpy = $null
    try { $vpy = Get-PmcTool -Name python } catch { return $null }
    $code = 'import sys; from proxmox_mcp.enrollment import load_enrollments; m = load_enrollments(sys.argv[1]); sys.exit(0 if m or sys.argv[2] == ''0'' else 3)'
    $out = & $vpy -I -c $code $File "$($users.Count + $services.Count)" 2>&1 | Out-String
    return @{ Code = $LASTEXITCODE; Output = $out.Trim() }
}

if (-not $PSCmdlet.ShouldProcess($path, "Write enrollment ($($users.Count) users)")) { return }
$grant = @("$($SidAdmins):F", "$($SidSystem):F", "$($PmcServiceAccount):R")
$tmp = Join-Path $PmcCredDir ('.tmp-enrollment-' + [guid]::NewGuid().ToString('N') + '.json')
$utf8 = New-Object Text.UTF8Encoding($false)
try {
    [IO.File]::WriteAllText($tmp, (ConvertTo-EnrollmentJson), $utf8)
    Set-PmcAcl -Path $tmp -Grant $grant -Confirm:$false
    $r = Test-WithBrokerParser -File $tmp
    if ($null -eq $r) {
        throw 'Broker venv not found: cannot validate with the broker parser. Install the broker first.'
    }
    $sidecar = $false
    if ($r.Code -ne 0 -and $r.Output -match 'token_expires') {
        # The installed broker does not know token_expires yet: keep the date beside the file.
        [IO.File]::WriteAllText($tmp, (ConvertTo-EnrollmentJson -WithoutExpiry), $utf8)
        $r = Test-WithBrokerParser -File $tmp
        $sidecar = $true
    }
    if ($r.Code -ne 0) { throw "The broker parser refuses the new enrollment (nothing changed):`n$($r.Output)" }
    Move-Item -LiteralPath $tmp -Destination $path -Force
    if ($sidecar) {
        Write-Warning "The installed broker does not accept token_expires in enrollment.json. Expiry dates are kept in $PmcExpiryFile."
    }
    ($expiry | ConvertTo-Json) | Set-Content -LiteralPath $PmcExpiryFile -Encoding ASCII
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
}
Write-Step "Enrollment written ($($users.Count) users). Restart the broker to apply it: Restart-Service $PmcServiceName"
