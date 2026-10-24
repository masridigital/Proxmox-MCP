<#
.SYNOPSIS
Adds, changes, removes or lists enrolled users in credentials\enrollment.json.

.DESCRIPTION
enrollment.json is the access list: the only place that grants a person access through
the MCP broker, and in which mode (ro | operator | rw). It is plain JSON (it holds no
secret), readable by the broker service SID and writable by Administrators only.
The broker validates it strictly and grants nobody when it is invalid; this script
validates the new file with the broker's own parser before it replaces the old one.

Every change is logged to the PowerShell operational log by script block logging, and
Export-AccessReview.ps1 records the current list for the quarterly review.

.EXAMPLE
.\Set-BrokerEnrollment.ps1 -Email alice@example.com -Mode ro -ProxmoxUserId mcp-alice@pve
.\Set-BrokerEnrollment.ps1 -Email alice@example.com -Remove
.\Set-BrokerEnrollment.ps1 -List
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Set')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Set')]
    [Parameter(Mandatory, ParameterSetName = 'Remove')]
    [string]$Email,
    [Parameter(Mandatory, ParameterSetName = 'Set')][ValidateSet('ro', 'operator', 'rw')][string]$Mode,
    [Parameter(Mandatory, ParameterSetName = 'Set')][string]$ProxmoxUserId,
    # Name of the DPAPI credential with this user's token. Default: pve-token-<name part of ProxmoxUserId without "mcp-">.
    [Parameter(ParameterSetName = 'Set')][string]$TokenCredential,
    [Parameter(Mandatory, ParameterSetName = 'Remove')][switch]$Remove,
    [Parameter(Mandatory, ParameterSetName = 'List')][switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator

$path = Join-Path $PmcCredDir 'enrollment.json'
$users = [ordered]@{}
$services = [ordered]@{}
if (Test-Path -LiteralPath $path) {
    $doc = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($doc.PSObject.Properties.Name -contains 'users') {
        foreach ($p in $doc.users.PSObject.Properties) { $users[$p.Name] = $p.Value }
    }
    if ($doc.PSObject.Properties.Name -contains 'services') {
        foreach ($p in $doc.services.PSObject.Properties) { $services[$p.Name] = $p.Value }
    }
}

if ($List) {
    foreach ($k in $users.Keys) {
        [pscustomobject]@{ Email = $k; Mode = $users[$k].mode; ProxmoxUserId = $users[$k].proxmox_userid
            TokenCredential = $users[$k].token_credential
            TokenStored = (Test-Path -LiteralPath (Join-Path $PmcCredDir ($users[$k].token_credential + '.dpapi'))) }
    }
    return
}

$Email = $Email.Trim().ToLowerInvariant()
if ($Email -notmatch '^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$') { throw "Invalid email '$Email'." }

if ($Remove) {
    if (-not $users.Contains($Email)) { Write-Step "$Email is not enrolled. Nothing to do."; return }
    $users.Remove($Email)
} else {
    if ($ProxmoxUserId -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$') { throw "Invalid Proxmox user id '$ProxmoxUserId'." }
    if ($ProxmoxUserId -match '^root@') { throw 'root is refused.' }
    if ($ProxmoxUserId -notmatch '^mcp-[a-z0-9-]+@pve$') {
        Write-Warning 'Proxmox user id does not follow mcp-<short>@pve (setup-proxmox-access.sh convention).'
    }
    if (-not $TokenCredential) {
        $short = ($ProxmoxUserId -split '@')[0] -replace '^mcp-', ''
        $TokenCredential = "pve-token-$short"
    }
    Assert-PmcName -Name $TokenCredential
    if ($TokenCredential.Length -gt 64) { throw 'TokenCredential is longer than 64 characters.' }
    $users[$Email] = [ordered]@{ mode = $Mode; proxmox_userid = $ProxmoxUserId; token_credential = $TokenCredential }
    if (-not (Test-Path -LiteralPath (Join-Path $PmcCredDir "$TokenCredential.dpapi"))) {
        Write-Warning "Credential $TokenCredential.dpapi does not exist yet. Store it with Protect-BrokerCredential.ps1."
    }
}

$out = [ordered]@{ users = $users }
if ($services.Count -gt 0) { $out.services = $services }
$json = $out | ConvertTo-Json -Depth 5

if (-not $PSCmdlet.ShouldProcess($path, "Write enrollment ($($users.Count) users)")) { return }
$tmp = Join-Path $PmcCredDir ('.tmp-enrollment-' + [guid]::NewGuid().ToString('N') + '.json')
[IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
try {
    Set-PmcAcl -Path $tmp -Grant @("$($SidAdmins):F", "$($SidSystem):F", "$($PmcServiceAccount):R")
    $vpy = Join-Path $PmcVenvDir 'Scripts\python.exe'
    if (Test-Path -LiteralPath $vpy) {
        # Validate with the broker's own strict parser. Fails on any error.
        Invoke-Native $vpy @('-I', '-c', 'import sys; from proxmox_mcp.enrollment import load_enrollments; m = load_enrollments(sys.argv[1]); sys.exit(0 if m or sys.argv[2] == "0" else 3)', $tmp, "$($users.Count)")
    } else {
        Write-Warning 'Broker venv not found; enrollment not validated by the broker parser.'
    }
    Move-Item -LiteralPath $tmp -Destination $path -Force
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
}
Write-Step "Enrollment written ($($users.Count) users). Restart the broker to apply it: Restart-Service ProxmoxMCPBroker"
