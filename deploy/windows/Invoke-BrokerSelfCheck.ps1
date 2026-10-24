<#
.SYNOPSIS
Runs proxmox-mcp-selfcheck with the service configuration, stores the JSON report as
evidence and writes an event. -Register schedules it (SOC 2 CC6.3 continuous evidence).

.DESCRIPTION
proxmox-mcp-selfcheck checks the configuration, the credential store, every enrolled token
(readable, matches its Proxmox user, not root@pam, not shared, expiry) and the Worker public
key. With -Live it also asks Proxmox, over the pinned TLS, which privileges each token
really holds, and fails on any privilege outside the user's mode. That turns least
privilege from a setup step into a measured, recurring control.

Report:  C:\ProgramData\ProxmoxMCP\evidence\selfcheck\selfcheck-<live|offline>-<UTC time>.json
         (Send-AuditLog.ps1 uploads it once to the WORM container)
Events:  Application log, source ProxmoxMCP-SelfCheck:
         4201 pass, 4202 warnings, 4203 failures, 4204 selfcheck crashed or could not run.
Exit:    the selfcheck exit code: 0 pass, 1 warnings, 2 failures, 3 crash.

-Register creates two scheduled tasks, both as SYSTEM:
  \ProxmoxMCP\SelfCheck Live      daily 06:10, with --live (evidence file every day)
  \ProxmoxMCP\SelfCheck Offline   hourly, offline checks (evidence file only when not pass)

.EXAMPLE
.\Invoke-BrokerSelfCheck.ps1 -Live
.\Invoke-BrokerSelfCheck.ps1 -Register -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')][switch]$Live,
    # Write the evidence file only when the result is not "pass" (hourly task).
    [Parameter(ParameterSetName = 'Run')][switch]$EvidenceOnProblem,
    [Parameter(Mandatory, ParameterSetName = 'Register')][switch]$Register
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator

$source = 'ProxmoxMCP-SelfCheck'
$outDir = Join-Path $PmcEvidenceDir 'selfcheck'

if ($Register) {
    if (-not [Diagnostics.EventLog]::SourceExists($source) -and $PSCmdlet.ShouldProcess($source, 'Create event source')) {
        [Diagnostics.EventLog]::CreateEventSource($source, 'Application')
    }
    $script = Join-Path $PmcScriptsDir 'Invoke-BrokerSelfCheck.ps1'
    if (-not (Test-Path -LiteralPath $script)) { throw "$script not found. Run Install-ProxmoxMcpBroker.ps1 first (it copies the scripts)." }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -StartWhenAvailable
    $tasks = @(
        @('SelfCheck Live', ('-NoProfile -NonInteractive -File "{0}" -Live' -f $script), (New-ScheduledTaskTrigger -Daily -At '06:10')),
        @('SelfCheck Offline', ('-NoProfile -NonInteractive -File "{0}" -EvidenceOnProblem' -f $script),
            (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours 1)))
    )
    foreach ($t in $tasks) {
        if ($PSCmdlet.ShouldProcess("\ProxmoxMCP\$($t[0])", 'Register scheduled task (SYSTEM)')) {
            $action = New-ScheduledTaskAction -Execute $ps -Argument $t[1]
            Register-ScheduledTask -TaskName $t[0] -TaskPath '\ProxmoxMCP\' -Action $action -Trigger $t[2] `
                -Principal $principal -Settings $settings -Force | Out-Null
        }
    }
    Write-Step 'Registered. Alert on events 4203 and 4204 (source ProxmoxMCP-SelfCheck) in the SIEM.'
    return
}

function Write-SelfCheckEvent {
    param([int]$Id, [string]$Message, [Diagnostics.EventLogEntryType]$Type)
    try {
        if ([Diagnostics.EventLog]::SourceExists($source)) { [Diagnostics.EventLog]::WriteEntry($source, $Message, $Type, $Id) }
    } catch { Write-Verbose "Event log write failed: $($_.Exception.Message)" }
}

$args4 = @()
if ($Live) { $args4 += '--live' }
try {
    $r = Invoke-PmcBrokerTool -Tool 'proxmox-mcp-selfcheck' -ArgumentList $args4
} catch {
    Write-SelfCheckEvent 4204 "proxmox-mcp-selfcheck could not run: $($_.Exception.Message)" 'Error'
    throw
}
$doc = $null
try { $doc = $r.Output | ConvertFrom-Json } catch { $doc = $null }
$status = 'crash'
if ($doc) { $status = [string]$doc.status }
$kind = 'offline'
if ($Live) { $kind = 'live' }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$file = Join-Path $outDir "selfcheck-$kind-$stamp.json"
if ((-not $EvidenceOnProblem -or $status -ne 'pass') -and $PSCmdlet.ShouldProcess($file, 'Write evidence')) {
    New-PmcDirectory -Path $outDir -Confirm:$false
    Set-Content -LiteralPath $file -Value $r.Output -Encoding UTF8
}
$summary = "selfcheck $kind exit $($r.Code) status $status"
if ($doc) {
    $bad = @($doc.checks | Where-Object { $_.status -in @('fail', 'warn') } | ForEach-Object { "$($_.status) $($_.id): $($_.message)" })
    if ($bad.Count -gt 0) { $summary += "`n" + ($bad -join "`n") }
}
switch ($r.Code) {
    0 { Write-SelfCheckEvent 4201 $summary 'Information' }
    1 { Write-SelfCheckEvent 4202 $summary 'Warning' }
    2 { Write-SelfCheckEvent 4203 $summary 'Error' }
    default { Write-SelfCheckEvent 4204 $summary 'Error' }
}
Write-Output $summary
exit $r.Code
