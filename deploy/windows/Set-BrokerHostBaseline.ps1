<#
.SYNOPSIS
Applies the scriptable part of the broker host baseline. Idempotent. Supports -WhatIf.

.DESCRIPTION
Applies:
  - Advanced audit policy: Process Creation, Logon, Logoff, Special Logon, Account Lockout,
    Credential Validation, Security Group Management, Audit Policy Change, File System.
  - Command line in process creation events (4688).
  - PowerShell script block logging.
  - SMBv1 off (server feature and protocol).
  - LSA protection (RunAsPPL = 2: enabled without UEFI lock; reboot needed).
  - Defender: real-time, behaviour, script scanning, cloud protection, PUA block,
    network protection on. Tamper protection is set from Defender for Endpoint / Intune.
  - Security event log size 1 GB.
Reports only (decide and apply through GPO / Intune / Azure Arc policy; see docs/RUNBOOK.md):
  BitLocker with TPM, Windows LAPS, Credential Guard, RDP restriction, WDAC/AppLocker.
Verify with: Test-ProxmoxMcpBroker.ps1 -Baseline
#>
[CmdletBinding(SupportsShouldProcess)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator

$auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
$subcats = [ordered]@{
    '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation'
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
    '{0CCE9216-69AE-11D9-BED3-505054503030}' = 'Logoff'
    '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'Special Logon'
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'Account Lockout'
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'Credential Validation'
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management'
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Audit Policy Change'
    '{0CCE921D-69AE-11D9-BED3-505054503030}' = 'File System'
}
foreach ($g in $subcats.Keys) {
    if ($PSCmdlet.ShouldProcess($subcats[$g], 'auditpol success+failure')) {
        Invoke-Native $auditpol @('/set', "/subcategory:$g", '/success:enable', '/failure:enable')
    }
}

function Set-RegDword {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Path, [string]$Name, [int]$Value)
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set DWORD $Value")) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    }
}
Set-RegDword 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
Set-RegDword 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
Set-RegDword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 2

if ($PSCmdlet.ShouldProcess('Security log', 'Max size 1 GB')) {
    Invoke-Native (Join-Path $env:SystemRoot 'System32\wevtutil.exe') @('sl', 'Security', '/ms:1073741824')
}

if ($PSCmdlet.ShouldProcess('SMBv1', 'Disable')) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -eq 'Enabled') { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
}

if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable protections')) {
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableScriptScanning $false `
        -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled -EnableNetworkProtection Enabled
    Update-MpSignature -ErrorAction SilentlyContinue
}

# ---- Report only ------------------------------------------------------------------------------
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
if (-not $bl -or $bl.ProtectionStatus -ne 'On') {
    Write-Warning (('BitLocker is not on for {0}. Required. Escrow the recovery password first, then: ' +
        'Enable-BitLocker -MountPoint {0} -EncryptionMethod XtsAes256 -TpmProtector') -f $env:SystemDrive)
}
if (-not ((Test-Path 'HKLM:\Software\Microsoft\Policies\LAPS') -or (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config'))) {
    Write-Warning 'No Windows LAPS policy. Required: manage the local Administrator password with Windows LAPS (GPO or Intune).'
}
Write-Step 'Baseline applied. Reboot for LSA protection, then run Test-ProxmoxMcpBroker.ps1 -Baseline.'
