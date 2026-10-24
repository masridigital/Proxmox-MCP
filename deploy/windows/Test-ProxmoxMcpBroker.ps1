<#
.SYNOPSIS
Post-install and periodic checks for the Windows broker. Exit code 0 = all PASS.

.DESCRIPTION
Checks: services, accounts and privileges; binary integrity (Authenticode, WinSW hash);
loopback-only listeners; firewall rules and logging; /healthz; cloudflared readiness; tunnel
token not in argv; file system ACLs (credentials, logs, program files); proxmox-mcp-selfcheck
(offline, or --live with -Live); audit hash chain; and (with -Baseline) the host hardening baseline: BitLocker with TPM,
Defender, LSA protection, Credential Guard, SMBv1 off, RDP NLA, Windows LAPS, audit policy.
Read-only: it changes nothing. Output is a table you can attach as audit evidence:
  .\Test-ProxmoxMcpBroker.ps1 -Baseline | Tee-Object -FilePath evidence\broker-test.txt
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Live', Justification = 'Used inside the Test-Step script block.')]
[CmdletBinding()]
param(
    [switch]$Baseline,
    # Also run proxmox-mcp-selfcheck --live (asks Proxmox what each token may do).
    [switch]$Live,
    # Skip the audit chain check (large files) when you only need a quick health view.
    [switch]$SkipAuditVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator

$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Check, [ValidateSet('PASS', 'FAIL', 'WARN')][string]$Status, [string]$Detail = '')
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
}
function Test-Step {
    param([string]$Check, [scriptblock]$Body)
    try { & $Body } catch { Add-Result $Check 'FAIL' $_.Exception.Message }
}

$envMap = Read-PmcEnvFile
$port = 8765
if ($envMap.Contains('MCP_PORT')) { $port = [int]$envMap['MCP_PORT'] }

# ---- Services --------------------------------------------------------------------------
foreach ($pair in @(@($PmcServiceName, $PmcServiceAccount), @($PmcCfServiceName, $PmcCfServiceAccount))) {
    $name = $pair[0]; $acct = $pair[1]
    Test-Step "service $name" {
        $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
        if (-not $s) { throw 'not installed' }
        if ($s.State -ne 'Running') { throw "state $($s.State), exit code $($s.ExitCode)" }
        if ($s.StartName -ne $acct) { throw "runs as '$($s.StartName)', expected '$acct'" }
        Add-Result "service $name" 'PASS' "running as $acct, start $($s.StartMode)"
    }
    Test-Step "privileges $name" {
        $q = (& (Join-Path $env:SystemRoot 'System32\sc.exe') qprivs $name 2>&1 | Out-String)
        $privs = @([regex]::Matches($q, 'Se[A-Za-z]+Privilege') | ForEach-Object Value | Sort-Object -Unique)
        if ($privs.Count -ne 1 -or $privs[0] -ne 'SeChangeNotifyPrivilege') { throw "required privileges: $($privs -join ', ')" }
        Add-Result "privileges $name" 'PASS' 'SeChangeNotifyPrivilege only'
    }
}

# Surface a startup failure (exit code 2 = configuration error: missing CF_ACCESS_* in
# access mode, missing BROKER_ALLOWED_SERVICE_CLIENT_IDS, worker-identity.pub missing or
# not Ed25519).
$svcState = Get-CimInstance -ClassName Win32_Service -Filter "Name='$PmcServiceName'"
if ($svcState -and $svcState.State -ne 'Running') {
    $err = Join-Path $PmcLogDir "service\$PmcServiceName.err.log"
    $tail = ''
    if (Test-Path -LiteralPath $err) { $tail = (Get-Content -LiteralPath $err -Tail 15) -join ' | ' }
    Add-Result 'broker startup log' 'FAIL' ("exit code 2 means a configuration error. Last lines: " + $tail)
}

# ---- Listeners -------------------------------------------------------------------------
Test-Step 'listeners' {
    $all = @(Get-CimInstance Win32_Process)
    function Get-Tree([int]$root) {
        $ids = @($root)
        foreach ($c in @($all | Where-Object { $_.ParentProcessId -eq $root })) { $ids += Get-Tree ([int]$c.ProcessId) }
        return $ids
    }
    $brokerPids = @()
    if ($svcState -and $svcState.ProcessId) { $brokerPids = Get-Tree ([int]$svcState.ProcessId) }
    $cfSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$PmcCfServiceName'"
    $cfPids = @()
    if ($cfSvc -and $cfSvc.ProcessId) { $cfPids = @([int]$cfSvc.ProcessId) }
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
    $mine = @($listen | Where-Object { ($brokerPids + $cfPids) -contains [int]$_.OwningProcess })
    $badBind = @($mine | Where-Object { $_.LocalAddress -ne '127.0.0.1' })
    if ($badBind.Count -gt 0) { throw ('non-loopback listener: ' + (($badBind | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ', ')) }
    $brokerListen = @($mine | Where-Object { $brokerPids -contains [int]$_.OwningProcess })
    if (@($brokerListen | Where-Object { $_.LocalPort -eq $port }).Count -ne 1) { throw "broker is not listening on 127.0.0.1:$port" }
    $other = @($listen | Where-Object { $_.LocalPort -eq $port -and $_.LocalAddress -ne '127.0.0.1' })
    if ($other.Count -gt 0) { throw "another process listens on port $port on a non-loopback address" }
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $brokerPids -contains [int]$_.OwningProcess })
    if ($udp.Count -gt 0) { throw 'the broker has UDP endpoints' }
    Add-Result 'listeners' 'PASS' ("broker 127.0.0.1:$port; " + (($mine | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ', '))
}

# ---- Firewall --------------------------------------------------------------------------
Test-Step 'firewall rules' {
    $rules = @(Get-NetFirewallRule -Group 'ProxmoxMCP' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
    if ($rules.Count -lt 9) { throw "only $($rules.Count) enabled rules in group ProxmoxMCP (expected 9 or more). Run Set-BrokerFirewall.ps1." }
    $inAllow = @($rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' })
    if ($inAllow.Count -gt 0) { throw 'an inbound allow rule exists in group ProxmoxMCP' }
    $portAllow = @(Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -contains "$port" } |
            Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' })
    if ($portAllow.Count -gt 0) { throw "inbound allow rule for port $port exists" }
    Add-Result 'firewall rules' 'PASS' "$($rules.Count) rules"
}
Test-Step 'firewall profiles' {
    $bad = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' -or $_.LogBlocked -ne 'True' -or $_.DefaultInboundAction -ne 'Block' })
    if ($bad.Count -gt 0) { throw ('profile not compliant: ' + (($bad | ForEach-Object Name) -join ', ')) }
    Add-Result 'firewall profiles' 'PASS' 'enabled, inbound block, dropped packets logged'
}

# ---- Health ----------------------------------------------------------------------------
Test-Step 'healthz' {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/healthz" -TimeoutSec 5
    if ($r.StatusCode -ne 200) { throw "status $($r.StatusCode)" }
    Add-Result 'healthz' 'PASS' '200'
}
Test-Step 'cloudflared ready' {
    $r = Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:20241/ready' -TimeoutSec 5
    if ([int]$r.readyConnections -lt 1) { throw 'no ready edge connections' }
    Add-Result 'cloudflared ready' 'PASS' "$($r.readyConnections) edge connections"
}
Test-Step 'tunnel token not in argv or environment' {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$PmcCfServiceName"
    $img = (Get-ItemProperty -LiteralPath $key).ImagePath
    if ($img -match '--token(\s|=)' -or $img -match 'ey[A-Za-z0-9_-]{40,}') { throw 'ImagePath contains a token' }
    if ($img -notmatch '--token-file') { throw 'ImagePath has no --token-file' }
    $envv = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object Name -eq 'Environment'
    if ($envv -and (($envv.Value -join ' ') -match 'TUNNEL_TOKEN')) { throw 'service Environment sets TUNNEL_TOKEN' }
    Add-Result 'tunnel token not in argv or environment' 'PASS' ''
}

# ---- Credentials -----------------------------------------------------------------------
Test-Step 'credential ACLs' {
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-2')  # Everyone, Auth Users, Users, Interactive, Network
    $paths = @($PmcCredDir, $PmcCfDir) + @(Get-ChildItem -LiteralPath $PmcCredDir -File | ForEach-Object FullName)
    $tok = Join-Path $PmcCfDir 'tunnel-token'
    if (Test-Path -LiteralPath $tok) { $paths += $tok }
    foreach ($p in $paths) {
        foreach ($ace in (Get-Acl -LiteralPath $p).Access) {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($broad -contains $sid) { throw "$p grants $($ace.IdentityReference)" }
        }
    }
    foreach ($n in @('enrollment.json', 'dpapi-entropy.bin')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PmcCredDir $n))) { throw "$n missing" }
    }
    $pub = Join-Path $PmcCredDir 'worker-identity.pub'
    if (-not ((Test-Path -LiteralPath $pub) -or (Test-Path -LiteralPath "$pub.dpapi"))) { throw 'worker-identity.pub missing' }
    $plainTokens = @(Get-ChildItem -LiteralPath $PmcCredDir -File -Filter 'pve-token-*' | Where-Object { $_.Name -notlike '*.dpapi' })
    if ($plainTokens.Count -gt 0) { throw ('plaintext token files: ' + (($plainTokens | ForEach-Object Name) -join ', ')) }
    Add-Result 'credential ACLs' 'PASS' 'no broad ACEs, tokens DPAPI-protected'
}

# ---- Binary integrity ---------------------------------------------------------------------
Test-Step 'binary integrity' {
    Assert-AuthenticodeSigner -Path $PmcPythonExe -SignerCommonName 'Python Software Foundation'
    $cfImg = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$PmcCfServiceName").ImagePath
    if ($cfImg -notmatch '^"([^"]+)"') { throw 'cloudflared ImagePath is not a quoted path' }
    Assert-AuthenticodeSigner -Path $Matches[1] -SignerCommonName 'Cloudflare, Inc.'
    $winsw = Join-Path $PmcServiceDir "$PmcServiceName.exe"
    $img = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$PmcServiceName").ImagePath.Trim('"')
    if ($img -ne $winsw) { throw "broker ImagePath is '$img', expected $winsw" }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $winsw).Hash.ToLowerInvariant()
    Add-Result 'binary integrity' 'PASS' "python and cloudflared signed; WinSW sha256 $h (compare with the release record)"
}

# ---- File system ACLs -------------------------------------------------------------------------
Test-Step 'program and log ACLs' {
    $writeRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership, Write'
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')
    $svcSid = (New-Object Security.Principal.NTAccount($PmcServiceAccount)).Translate([Security.Principal.SecurityIdentifier]).Value
    foreach ($p in @($PmcProgramDir, $PmcPythonDir, $PmcServiceDir, $PmcScriptsDir, (Get-PmcVenvDir), $PmcConfigDir)) {
        foreach ($ace in (Get-Acl -LiteralPath $p).Access) {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($ace.AccessControlType -eq 'Allow' -and ($ace.FileSystemRights -band $writeRights) -and $trusted -notcontains $sid) {
                throw "$p grants write to $($ace.IdentityReference)"
            }
        }
    }
    foreach ($ace in (Get-Acl -LiteralPath $PmcLogDir).Access) {
        $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $del = [Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
        if ($sid -eq $svcSid -and ($ace.FileSystemRights -band $del)) { throw 'the broker service can delete or re-permission audit logs' }
    }
    Add-Result 'program and log ACLs' 'PASS' 'no write for non-admins on code and config; service cannot delete audit logs'
}

# ---- Selfcheck (the broker's own view of its secrets and least privilege) ----------------------
Test-Step 'proxmox-mcp-selfcheck' {
    $args3 = @()
    if ($Live) { $args3 += '--live' }
    $r = Invoke-PmcBrokerTool -Tool 'proxmox-mcp-selfcheck' -ArgumentList $args3
    $doc = $null
    try { $doc = $r.Output | ConvertFrom-Json } catch { throw "selfcheck exit $($r.Code), output is not JSON" }
    # Run as an administrator here: the audit_path check reflects this account, not the
    # service. The ACL test above covers the service's write access.
    $bad = @($doc.checks | Where-Object { $_.status -eq 'fail' -and $_.id -ne 'audit_path' })
    $warn = @($doc.checks | Where-Object { $_.status -eq 'warn' })
    if ($r.Code -eq 3) { throw 'selfcheck crashed (exit 3)' }
    if ($bad.Count -gt 0) { throw ('selfcheck FAIL: ' + (($bad | ForEach-Object { "$($_.id): $($_.message)" }) -join '; ')) }
    if ($warn.Count -gt 0) { Add-Result 'proxmox-mcp-selfcheck' 'WARN' (($warn | ForEach-Object { "$($_.id): $($_.message)" }) -join '; '); return }
    Add-Result 'proxmox-mcp-selfcheck' 'PASS' ("{0} checks pass (live: {1})" -f @($doc.checks).Count, [bool]$Live)
}

# ---- Audit chain -----------------------------------------------------------------------
if (-not $SkipAuditVerify) {
    Test-Step 'audit chain' {
        if (-not (Test-Path -LiteralPath $PmcAuditLog) -and @(Get-ChildItem -LiteralPath $PmcLogDir -File -Filter 'audit-*.jsonl').Count -eq 0) {
            Add-Result 'audit chain' 'WARN' 'no audit file yet'; return
        }
        $r = Invoke-PmcBrokerTool -Tool 'proxmox-mcp-audit-verify' -ArgumentList @('--dir', $PmcLogDir, '--require-mac')
        $out = $r.Output
        if ($r.Code -ne 0) { throw "verify exit $($r.Code): $($out.Trim())" }
        Add-Result 'audit chain' 'PASS' ($out.Trim() -replace '\s+', ' ')
    }
}

# ---- Host baseline ---------------------------------------------------------------------
if ($Baseline) {
    Test-Step 'BitLocker (TPM) on system drive' {
        $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
        $tpm = @($v.KeyProtector | Where-Object { $_.KeyProtectorType -match 'Tpm' })
        if ($v.ProtectionStatus -ne 'On' -or $tpm.Count -eq 0) { throw "protection $($v.ProtectionStatus), TPM protectors $($tpm.Count)" }
        Add-Result 'BitLocker (TPM) on system drive' 'PASS' "$($v.EncryptionMethod)"
    }
    Test-Step 'BitLocker on data drive' {
        $d = Split-Path -Qualifier $env:ProgramData
        if ($d -ne $env:SystemDrive) {
            $v = Get-BitLockerVolume -MountPoint $d
            if ($v.ProtectionStatus -ne 'On') { throw "$d protection $($v.ProtectionStatus)" }
        }
        Add-Result 'BitLocker on data drive' 'PASS' ''
    }
    Test-Step 'Defender' {
        $m = Get-MpComputerStatus
        if (-not ($m.AntivirusEnabled -and $m.RealTimeProtectionEnabled -and $m.IsTamperProtected)) {
            throw "AV $($m.AntivirusEnabled), realtime $($m.RealTimeProtectionEnabled), tamper $($m.IsTamperProtected)"
        }
        if ($m.AntivirusSignatureAge -gt 2) { throw "signatures are $($m.AntivirusSignatureAge) days old" }
        Add-Result 'Defender' 'PASS' "signature age $($m.AntivirusSignatureAge) d"
    }
    Test-Step 'LSA protection' {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object Name -eq 'RunAsPPL'
        if (-not $v -or @(1, 2) -notcontains [int]$v.Value) { throw 'RunAsPPL is not 1 or 2' }
        Add-Result 'LSA protection' 'PASS' "RunAsPPL=$($v.Value)"
    }
    Test-Step 'Credential Guard' {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
        if (@($dg.SecurityServicesRunning) -notcontains 1) { throw 'Credential Guard is not running' }
        Add-Result 'Credential Guard' 'PASS' ''
    }
    Test-Step 'SMBv1 off' {
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { throw 'SMB1 server is enabled' }
        Add-Result 'SMBv1 off' 'PASS' ''
    }
    Test-Step 'RDP' {
        $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if ((Get-PmcProp $ts 'fDenyTSConnections') -eq 0) {
            $nla = Get-PmcProp (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp') 'UserAuthentication'
            if ($nla -ne 1) { throw 'RDP on without NLA' }
            Add-Result 'RDP' 'WARN' 'RDP enabled with NLA: allow it only from the management network, never from the internet'
        } else { Add-Result 'RDP' 'PASS' 'disabled' }
    }
    Test-Step 'Windows LAPS' {
        $p = 'HKLM:\Software\Microsoft\Policies\LAPS'
        $p2 = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config'
        if (-not ((Test-Path $p) -or (Test-Path $p2))) { throw 'no Windows LAPS policy found' }
        Add-Result 'Windows LAPS' 'PASS' 'policy present'
    }
    Test-Step 'audit policy' {
        $need = @('{0CCE922B-69AE-11D9-BED3-505054503030}', '{0CCE9215-69AE-11D9-BED3-505054503030}', '{0CCE9217-69AE-11D9-BED3-505054503030}')
        # Process Creation, Logon, Account Lockout
        foreach ($g in $need) {
            $o = & (Join-Path $env:SystemRoot 'System32\auditpol.exe') /get "/subcategory:$g" /r | ConvertFrom-Csv
            if ($o.'Inclusion Setting' -notmatch 'Success') { throw "$($o.Subcategory): $($o.'Inclusion Setting')" }
        }
        $cl = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue)
        if ((Get-PmcProp $cl 'ProcessCreationIncludeCmdLine_Enabled') -ne 1) { throw 'command line in process creation events is off' }
        Add-Result 'audit policy' 'PASS' 'process creation (+cmdline), logon, lockout'
    }
    Test-Step 'PowerShell logging' {
        $sb = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
        if ((Get-PmcProp $sb 'EnableScriptBlockLogging') -ne 1) { throw 'script block logging is off' }
        Add-Result 'PowerShell logging' 'PASS' 'script block logging on'
    }
}

$results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Output
$fails = @($results | Where-Object Status -eq 'FAIL').Count
if ($fails -gt 0) { Write-Output "$fails check(s) FAILED"; exit 1 }
Write-Output 'All checks passed.'
exit 0
