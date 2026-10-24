<#
.SYNOPSIS
Installs, updates or rolls back the Proxmox MCP broker on Windows Server 2025 (idempotent).

.DESCRIPTION
- Copies every artifact into an Administrators-only staging folder and checks the SHA-256
  of THAT copy (the file that runs), plus the Authenticode signer of the Python installer.
- Installs a private Python (python.org installer) into C:\Program Files\ProxmoxMCP\python.
  The Python major.minor MUST equal the "CPython X.Y" line in the header of the hashed lock
  (requirements\broker-win.txt). The installer refuses any other version.
- Builds a NEW versioned venv C:\Program Files\ProxmoxMCP\venvs\<id> from the hashed lock
  (pip --require-hashes, wheels only) and the broker wheel. The running service is not
  touched until the new venv passes its checks (entry points, pip check, and the broker's
  own config parser on the new broker.env). Then the service is switched to it. The
  previous venv is kept for -Rollback.
- Wraps the console entry point with WinSW v2 (pinned by SHA-256) as service ProxmoxMCPBroker,
  running as the virtual account NT SERVICE\ProxmoxMCPBroker (never LocalSystem), with only
  SeChangeNotifyPrivilege.
- Creates C:\ProgramData\ProxmoxMCP\{credentials,logs,config,ship,evidence} under a parent
  that is locked first, so no other account can plant a file or junction in them.
- Writes config\broker.env (non-secret settings only) and the WinSW XML from it.
- Generates the DPAPI entropy file and the audit HMAC key once.

Service wrapper decision: WinSW v2.12.0 (WinSW.NET461.exe, runs on the in-box .NET
Framework 4.8.1 that Windows Update patches). Python cannot answer the Service Control
Manager without pywin32. sc.exe around python.exe fails (the SCM kills a process that does
not report SERVICE_RUNNING within 30 s). NSSM has had no release since 2017. WinSW is not
Authenticode signed, so the SHA-256 pin plus a WDAC/AppLocker hash rule are the integrity
controls.

Secrets are not handled here. Use Protect-BrokerCredential.ps1.

.EXAMPLE
.\Install-ProxmoxMcpBroker.ps1 -PythonInstaller .\python-3.12.10-amd64.exe -PythonSha256 <hex> `
  -WheelPath .\proxmox_mcp_server-<v>-py3-none-any.whl -WheelSha256 <hex> `
  -RequirementsLock .\broker-win.txt -RequirementsLockSha256 <hex> -WinSWPath .\WinSW.NET461.exe `
  -ProxmoxHost <proxmox-host> -ProxmoxTlsFingerprint <sha256 hex> -BrokerMode vpc -WhatIf

.EXAMPLE
.\Install-ProxmoxMcpBroker.ps1 -Rollback -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Install')]
param(
    # Python installer from python.org (python-<version>-amd64.exe). Get the SHA-256 from the
    # python.org release page and confirm it from a second network.
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$PythonInstaller,
    [Parameter(Mandatory, ParameterSetName = 'Install')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PythonSha256,

    # Broker wheel and the hashed lock (requirements\broker-win.txt) from the approved
    # release, with the SHA-256 values from the release SHA256SUMS.
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$WheelPath,
    [Parameter(Mandatory, ParameterSetName = 'Install')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$WheelSha256,
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$RequirementsLock,
    [Parameter(Mandatory, ParameterSetName = 'Install')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$RequirementsLockSha256,
    # Optional offline wheelhouse (pip download of the lock on the build host). Without it,
    # pip fetches the wheels from PyPI; --require-hashes still pins every byte.
    [Parameter(ParameterSetName = 'Install')][string]$Wheelhouse,

    # WinSW v2.12.0 WinSW.NET461.exe from the winsw/winsw GitHub release v2.12.0.
    [Parameter(Mandatory, ParameterSetName = 'Install')][string]$WinSWPath,
    # SHA-256 measured from the GitHub release asset (WinSW publishes no hash file, so this
    # is trust on first download; confirm it from a second network).
    [Parameter(ParameterSetName = 'Install')][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$WinSWSha256 = 'b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f',

    # ---- broker.env (non-secret). Required on first install; later runs keep the file
    # unless -ProxmoxHost is passed again (then the whole file is rewritten).
    [Parameter(ParameterSetName = 'Install')][string]$ProxmoxHost,
    [Parameter(ParameterSetName = 'Install')][ValidateRange(1, 65535)][int]$ProxmoxPort = 8006,
    [Parameter(ParameterSetName = 'Install')][ValidatePattern('^([0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2}$')][string]$ProxmoxTlsFingerprint,
    [Parameter(ParameterSetName = 'Install')][string]$ProxmoxCaBundle,
    [Parameter(ParameterSetName = 'Install')][ValidateRange(1024, 65535)][int]$BrokerPort = 8765,
    # vpc: Worker reaches the broker through a Workers VPC service (identity assertion only).
    # access: broker hostname behind an Access app with a service-token policy (JWT + assertion).
    [Parameter(ParameterSetName = 'Install')][ValidateSet('vpc', 'access')][string]$BrokerMode = 'vpc',
    # Host header the Worker sends. vpc: broker.internal. access: the broker hostname.
    [Parameter(ParameterSetName = 'Install')][string]$BrokerHostHeader = 'broker.internal',
    [Parameter(ParameterSetName = 'Install')][string]$CfAccessTeamDomain,
    [Parameter(ParameterSetName = 'Install')][string]$BrokerAccessAud,
    [Parameter(ParameterSetName = 'Install')][string]$BrokerServiceClientIds,
    [Parameter(ParameterSetName = 'Install')][switch]$AllowAdminTools,
    # Optional: run the service with a write-restricted service SID. Test first.
    [Parameter(ParameterSetName = 'Install')][switch]$RestrictedServiceSid,
    # How many earlier venvs to keep besides the active one (rollback targets).
    [Parameter(ParameterSetName = 'Install')][ValidateRange(1, 5)][int]$KeepPrevious = 1,

    # Switch the service back to the previous venv (installed.json "previous").
    [Parameter(Mandatory, ParameterSetName = 'Rollback')][switch]$Rollback,

    [switch]$Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')

Assert-Administrator
Initialize-PmcTlsProtocol

$svcExe = Join-Path $PmcServiceDir "$PmcServiceName.exe"
$svcXml = Join-Path $PmcServiceDir "$PmcServiceName.xml"
$sc = Join-Path $env:SystemRoot 'System32\sc.exe'

function ConvertTo-XmlText([string]$s) { return [Security.SecurityElement]::Escape($s) }

function ConvertTo-ServiceXml {
    # WinSW XML. Values are validated by Assert-PmcEnvEntry and XML-escaped here.
    param([Parameter(Mandatory)][string]$VenvDir, [Parameter(Mandatory)]$EnvMap)
    $x = New-Object System.Collections.Generic.List[string]
    $x.Add('<service>')
    $x.Add("  <id>$PmcServiceName</id>")
    $x.Add('  <name>Proxmox MCP Broker</name>')
    $x.Add('  <description>Outbound MCP gateway to Proxmox VE (loopback HTTP, per-user tokens). See docs\RUNBOOK.md.</description>')
    $x.Add('  <executable>' + (ConvertTo-XmlText (Join-Path $VenvDir 'Scripts\proxmox-mcp-http.exe')) + '</executable>')
    $x.Add('  <workingdirectory>' + (ConvertTo-XmlText $PmcDataDir) + '</workingdirectory>')
    $x.Add('  <startmode>Automatic</startmode>')
    $x.Add('  <delayedAutoStart/>')
    $x.Add('  <stoptimeout>20 sec</stoptimeout>')
    $x.Add('  <onfailure action="restart" delay="10 sec"/>')
    $x.Add('  <onfailure action="restart" delay="30 sec"/>')
    $x.Add('  <onfailure action="restart" delay="60 sec"/>')
    $x.Add('  <resetfailure>1 day</resetfailure>')
    # stdout/stderr of the broker. The broker never logs secrets or argument values; the
    # folder is still Administrators-read only and rolls at 10 MB x 8.
    $x.Add('  <logpath>' + (ConvertTo-XmlText (Join-Path $PmcLogDir 'service')) + '</logpath>')
    $x.Add('  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>8</keepFiles></log>')
    foreach ($k in $EnvMap.Keys) {
        Assert-PmcEnvEntry -Name $k -Value $EnvMap[$k]
        if ($EnvMap[$k] -ne '') { $x.Add("  <env name=`"$(ConvertTo-XmlText $k)`" value=`"$(ConvertTo-XmlText $EnvMap[$k])`"/>") }
    }
    $fixed = Get-PmcFixedEnv
    foreach ($k in $fixed.Keys) { $x.Add("  <env name=`"$k`" value=`"$(ConvertTo-XmlText $fixed[$k])`"/>") }
    $x.Add('</service>')
    return , $x.ToArray()
}

function Set-ServiceDefinition {
    # Write the XML for $VenvDir, register or refresh the WinSW service, then enforce the
    # account, privileges and recovery with sc.exe (WinSW refresh may reset some of them).
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$VenvDir, [Parameter(Mandatory)]$EnvMap)
    $xmlLines = ConvertTo-ServiceXml -VenvDir $VenvDir -EnvMap $EnvMap
    if (-not $PSCmdlet.ShouldProcess($PmcServiceName, "Point service at $VenvDir")) { return }
    Set-Content -LiteralPath $svcXml -Value $xmlLines -Encoding UTF8
    $exists = Get-Service -Name $PmcServiceName -ErrorAction SilentlyContinue
    if (-not $exists) { Invoke-Native $svcExe @('install') } else { Invoke-Native $svcExe @('refresh') }
    # Virtual account: no password, the SCM manages it. Never LocalSystem.
    Invoke-Native $sc @('config', $PmcServiceName, 'obj=', $PmcServiceAccount, 'start=', 'delayed-auto')
    $sidType = 'unrestricted'
    if ($script:UseRestrictedSid) { $sidType = 'restricted' }
    Invoke-Native $sc @('sidtype', $PmcServiceName, $sidType)
    # Drop SeImpersonatePrivilege, SeCreateGlobalPrivilege, SeAssignPrimaryToken etc.
    Invoke-Native $sc @('privs', $PmcServiceName, 'SeChangeNotifyPrivilege')
    Invoke-Native $sc @('failure', $PmcServiceName, 'reset=', '86400', 'actions=', 'restart/10000/restart/30000/restart/60000')
    Invoke-Native $sc @('failureflag', $PmcServiceName, '1')
    $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='$PmcServiceName'"
    if ($s.StartName -ne $PmcServiceAccount) { throw "Service runs as '$($s.StartName)', expected $PmcServiceAccount." }
}

function Start-AndCheck {
    # Start the service and confirm it stays up (a configuration error exits with code 2).
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $PSCmdlet.ShouldProcess($PmcServiceName, 'Start service and check it stays running')) { return $true }
    Start-Service -Name $PmcServiceName
    Start-Sleep -Seconds 8
    return ((Get-Service -Name $PmcServiceName).Status -eq 'Running')
}

function Save-Marker {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Doc)
    if ($PSCmdlet.ShouldProcess($PmcMarkerFile, 'Write installed.json')) {
        ($Doc | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $PmcMarkerFile -Encoding ASCII
    }
}

# ======================================== Rollback ========================================
if ($Rollback) {
    $m = Get-PmcInstalled
    $prev = Get-PmcProp $m 'previous'
    $active = Get-PmcProp $m 'active'
    if (-not $prev -or -not (Test-Path -LiteralPath $prev.venv)) { throw 'No previous venv recorded in installed.json. Reinstall the earlier release instead.' }
    Write-Step "Roll back: $($active.wheel) -> $($prev.wheel)"
    $script:UseRestrictedSid = $false
    $envMap = Read-PmcEnvFile
    if ($PSCmdlet.ShouldProcess($PmcServiceName, 'Stop service for rollback')) { Stop-Service -Name $PmcServiceName -Force -ErrorAction SilentlyContinue }
    Set-ServiceDefinition -VenvDir $prev.venv -EnvMap $envMap
    Save-Marker -Doc ([ordered]@{ active = $prev; previous = $active })
    if (-not (Start-AndCheck)) { throw "Service did not stay running after rollback. Read $PmcLogDir\service\$PmcServiceName.err.log." }
    Write-Step 'Rolled back. Run Test-ProxmoxMcpBroker.ps1 and record the change ticket.'
    return
}

# ======================================== Install =========================================
$script:UseRestrictedSid = [bool]$RestrictedServiceSid

# ---- 1. Locked parents before anything is created inside them -----------------------------
Write-Step 'Directories and parent ACLs'
$adminOnly = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F")
New-PmcDirectory -Path $PmcProgramDir
Set-PmcAcl -Path $PmcProgramDir -Grant $adminOnly
New-PmcDirectory -Path $PmcDataDir
Set-PmcAcl -Path $PmcDataDir -Grant $adminOnly
# Per-file ACLs in credentials\ and cloudflared\ must survive, so the tree is checked
# (owner, no junctions) instead of reset.
Assert-PmcTrustedTree -Path $PmcDataDir
foreach ($d in @($PmcServiceDir, $PmcScriptsDir, $PmcVenvRoot, $PmcCredDir, $PmcLogDir,
        (Join-Path $PmcLogDir 'service'), $PmcConfigDir, $PmcShipDir, $PmcEvidenceDir)) {
    New-PmcDirectory -Path $d
}

# ---- 2. Stage and verify every artifact (hash of the copy that runs) ------------------------
Write-Step 'Stage and verify artifacts (SHA-256 of the staged copies, Authenticode)'
$stage = $null
if ($PSCmdlet.ShouldProcess($PmcStagingDir, 'Create private staging folder')) { $stage = New-PmcStagingDir }
if ($stage) {
    $PythonInstaller = Copy-PmcVerifiedArtifact -Source $PythonInstaller -Sha256 $PythonSha256 -StagingDir $stage
    $WheelPath = Copy-PmcVerifiedArtifact -Source $WheelPath -Sha256 $WheelSha256 -StagingDir $stage
    $RequirementsLock = Copy-PmcVerifiedArtifact -Source $RequirementsLock -Sha256 $RequirementsLockSha256 -StagingDir $stage
    $WinSWPath = Copy-PmcVerifiedArtifact -Source $WinSWPath -Sha256 $WinSWSha256 -StagingDir $stage
} else {
    foreach ($pair in @(@($PythonInstaller, $PythonSha256), @($WheelPath, $WheelSha256), @($RequirementsLock, $RequirementsLockSha256), @($WinSWPath, $WinSWSha256))) {
        Assert-Sha256 -Path $pair[0] -Expected $pair[1]
    }
}
Assert-AuthenticodeSigner -Path $PythonInstaller -SignerCommonName 'Python Software Foundation'
if ((Split-Path -Leaf $WheelPath) -notmatch '^proxmox_mcp_server-[0-9][^-]*-py3-none-any\.whl$') {
    throw 'WheelPath must be the proxmox_mcp_server pure-Python wheel.'
}
$lockText = Get-Content -LiteralPath $RequirementsLock -Raw
if ($lockText -notmatch '--hash=sha256:[0-9a-f]{64}') { throw 'RequirementsLock has no --hash entries.' }
if ($lockText -match '(?m)^\s*(-e|--editable|-i|--index-url|--extra-index-url|--trusted-host|--find-links|-f|-r|-c|git\+|https?://|file:)') {
    throw 'RequirementsLock must not contain editable, URL, index, include or file options.'
}
if ($lockText -notmatch '(?m)^--only-binary :all:') { throw 'RequirementsLock must start with --only-binary :all: (wheels only).' }

# ---- 3. Python version must match the lock -------------------------------------------------
$lockPy = Get-PmcLockPythonVersion -LockPath $RequirementsLock
if ((Split-Path -Leaf $PythonInstaller) -notmatch '^python-(\d+\.\d+)\.(\d+)-amd64\.exe$') {
    throw 'PythonInstaller must be the python.org file python-<major>.<minor>.<patch>-amd64.exe.'
}
$wantPy = "$($Matches[1]).$($Matches[2])"
if ($Matches[1] -ne $lockPy) {
    throw "Python $wantPy does not match the lock (CPython $lockPy). Use a CPython $lockPy installer, or regenerate the lock for $($Matches[1]) (requirements/generate_broker_lock.py)."
}

Write-Step "Private Python $wantPy in $PmcPythonDir"
$havePy = $null
if (Test-Path -LiteralPath $PmcPythonExe) {
    $havePy = (& $PmcPythonExe -I -c 'import sys; print(sys.version.split()[0])' | Out-String).Trim()
}
$svc = Get-Service -Name $PmcServiceName -ErrorAction SilentlyContinue
$wasRunning = [bool]($svc -and $svc.Status -eq 'Running')
if ($havePy -ne $wantPy) {
    if ($havePy -and ($havePy -replace '^(\d+\.\d+)\..*$', '$1') -ne $lockPy) {
        Write-Warning "Installed Python $havePy has another minor version. Every venv will be rebuilt; -Rollback to an older venv will not work."
    }
    if ($PSCmdlet.ShouldProcess($PmcPythonDir, "Install Python $wantPy (all users, no PATH, no launcher)")) {
        # Files in use cannot be replaced: stop the broker during the interpreter update.
        if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name $PmcServiceName -Force }
        $log = Join-Path $stage 'python-install.log'
        $pyArgs = @('/quiet', 'InstallAllUsers=1', "TargetDir=`"$PmcPythonDir`"", 'PrependPath=0',
            'AssociateFiles=0', 'Shortcuts=0', 'Include_launcher=0', 'InstallLauncherAllUsers=0',
            'Include_test=0', 'Include_doc=0', 'Include_tcltk=0', 'Include_dev=0',
            'Include_debug=0', 'Include_symbols=0', 'Include_pip=1', 'CompileAll=0', '/log', "`"$log`"")
        $p = Start-Process -FilePath $PythonInstaller -ArgumentList $pyArgs -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "Python installer failed with exit code $($p.ExitCode). Log: $log" }
        $havePy = (& $PmcPythonExe -I -c 'import sys; print(sys.version.split()[0])' | Out-String).Trim()
        if ($havePy -ne $wantPy) { throw "python.exe reports $havePy after installing $wantPy." }
        Assert-AuthenticodeSigner -Path $PmcPythonExe -SignerCommonName 'Python Software Foundation'
    }
}

# ---- 4. broker.env (non-secret configuration) -----------------------------------------
Write-Step "Configuration $PmcEnvFile"
$envMap = Read-PmcEnvFile
$writeEnv = $false
if ($PSBoundParameters.ContainsKey('ProxmoxHost')) {
    if ($ProxmoxHost -cnotmatch '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' -and -not [Net.IPAddress]::TryParse($ProxmoxHost, [ref]$null)) {
        throw 'ProxmoxHost must be a lower-case DNS name or an IP address (no scheme, no port).'
    }
    if (-not $ProxmoxTlsFingerprint -and -not $ProxmoxCaBundle) {
        throw 'Pass -ProxmoxTlsFingerprint (SHA-256 of the PVE certificate) or -ProxmoxCaBundle. TLS verification is mandatory.'
    }
    if ($ProxmoxCaBundle -and -not ([IO.Path]::IsPathRooted($ProxmoxCaBundle) -and (Test-Path -LiteralPath $ProxmoxCaBundle -PathType Leaf))) {
        throw '-ProxmoxCaBundle must be an absolute path of an existing PEM file.'
    }
    $BrokerHostHeader = $BrokerHostHeader.ToLowerInvariant()
    if ($BrokerHostHeader -cnotmatch '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$') { throw '-BrokerHostHeader must be a host name.' }
    if ($BrokerMode -eq 'vpc' -and $BrokerHostHeader -ne 'broker.internal') {
        throw 'vpc mode: -BrokerHostHeader must be broker.internal (the Worker fetches http://broker.internal/...).'
    }
    if ($BrokerMode -eq 'access') {
        if ($CfAccessTeamDomain -cnotmatch '^https://[a-z0-9-]+\.cloudflareaccess\.com$') {
            throw 'access mode: -CfAccessTeamDomain must be https://<team>.cloudflareaccess.com'
        }
        if ($BrokerAccessAud -cnotmatch '^[0-9a-f]{64}$') { throw 'access mode: -BrokerAccessAud must be the 64-hex AUD tag of the broker Access app.' }
        if ($BrokerServiceClientIds -cnotmatch '^[A-Za-z0-9._-]{1,128}(,[A-Za-z0-9._-]{1,128})*$') { throw 'access mode: -BrokerServiceClientIds is required.' }
    }
    $envMap = [ordered]@{
        PROXMOX_HOST                      = $ProxmoxHost
        PROXMOX_PORT                      = "$ProxmoxPort"
        PROXMOX_TLS_FINGERPRINT           = "$ProxmoxTlsFingerprint"
        PROXMOX_CA_BUNDLE                 = "$ProxmoxCaBundle"
        PROXMOX_TIMEOUT                   = '30'
        PROXMOX_TOTAL_TIMEOUT             = '120'
        MCP_BIND                          = '127.0.0.1'
        MCP_PORT                          = "$BrokerPort"
        MCP_ALLOWED_HOSTS                 = $BrokerHostHeader
        MCP_REQUEST_TIMEOUT               = '120'
        MCP_BODY_TIMEOUT                  = '15'
        MCP_HEADER_TIMEOUT                = '10'
        MCP_MAX_CONCURRENCY               = '64'
        MCP_MAX_REQUEST_BYTES             = '262144'
        MCP_MAX_RESULT_BYTES              = '2097152'
        MCP_RATE_PER_MIN                  = '60'
        MCP_RATE_PER_DAY                  = '2000'
        MCP_TOOL_MODE                     = 'dynamic'
        MCP_ALLOW_ADMIN_TOOLS             = $(if ($AllowAdminTools) { '1' } else { '0' })
        BROKER_REQUIRE_ACCESS_JWT         = $(if ($BrokerMode -eq 'access') { '1' } else { '0' })
        CF_ACCESS_TEAM_DOMAIN             = $(if ($BrokerMode -eq 'access') { $CfAccessTeamDomain } else { '' })
        CF_ACCESS_AUD                     = $(if ($BrokerMode -eq 'access') { $BrokerAccessAud } else { '' })
        BROKER_ALLOWED_SERVICE_CLIENT_IDS = $(if ($BrokerMode -eq 'access') { $BrokerServiceClientIds } else { '' })
    }
    foreach ($k in $envMap.Keys) { Assert-PmcEnvEntry -Name $k -Value $envMap[$k] }
    $writeEnv = $true
} elseif ($envMap.Count -eq 0) {
    throw "No $PmcEnvFile yet. Pass -ProxmoxHost, -ProxmoxTlsFingerprint (and access-mode values) on the first install."
}

# ---- 5. New versioned venv (the running service is not touched yet) ------------------------
$lockSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $RequirementsLock).Hash.ToLowerInvariant()
$venvId = '{0}-{1}-py{2}' -f $WheelSha256.Substring(0, 12).ToLowerInvariant(), $lockSha.Substring(0, 12), $wantPy
$newVenv = Join-Path $PmcVenvRoot $venvId
$marker = Get-PmcInstalled
$active = Get-PmcProp $marker 'active'
$sameBuild = $active -and ((Get-PmcProp $active 'venv') -eq $newVenv) -and ((Get-PmcProp $active 'python') -eq $wantPy) -and (Test-Path -LiteralPath $newVenv)

if (-not $sameBuild) {
    Write-Step "Build venv $newVenv"
    if ($PSCmdlet.ShouldProcess($newVenv, 'Create venv and install hashed dependencies + wheel')) {
        if (Test-Path -LiteralPath $newVenv) { Remove-Item -LiteralPath $newVenv -Recurse -Force }   # a failed earlier attempt
        Invoke-Native $PmcPythonExe @('-I', '-m', 'venv', $newVenv)
        $vpy = Join-Path $newVenv 'Scripts\python.exe'
        $pipCommon = @('-I', '-m', 'pip', '--no-input', '--disable-pip-version-check', '--no-cache-dir', '--isolated')
        $src = @()
        if ($Wheelhouse) {
            if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) { throw "Wheelhouse not found: $Wheelhouse" }
            $src = @('--no-index', '--find-links', (Resolve-Path -LiteralPath $Wheelhouse).Path)
        }
        Invoke-Native $vpy ($pipCommon + @('install', '--require-hashes', '--no-deps', '--only-binary=:all:') + $src + @('-r', $RequirementsLock))
        Invoke-Native $vpy ($pipCommon + @('install', '--no-deps', '--no-index', $WheelPath))
        Invoke-Native $vpy ($pipCommon + @('check'))
        # Precompile: the service cannot write .pyc files into Program Files.
        Invoke-Native $vpy @('-I', '-m', 'compileall', '-q', (Join-Path $newVenv 'Lib\site-packages'))
        foreach ($ep in @('proxmox-mcp-http', 'proxmox-mcp-audit-verify', 'proxmox-mcp-protect-credential', 'proxmox-mcp-selfcheck')) {
            if (-not (Test-Path -LiteralPath (Join-Path $newVenv "Scripts\$ep.exe"))) {
                throw "Entry point $ep is missing from the wheel. Build the wheel from the current pyproject.toml."
            }
        }
    }
} else {
    Write-Step 'Package already installed with the same wheel, lock and Python'
}

# ---- 6. The broker's own parser must accept the configuration -----------------------------
# config.load(role="broker") is what the service runs at start. Feed it exactly the
# service environment as JSON on stdin (no secrets: broker.env holds none).
$checkVenv = $newVenv
if (-not (Test-Path -LiteralPath (Join-Path $checkVenv 'Scripts\python.exe'))) { $checkVenv = $null }
if ($checkVenv) {
    Write-Step 'Validate broker.env with proxmox_mcp.config (role broker)'
    $cfg = [ordered]@{}
    foreach ($k in $envMap.Keys) { if ($envMap[$k] -ne '') { $cfg[$k] = $envMap[$k] } }
    $fixed = Get-PmcFixedEnv
    foreach ($k in $fixed.Keys) { $cfg[$k] = $fixed[$k] }
    $OutputEncoding = New-Object Text.UTF8Encoding($false)
    $code = 'import json,sys; from proxmox_mcp import config as c; s=c.load(json.load(sys.stdin), role=''broker''); print(s.config_sha256())'
    $out = ($cfg | ConvertTo-Json -Compress) | & (Join-Path $checkVenv 'Scripts\python.exe') -I -c $code 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "The broker refuses this configuration:`n$($out.Trim())" }
    Write-Step "Configuration accepted (config_sha256 $($out.Trim()))"
}
if ($writeEnv -and $PSCmdlet.ShouldProcess($PmcEnvFile, 'Write broker.env')) {
    $lines = @('# Proxmox MCP broker: non-secret configuration. Secrets go in ..\credentials only.',
        '# Written by Install-ProxmoxMcpBroker.ps1. Re-run the installer to change it; do not edit by hand.',
        '# Never set: PROXMOX_INSECURE_TLS, MCP_ALLOW_NON_LOOPBACK, MCP_ALLOW_SERVICE_TOKENS, PROXMOX_TOKEN_*.')
    foreach ($k in $envMap.Keys) { if ($envMap[$k] -ne '') { $lines += "$k=$($envMap[$k])" } }
    Set-Content -LiteralPath $PmcEnvFile -Value $lines -Encoding ASCII
}

# ---- 7. Operator scripts (used by the scheduled tasks) --------------------------------------
if ($PSCmdlet.ShouldProcess($PmcScriptsDir, 'Copy deploy\windows scripts')) {
    Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object { $_.Extension -in @('.ps1', '.py') } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $PmcScriptsDir $_.Name) -Force
        Remove-Item -LiteralPath (Join-Path $PmcScriptsDir $_.Name) -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
    }
}

# ---- 8. Switch the service to the new venv --------------------------------------------------
Write-Step "Service wrapper $svcExe"
if ($PSCmdlet.ShouldProcess($svcExe, 'Install WinSW wrapper')) {
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name $PmcServiceName -Force }
    Copy-Item -LiteralPath $WinSWPath -Destination $svcExe -Force
    Assert-Sha256 -Path $svcExe -Expected $WinSWSha256
}
if ($svc -and $svc.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($PmcServiceName, 'Stop service for the switch')) {
    Stop-Service -Name $PmcServiceName -Force
}
Set-ServiceDefinition -VenvDir $newVenv -EnvMap $envMap

$entry = [ordered]@{ venv = $newVenv; wheel = (Split-Path -Leaf $WheelPath); wheel_sha256 = $WheelSha256.ToLowerInvariant()
    lock_sha256 = $lockSha; python = $wantPy; installed = (Get-Date).ToUniversalTime().ToString('s') + 'Z' }
if (-not $sameBuild) {
    $previous = $active
    Save-Marker -Doc ([ordered]@{ active = $entry; previous = $previous })
    # Keep the active venv and up to -KeepPrevious earlier ones.
    if ($PSCmdlet.ShouldProcess($PmcVenvRoot, "Prune venvs (keep active + $KeepPrevious)")) {
        $keep = @($newVenv)
        if ($previous) { $keep += $previous.venv }
        $old = @(Get-ChildItem -LiteralPath $PmcVenvRoot -Directory | Where-Object { $keep -notcontains $_.FullName } | Sort-Object LastWriteTime -Descending)
        $old | Select-Object -Skip ([Math]::Max(0, $KeepPrevious - 1)) | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force }
    }
}

# ---- 9. ACLs (the service SID resolves now) -------------------------------------------------
Write-Step 'ACLs'
$svcR = "$($PmcServiceAccount):(OI)(CI)RX"
$aclPlan = [ordered]@{
    $PmcProgramDir = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR)
    # Traverse only: the service may open the subfolders it is granted below.
    $PmcDataDir    = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "$($PmcServiceAccount):RX")
    $PmcCredDir    = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR, "$($SidOwnerRights):(OI)(CI)RX")
    $PmcConfigDir  = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR)
    # Audit log: the service creates and appends; it cannot delete, rename or change ACLs
    # (no D, no DC, and OWNER RIGHTS removes the owner's implicit WRITE_DAC).
    # Administrators read; SYSTEM (the shipping task) rotates after a confirmed upload.
    $PmcLogDir     = @("$($SidAdmins):(OI)(CI)RX", "$($SidSystem):(OI)(CI)F", "$($PmcServiceAccount):(OI)(CI)(RX,W)", "$($SidOwnerRights):(OI)(CI)(RX,W)")
    (Join-Path $PmcLogDir 'service') = @("$($SidAdmins):(OI)(CI)RX", "$($SidSystem):(OI)(CI)F", "$($PmcServiceAccount):(OI)(CI)M", "$($SidOwnerRights):(OI)(CI)M")
    $PmcShipDir    = $adminOnly
    $PmcEvidenceDir = $adminOnly
    $PmcVenvRoot   = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR)
}
# Reset children only where no file carries its own ACL. credentials\ keeps per-file ACLs
# (for example audit-ship-sas is SYSTEM-only) and is checked by Assert-PmcTrustedTree.
$resetDirs = @($PmcLogDir, (Join-Path $PmcLogDir 'service'), $PmcConfigDir, $PmcShipDir, $PmcEvidenceDir)
foreach ($path in $aclPlan.Keys) {
    Set-PmcAcl -Path $path -Grant $aclPlan[$path] -ResetChildren:($resetDirs -contains $path)
}
Assert-PmcTrustedTree -Path $PmcCredDir

# SACLs: who deleted, re-permissioned or took ownership of the logs; who tried and failed
# to read a credential; who wrote, deleted or re-permissioned one.
if ($PSCmdlet.ShouldProcess("$PmcLogDir, $PmcCredDir", 'Add SACLs')) {
    Invoke-Native (Join-Path $env:SystemRoot 'System32\auditpol.exe') @('/set', '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')
    $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $plan = @(
        @($PmcLogDir, 'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership', 'Success, Failure'),
        @($PmcCredDir, 'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership', 'Success, Failure'),
        @($PmcCredDir, 'ReadData', 'Failure')
    )
    foreach ($p in $plan) {
        $acl = Get-Acl -LiteralPath $p[0] -Audit
        $rule = New-Object Security.AccessControl.FileSystemAuditRule($everyone, [Security.AccessControl.FileSystemRights]$p[1],
            $inh, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AuditFlags]$p[2])
        $acl.AddAuditRule($rule)
        Set-Acl -LiteralPath $p[0] -AclObject $acl
    }
}

# ---- 10. DPAPI entropy and audit HMAC key (once) ------------------------------------------
$secretGrant = @("$($SidAdmins):F", "$($SidSystem):F", "$($PmcServiceAccount):R")
if (-not (Test-Path -LiteralPath $PmcEntropyFile)) {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        Write-PmcFileAtomic -Path $PmcEntropyFile -Bytes $bytes -Grant $secretGrant
    } finally { $rng.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
}
$hmacFile = Join-Path $PmcCredDir 'audit-hmac.key.dpapi'
if (-not (Test-Path -LiteralPath $hmacFile) -and (Test-Path -LiteralPath $PmcEntropyFile)) {
    $k = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $hex = $null
    try {
        $rng.GetBytes($k)
        $hex = [Text.Encoding]::ASCII.GetBytes([BitConverter]::ToString($k).Replace('-', '').ToLowerInvariant())
        $blob = Protect-PmcData -Data $hex
        Write-PmcFileAtomic -Path $hmacFile -Bytes $blob -Grant $secretGrant
        if (-not $WhatIfPreference) {
            Write-Warning 'New audit HMAC key. Escrow it now with two custodians: Export-AuditKeyEscrow.ps1 (docs/COMPLIANCE.md, "Audit key escrow").'
        }
    } finally {
        $rng.Dispose(); [Array]::Clear($k, 0, $k.Length); if ($hex) { [Array]::Clear($hex, 0, $hex.Length) }
    }
}

# ---- 11. Clean staging, start ---------------------------------------------------------------
if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }

$required = @((Join-Path $PmcCredDir 'enrollment.json'), $hmacFile)
$pub = Join-Path $PmcCredDir 'worker-identity.pub'
if (-not ((Test-Path -LiteralPath $pub) -or (Test-Path -LiteralPath "$pub.dpapi"))) { $required += $pub }
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing.Count -gt 0) {
    Write-Warning ("Service not started. Missing: {0}. See docs\RUNBOOK.md, 'Enroll a user'." -f ($missing -join ', '))
} elseif ($Start -or $wasRunning) {
    if (-not (Start-AndCheck)) {
        $prev = Get-PmcProp (Get-PmcInstalled) 'previous'
        if (-not $sameBuild -and $prev -and (Test-Path -LiteralPath $prev.venv)) {
            Write-Warning 'The new version did not stay running. Rolling back to the previous venv.'
            Stop-Service -Name $PmcServiceName -Force -ErrorAction SilentlyContinue
            Set-ServiceDefinition -VenvDir $prev.venv -EnvMap $envMap
            Save-Marker -Doc ([ordered]@{ active = $prev; previous = $entry })
            [void](Start-AndCheck)
        }
        throw "Service did not stay running. Read $PmcLogDir\service\$PmcServiceName.err.log (exit code 2 = configuration error)."
    }
    Write-Step 'Service started. Run Test-ProxmoxMcpBroker.ps1.'
}
Write-Step 'Done. Next: Install-Cloudflared.ps1, Set-BrokerFirewall.ps1, Protect-BrokerCredential.ps1, Invoke-BrokerSelfCheck.ps1 -Register.'
