<#
.SYNOPSIS
Installs or updates the Proxmox MCP broker on Windows Server 2025 (idempotent).

.DESCRIPTION
- Installs a private Python (python.org installer, pinned by SHA-256 and Authenticode signer)
  into C:\Program Files\ProxmoxMCP\python. No other software uses this interpreter, so the
  firewall and WDAC rules can target it.
- Creates C:\Program Files\ProxmoxMCP\venv and installs the dependencies from a hashed
  lock file (pip --require-hashes, wheels only), then the broker wheel (SHA-256 checked).
- Wraps the console entry point with WinSW v2 (pinned by SHA-256) as service ProxmoxMCPBroker
  and runs it as the virtual account NT SERVICE\ProxmoxMCPBroker (never LocalSystem).
  Service privileges are reduced to SeChangeNotifyPrivilege.
- Creates C:\ProgramData\ProxmoxMCP\{credentials,logs,config,ship,cloudflared} with strict ACLs.
- Writes config\broker.env (non-secret settings only) and the WinSW XML from it.
- Generates the DPAPI entropy file (32 random bytes) once.

Service wrapper decision: WinSW v2.12.0 (WinSW.NET461.exe, runs on the in-box .NET
Framework 4.8.1 that Windows Update patches). Python cannot answer the Service Control
Manager without pywin32, which the design excludes. sc.exe around python.exe fails (SCM
kills a process that does not report SERVICE_RUNNING within 30 s). NSSM has had no release
since 2017. WinSW is not Authenticode signed, so the SHA-256 pin is the integrity control;
add a WDAC/AppLocker hash rule for it.

Secrets are not handled here. Use Protect-BrokerCredential.ps1.

.EXAMPLE
.\Install-ProxmoxMcpBroker.ps1 -PythonInstaller .\python-3.13.x-amd64.exe -PythonSha256 <hex> `
  -WheelPath .\proxmox_mcp_server-2.4.0-py3-none-any.whl -WheelSha256 <hex> `
  -RequirementsLock .\requirements.lock -WinSWPath .\WinSW.NET461.exe `
  -ProxmoxHost pve.example.internal -ProxmoxTlsFingerprint <sha256 hex> `
  -BrokerMode vpc -BrokerHostHeader broker.internal -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Python installer from python.org (python-<version>-amd64.exe). Get the SHA-256 from the
    # python.org release page and compare it with a second source before use.
    [Parameter(Mandatory)][string]$PythonInstaller,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PythonSha256,

    # Broker wheel and the hashed lock file made by the release build (see docs/RUNBOOK.md).
    [Parameter(Mandatory)][string]$WheelPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$WheelSha256,
    [Parameter(Mandatory)][string]$RequirementsLock,

    # WinSW v2.12.0 WinSW.NET461.exe from https://github.com/winsw/winsw/releases/tag/v2.12.0
    [Parameter(Mandatory)][string]$WinSWPath,
    # SHA-256 measured from the GitHub release asset on 2026-10-24 (WinSW publishes no hash
    # file, so this is trust on first download; confirm it from a second network).
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$WinSWSha256 = 'b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f',

    # ---- broker.env (non-secret). Required on first install; later runs keep the file
    # unless you pass the values again.
    [string]$ProxmoxHost,
    [ValidateRange(1, 65535)][int]$ProxmoxPort = 8006,
    [ValidatePattern('^([0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2}$')][string]$ProxmoxTlsFingerprint,
    [string]$ProxmoxCaBundle,
    [ValidateRange(1024, 65535)][int]$BrokerPort = 8765,
    # vpc: Worker reaches the broker through a Workers VPC service (identity assertion only).
    # access: broker hostname behind an Access app with a service-token policy (JWT + assertion).
    [ValidateSet('vpc', 'access')][string]$BrokerMode = 'vpc',
    # Host header the Worker sends. VPC mode: must be broker.internal (the host in the Worker's
    # fetch URL). access mode: the broker hostname published by the tunnel.
    [string]$BrokerHostHeader = 'broker.internal',
    [string]$CfAccessTeamDomain,
    [string]$BrokerAccessAud,
    [string]$BrokerServiceClientIds,
    [switch]$AllowAdminTools,

    # Optional: run the service with a write-restricted service SID. Test first: Python must
    # not write outside the paths granted to the service SID.
    [switch]$RestrictedServiceSid,
    [switch]$Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')

Assert-Administrator
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

foreach ($f in @($PythonInstaller, $WheelPath, $RequirementsLock, $WinSWPath)) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "File not found: $f" }
}
$PythonInstaller = (Resolve-Path -LiteralPath $PythonInstaller).Path
$WheelPath = (Resolve-Path -LiteralPath $WheelPath).Path
$RequirementsLock = (Resolve-Path -LiteralPath $RequirementsLock).Path
$WinSWPath = (Resolve-Path -LiteralPath $WinSWPath).Path

# ---- 1. Verify every artifact before anything changes ------------------------------------
Write-Step 'Verify artifacts (SHA-256, Authenticode)'
Assert-Sha256 -Path $PythonInstaller -Expected $PythonSha256
Assert-AuthenticodeSigner -Path $PythonInstaller -SubjectPattern 'CN="?Python Software Foundation"?'
Assert-Sha256 -Path $WheelPath -Expected $WheelSha256
Assert-Sha256 -Path $WinSWPath -Expected $WinSWSha256
if ((Split-Path -Leaf $WheelPath) -notmatch '^proxmox_mcp_server-[0-9][^-]*-py3-none-any\.whl$') {
    throw 'WheelPath must be the proxmox_mcp_server pure-Python wheel.'
}
# Every requirement line must carry a hash, so pip --require-hashes has something to check.
$lockText = Get-Content -LiteralPath $RequirementsLock -Raw
if ($lockText -notmatch '--hash=sha256:[0-9a-f]{64}') { throw 'RequirementsLock has no --hash entries.' }
if ($lockText -match '(?m)^\s*(-e|--editable|git\+|https?://|--index-url|--extra-index-url|--trusted-host)') {
    throw 'RequirementsLock must not contain editable, URL or index options.'
}

# ---- 2. Directories and ACLs -----------------------------------------------------------
Write-Step 'Directories and ACLs'
foreach ($d in @($PmcProgramDir, $PmcServiceDir, $PmcScriptsDir, $PmcDataDir, $PmcCredDir,
        $PmcLogDir, (Join-Path $PmcLogDir 'service'), $PmcConfigDir, $PmcShipDir)) {
    New-PmcDirectory -Path $d
}

# The service SID exists only after the service is registered, so register first (stopped,
# disabled), set ACLs, then configure. Create-or-update is idempotent.
$svcExe = Join-Path $PmcServiceDir "$PmcServiceName.exe"
$svcXml = Join-Path $PmcServiceDir "$PmcServiceName.xml"

# ---- 3. Python ---------------------------------------------------------------------------
Write-Step "Private Python in $PmcPythonDir"
$needPython = $true
if (Test-Path -LiteralPath $PmcPythonExe) {
    $have = & $PmcPythonExe -I -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])'
    if ($PythonInstaller -match [regex]::Escape("python-$have-amd64.exe")) { $needPython = $false }
    Write-Verbose "Installed Python: $have"
}
if ($needPython -and $PSCmdlet.ShouldProcess($PmcPythonDir, 'Install Python (all users, no PATH, no launcher)')) {
    $log = Join-Path $env:TEMP ('python-install-{0:yyyyMMddHHmmss}.log' -f (Get-Date))
    $pyArgs = @('/quiet', 'InstallAllUsers=1', "TargetDir=`"$PmcPythonDir`"", 'PrependPath=0',
        'AssociateFiles=0', 'Shortcuts=0', 'Include_launcher=0', 'InstallLauncherAllUsers=0',
        'Include_test=0', 'Include_doc=0', 'Include_tcltk=0', 'Include_dev=0',
        'Include_debug=0', 'Include_symbols=0', 'Include_pip=1', 'CompileAll=0', '/log', "`"$log`"")
    $p = Start-Process -FilePath $PythonInstaller -ArgumentList $pyArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Python installer failed with exit code $($p.ExitCode). Log: $log" }
    if (-not (Test-Path -LiteralPath $PmcPythonExe)) { throw "python.exe not found in $PmcPythonDir after install." }
}

# ---- 4. Virtual environment and package --------------------------------------------------
$marker = Join-Path $PmcProgramDir 'installed.json'
$wanted = @{ wheel = (Split-Path -Leaf $WheelPath); wheel_sha256 = $WheelSha256.ToLowerInvariant()
    lock_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $RequirementsLock).Hash.ToLowerInvariant() }
$current = $null
if (Test-Path -LiteralPath $marker) { $current = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json }
$needVenv = ($null -eq $current) -or ($current.wheel_sha256 -ne $wanted.wheel_sha256) -or
    ($current.lock_sha256 -ne $wanted.lock_sha256) -or (-not (Test-Path -LiteralPath $PmcVenvDir))

$svc = Get-Service -Name $PmcServiceName -ErrorAction SilentlyContinue
if ($needVenv) {
    Write-Step "Virtual environment $PmcVenvDir (new package or lock)"
    if ($svc -and $svc.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($PmcServiceName, 'Stop service for update')) {
        Stop-Service -Name $PmcServiceName -Force
    }
    if ($PSCmdlet.ShouldProcess($PmcVenvDir, 'Recreate venv and install hashed dependencies + wheel')) {
        Invoke-Native $PmcPythonExe @('-I', '-m', 'venv', '--clear', $PmcVenvDir)
        $vpy = Join-Path $PmcVenvDir 'Scripts\python.exe'
        $pipCommon = @('-I', '-m', 'pip', '--no-input', '--disable-pip-version-check', '--no-cache-dir')
        Invoke-Native $vpy ($pipCommon + @('install', '--require-hashes', '--no-deps', '--only-binary=:all:', '-r', $RequirementsLock))
        Invoke-Native $vpy ($pipCommon + @('install', '--no-deps', '--no-index', $WheelPath))
        Invoke-Native $vpy ($pipCommon + @('check'))
        # Precompile: the service cannot write .pyc files into Program Files.
        Invoke-Native $vpy @('-I', '-m', 'compileall', '-q', (Join-Path $PmcVenvDir 'Lib\site-packages'))
        foreach ($ep in @('proxmox-mcp-http.exe', 'proxmox-mcp-audit-verify.exe', 'proxmox-mcp-protect-credential.exe')) {
            if (-not (Test-Path -LiteralPath (Join-Path $PmcVenvDir "Scripts\$ep"))) {
                throw "Entry point $ep is missing from the wheel. Build the wheel from the current pyproject.toml."
            }
        }
        ($wanted | ConvertTo-Json) | Set-Content -LiteralPath $marker -Encoding ASCII
    }
} else {
    Write-Step 'Package already installed with the same wheel and lock hash'
}

# ---- 5. Copy operator scripts (used by the audit shipping task) ------------------------
if ($PSCmdlet.ShouldProcess($PmcScriptsDir, 'Copy deploy\windows scripts')) {
    Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object { $_.Extension -in @('.ps1', '.py') } | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $PmcScriptsDir $_.Name) -Force
    }
}

# ---- 6. broker.env (non-secret configuration) -----------------------------------------
Write-Step "Configuration $PmcEnvFile"
$envMap = Read-PmcEnvFile
if ($PSBoundParameters.ContainsKey('ProxmoxHost')) {
    if ($ProxmoxHost -notmatch '^[A-Za-z0-9.-]{1,253}$' -and -not [Net.IPAddress]::TryParse($ProxmoxHost, [ref]$null)) {
        throw 'ProxmoxHost must be a DNS name or an IP address (no scheme, no port).'
    }
    if (-not $ProxmoxTlsFingerprint -and -not $ProxmoxCaBundle) {
        throw 'Pass -ProxmoxTlsFingerprint (SHA-256 of the PVE certificate) or -ProxmoxCaBundle. TLS verification is mandatory.'
    }
    if ($BrokerMode -eq 'access') {
        if ($CfAccessTeamDomain -notmatch '^https://[a-z0-9-]+\.cloudflareaccess\.com$') {
            throw 'access mode: -CfAccessTeamDomain must be https://<team>.cloudflareaccess.com'
        }
        if ($BrokerAccessAud -notmatch '^[0-9a-f]{64}$') { throw 'access mode: -BrokerAccessAud must be the 64-hex AUD tag of the broker Access app.' }
        if ($BrokerServiceClientIds -notmatch '^[A-Za-z0-9.]+(,[A-Za-z0-9.]+)*$') { throw 'access mode: -BrokerServiceClientIds is required.' }
    }
    if ($BrokerHostHeader -notmatch '^[A-Za-z0-9.-]{1,253}$') { throw '-BrokerHostHeader must be a host name.' }
    if ($BrokerMode -eq 'vpc' -and $BrokerHostHeader -ne 'broker.internal') {
        throw 'vpc mode: -BrokerHostHeader must be broker.internal (the Worker fetches http://broker.internal/...).'
    }
    $envMap = [ordered]@{
        PROXMOX_HOST                      = $ProxmoxHost
        PROXMOX_PORT                      = "$ProxmoxPort"
        PROXMOX_TLS_FINGERPRINT           = "$ProxmoxTlsFingerprint"
        PROXMOX_CA_BUNDLE                 = "$ProxmoxCaBundle"
        MCP_BIND                          = '127.0.0.1'
        MCP_PORT                          = "$BrokerPort"
        MCP_ALLOWED_HOSTS                 = "$BrokerHostHeader"
        BROKER_REQUIRE_ACCESS_JWT         = $(if ($BrokerMode -eq 'access') { '1' } else { '0' })
        CF_ACCESS_TEAM_DOMAIN             = "$CfAccessTeamDomain"
        CF_ACCESS_AUD                     = "$BrokerAccessAud"
        BROKER_ALLOWED_SERVICE_CLIENT_IDS = "$BrokerServiceClientIds"
        MCP_ALLOW_ADMIN_TOOLS             = $(if ($AllowAdminTools) { '1' } else { '0' })
        MCP_RATE_PER_MIN                  = '60'
        MCP_RATE_PER_DAY                  = '2000'
        MCP_TOOL_MODE                     = 'dynamic'
        MCP_REQUEST_TIMEOUT               = '120'
        MCP_MAX_REQUEST_BYTES             = '262144'
        MCP_MAX_RESULT_BYTES              = '2097152'
    }
    # Never written: MCP_ALLOW_NON_LOOPBACK, MCP_ALLOW_SERVICE_TOKENS, PROXMOX_INSECURE_TLS.
    $lines = @('# Proxmox MCP broker: non-secret configuration. Secrets go in ..\credentials only.',
        "# Written by Install-ProxmoxMcpBroker.ps1 on $(Get-Date -Format s). Re-run the installer to change it.")
    foreach ($k in $envMap.Keys) { $lines += "$k=$($envMap[$k])" }
    if ($PSCmdlet.ShouldProcess($PmcEnvFile, 'Write broker.env')) {
        Set-Content -LiteralPath $PmcEnvFile -Value $lines -Encoding ASCII
    }
} elseif ($envMap.Count -eq 0) {
    throw "No $PmcEnvFile yet. Pass -ProxmoxHost, -ProxmoxTlsFingerprint, -BrokerHostHeader (and access-mode values) on the first install."
}

# Fixed paths: not operator settings.
$fixedEnv = [ordered]@{
    BROKER_CREDENTIALS_DIR    = $PmcCredDir
    BROKER_DPAPI_ENTROPY_FILE = $PmcEntropyFile
    MCP_ENROLLMENT_FILE       = (Join-Path $PmcCredDir 'enrollment.json')
    MCP_AUDIT_LOG             = $PmcAuditLog
    MCP_AUDIT_HMAC            = 'required'
    PYTHONDONTWRITEBYTECODE   = '1'
    PYTHONNOUSERSITE          = '1'
    PYTHONUTF8                = '1'
}

# ---- 7. WinSW wrapper + XML ---------------------------------------------------------
Write-Step "Service wrapper $svcExe"
function ConvertTo-XmlText([string]$s) { return [Security.SecurityElement]::Escape($s) }
$xml = New-Object System.Collections.Generic.List[string]
$xml.Add('<service>')
$xml.Add("  <id>$PmcServiceName</id>")
$xml.Add('  <name>Proxmox MCP Broker</name>')
$xml.Add('  <description>Outbound MCP gateway to Proxmox VE (loopback HTTP, per-user tokens). See docs\RUNBOOK.md.</description>')
$xml.Add('  <executable>' + (ConvertTo-XmlText (Join-Path $PmcVenvDir 'Scripts\proxmox-mcp-http.exe')) + '</executable>')
$xml.Add('  <workingdirectory>' + (ConvertTo-XmlText $PmcDataDir) + '</workingdirectory>')
$xml.Add('  <startmode>Automatic</startmode>')
$xml.Add('  <delayedAutoStart/>')
$xml.Add('  <stoptimeout>20 sec</stoptimeout>')
$xml.Add('  <onfailure action="restart" delay="10 sec"/>')
$xml.Add('  <onfailure action="restart" delay="30 sec"/>')
$xml.Add('  <onfailure action="restart" delay="60 sec"/>')
$xml.Add('  <resetfailure>1 day</resetfailure>')
$xml.Add('  <logpath>' + (ConvertTo-XmlText (Join-Path $PmcLogDir 'service')) + '</logpath>')
$xml.Add('  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>8</keepFiles></log>')
foreach ($k in $envMap.Keys) {
    if ($envMap[$k] -ne '') { $xml.Add("  <env name=`"$k`" value=`"$(ConvertTo-XmlText $envMap[$k])`"/>") }
}
foreach ($k in $fixedEnv.Keys) { $xml.Add("  <env name=`"$k`" value=`"$(ConvertTo-XmlText $fixedEnv[$k])`"/>") }
$xml.Add('</service>')

if ($PSCmdlet.ShouldProcess($svcXml, 'Write WinSW config and wrapper')) {
    Copy-Item -LiteralPath $WinSWPath -Destination $svcExe -Force
    Assert-Sha256 -Path $svcExe -Expected $WinSWSha256
    Set-Content -LiteralPath $svcXml -Value $xml -Encoding UTF8
}

$sc = Join-Path $env:SystemRoot 'System32\sc.exe'
if (-not $svc -and $PSCmdlet.ShouldProcess($PmcServiceName, 'Register service (WinSW install)')) {
    Invoke-Native $svcExe @('install')
} elseif ($svc -and $PSCmdlet.ShouldProcess($PmcServiceName, 'Refresh service definition (WinSW refresh)')) {
    Invoke-Native $svcExe @('refresh') -OkExitCodes @(0, 1)
}

if ($PSCmdlet.ShouldProcess($PmcServiceName, "Run as $PmcServiceAccount, delayed auto start, least privileges, recovery")) {
    # Virtual account: no password, the SCM manages it. Never LocalSystem.
    Invoke-Native $sc @('config', $PmcServiceName, 'obj=', $PmcServiceAccount, 'start=', 'delayed-auto')
    $sidType = 'unrestricted'
    if ($RestrictedServiceSid) { $sidType = 'restricted' }
    Invoke-Native $sc @('sidtype', $PmcServiceName, $sidType)
    # Drop SeImpersonatePrivilege, SeCreateGlobalPrivilege, SeAssignPrimaryToken etc.
    Invoke-Native $sc @('privs', $PmcServiceName, 'SeChangeNotifyPrivilege')
    Invoke-Native $sc @('failure', $PmcServiceName, 'reset=', '86400', 'actions=', 'restart/10000/restart/30000/restart/60000')
    Invoke-Native $sc @('failureflag', $PmcServiceName, '1')
}

# ---- 8. ACLs (service SID now resolves) ---------------------------------------------------
$svcR = "$($PmcServiceAccount):(OI)(CI)RX"
$aclPlan = [ordered]@{
    $PmcProgramDir = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR)
    $PmcDataDir    = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", "$($PmcServiceAccount):RX")
    $PmcCredDir    = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR)
    $PmcConfigDir  = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F", $svcR)
    # Audit log: the service creates and appends; it cannot delete or rename (no D, no DC).
    # Administrators read; SYSTEM (the shipping task) rotates after a confirmed upload.
    $PmcLogDir     = @("$($SidAdmins):(OI)(CI)RX", "$($SidSystem):(OI)(CI)F", "$($PmcServiceAccount):(OI)(CI)(RX,W)")
    (Join-Path $PmcLogDir 'service') = @("$($SidAdmins):(OI)(CI)RX", "$($SidSystem):(OI)(CI)F", "$($PmcServiceAccount):(OI)(CI)M")
    $PmcShipDir    = @("$($SidAdmins):(OI)(CI)F", "$($SidSystem):(OI)(CI)F")
}
foreach ($path in $aclPlan.Keys) { Set-PmcAcl -Path $path -Grant $aclPlan[$path] }

# Audit (SACL) on the logs directory: record delete, ACL change and ownership change by anyone.
if ($PSCmdlet.ShouldProcess($PmcLogDir, 'Add SACL (delete / change permissions / take ownership)')) {
    Invoke-Native (Join-Path $env:SystemRoot 'System32\auditpol.exe') @('/set', '/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')
    $acl = Get-Acl -LiteralPath $PmcLogDir -Audit
    $everyone = New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
    $rights = [Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $rule = New-Object Security.AccessControl.FileSystemAuditRule($everyone, $rights,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AuditFlags]'Success, Failure')
    $acl.AddAuditRule($rule)
    Set-Acl -LiteralPath $PmcLogDir -AclObject $acl
}

# ---- 9. DPAPI entropy (once) ---------------------------------------------------------------
if (-not (Test-Path -LiteralPath $PmcEntropyFile) -and $PSCmdlet.ShouldProcess($PmcEntropyFile, 'Generate 32 random bytes')) {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [IO.File]::WriteAllBytes($PmcEntropyFile, $bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
}

# ---- 9b. Audit HMAC key (once): keyed hash chain, see proxmox_mcp/audit.py ----------------
$hmacFile = Join-Path $PmcCredDir 'audit-hmac.key.dpapi'
if (-not (Test-Path -LiteralPath $hmacFile) -and $PSCmdlet.ShouldProcess($hmacFile, 'Generate audit HMAC key (32 bytes, hex, DPAPI)')) {
    $k = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($k) } finally { $rng.Dispose() }
    $hex = [Text.Encoding]::ASCII.GetBytes((-join ($k | ForEach-Object { $_.ToString('x2') })))
    try {
        $blob = Protect-PmcBytes -Data $hex
        [IO.File]::WriteAllBytes($hmacFile, $blob)
        Set-PmcAcl -Path $hmacFile -Grant @("$($SidAdmins):F", "$($SidSystem):F", "$($PmcServiceAccount):R")
    } finally {
        [Array]::Clear($k, 0, $k.Length); [Array]::Clear($hex, 0, $hex.Length)
    }
    Write-Warning 'New audit HMAC key. Escrow a copy for auditors now (docs/RUNBOOK.md, "Escrow the audit key").'
}

# ---- 10. Start when the credentials exist ---------------------------------------------
$required = @((Join-Path $PmcCredDir 'enrollment.json'))
$pub = Join-Path $PmcCredDir 'worker-identity.pub'
if (-not ((Test-Path -LiteralPath $pub) -or (Test-Path -LiteralPath "$pub.dpapi"))) { $required += $pub }
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing.Count -gt 0) {
    Write-Warning ("Service not started. Missing: {0}. See docs\RUNBOOK.md, 'Enroll a user'." -f ($missing -join ', '))
} elseif ($Start -and $PSCmdlet.ShouldProcess($PmcServiceName, 'Start service')) {
    Start-Service -Name $PmcServiceName
    Write-Step 'Service started. Run Test-ProxmoxMcpBroker.ps1.'
}
Write-Step 'Done. Next: Install-Cloudflared.ps1, Set-BrokerFirewall.ps1, Protect-BrokerCredential.ps1.'
