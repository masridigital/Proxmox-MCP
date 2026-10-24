# ProxmoxMcp.Common.ps1: shared helpers for the Proxmox MCP broker scripts.
# Dot-source this file from a script that has [CmdletBinding(SupportsShouldProcess)].
# Dot-sourcing (not Import-Module) keeps -WhatIf working: the helpers run in the
# caller's scope and see its $WhatIfPreference.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.x.
#
# Secret handling rules for every script in this folder:
#  - A secret never is a parameter, an environment variable, a temp file or console output.
#  - A secret never is bound to a cmdlet parameter. PowerShell module logging (event 4103)
#    records cmdlet parameter values. Secrets go only through .NET method calls and
#    script-local variables.
#  - Run the scripts with -NoProfile. A profile can change cmdlet defaults.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Script-scope copy: a profile or the caller cannot inject cmdlet defaults (for example
# a default -Path or -Encoding) into these scripts.
$PSDefaultParameterValues = @{}

# ---- Fixed layout (no site values here) --------------------------------------------------
$script:PmcServiceName      = 'ProxmoxMCPBroker'
$script:PmcServiceAccount   = 'NT SERVICE\ProxmoxMCPBroker'
$script:PmcCfServiceName    = 'cloudflared-proxmox-mcp'
$script:PmcCfServiceAccount = 'NT SERVICE\cloudflared-proxmox-mcp'
$script:PmcProgramDir       = Join-Path $env:ProgramFiles 'ProxmoxMCP'
$script:PmcPythonDir        = Join-Path $script:PmcProgramDir 'python'
$script:PmcPythonExe        = Join-Path $script:PmcPythonDir 'python.exe'
$script:PmcVenvRoot         = Join-Path $script:PmcProgramDir 'venvs'
$script:PmcLegacyVenvDir    = Join-Path $script:PmcProgramDir 'venv'
$script:PmcStagingDir       = Join-Path $script:PmcProgramDir 'staging'
$script:PmcServiceDir       = Join-Path $script:PmcProgramDir 'service'
$script:PmcScriptsDir       = Join-Path $script:PmcProgramDir 'scripts'
$script:PmcMarkerFile       = Join-Path $script:PmcProgramDir 'installed.json'
$script:PmcDataDir          = Join-Path $env:ProgramData 'ProxmoxMCP'
$script:PmcCredDir          = Join-Path $script:PmcDataDir 'credentials'
$script:PmcLogDir           = Join-Path $script:PmcDataDir 'logs'
$script:PmcConfigDir        = Join-Path $script:PmcDataDir 'config'
$script:PmcShipDir          = Join-Path $script:PmcDataDir 'ship'
$script:PmcEvidenceDir      = Join-Path $script:PmcDataDir 'evidence'
$script:PmcCfDir            = Join-Path $script:PmcDataDir 'cloudflared'
$script:PmcEntropyFile      = Join-Path $script:PmcCredDir 'dpapi-entropy.bin'
$script:PmcAuditLog         = Join-Path $script:PmcLogDir 'audit.jsonl'
$script:PmcEnvFile          = Join-Path $script:PmcConfigDir 'broker.env'
$script:PmcExpiryFile       = Join-Path $script:PmcConfigDir 'token-expiry.json'

# Well-known SIDs, so ACLs do not depend on the OS language.
$script:SidAdmins      = '*S-1-5-32-544'
$script:SidSystem      = '*S-1-5-18'
# OWNER RIGHTS: an ACE for this SID replaces the implicit READ_CONTROL and WRITE_DAC
# rights of the object owner. Without it, the service owns the files it creates and
# could rewrite their DACL (for example grant itself Delete on the audit log).
$script:SidOwnerRights = '*S-1-3-4'

# Variables the installer may write to broker.env. Same names as KNOWN_VARS in
# proxmox_mcp/config.py; config.load(role="broker") refuses any other PROXMOX_/MCP_/
# BROKER_/CF_ACCESS_ name.
$script:PmcEnvAllowed = @(
    'PROXMOX_HOST', 'PROXMOX_PORT', 'PROXMOX_CA_BUNDLE', 'PROXMOX_TLS_FINGERPRINT',
    'PROXMOX_READ_ONLY', 'PROXMOX_TIMEOUT', 'PROXMOX_TOTAL_TIMEOUT', 'PROXMOX_MAX_RESPONSE_BYTES',
    'MCP_TOOL_MODE', 'MCP_ALLOW_ADMIN_TOOLS', 'MCP_TOOL_ALLOW', 'MCP_TOOL_DENY',
    'MCP_RATE_PER_MIN', 'MCP_RATE_PER_DAY', 'MCP_MAX_RESULT_BYTES', 'MCP_PHI_CONTACT',
    'MCP_BIND', 'MCP_PORT', 'MCP_ALLOWED_HOSTS', 'MCP_MAX_REQUEST_BYTES', 'MCP_REQUEST_TIMEOUT',
    'MCP_BODY_TIMEOUT', 'MCP_HEADER_TIMEOUT', 'MCP_MAX_CONCURRENCY',
    'BROKER_REQUIRE_ACCESS_JWT', 'BROKER_ALLOWED_SERVICE_CLIENT_IDS',
    'CF_ACCESS_TEAM_DOMAIN', 'CF_ACCESS_AUD'
)
# Never written by any script in this folder (DANGEROUS flags or stdio-only secrets).
$script:PmcEnvForbidden = @('PROXMOX_INSECURE_TLS', 'MCP_ALLOW_NON_LOOPBACK', 'MCP_ALLOW_SERVICE_TOKENS',
    'PROXMOX_USER', 'PROXMOX_TOKEN_NAME', 'PROXMOX_TOKEN_VALUE', 'PROXMOX_PASSWORD', 'MCP_LOCAL_MODE')

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    # Information stream: visible on the console, and capturable with 6>&1.
    Write-Information -MessageData "==> $Message" -InformationAction Continue
}

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell (Run as Administrator).'
    }
}

function Initialize-PmcTlsProtocol {
    # Windows PowerShell 5.1 (.NET Framework) may default to SSL3/TLS 1.0. Add TLS 1.2 and
    # keep TLS 1.3 when the OS offers it; remove the old protocols.
    $p = [Net.ServicePointManager]::SecurityProtocol
    $p = $p -bor [Net.SecurityProtocolType]::Tls12
    foreach ($old in @('Ssl3', 'Tls', 'Tls11')) {
        $v = $old -as [Net.SecurityProtocolType]
        if ($null -ne $v) { $p = $p -band (-bnot $v) }
    }
    [Net.ServicePointManager]::SecurityProtocol = $p
}

function Assert-Sha256 {
    # Fail closed when the expected hash is missing, malformed or different.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Expected
    )
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Expected SHA-256 for '$Path' is not 64 hex characters."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    if ($actual.ToUpperInvariant() -ne $Expected.ToUpperInvariant()) {
        throw "SHA-256 mismatch for '$Path'. Expected $Expected, got $actual. Do not continue."
    }
}

function Assert-AuthenticodeSigner {
    # Valid signature, chain trusted by this machine, signer CN equals the expected name.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SignerCommonName
    )
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') {
        throw "Authenticode signature of '$Path' is not valid: $($sig.Status) $($sig.StatusMessage)"
    }
    $cn = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($cn -ne $SignerCommonName) {
        throw "Unexpected signer for '$Path': '$cn' (expected '$SignerCommonName')."
    }
}

function Invoke-Native {
    # Run a native command and throw on a non-zero exit code. Never pass secrets as arguments.
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$OkExitCodes = @(0)
    )
    & $FilePath @ArgumentList
    $code = $LASTEXITCODE
    if ($OkExitCodes -notcontains $code) {
        throw "'$FilePath $($ArgumentList -join ' ')' failed with exit code $code."
    }
}

function Assert-PmcNotReparsePoint {
    # A junction or symlink in a security-relevant path can redirect writes elsewhere.
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "'$Path' is a junction or symbolic link. Remove it and investigate who created it."
        }
    }
}

function Assert-PmcTrustedOwner {
    # Only Administrators, SYSTEM or TrustedInstaller may own a pre-existing broker path.
    # Any user can create folders in C:\ProgramData. A folder created there in advance by
    # another account stays under that account's control (owner = WRITE_DAC).
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    $ok = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($ok -notcontains $owner) {
        throw "'$Path' is owned by $owner, not Administrators or SYSTEM. Someone created it before the installer. Investigate, then delete it."
    }
}

function Assert-PmcTrustedTree {
    # Every item below $Path: no junction or symlink, owner Administrators, SYSTEM,
    # TrustedInstaller or one of the two broker service SIDs. Used where per-file ACLs must
    # survive (credentials), so the tree is checked instead of reset.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $ok = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    foreach ($acct in @($script:PmcServiceAccount, $script:PmcCfServiceAccount)) {
        try { $ok += (New-Object Security.Principal.NTAccount($acct)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { Write-Verbose "$acct does not exist yet." }
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "'$($child.FullName)' is a junction or symbolic link inside a broker directory. Investigate."
        }
        $owner = (Get-Acl -LiteralPath $child.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($ok -notcontains $owner) {
            throw "'$($child.FullName)' is owned by $owner. Only Administrators, SYSTEM or the broker services may own files here. Investigate, then delete it."
        }
    }
}

function New-PmcDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    Assert-PmcNotReparsePoint -Path $Path
    Assert-PmcTrustedOwner -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }
}

function Set-PmcAcl {
    # Replace the DACL of a file or directory: owner Administrators, no inheritance, exactly
    # the listed entries. Grants use icacls syntax, for example
    #   "*S-1-5-32-544:(OI)(CI)F"  or  "NT SERVICE\ProxmoxMCPBroker:(OI)(CI)RX".
    # -ResetChildren: every existing child gets owner Administrators and inherits only
    # from this directory (removes explicit ACEs that a pre-created file may carry).
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Grant,
        [switch]$ResetChildren
    )
    if (-not $PSCmdlet.ShouldProcess($Path, "Set ACL: $($Grant -join ', ')")) { return }
    Assert-PmcNotReparsePoint -Path $Path
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    # Owner = Administrators, so no other account keeps WRITE_DAC through ownership.
    Invoke-Native $icacls @($Path, '/setowner', '*S-1-5-32-544', '/Q')
    $args2 = @($Path, '/inheritance:r', '/Q')
    foreach ($g in $Grant) { $args2 += @('/grant:r', $g) }
    Invoke-Native $icacls $args2
    # Remove every entry that is not in the grant list (CREATOR OWNER, Users, ...).
    $keepSids = @()
    foreach ($g in $Grant) {
        $who = ($g -split ':\(|:[A-Z]')[0]
        if ($who.StartsWith('*')) {
            $keepSids += $who.Substring(1)
        } else {
            $keepSids += (New-Object Security.Principal.NTAccount($who)).Translate([Security.Principal.SecurityIdentifier]).Value
        }
    }
    $acl = Get-Acl -LiteralPath $Path
    foreach ($ace in @($acl.Access)) {
        $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($keepSids -notcontains $sid) {
            Invoke-Native $icacls @($Path, '/remove:g', "*$sid", '/Q')
        }
    }
    if ($ResetChildren -and (Test-Path -LiteralPath $Path -PathType Container)) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "'$($child.FullName)' is a junction or symbolic link inside a broker directory. Investigate."
            }
        }
        $children = Join-Path $Path '*'
        if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
            Invoke-Native $icacls @($children, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q')
            Invoke-Native $icacls @($children, '/reset', '/T', '/C', '/Q')
        }
    }
}

function Read-PmcSecret {
    # Read one secret from redirected stdin (ssh pipe, file redirect) or from the console
    # without echo. Never accept a secret as a parameter: parameters land in history, logs
    # and process listings (event 4688 with command line).
    param([string]$Prompt = 'Secret')
    if ([Console]::IsInputRedirected) {
        $text = [Console]::In.ReadToEnd()
    } else {
        $sec = Read-Host -Prompt $Prompt -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try {
            $text = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            $sec.Dispose()
        }
    }
    if ($null -eq $text) { $text = '' }
    # Strip one trailing newline (CRLF or LF), like the broker does on read.
    $text = $text -replace "(\r?\n)\z", ''
    if ($text.Length -eq 0) { throw 'No secret received.' }
    if ($text.Length -gt 65536) { throw 'Secret is larger than 64 KiB.' }
    return $text
}

function Initialize-PmcDpapi {
    # [System.Security.Cryptography.ProtectedData]: in System.Security.dll on .NET
    # Framework (Windows PowerShell 5.1) and shipped with PowerShell 7 on Windows.
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    } catch {
        Write-Verbose 'System.Security assembly not loaded by name; trying the type directly.'
    }
    $t = 'System.Security.Cryptography.ProtectedData' -as [type]
    if ($null -eq $t) {
        throw 'ProtectedData is not available. Use the package CLI: proxmox-mcp-protect-credential.'
    }
}

function Get-PmcEntropy {
    # The whole file, byte for byte: proxmox_mcp.credentials._dpapi_entropy reads the same.
    if (-not (Test-Path -LiteralPath $script:PmcEntropyFile -PathType Leaf)) {
        throw "DPAPI entropy file '$($script:PmcEntropyFile)' is missing. Run Install-ProxmoxMcpBroker.ps1 first."
    }
    return [IO.File]::ReadAllBytes($script:PmcEntropyFile)
}

function Protect-PmcData {
    # DPAPI, LocalMachine scope, with the broker entropy. ProtectedData.Protect always sets
    # CRYPTPROTECT_UI_FORBIDDEN and adds CRYPTPROTECT_LOCAL_MACHINE for this scope: the same
    # flags as proxmox_mcp.credentials.dpapi_protect, so the broker can decrypt the blob.
    # Takes bytes, never a string, so no logging layer can record the value.
    param([Parameter(Mandatory)][byte[]]$Data)
    Initialize-PmcDpapi
    $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    return [System.Security.Cryptography.ProtectedData]::Protect($Data, (Get-PmcEntropy), $scope)
}

function Unprotect-PmcData {
    param([Parameter(Mandatory)][byte[]]$Data)
    Initialize-PmcDpapi
    $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    return [System.Security.Cryptography.ProtectedData]::Unprotect($Data, (Get-PmcEntropy), $scope)
}

function Read-PmcProtectedText {
    # Decrypt <credentials>\<Name>.dpapi to a string. Caller must clear the variable.
    param([Parameter(Mandatory)][string]$Name)
    Assert-PmcName -Name $Name
    $path = Join-Path $script:PmcCredDir ($Name + '.dpapi')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Credential '$Name' not found."
    }
    Assert-PmcNotReparsePoint -Path $path
    $plain = Unprotect-PmcData -Data ([IO.File]::ReadAllBytes($path))
    try {
        return [Text.Encoding]::UTF8.GetString($plain)
    } finally {
        [Array]::Clear($plain, 0, $plain.Length)
    }
}

function Assert-PmcName {
    # Same rule as proxmox_mcp.credentials.NAME_RE. A name can never be a path.
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or $Name -like '*.dpapi' -or $Name.Contains('..')) {
        throw "Invalid credential name '$Name'."
    }
}

function Write-PmcFileAtomic {
    # Write bytes to a temp file in the target directory, set its ACL, then replace the
    # target. There is never a window in which the target has a loose ACL.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string[]]$Grant
    )
    if (-not $PSCmdlet.ShouldProcess($Path, 'Write file (ACL first, then replace)')) { return }
    Assert-PmcNotReparsePoint -Path $Path
    $dir = Split-Path -Parent $Path
    $tmp = Join-Path $dir ('.tmp-' + [guid]::NewGuid().ToString('N'))
    try {
        $fs = New-Object IO.FileStream($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $fs.Write($Bytes, 0, $Bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
        Set-PmcAcl -Path $tmp -Grant $Grant -Confirm:$false
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    }
}

# ---- Artifacts --------------------------------------------------------------------------------

function Copy-PmcVerifiedArtifact {
    # TOCTOU defence: copy the artifact into an Administrators-only staging folder first,
    # then check the hash of THAT copy. The copy is the file that runs. A file in a
    # Downloads folder can be swapped between "hash checked" and "executed"; the staged
    # copy cannot, because only Administrators and SYSTEM can write the staging folder.
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][string]$StagingDir
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "File not found: $Source" }
    $dest = Join-Path $StagingDir (Split-Path -Leaf $Source)
    Copy-Item -LiteralPath $Source -Destination $dest -Force
    # Drop the Mark of the Web, if any: the hash and signature checks are the trust decision.
    Remove-Item -LiteralPath $dest -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
    Assert-Sha256 -Path $dest -Expected $Sha256
    return $dest
}

function New-PmcStagingDir {
    # A fresh, Administrators/SYSTEM-only folder under Program Files\ProxmoxMCP\staging.
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $PSCmdlet.ShouldProcess($script:PmcStagingDir, 'Create private staging folder')) { return $null }
    $root = $script:PmcStagingDir
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    Set-PmcAcl -Path $root -Grant @("$($script:SidAdmins):(OI)(CI)F", "$($script:SidSystem):(OI)(CI)F") -Confirm:$false
    $dir = Join-Path $root ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    return $dir
}

function Get-PmcLockPythonVersion {
    # The lock header names the interpreter the hashes were computed for, e.g.
    #   "# Broker runtime lock: CPython 3.14 on win_amd64 ..."
    # Returns "3.14". The installer refuses any other major.minor: a wheel built for
    # another ABI is either refused by pip or, worse, missing a hash for that ABI.
    param([Parameter(Mandatory)][string]$LockPath)
    $head = @(Get-Content -LiteralPath $LockPath -TotalCount 10)
    foreach ($line in $head) {
        if ($line -match '^#.*\bCPython (3\.\d{1,2})\b') { return $Matches[1] }
    }
    throw "The lock file '$LockPath' does not name its CPython version in the header (expected 'CPython 3.NN'). Regenerate it with requirements/generate_broker_lock.py."
}

# ---- Installed version (versioned venvs) --------------------------------------------------------

function Get-PmcInstalled {
    # installed.json: { active: {...}, previous: {...} }, each with venv, wheel, hashes, python.
    if (-not (Test-Path -LiteralPath $script:PmcMarkerFile)) { return $null }
    return (Get-Content -LiteralPath $script:PmcMarkerFile -Raw | ConvertFrom-Json)
}

function Get-PmcVenvDir {
    # The venv the service runs now. Falls back to the pre-versioning layout.
    $m = Get-PmcInstalled
    $active = Get-PmcProp $m 'active'
    $venv = Get-PmcProp $active 'venv'
    if ($venv -and (Test-Path -LiteralPath $venv -PathType Container)) { return [string]$venv }
    if (Test-Path -LiteralPath $script:PmcLegacyVenvDir -PathType Container) { return $script:PmcLegacyVenvDir }
    throw 'No broker virtual environment found. Run Install-ProxmoxMcpBroker.ps1.'
}

function Get-PmcTool {
    # Full path of a console entry point in the active venv, e.g. proxmox-mcp-selfcheck.
    param([Parameter(Mandatory)][ValidateSet('proxmox-mcp-http', 'proxmox-mcp-audit-verify',
            'proxmox-mcp-protect-credential', 'proxmox-mcp-selfcheck', 'python')][string]$Name)
    $p = Join-Path (Get-PmcVenvDir) ("Scripts\$Name.exe")
    if (-not (Test-Path -LiteralPath $p)) { throw "$Name.exe is missing from the broker venv. Reinstall with a current wheel." }
    return $p
}

# ---- broker.env -----------------------------------------------------------------------------------

function Read-PmcEnvFile {
    # broker.env: KEY=VALUE lines, # comments. Returns an ordered hashtable. Unknown keys,
    # forbidden keys and control characters are errors: this file feeds the service XML.
    param([string]$Path = $script:PmcEnvFile)
    $h = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $h }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { throw "broker.env: malformed line (no KEY=VALUE)." }
        $k = $t.Substring(0, $i).Trim()
        $v = $t.Substring($i + 1).Trim()
        Assert-PmcEnvEntry -Name $k -Value $v
        $h[$k] = $v
    }
    return $h
}

function Assert-PmcEnvEntry {
    param([Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Value)
    if ($Name -cnotmatch '^[A-Z][A-Z0-9_]{1,63}$') { throw "broker.env: invalid variable name '$Name'." }
    if ($script:PmcEnvForbidden -contains $Name) { throw "broker.env: $Name must never be set on the broker." }
    if ($script:PmcEnvAllowed -notcontains $Name) { throw "broker.env: unknown variable $Name (config.py would refuse to start)." }
    # No control characters, no '%' (WinSW expands %VAR% in <env> values), no quotes or
    # angle brackets (defence in depth for the XML), no leading/trailing space.
    if ($Value -match '[\x00-\x1f\x7f%"<>&'']' -or $Value -ne $Value.Trim()) {
        throw "broker.env: $Name has a character that is not allowed."
    }
}

# ---- Firewall helpers -----------------------------------------------------------------------------

function ConvertTo-PmcIPv4Range {
    # "192.0.2.0/24" or "192.0.2.10" -> [uint64 start, uint64 end]
    param([Parameter(Mandatory)][string]$Cidr)
    $parts = $Cidr.Split('/')
    if ($parts.Count -gt 2) { throw "Bad CIDR '$Cidr'." }
    $ip = [Net.IPAddress]::Parse($parts[0])
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 is supported here: '$Cidr'."
    }
    $len = 32
    if ($parts.Count -eq 2) { $len = [int]$parts[1] }
    if ($len -lt 0 -or $len -gt 32) { throw "Bad prefix length in '$Cidr'." }
    $b = $ip.GetAddressBytes()
    [Array]::Reverse($b)
    $n = [uint64][BitConverter]::ToUInt32($b, 0)
    $size = [uint64]1 -shl (32 - $len)
    if ($len -eq 0) { $size = [uint64]4294967296 }
    $start = [uint64]($n - ($n % $size))
    return @($start, [uint64]($start + $size - 1))
}

function ConvertFrom-PmcUInt32 {
    param([Parameter(Mandatory)][uint64]$Value)
    $b = [BitConverter]::GetBytes([uint32]$Value)
    [Array]::Reverse($b)
    return ([Net.IPAddress]::new($b)).ToString()
}

function Get-PmcIPv4Complement {
    # Every IPv4 range NOT covered by the given CIDRs, as "a.b.c.d-e.f.g.h" strings.
    # Used for block rules: Windows Firewall evaluates block before allow, so a
    # block rule must exclude the allowed destinations explicitly.
    param([Parameter(Mandatory)][string[]]$Cidr)
    $ranges = @()
    foreach ($c in $Cidr) { $ranges += , (ConvertTo-PmcIPv4Range $c) }
    $ranges = @($ranges | Sort-Object { $_[0] })
    $out = @()
    [uint64]$cursor = 0
    foreach ($r in $ranges) {
        if ($r[0] -gt $cursor) {
            $out += ('{0}-{1}' -f (ConvertFrom-PmcUInt32 $cursor), (ConvertFrom-PmcUInt32 ($r[0] - 1)))
        }
        if ($r[1] + 1 -gt $cursor) { $cursor = $r[1] + 1 }
    }
    if ($cursor -le 4294967295) {
        $out += ('{0}-{1}' -f (ConvertFrom-PmcUInt32 $cursor), '255.255.255.255')
    }
    return $out
}

function Get-PmcPortComplement {
    # "1-442","444-7843",... for the ports NOT in the list.
    param([Parameter(Mandatory)][int[]]$Port)
    $sorted = @($Port | Sort-Object -Unique)
    $out = @()
    $cursor = 1
    foreach ($p in $sorted) {
        if ($p -gt $cursor) {
            if ($p - 1 -eq $cursor) { $out += "$cursor" } else { $out += "$cursor-$($p - 1)" }
        }
        $cursor = $p + 1
    }
    if ($cursor -le 65535) { $out += "$cursor-65535" }
    return $out
}

function Get-PmcProp {
    # Property value or $null. Set-StrictMode -Version Latest throws on a missing property
    # of a PSCustomObject from ConvertFrom-Json; API objects omit empty fields.
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Invoke-PmcBrokerTool {
    # Run a broker console tool (selfcheck, audit-verify) with exactly the service's
    # configuration: broker.env plus the fixed paths. The current process environment is
    # restored afterwards. Returns @{ Code = <exit code>; Output = <stdout text> }.
    param(
        [Parameter(Mandatory)][string]$Tool,
        [string[]]$ArgumentList = @()
    )
    $envMap = Read-PmcEnvFile
    $fixed = Get-PmcFixedEnv
    $names = @($envMap.Keys) + @($fixed.Keys)
    # Clear every checked-prefix variable of this shell first: config.py would refuse an
    # unrelated PROXMOX_*/MCP_* variable that happens to be set in the admin session.
    $saved = @{}
    foreach ($e in @(Get-ChildItem Env:)) {
        if ($e.Name -match '^(PROXMOX_|MCP_|BROKER_|CF_ACCESS_)' -or $names -contains $e.Name) {
            $saved[$e.Name] = $e.Value
            [Environment]::SetEnvironmentVariable($e.Name, $null, 'Process')
        }
    }
    try {
        foreach ($k in $envMap.Keys) { if ($envMap[$k] -ne '') { [Environment]::SetEnvironmentVariable($k, $envMap[$k], 'Process') } }
        foreach ($k in $fixed.Keys) { [Environment]::SetEnvironmentVariable($k, $fixed[$k], 'Process') }
        $exe = Get-PmcTool -Name $Tool
        $out = & $exe @ArgumentList 2>$null | Out-String
        return @{ Code = $LASTEXITCODE; Output = $out }
    } finally {
        foreach ($k in $names) { [Environment]::SetEnvironmentVariable($k, $null, 'Process') }
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
}

function Get-PmcFixedEnv {
    # Fixed paths and settings of the service: not operator settings.
    return [ordered]@{
        BROKER_CREDENTIALS_DIR    = $script:PmcCredDir
        BROKER_DPAPI_ENTROPY_FILE = $script:PmcEntropyFile
        MCP_ENROLLMENT_FILE       = (Join-Path $script:PmcCredDir 'enrollment.json')
        MCP_AUDIT_LOG             = $script:PmcAuditLog
        # Production: no key, no audit, no service (proxmox_mcp/audit.py).
        MCP_AUDIT_HMAC            = 'required'
        PYTHONDONTWRITEBYTECODE   = '1'
        PYTHONNOUSERSITE          = '1'
        PYTHONUTF8                = '1'
    }
}
