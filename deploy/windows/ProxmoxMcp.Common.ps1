# ProxmoxMcp.Common.ps1: shared helpers for the Proxmox MCP broker scripts.
# Dot-source this file from a script that has [CmdletBinding(SupportsShouldProcess)].
# Dot-sourcing (not Import-Module) keeps -WhatIf working: the helpers run in the
# caller's scope and see its $WhatIfPreference.
# Compatible with Windows PowerShell 5.1 and PowerShell 7.x.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- Fixed layout (no site values here) --------------------------------------------------
$script:PmcServiceName      = 'ProxmoxMCPBroker'
$script:PmcServiceAccount   = 'NT SERVICE\ProxmoxMCPBroker'
$script:PmcCfServiceName    = 'cloudflared-proxmox-mcp'
$script:PmcCfServiceAccount = 'NT SERVICE\cloudflared-proxmox-mcp'
$script:PmcProgramDir       = Join-Path $env:ProgramFiles 'ProxmoxMCP'
$script:PmcPythonDir        = Join-Path $script:PmcProgramDir 'python'
$script:PmcPythonExe        = Join-Path $script:PmcPythonDir 'python.exe'
$script:PmcVenvDir          = Join-Path $script:PmcProgramDir 'venv'
$script:PmcServiceDir       = Join-Path $script:PmcProgramDir 'service'
$script:PmcScriptsDir       = Join-Path $script:PmcProgramDir 'scripts'
$script:PmcDataDir          = Join-Path $env:ProgramData 'ProxmoxMCP'
$script:PmcCredDir          = Join-Path $script:PmcDataDir 'credentials'
$script:PmcLogDir           = Join-Path $script:PmcDataDir 'logs'
$script:PmcConfigDir        = Join-Path $script:PmcDataDir 'config'
$script:PmcShipDir          = Join-Path $script:PmcDataDir 'ship'
$script:PmcCfDir            = Join-Path $script:PmcDataDir 'cloudflared'
$script:PmcEntropyFile      = Join-Path $script:PmcCredDir 'dpapi-entropy.bin'
$script:PmcAuditLog         = Join-Path $script:PmcLogDir 'audit.jsonl'
$script:PmcEnvFile          = Join-Path $script:PmcConfigDir 'broker.env'

# Well-known SIDs, so ACLs do not depend on the OS language.
$script:SidAdmins = '*S-1-5-32-544'
$script:SidSystem = '*S-1-5-18'

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "==> $Message"
}

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell (Run as Administrator).'
    }
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
    # Valid signature, chain trusted by this machine, signer subject matches the pattern.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SubjectPattern
    )
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') {
        throw "Authenticode signature of '$Path' is not valid: $($sig.Status) $($sig.StatusMessage)"
    }
    if ($sig.SignerCertificate.Subject -notmatch $SubjectPattern) {
        throw "Unexpected signer for '$Path': $($sig.SignerCertificate.Subject)"
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

function New-PmcDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }
}

function Set-PmcAcl {
    # Replace the DACL of a file or directory: remove inheritance, then grant exactly
    # the listed entries. Grants use icacls syntax, for example
    #   "*S-1-5-32-544:(OI)(CI)F"  or  "NT SERVICE\ProxmoxMCPBroker:(OI)(CI)RX".
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Grant
    )
    if (-not $PSCmdlet.ShouldProcess($Path, "Set ACL: $($Grant -join ', ')")) { return }
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    # Owner = Administrators, so no other account keeps WRITE_DAC through ownership.
    Invoke-Native $icacls @($Path, '/setowner', '*S-1-5-32-544', '/Q')
    $args2 = @($Path, '/inheritance:r', '/Q')
    foreach ($g in $Grant) { $args2 += @('/grant:r', $g) }
    Invoke-Native $icacls $args2
    # Remove every entry that is not in the grant list (e.g. CREATOR OWNER, Users).
    $keep = @()
    foreach ($g in $Grant) { $keep += ($g -split ':')[0] }
    $acl = Get-Acl -LiteralPath $Path
    foreach ($ace in @($acl.Access)) {
        $name = $ace.IdentityReference.Value
        try {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $name
        }
        $match = $false
        foreach ($k in $keep) {
            if ($k -eq "*$sid" -or $k -ieq $name) { $match = $true }
        }
        if (-not $match) {
            Invoke-Native $icacls @($Path, '/remove:g', $name, '/Q')
        }
    }
}

function Read-PmcSecret {
    # Read one secret from stdin (when piped) or from the console without echo.
    # Never accept a secret as a parameter: parameters land in history, logs and
    # process listings (Event ID 4688 with command line auditing).
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
    if (-not (Test-Path -LiteralPath $script:PmcEntropyFile -PathType Leaf)) {
        throw "DPAPI entropy file '$($script:PmcEntropyFile)' is missing. Run Install-ProxmoxMcpBroker.ps1 first."
    }
    return [IO.File]::ReadAllBytes($script:PmcEntropyFile)
}

function Protect-PmcBytes {
    # DPAPI, LocalMachine scope, with the broker entropy. Same parameters as
    # proxmox_mcp.credentials.dpapi_protect (CRYPTPROTECT_LOCAL_MACHINE | UI_FORBIDDEN).
    param([Parameter(Mandatory)][byte[]]$Data)
    Initialize-PmcDpapi
    $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    return [System.Security.Cryptography.ProtectedData]::Protect($Data, (Get-PmcEntropy), $scope)
}

function Unprotect-PmcBytes {
    param([Parameter(Mandatory)][byte[]]$Data)
    Initialize-PmcDpapi
    $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    return [System.Security.Cryptography.ProtectedData]::Unprotect($Data, (Get-PmcEntropy), $scope)
}

function Read-PmcProtectedText {
    # Decrypt <credentials>\<Name>.dpapi to a string. Caller must clear the variable.
    param([Parameter(Mandatory)][string]$Name)
    $path = Join-Path $script:PmcCredDir ($Name + '.dpapi')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Credential '$Name' not found."
    }
    $plain = Unprotect-PmcBytes -Data ([IO.File]::ReadAllBytes($path))
    try {
        return [Text.Encoding]::UTF8.GetString($plain)
    } finally {
        [Array]::Clear($plain, 0, $plain.Length)
    }
}

function Assert-PmcName {
    # Same rule as proxmox_mcp.credentials.NAME_RE. A name can never be a path.
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or $Name -like '*.dpapi') {
        throw "Invalid credential name '$Name'."
    }
}

function ConvertTo-PmcIPv4Range {
    # "192.0.2.0/24" or "192.0.2.10" -> [uint32 start, uint32 end]
    param([Parameter(Mandatory)][string]$Cidr)
    $parts = $Cidr.Split('/')
    $ip = [Net.IPAddress]::Parse($parts[0])
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 is supported here: '$Cidr'."
    }
    $len = 32
    if ($parts.Count -eq 2) { $len = [int]$parts[1] }
    if ($len -lt 0 -or $len -gt 32) { throw "Bad prefix length in '$Cidr'." }
    $b = $ip.GetAddressBytes()
    [Array]::Reverse($b)
    $n = [BitConverter]::ToUInt32($b, 0)
    $size = [uint64][math]::Pow(2, 32 - $len)
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

function Read-PmcEnvFile {
    # broker.env: KEY=VALUE lines, # comments. Returns an ordered hashtable.
    param([string]$Path = $script:PmcEnvFile)
    $h = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $h }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { continue }
        $h[$t.Substring(0, $i).Trim()] = $t.Substring($i + 1).Trim()
    }
    return $h
}

function Get-PmcProp {
    # Property value or $null. Set-StrictMode -Version Latest throws on a missing property
    # of a PSCustomObject from ConvertFrom-Json; API objects omit empty fields.
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}
