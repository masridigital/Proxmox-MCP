<#
.SYNOPSIS
Two-person escrow of the audit HMAC key: splits audit-hmac.key into two shares, or joins
two shares into a key file for the auditor's verifier.

.DESCRIPTION
The audit HMAC key (credentials\audit-hmac.key.dpapi) authenticates every audit line.
Auditors need a copy to verify shipped logs; nobody may hold a usable copy alone.

Split (on the broker, both custodians present, Administrators only):
  share A = 32 random bytes; share B = key XOR share A. One share alone reveals nothing
  about the key. Each share file holds: format line, key id (kid), share letter, the
  share in hex, and a checksum. The key id is the one written in every audit line (kid),
  computed exactly as proxmox_mcp.audit.key_id. The script writes each share straight to
  the path given (custodian A's and custodian B's encrypted removable media). It never
  shows the key or a share on screen and never uses the clipboard.

Join (auditor workstation, both custodians present): reads both shares, checks the
checksums and that the result has the recorded kid, and writes the key as 64 hex digits:
the format proxmox-mcp-audit-verify --key-file reads. Delete it after the verification.

Evidence: a split writes evidence\key-escrow\escrow-<kid>-<UTC time>.json (kid, custodian
role names, share checksums; no key material) and Application event 4301
(source ProxmoxMCP-KeyEscrow).

.EXAMPLE
.\Export-AuditKeyEscrow.ps1 -ShareAPath E:\audit-key-share-A.txt -ShareBPath F:\audit-key-share-B.txt `
  -CustodianA 'Security Officer' -CustodianB 'System Owner'

.EXAMPLE
.\Export-AuditKeyEscrow.ps1 -Join -ShareAPath E:\audit-key-share-A.txt -ShareBPath F:\audit-key-share-B.txt -OutFile .\audit-hmac.key
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Split')]
param(
    [Parameter(Mandatory)][string]$ShareAPath,
    [Parameter(Mandatory)][string]$ShareBPath,
    # Role names, not personal names (the evidence file is kept 6 years).
    [Parameter(Mandatory, ParameterSetName = 'Split')][ValidatePattern('^[A-Za-z0-9 ._-]{2,64}$')][string]$CustodianA,
    [Parameter(Mandatory, ParameterSetName = 'Split')][ValidatePattern('^[A-Za-z0-9 ._-]{2,64}$')][string]$CustodianB,
    [Parameter(Mandatory, ParameterSetName = 'Join')][switch]$Join,
    [Parameter(Mandatory, ParameterSetName = 'Join')][string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')

$format = 'proxmox-mcp-audit-key-share v1'

function Get-Sha256Hex([byte[]]$Data) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Data))).Replace('-', '').ToLowerInvariant() } finally { $h.Dispose() }
}
function ConvertFrom-Hex([string]$Hex) {
    if ($Hex -cnotmatch '^([0-9a-f]{2})+$') { throw 'not lower-case hex' }
    $b = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring(2 * $i, 2), 16) }
    return , $b
}
function ConvertTo-Hex([byte[]]$Data) { return ([BitConverter]::ToString($Data)).Replace('-', '').ToLowerInvariant() }
function Get-KeyId([byte[]]$Key) {
    # proxmox_mcp.audit.key_id: sha256("proxmox-mcp-audit-kid\0" || key)[:16]
    $domain = [Text.Encoding]::ASCII.GetBytes("proxmox-mcp-audit-kid`0")
    $buf = New-Object byte[] ($domain.Length + $Key.Length)
    [Array]::Copy($domain, $buf, $domain.Length)
    [Array]::Copy($Key, 0, $buf, $domain.Length, $Key.Length)
    try { return (Get-Sha256Hex $buf).Substring(0, 16) } finally { [Array]::Clear($buf, 0, $buf.Length) }
}
function Read-Share([string]$Path, [string]$Letter) {
    $lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).Path)
    $map = @{}
    if ($lines[0] -ne $format) { throw "$Path is not a key share ($format)." }
    foreach ($l in $lines[1..($lines.Count - 1)]) { if ($l -match '^([a-z]+)=(.*)$') { $map[$Matches[1]] = $Matches[2] } }
    if ($map['share'] -ne $Letter) { throw "$Path is share '$($map['share'])', expected '$Letter'." }
    $data = ConvertFrom-Hex $map['data']
    if ((Get-Sha256Hex $data).Substring(0, 16) -ne $map['check']) { throw "$Path checksum does not match (damaged share)." }
    return @{ Kid = $map['kid']; Data = $data }
}

if ($Join) {
    if (Test-Path -LiteralPath $OutFile) { throw "$OutFile exists. Refusing to overwrite." }
    $a = Read-Share $ShareAPath 'A'
    $b = Read-Share $ShareBPath 'B'
    if ($a.Kid -ne $b.Kid -or $a.Data.Length -ne $b.Data.Length) { throw 'The two shares belong to different keys.' }
    $key = New-Object byte[] $a.Data.Length
    try {
        for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = $a.Data[$i] -bxor $b.Data[$i] }
        if ((Get-KeyId $key) -ne $a.Kid) { throw 'Joined key does not have the recorded key id. Do not use it.' }
        if ($PSCmdlet.ShouldProcess($OutFile, "Write audit key (kid $($a.Kid))")) {
            [IO.File]::WriteAllText($OutFile, (ConvertTo-Hex $key), (New-Object Text.ASCIIEncoding))
            Write-Step "Wrote key kid $($a.Kid) to $OutFile. Use it with proxmox-mcp-audit-verify --key-file, then delete it."
        }
    } finally {
        [Array]::Clear($key, 0, $key.Length); [Array]::Clear($a.Data, 0, $a.Data.Length); [Array]::Clear($b.Data, 0, $b.Data.Length)
    }
    return
}

# ---- Split (broker) ----------------------------------------------------------------------------
Assert-Administrator
$pa = [IO.Path]::GetFullPath($ShareAPath); $pb = [IO.Path]::GetFullPath($ShareBPath)
if ([IO.Path]::GetPathRoot($pa) -eq [IO.Path]::GetPathRoot($pb)) {
    throw 'Share A and share B must be on different volumes (each custodian brings their own encrypted media).'
}
foreach ($p in @($pa, $pb)) {
    if (Test-Path -LiteralPath $p) { throw "$p exists. Refusing to overwrite a share." }
    if ([IO.Path]::GetPathRoot($p) -eq [IO.Path]::GetPathRoot($env:SystemRoot)) { throw "$p is on the system volume. Write shares to removable media only." }
}
if (-not $PSCmdlet.ShouldProcess("$pa and $pb", 'Split the audit HMAC key into two shares')) { return }

$text = Read-PmcProtectedText -Name 'audit-hmac.key'
$key = $null; $sa = $null; $sb = $null
try {
    $key = ConvertFrom-Hex ($text.Trim().ToLowerInvariant())
    $text = $null
    if ($key.Length -lt 32) { throw 'audit-hmac.key is shorter than 32 bytes.' }
    $kid = Get-KeyId $key
    $sa = New-Object byte[] $key.Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($sa) } finally { $rng.Dispose() }
    $sb = New-Object byte[] $key.Length
    for ($i = 0; $i -lt $key.Length; $i++) { $sb[$i] = $key[$i] -bxor $sa[$i] }
    $checks = @{}
    foreach ($s in @(@('A', $pa, $sa), @('B', $pb, $sb))) {
        $check = (Get-Sha256Hex $s[2]).Substring(0, 16)
        $checks[$s[0]] = $check
        $content = @($format, "kid=$kid", "share=$($s[0])", "data=$(ConvertTo-Hex $s[2])", "check=$check") -join "`r`n"
        [IO.File]::WriteAllText($s[1], $content + "`r`n", (New-Object Text.ASCIIEncoding))
    }
} finally {
    $text = $null
    foreach ($arr in @($key, $sa, $sb)) { if ($arr) { [Array]::Clear($arr, 0, $arr.Length) } }
}

$evDir = Join-Path $PmcEvidenceDir 'key-escrow'
New-PmcDirectory -Path $evDir -Confirm:$false
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$ev = [ordered]@{ event = 'audit-key-escrow'; time = $stamp; kid = $kid; host = $env:COMPUTERNAME.ToLowerInvariant()
    custodian_a = $CustodianA; custodian_b = $CustodianB; share_a_check = $checks['A']; share_b_check = $checks['B']
    operator = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
($ev | ConvertTo-Json) | Set-Content -LiteralPath (Join-Path $evDir "escrow-$kid-$stamp.json") -Encoding UTF8
$src = 'ProxmoxMCP-KeyEscrow'
try {
    if (-not [Diagnostics.EventLog]::SourceExists($src)) { [Diagnostics.EventLog]::CreateEventSource($src, 'Application') }
    [Diagnostics.EventLog]::WriteEntry($src, "Audit key kid $kid split into two shares (custodians: $CustodianA, $CustodianB).", 'Information', 4301)
} catch { Write-Verbose "Event log write failed: $($_.Exception.Message)" }
Write-Step "Key kid $kid split. Each custodian seals their share (tamper-evident bag), signs the escrow log, and stores it in a separate safe."
