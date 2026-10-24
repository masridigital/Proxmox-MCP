<#
.SYNOPSIS
Stores one broker secret in C:\ProgramData\ProxmoxMCP\credentials as <Name>.dpapi.

.DESCRIPTION
The secret comes from stdin (piped) or from a hidden console prompt. It is never a
parameter, so it never appears in command history, transcripts or process-creation
events (4688 with command line).

Encryption: DPAPI, LocalMachine scope, plus the broker entropy file
(credentials\dpapi-entropy.bin). This matches proxmox_mcp.credentials (ctypes
CryptUnprotectData). LocalMachine scope means any local process could call DPAPI; the
file ACL and the entropy file ACL are what keep other accounts out. DPAPI keeps the
secret unreadable in backups and copies taken off this host.

Readers: the broker service SID by default. Use -Reader System for secrets that only
the SYSTEM scheduled task uses (the audit shipping SAS).

Known names and the checks applied:
  pve-token-<short>   one line  user@realm!tokenname=<uuid>  (Proxmox API token)
  worker-identity.pub Ed25519 public key PEM (not secret; use -NoEncrypt; ACL still applies)
  audit-ship-sas      Azure Blob container SAS query string, permissions c only
  pve-review-token    read-only token for Export-AccessReview.ps1 (-Reader Administrators)

.EXAMPLE
# From the Proxmox host straight into DPAPI. The token is never on disk or in argv:
ssh root@pve.example.internal 'bash -s -- issue-token alice ro' < deploy/proxmox/setup-proxmox-access.sh |
  ssh admin@broker.example.internal "pwsh -NoProfile -File 'C:\Program Files\ProxmoxMCP\scripts\Protect-BrokerCredential.ps1' -Name pve-token-alice"

.EXAMPLE
Get-Content .\worker-identity.pub | .\Protect-BrokerCredential.ps1 -Name worker-identity.pub -NoEncrypt
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Name,
    [ValidateSet('Service', 'System', 'Administrators')][string]$Reader = 'Service',
    # Store as plain file (public key only). The ACL still applies.
    [switch]$NoEncrypt,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')

Assert-Administrator
Assert-PmcName -Name $Name
if (-not (Test-Path -LiteralPath $PmcCredDir -PathType Container)) {
    throw "$PmcCredDir does not exist. Run Install-ProxmoxMcpBroker.ps1 first."
}
if ($Name -eq 'enrollment.json') { throw 'Use Set-BrokerEnrollment.ps1 for the enrollment list.' }

$target = Join-Path $PmcCredDir $Name
if (-not $NoEncrypt) { $target = "$target.dpapi" }
$other = if ($NoEncrypt) { "$(Join-Path $PmcCredDir $Name).dpapi" } else { Join-Path $PmcCredDir $Name }
if ((Test-Path -LiteralPath $target) -and -not $Force) {
    throw "$target exists. Pass -Force to replace it (rotation)."
}

$secret = Read-PmcSecret -Prompt "Value for $Name"
try {
    # ---- Validate the shape, never echo the value -------------------------------------
    switch -Regex ($Name) {
        '^pve-(token-[A-Za-z0-9_.-]+|review-token)$' {
            $re = '^[A-Za-z0-9._+-]{1,64}@[A-Za-z][A-Za-z0-9._-]{0,31}![A-Za-z][A-Za-z0-9._-]{0,63}=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            if ($secret -notmatch $re) { throw "Value for $Name is not 'user@realm!tokenname=<uuid>'." }
            if ($secret -match '^root@pam!') { throw 'root@pam tokens are refused.' }
        }
        '^worker-identity\.pub$' {
            if ($secret -notmatch '^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*$') {
                throw 'worker-identity.pub must be a PEM SubjectPublicKeyInfo (Ed25519).'
            }
            if ($secret -match 'PRIVATE KEY') { throw 'This is a private key. Store only the public key on the broker.' }
        }
        '^audit-ship-sas$' {
            if ($secret -notmatch '(^|[?&])sp=c(&|$)') {
                throw 'audit-ship-sas must be a SAS with permissions sp=c only (create; no read, write, delete or list).'
            }
            if ($secret -notmatch '(^|[?&])spr=https(&|$)') { throw 'audit-ship-sas must be HTTPS-only (spr=https).' }
        }
        default { Write-Verbose "No shape check for $Name." }
    }

    if (-not $PSCmdlet.ShouldProcess($target, "Store credential (reader: $Reader, encrypted: $(-not $NoEncrypt))")) { return }

    $bytes = [Text.Encoding]::UTF8.GetBytes($secret)
    try {
        if (-not $NoEncrypt) {
            $blob = Protect-PmcBytes -Data $bytes
        } else {
            $blob = $bytes
        }
        # Write next to the target, set the ACL, then replace: no window with a loose ACL.
        $tmp = Join-Path $PmcCredDir ('.tmp-' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllBytes($tmp, $blob)
        $grants = @("$($SidAdmins):F", "$($SidSystem):F")
        switch ($Reader) {
            'Service' { $grants += "$($PmcServiceAccount):R" }
            'System' { }
            'Administrators' { }
        }
        Set-PmcAcl -Path $tmp -Grant $grants
        Move-Item -LiteralPath $tmp -Destination $target -Force
        # Only one form may exist; the broker prefers .dpapi and a stale twin is confusing.
        if (Test-Path -LiteralPath $other) { Remove-Item -LiteralPath $other -Force }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
} finally {
    $secret = $null
    [GC]::Collect()
}
Write-Step "Stored $target. Restart the broker to pick up a changed key: Restart-Service $PmcServiceName"
