<#
.SYNOPSIS
Verifies audit chunks downloaded from the WORM container (auditor tool, read-only).

.DESCRIPTION
1. For each chunk: SHA-256 of the bytes equals metadata "sha256".
2. Per (host, file id, generation): chunks are contiguous (offset = previous offset + length)
   and "prevsha256" equals the previous chunk's sha256. A gap or a fork is a FAIL.
3. Reassembles each file in order and runs proxmox-mcp-audit-verify over all files of a
   host in upload order, which checks the line hash chain (ph) across files.

Get the inputs with a reader identity (never the shipping credential, which cannot read):
  az storage blob list --account-name <acct> --container-name <container> --prefix proxmox-mcp/<host>/ `
     --include m --num-results '*' --auth-mode login -o json > blobs.json
  az storage blob download-batch --account-name <acct> --source <container> --pattern 'proxmox-mcp/<host>/*' `
     --destination .\dl --auth-mode login

.EXAMPLE
.\Test-ShippedAudit.ps1 -BlobListJson .\blobs.json -DownloadDir .\dl -KeyFile .\audit-hmac.key -Anchor <seq>:<hash> `
  -VerifyExe 'C:\Program Files\ProxmoxMCP\venv\Scripts\proxmox-mcp-audit-verify.exe'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BlobListJson,
    [Parameter(Mandatory)][string]$DownloadDir,
    [string]$VerifyExe,
    # Escrowed copy of audit-hmac.key (hex) and the newest anchor "SEQ:HASH" from <prefix>/<host>/anchors/.
    [string[]]$KeyFile = @(),
    [string]$Anchor,
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) ('pmc-verify-' + [guid]::NewGuid().ToString('N')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Meta($blob, [string]$name) {
    $m = $blob.metadata
    if ($null -eq $m) { return $null }
    $p = $m.PSObject.Properties[$name]
    if ($null -eq $p) { return $null }
    return [string]$p.Value
}

$blobs = @(Get-Content -LiteralPath $BlobListJson -Raw | ConvertFrom-Json | Where-Object { $_.name -like '*.jsonl' -and $_.name -notlike '*/canary/*' })
$groups = @{}
$fails = 0
foreach ($b in $blobs) {
    $local = Join-Path $DownloadDir ($b.name -replace '/', '\')
    if (-not (Test-Path -LiteralPath $local)) { Write-Output "FAIL missing download: $($b.name)"; $fails++; continue }
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $local).Hash.ToLowerInvariant()
    if ($sha -ne (Get-Meta $b 'sha256')) { Write-Output "FAIL sha256 mismatch: $($b.name)"; $fails++ }
    $leaf = Split-Path -Leaf $b.name
    if ($leaf -notmatch '^([0-9a-f]+)-g(\d+)-(\d{12})-(\d{12})\.jsonl$') { Write-Output "FAIL unexpected name: $($b.name)"; $fails++; continue }
    $key = '{0}|{1}|{2}' -f (Get-Meta $b 'host'), $Matches[1], $Matches[2]
    if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
    $groups[$key].Add([pscustomobject]@{ Name = $b.name; Local = $local; Offset = [int64]$Matches[3]; End = [int64]$Matches[4]
            Sha = $sha; Prev = (Get-Meta $b 'prevsha256'); Created = [datetime]$b.properties.creationTime })
}

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$assembled = @()
foreach ($key in $groups.Keys) {
    $chunks = @($groups[$key] | Sort-Object Offset)
    $expectOffset = [int64]0
    $prev = 'none'
    $out = Join-Path $WorkDir (($key -replace '\|', '_') + '.jsonl')
    $fs = [IO.File]::Create($out)
    try {
        foreach ($c in $chunks) {
            if ($c.Offset -ne $expectOffset) { Write-Output "FAIL gap or overlap in $key at $expectOffset (next chunk starts at $($c.Offset))"; $fails++ }
            if ($c.Prev -ne $prev) { Write-Output "FAIL prevsha256 chain broken at $($c.Name)"; $fails++ }
            $bytes = [IO.File]::ReadAllBytes($c.Local)
            $fs.Write($bytes, 0, $bytes.Length)
            $expectOffset = $c.End
            $prev = $c.Sha
        }
    } finally { $fs.Dispose() }
    $assembled += [pscustomobject]@{ Key = $key; Path = $out; First = ($chunks | Select-Object -First 1).Created; Chunks = $chunks.Count; Bytes = $expectOffset }
}
$assembled | Sort-Object First | Format-Table Key, Chunks, Bytes, First -AutoSize | Out-String | Write-Output

if ($VerifyExe) {
    $ordered = @($assembled | Sort-Object First | ForEach-Object Path)
    $vargs = @('--no-credential')
    foreach ($k in $KeyFile) { $vargs += @('--key-file', $k) }
    if ($KeyFile.Count -gt 0) { $vargs += '--require-mac' }
    if ($Anchor) { $vargs += @('--anchor', $Anchor) }
    & $VerifyExe @vargs @ordered
    if ($LASTEXITCODE -ne 0) { Write-Output "FAIL hash chain verify exit code $LASTEXITCODE"; $fails++ }
}
if ($fails -gt 0) { Write-Output "$fails failure(s)"; exit 1 }
$what = 'hashes, contiguity, chunk chain'
if ($VerifyExe) { $what += ', line hash chain' }
Write-Output "Shipped audit verified: $what"
exit 0
