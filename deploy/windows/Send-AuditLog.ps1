<#
.SYNOPSIS
Ships new audit bytes from the broker to WORM storage (Azure Blob, time-based immutability).

.DESCRIPTION
Runs every 5 minutes as SYSTEM (scheduled task "ProxmoxMCP Audit Ship"). For each local
audit file (archived audit-YYYYMM.jsonl and the live audit.jsonl) it uploads the complete
lines added since the last run as ONE new block blob:

  <prefix>/<host>/<yyyy>/<MM>/<dd>/<fileid>-g<generation>-<start>-<end>.jsonl
  metadata: sha256 (of the chunk), prevsha256 (previous chunk of the same file: a chain),
            host, fileid, offset, length.  Content-MD5 lets the service check transport.
  If-None-Match: *  so a blob is never replaced, even with a broader credential.

Also uploads, once each, the evidence files under C:\ProgramData\ProxmoxMCP\evidence
(selfcheck reports, access reviews) to <prefix>/<host>/evidence/, so they are WORM too.

Event IDs (Application log, source ProxmoxMCP-AuditShip): 4001 ok, 4002 rotated,
4003 immutability test ok, 4004 local file deleted after retention, 4101 file shrank,
4102 upload failed, 4103 immutability test failed, 4105 chain verify failed,
4106 SAS expires within 30 days.

Credentials, in order:
  - Azure Arc managed identity (when the Arc agent is present and -Auth Arc): bearer token
    from the local Arc identity endpoint. Give the identity a custom role with
    ".../blobs/write" only (no delete, no read).
  - SAS (default): credential "audit-ship-sas" (Protect-BrokerCredential.ps1 -Reader System),
    container scope, permission sp=c only (create new blobs; cannot read, list, overwrite
    or delete), HTTPS only, expiry within one year.

The container must have a time-based retention policy of 2190 days (6 years), locked.
Prove it with -TestImmutability (and -AdminCheck with the Azure CLI signed in).

File identity: Windows file ID (fsutil), not the name or creation time. A rename keeps
the ID. NTFS "file system tunneling" can give a new audit.jsonl the old creation time,
so creation time is not used.

Rotation (this script is the only rotator; the broker never rotates): when the live file
is fully shipped and its first-seen month is over, rename it to audit-YYYYMM.jsonl. The
broker continues the hash chain in the new audit.jsonl.
Retention: archived files older than 400 days are deleted only when fully shipped.

.EXAMPLE
.\Send-AuditLog.ps1 -Register -StorageAccount examplelogs -Container proxmox-mcp-audit
.\Send-AuditLog.ps1 -TestImmutability -AdminCheck
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Register')][switch]$Register,
    [Parameter(Mandatory, ParameterSetName = 'Register')][ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccount,
    [Parameter(Mandatory, ParameterSetName = 'Register')][ValidatePattern('^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$')][string]$Container,
    [Parameter(ParameterSetName = 'Register')][ValidateSet('Sas', 'Arc')][string]$Auth = 'Sas',
    [Parameter(ParameterSetName = 'Register')][string]$Prefix = 'proxmox-mcp',
    [Parameter(ParameterSetName = 'Register')][string]$BlobEndpointSuffix = 'blob.core.windows.net',

    [Parameter(Mandatory, ParameterSetName = 'Test')][switch]$TestImmutability,
    [Parameter(ParameterSetName = 'Test')][switch]$AdminCheck,

    [ValidateRange(1, 3650)][int]$LocalRetentionDays = 400
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProxmoxMcp.Common.ps1')
Assert-Administrator
Initialize-PmcTlsProtocol

$cfgFile = Join-Path $PmcConfigDir 'ship.json'
$stateFile = Join-Path $PmcShipDir 'state.json'
$eventSource = 'ProxmoxMCP-AuditShip'
$taskName = 'ProxmoxMCP Audit Ship'
$maxChunk = 32MB
$apiVersion = '2023-11-03'

function Write-ShipEvent {
    param([int]$Id, [string]$Message, [Diagnostics.EventLogEntryType]$Type = 'Information')
    try {
        if ([Diagnostics.EventLog]::SourceExists($eventSource)) {
            [Diagnostics.EventLog]::WriteEntry($eventSource, $Message, $Type, $Id)
        }
    } catch {
        Write-Verbose "Event log write failed: $($_.Exception.Message)"
    }
    Write-Output $Message
}

# ---- Register ------------------------------------------------------------------------
if ($Register) {
    $cfg = [ordered]@{ account = $StorageAccount; container = $Container; auth = $Auth; prefix = $Prefix
        endpoint_suffix = $BlobEndpointSuffix; host = $env:COMPUTERNAME.ToLowerInvariant() }
    if ($PSCmdlet.ShouldProcess($cfgFile, 'Write shipping config')) {
        ($cfg | ConvertTo-Json) | Set-Content -LiteralPath $cfgFile -Encoding ASCII
    }
    if (-not [Diagnostics.EventLog]::SourceExists($eventSource) -and $PSCmdlet.ShouldProcess($eventSource, 'Create event source in Application log')) {
        [Diagnostics.EventLog]::CreateEventSource($eventSource, 'Application')
    }
    if ($PSCmdlet.ShouldProcess($taskName, 'Register scheduled task (SYSTEM, every 5 minutes)')) {
        $script = Join-Path $PmcScriptsDir 'Send-AuditLog.ps1'
        if (-not (Test-Path -LiteralPath $script)) { throw "$script not found. Run Install-ProxmoxMcpBroker.ps1 first (it copies the scripts)." }
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $action = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -File "{0}"' -f $script)
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -TaskPath '\ProxmoxMCP\' -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null
    }
    Write-Step "Registered. Store the SAS (sp=c only) if Auth=Sas: ... | Protect-BrokerCredential.ps1 -Name audit-ship-sas -Reader System"
    return
}

if (-not (Test-Path -LiteralPath $cfgFile)) { throw "No $cfgFile. Run with -Register first." }
$cfg = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
$baseUrl = 'https://{0}.{1}/{2}' -f $cfg.account, $cfg.endpoint_suffix, $cfg.container

# ---- HTTP (works on 5.1 and 7.x, returns status instead of throwing) -----------------
function Invoke-BlobRequest {
    param([string]$Method, [string]$Url, [hashtable]$Headers = @{}, [byte[]]$Body = $null)
    $req = [Net.HttpWebRequest]::Create($Url)
    $req.Method = $Method
    $req.Timeout = 120000
    $req.AllowAutoRedirect = $false
    foreach ($k in $Headers.Keys) {
        if ($k -eq 'Content-Type') { $req.ContentType = $Headers[$k] } else { $req.Headers.Add($k, $Headers[$k]) }
    }
    if ($null -ne $Body) {
        $req.ContentLength = $Body.Length
        $s = $req.GetRequestStream()
        try { $s.Write($Body, 0, $Body.Length) } finally { $s.Dispose() }
    } elseif ($Method -eq 'PUT') {
        $req.ContentLength = 0
    }
    try {
        $resp = $req.GetResponse()
    } catch [Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
    }
    try {
        $code = [int]$resp.StatusCode
        $errCode = $resp.Headers['x-ms-error-code']
        return [pscustomobject]@{ Status = $code; ErrorCode = $errCode }
    } finally { $resp.Dispose() }
}

$script:AuthQuery = ''
$script:AuthHeader = @{}
function Get-ArcToken {
    # Azure Arc connected machine agent: local identity endpoint with a challenge file.
    # Any local user can listen on port 40342 when the agent is not running, and the
    # endpoint names a file for SYSTEM to read and send back. So: the agent service must
    # be running, and the challenge file must be a small .key file in the agent's own
    # Tokens folder. Otherwise a local user could make SYSTEM read any file.
    $himds = Get-Service -Name 'himds' -ErrorAction SilentlyContinue
    if (-not $himds -or $himds.Status -ne 'Running') { throw 'Azure Connected Machine agent (himds) is not running.' }
    $uri = 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https%3A%2F%2Fstorage.azure.com%2F'
    $req = [Net.HttpWebRequest]::Create($uri)
    $req.Headers.Add('Metadata', 'true'); $req.Timeout = 10000; $req.AllowAutoRedirect = $false
    $realm = $null
    try { $req.GetResponse().Dispose() } catch [Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { $wa = $r.Headers['WWW-Authenticate']; $r.Dispose(); if ($wa -match 'realm=(\S+)') { $realm = $Matches[1].Trim() } }
    }
    $tokDir = Join-Path $env:ProgramData 'AzureConnectedMachineAgent\Tokens'
    if (-not $realm) { throw 'Arc identity challenge failed.' }
    $full = [IO.Path]::GetFullPath($realm)
    if (-not $full.StartsWith($tokDir + '\', [StringComparison]::OrdinalIgnoreCase) -or $full -notmatch '\.key$') {
        throw 'Arc identity challenge names a file outside the agent Tokens folder. Refused.'
    }
    if ((Get-Item -LiteralPath $full).Length -gt 4096) { throw 'Arc challenge file is too large. Refused.' }
    $secret = [IO.File]::ReadAllText($full).Trim()
    try {
        $req = [Net.HttpWebRequest]::Create($uri)
        $req.Headers.Add('Metadata', 'true'); $req.Headers.Add('Authorization', "Basic $secret"); $req.Timeout = 10000
        $resp = $req.GetResponse()
        try { $body = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } finally { $resp.Dispose() }
    } finally { $secret = $null }
    if ($body -notmatch '"access_token"\s*:\s*"([^"]+)"') { throw 'Arc identity endpoint returned no access token.' }
    return $Matches[1]
}

function Initialize-ShipAuth {
    if ($cfg.auth -eq 'Arc') {
        $script:AuthHeader = @{ Authorization = "Bearer $(Get-ArcToken)" }
    } else {
        $sas = (Read-PmcProtectedText -Name 'audit-ship-sas').Trim().TrimStart('?')
        if ($sas -notmatch '(^|&)sp=c(&|$)') { throw 'audit-ship-sas must have sp=c only.' }
        if ($sas -match '(^|&)se=(\d{4}-\d{2}-\d{2})') {
            $left = ([datetime]::ParseExact($Matches[2], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) - (Get-Date)).TotalDays
            if ($left -lt 30) { Write-ShipEvent 4106 ("audit-ship-sas expires in {0:N0} days. Issue a new sp=c SAS (RUNBOOK, Rotate)." -f $left) 'Warning' | Out-Null }
        }
        $script:AuthQuery = $sas
    }
}
function Get-BlobUrl([string]$Name) {
    $u = "$baseUrl/$Name"
    if ($script:AuthQuery) { $u = "$u`?$($script:AuthQuery)" }
    return $u
}
function Get-Hash([string]$Alg, [byte[]]$Data) {
    $h = [Security.Cryptography.HashAlgorithm]::Create($Alg)
    try { return $h.ComputeHash($Data) } finally { $h.Dispose() }
}
function Get-FileId([string]$Path) {
    $o = & (Join-Path $env:SystemRoot 'System32\fsutil.exe') file queryFileID $Path 2>&1 | Out-String
    if ($o -match '0x([0-9a-fA-F]+)') { return $Matches[1].ToLowerInvariant() }
    throw "Cannot read the file ID of $Path"
}

# ---- Immutability test ---------------------------------------------------------------
if ($TestImmutability) {
    Initialize-ShipAuth
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $name = "$($cfg.prefix)/canary/$($cfg.host)/$stamp.txt"
    $body = [Text.Encoding]::UTF8.GetBytes("immutability canary $stamp`n")
    $hdr = @{ 'x-ms-version' = $apiVersion; 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'text/plain' } + $script:AuthHeader
    $evidence = [ordered]@{ time = $stamp; blob = $name; steps = @() }
    $r1 = Invoke-BlobRequest -Method PUT -Url (Get-BlobUrl $name) -Headers $hdr -Body $body
    $evidence.steps += [ordered]@{ step = 'create'; expect = 201; got = $r1.Status; code = $r1.ErrorCode }
    $r2 = Invoke-BlobRequest -Method PUT -Url (Get-BlobUrl $name) -Headers $hdr -Body $body
    $evidence.steps += [ordered]@{ step = 'overwrite with ship credential'; expect = '409 or 403'; got = $r2.Status; code = $r2.ErrorCode }
    $r3 = Invoke-BlobRequest -Method DELETE -Url (Get-BlobUrl $name) -Headers (@{ 'x-ms-version' = $apiVersion } + $script:AuthHeader)
    $evidence.steps += [ordered]@{ step = 'delete with ship credential'; expect = '409 or 403'; got = $r3.Status; code = $r3.ErrorCode }
    $ok = ($r1.Status -eq 201) -and (@(403, 409) -contains $r2.Status) -and (@(403, 409) -contains $r3.Status)
    if ($AdminCheck) {
        # With an identity that HAS delete/write rights, the policy itself must refuse (409).
        $az = Get-Command az -ErrorAction SilentlyContinue
        if (-not $az) { throw '-AdminCheck needs the Azure CLI, signed in with a role that can delete blobs.' }
        $del = & az storage blob delete --account-name $cfg.account --container-name $cfg.container --name $name --auth-mode login 2>&1 | Out-String
        $evidence.steps += [ordered]@{ step = 'delete with admin identity'; expect = 'BlobImmutableDueToPolicy (409)'; got = ($del.Trim() -replace '\s+', ' ') }
        $tmp = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($tmp, 'overwrite attempt')
        $ow = & az storage blob upload --account-name $cfg.account --container-name $cfg.container --name $name --file $tmp --overwrite true --auth-mode login 2>&1 | Out-String
        Remove-Item -LiteralPath $tmp -Force
        $evidence.steps += [ordered]@{ step = 'overwrite with admin identity'; expect = 'BlobImmutableDueToPolicy (409)'; got = ($ow.Trim() -replace '\s+', ' ') }
        $pol = & az storage container immutability-policy show --account-name $cfg.account --container-name $cfg.container 2>&1 | Out-String
        $evidence.immutability_policy = $pol.Trim()
        $ok = $ok -and ($del -match 'BlobImmutableDueToPolicy') -and ($ow -match 'BlobImmutableDueToPolicy') -and ($pol -match '"immutabilityPeriodSinceCreationInDays":\s*2190') -and ($pol -match '"state":\s*"Locked"')
    }
    $evidence.pass = $ok
    $out = Join-Path $PmcShipDir "immutability-test-$stamp.json"
    ($evidence | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $out -Encoding UTF8
    Write-Output ($evidence | ConvertTo-Json -Depth 5)
    if (-not $ok) { Write-ShipEvent 4103 "Immutability test FAILED. Evidence: $out" 'Error'; exit 1 }
    Write-ShipEvent 4003 "Immutability test passed. Evidence: $out"
    exit 0
}

# ---- Ship run ---------------------------------------------------------------------------
$state = @{ files = @{}; evidence = @{} }
if (Test-Path -LiteralPath $stateFile) {
    $raw = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    $rawEv = Get-PmcProp $raw 'evidence'
    if ($rawEv) { foreach ($p in $rawEv.PSObject.Properties) { $state.evidence[$p.Name] = [string]$p.Value } }
    foreach ($p in $raw.files.PSObject.Properties) {
        $state.files[$p.Name] = @{ path = $p.Value.path; offset = [int64]$p.Value.offset; prevsha256 = $p.Value.prevsha256
            month = $p.Value.month; complete = [bool]$p.Value.complete; gen = [int]$p.Value.gen }
    }
}
function Save-State {
    $tmp = "$stateFile.tmp"
    ($state | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $stateFile -Force
}

$files = @(Get-ChildItem -LiteralPath $PmcLogDir -File -Filter 'audit-*.jsonl' | Sort-Object Name)
if (Test-Path -LiteralPath $PmcAuditLog) { $files += Get-Item -LiteralPath $PmcAuditLog }

Initialize-ShipAuth
$shipped = 0
$errors = 0
$nowMonth = (Get-Date).ToString('yyyyMM')
foreach ($f in $files) {
    $id = Get-FileId $f.FullName
    if (-not $state.files.ContainsKey($id)) {
        $state.files[$id] = @{ path = $f.FullName; offset = [int64]0; prevsha256 = ''; month = $nowMonth; complete = $false; gen = 0 }
    }
    $st = $state.files[$id]
    $st.path = $f.FullName
    $size = $f.Length
    if ($size -lt $st.offset) {
        # Shrunk or replaced in place: the chain is broken locally. Never skip silently.
        Write-ShipEvent 4101 "Audit file $($f.Name) (id $id) shrank from $($st.offset) to $size bytes. Shipping from 0; investigate." 'Warning'
        $st.offset = 0
        $st.prevsha256 = ''
        $st.gen = [int]$st.gen + 1   # new blob names: never collide with the earlier content
    }
    while ($st.offset -lt $size) {
        $len = [int64][math]::Min($maxChunk, $size - $st.offset)
        $buf = New-Object byte[] $len
        $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            [void]$fs.Seek($st.offset, 'Begin')
            $read = 0
            while ($read -lt $len) {
                $n = $fs.Read($buf, $read, $len - $read)
                if ($n -le 0) { break }
                $read += $n
            }
        } finally { $fs.Dispose() }
        # Only complete lines: cut after the last LF.
        $cut = [Array]::LastIndexOf($buf, [byte]10, $read - 1)
        if ($cut -lt 0) { break }
        $chunk = New-Object byte[] ($cut + 1)
        [Array]::Copy($buf, $chunk, $cut + 1)
        $sha = -join ((Get-Hash 'SHA256' $chunk) | ForEach-Object { $_.ToString('x2') })
        $md5 = $null
        try { $md5 = [Convert]::ToBase64String((Get-Hash 'MD5' $chunk)) } catch { Write-Verbose 'MD5 unavailable (FIPS mode); relying on TLS and the sha256 metadata.' }
        $start = $st.offset
        $end = $st.offset + $chunk.Length
        $utc = (Get-Date).ToUniversalTime()
        $name = '{0}/{1}/{2:yyyy}/{2:MM}/{2:dd}/{3}-g{6}-{4:D12}-{5:D12}.jsonl' -f $cfg.prefix, $cfg.host, $utc, $id, $start, $end, $st.gen
        $hdr = @{ 'x-ms-version' = $apiVersion; 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/x-ndjson'
            'If-None-Match' = '*'
            'x-ms-meta-sha256' = $sha; 'x-ms-meta-prevsha256' = $st.prevsha256; 'x-ms-meta-host' = $cfg.host
            'x-ms-meta-fileid' = $id; 'x-ms-meta-offset' = "$start"; 'x-ms-meta-length' = "$($chunk.Length)" } + $script:AuthHeader
        if (-not $hdr['x-ms-meta-prevsha256']) { $hdr['x-ms-meta-prevsha256'] = 'none' }
        if ($md5) { $hdr['Content-MD5'] = $md5 }
        if (-not $PSCmdlet.ShouldProcess($name, "Upload $($chunk.Length) bytes")) { break }
        $r = Invoke-BlobRequest -Method PUT -Url (Get-BlobUrl $name) -Headers $hdr -Body $chunk
        if ($r.Status -eq 201 -or ($r.Status -eq 409 -and $r.ErrorCode -eq 'BlobAlreadyExists')) {
            # 409 BlobAlreadyExists: a previous run uploaded this exact range and stopped before
            # saving state. The name encodes file ID and byte range of an append-only file.
            $st.offset = $end
            $st.prevsha256 = $sha
            $shipped += $chunk.Length
            Save-State
        } else {
            $errors++
            Write-ShipEvent 4102 "Upload of $name failed: HTTP $($r.Status) $($r.ErrorCode)" 'Error'
            break
        }
    }
    $st.complete = ($st.offset -eq (Get-Item -LiteralPath $f.FullName).Length)
}
Save-State

# ---- Rotation (live file, month over, fully shipped) -------------------------------------
if (Test-Path -LiteralPath $PmcAuditLog) {
    $id = Get-FileId $PmcAuditLog
    $st = $state.files[$id]
    if ($st -and $st.complete -and $st.month -ne $nowMonth -and $st.offset -eq (Get-Item -LiteralPath $PmcAuditLog).Length) {
        $dest = Join-Path $PmcLogDir "audit-$($st.month).jsonl"
        $i = 2
        while (Test-Path -LiteralPath $dest) { $dest = Join-Path $PmcLogDir "audit-$($st.month)-$i.jsonl"; $i++ }
        if ($PSCmdlet.ShouldProcess($PmcAuditLog, "Rename to $dest")) {
            try {
                Move-Item -LiteralPath $PmcAuditLog -Destination $dest
                $st.path = $dest
                Write-ShipEvent 4002 "Rotated audit.jsonl to $(Split-Path -Leaf $dest)."
            } catch {
                Write-Verbose "Rotation deferred (file in use): $($_.Exception.Message)"
            }
        }
    }
}

# ---- Local retention (only files confirmed in WORM storage) ---------------------------------
$cutoff = (Get-Date).AddDays(-$LocalRetentionDays)
foreach ($f in @(Get-ChildItem -LiteralPath $PmcLogDir -File -Filter 'audit-*.jsonl')) {
    if ($f.LastWriteTime -ge $cutoff) { continue }
    $id = Get-FileId $f.FullName
    $st = $state.files[$id]
    if ($st -and $st.complete -and $st.offset -eq $f.Length -and $PSCmdlet.ShouldProcess($f.FullName, 'Delete (older than retention, fully shipped)')) {
        Remove-Item -LiteralPath $f.FullName -Force
        $state.files.Remove($id)
        Write-ShipEvent 4004 "Deleted $($f.Name): older than $LocalRetentionDays days and confirmed in WORM storage."
    }
}
Save-State

# ---- Anchor: verify the local chain and store the summary (last seq + hash) in WORM -----------
# The auditor passes it to proxmox-mcp-audit-verify --anchor to prove the tail was not cut.
if ($errors -eq 0 -and $shipped -gt 0) {
    $r = Invoke-PmcBrokerTool -Tool 'proxmox-mcp-audit-verify' -ArgumentList @('--dir', $PmcLogDir, '--require-mac')
    $summary = $r.Output
    $vcode = $r.Code
    if ($vcode -ne 0) {
        $errors++
        Write-ShipEvent 4105 "proxmox-mcp-audit-verify exit $vcode (chain break or missing mac): $($summary.Trim())" 'Error'
    } elseif ($PSCmdlet.ShouldProcess('anchor', 'Upload verify summary')) {
        $utc = (Get-Date).ToUniversalTime()
        $aname = '{0}/{1}/anchors/{2:yyyy}/{2:MM}/{2:yyyyMMddTHHmmssZ}.json' -f $cfg.prefix, $cfg.host, $utc
        $abody = [Text.Encoding]::UTF8.GetBytes($summary.Trim())
        $ahdr = @{ 'x-ms-version' = $apiVersion; 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/json'; 'If-None-Match' = '*' } + $script:AuthHeader
        $r = Invoke-BlobRequest -Method PUT -Url (Get-BlobUrl $aname) -Headers $ahdr -Body $abody
        if ($r.Status -ne 201) { $errors++; Write-ShipEvent 4102 "Anchor upload failed: HTTP $($r.Status) $($r.ErrorCode)" 'Error' }
    }
}

# ---- Evidence files (selfcheck reports, access reviews): each uploaded once --------------
if (-not $state.ContainsKey('evidence')) { $state.evidence = @{} }
if (Test-Path -LiteralPath $PmcEvidenceDir) {
    $evFiles = @(Get-ChildItem -LiteralPath $PmcEvidenceDir -File -Recurse -Include '*.json', '*.csv', '*.txt' |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-2) })
    foreach ($ev in $evFiles) {
        $rel = $ev.FullName.Substring($PmcEvidenceDir.Length + 1).Replace('\', '/')
        if ($state.evidence.ContainsKey($rel)) { continue }
        $bytes = [IO.File]::ReadAllBytes($ev.FullName)
        $sha = -join ((Get-Hash 'SHA256' $bytes) | ForEach-Object { $_.ToString('x2') })
        $ename = '{0}/{1}/evidence/{2}' -f $cfg.prefix, $cfg.host, $rel
        $ehdr = @{ 'x-ms-version' = $apiVersion; 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/octet-stream'
            'If-None-Match' = '*'; 'x-ms-meta-sha256' = $sha } + $script:AuthHeader
        if (-not $PSCmdlet.ShouldProcess($ename, 'Upload evidence file')) { continue }
        $r = Invoke-BlobRequest -Method PUT -Url (Get-BlobUrl $ename) -Headers $ehdr -Body $bytes
        if ($r.Status -eq 201 -or ($r.Status -eq 409 -and $r.ErrorCode -eq 'BlobAlreadyExists')) {
            $state.evidence[$rel] = $sha
        } else {
            $errors++
            Write-ShipEvent 4102 "Upload of evidence $rel failed: HTTP $($r.Status) $($r.ErrorCode)" 'Error'
        }
    }
    Save-State
}

if ($errors -gt 0) { exit 1 }
Write-ShipEvent 4001 "Audit ship OK: $shipped bytes."
exit 0
