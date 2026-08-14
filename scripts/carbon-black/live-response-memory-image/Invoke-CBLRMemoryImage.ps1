#requires -Version 7.0
<#
.SYNOPSIS
    Acquire a live memory image (RAM + pagefile) from a remote host using the
    Carbon Black EDR (on-premise / "CB Response") Live Response API and Winpmem.

.DESCRIPTION
    End-to-end memory acquisition over Carbon Black EDR 7.9.2 Live Response:

      1. Resolve the target sensor by hostname (preferred) or Sensor ID.
      2. Open a Live Response session and wait for it to become active.
      3. Upload the Winpmem binary to the CB server, then push it to the endpoint
         ('put file').
      4. Run Winpmem on the endpoint with 'create process' (NOT via a PowerShell
         shell inside Live Response), directing it to capture physical memory and
         the pagefile to a target path on the endpoint.
      5. Confirm the image was written ('directory list') and read its size.
      6. Export the image back to this (the analyst's) machine with chunked
         'get file' reads, streamed to disk.
      7. Verify the local copy (size match + SHA256) and write a sidecar manifest.
      8. Prompt the analyst to optionally clean up the remote artifacts.
      9. Close the Live Response session.

    The Winpmem command-line flags are exposed as a runtime parameter
    (-WinpmemArguments) so the analyst controls exactly how the image is written.
    The default targets go-winpmem ('acquire --progress "<image>"'), which writes
    a raw physical-memory image using a modern signed driver that loads under
    Secure Boot. To capture the pagefile instead, switch to the legacy
    AFF4-capable winpmem build and its '-o "<image>" -p "<pagefile>"' arguments
    (see the "Choosing a Winpmem binary" table in the README). go-winpmem and
    winpmem_mini do not capture the pagefile.

    Live Response API endpoints used (all under the CB server base URL):
      POST   /api/v1/sensor  (lookup)         GET /api/v1/sensor?hostname=<h>
      POST   /api/v1/cblr/session             GET /api/v1/cblr/session/<sid>
      GET    /api/v1/cblr/session/<sid>/keepalive
      POST   /api/v1/cblr/session/<sid>/file  (multipart upload to CB server)
      POST   /api/v1/cblr/session/<sid>/command
      GET    /api/v1/cblr/session/<sid>/command/<cid>
      GET    /api/v1/cblr/session/<sid>/file/<fid>/content
      PUT    /api/v1/cblr/session/<sid>        ({ "status": "close" })

.NOTES
    The API key is deliberately NOT a parameter. It is always prompted for and
    read as a SecureString.

    On-premise CB servers frequently use self-signed certificates; use
    -SkipCertificateCheck if your server's certificate is not trusted by this
    machine.
#>

[CmdletBinding(DefaultParameterSetName = 'ByHostname')]
param(
    # Base URL of the Carbon Black EDR server, e.g. https://cb.example.local
    [Parameter(Position = 0)]
    [string]$CbServerUrl,

    # Target host name (preferred way to identify the endpoint).
    [Parameter(ParameterSetName = 'ByHostname')]
    [string]$Hostname,

    # Target Sensor ID (use when hostname resolution is not feasible).
    [Parameter(ParameterSetName = 'BySensorId')]
    [int]$SensorId,

    # Local path to the Winpmem binary to push (SOURCE path for the binary).
    [string]$WinpmemSourcePath,

    # Destination path for the binary ON THE ENDPOINT (TARGET path for the binary).
    # Default: C:\Windows\Temp\<source-file-name>
    [string]$RemoteBinaryPath,

    # Path ON THE ENDPOINT where Winpmem writes the memory image (TARGET image path).
    # Default: C:\Windows\Temp\<host>_<timestamp>.raw
    [string]$RemoteImagePath,

    # Path to the pagefile on the endpoint (substituted into {PagefilePath}).
    # Only used when -WinpmemArguments references {PagefilePath} (legacy AFF4 build).
    [string]$PagefilePath = 'C:\pagefile.sys',

    # Winpmem argument string, exposed for runtime control. The tokens
    # {ImagePath} and {PagefilePath} are substituted with -RemoteImagePath and
    # -PagefilePath. The default targets go-winpmem with snappy compression, which
    # shrinks the image before it crosses the (slow) Live Response transfer - the
    # retrieved file must be decompressed with 'go-winpmem extract' (the script
    # prints the exact command at the end).
    # For an uncompressed raw image, drop '--compression snappy'.
    # For the legacy AFF4 build that captures the pagefile, pass instead:
    #   -o "{ImagePath}" -p "{PagefilePath}" -dd
    # Provide your own to change binary/format/flags (keep {ImagePath} so retrieval
    # knows where the image landed). See the README binary table.
    [string]$WinpmemArguments = 'acquire --compression snappy --progress "{ImagePath}"',

    # Where to save the exported image on THIS machine (analyst's DESTINATION).
    # May be a directory (file name is derived) or a full file path.
    [string]$LocalDestinationPath,

    # Retrieval chunk size in MB for chunked 'get file'. Larger chunks mean fewer
    # round-trips (faster export) but stage more in the CB server file store, which
    # must be able to hold one chunk (CbLRMaxStoreSizeMB). Set to 0 to pull the
    # whole file in a single request instead.
    [int]$RetrievalChunkSizeMB = 256,

    # Polling / timeout controls. Status polling is adaptive: it starts fast and
    # backs off up to PollIntervalSeconds (the ceiling), so small fast commands
    # (e.g. get-file chunks) return in well under a second instead of waiting a
    # fixed interval each time.
    [int]$PollIntervalSeconds       = 5,
    [int]$SessionTimeoutSeconds     = 300,
    [int]$CommandTimeoutSeconds     = 120,
    [int]$AcquisitionTimeoutSeconds = 3600,

    # Optionally hash the image on the endpoint with certutil (native, not
    # PowerShell) and compare to the local SHA256.
    [switch]$VerifyRemoteHash,

    # Skip TLS certificate validation (self-signed on-prem CB servers).
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = 'Stop'

# =================================================================================
#  Helpers
# =================================================================================

function Read-Default {
    param([string]$Prompt, [string]$Default)
    $suffix = if ($Default) { " [$Default]" } else { '' }
    $value  = Read-Host ($Prompt + $suffix)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Invoke-CbApi {
    <#
        Thin wrapper around Invoke-RestMethod for the CB REST/LR API.
        $Path is the URI path beginning with '/', e.g. /api/v1/cblr/session
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [hashtable]$Form,
        [string]$OutFile,
        [int]$TimeoutSec = 100
    )

    $params = @{
        Method      = $Method
        Uri         = "$script:BaseUrl$Path"
        Headers     = $script:Headers
        TimeoutSec  = $TimeoutSec
        ErrorAction = 'Stop'
    }
    if ($script:SkipCert)                        { $params.SkipCertificateCheck = $true }
    if ($PSBoundParameters.ContainsKey('OutFile')) { $params.OutFile = $OutFile }

    if ($Form) {
        $params.Form = $Form                       # multipart/form-data
    }
    elseif ($null -ne $Body) {
        $params.Body        = ($Body | ConvertTo-Json -Depth 10 -Compress)
        $params.ContentType = 'application/json'
    }

    return Invoke-RestMethod @params
}

function Send-KeepAlive {
    param([string]$SessionId)
    try { Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$SessionId/keepalive" | Out-Null } catch { }
}

function Wait-Session {
    <# Poll a session until it is active, or throw on timeout / terminal state. #>
    param([string]$SessionId, [int]$TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $session = Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$SessionId"
        switch ($session.status) {
            'active'  { return $session }
            'pending' { }   # sensor has not picked up the session yet
            default   { throw "Live Response session $SessionId entered status '$($session.status)' before becoming active." }
        }
        if ((Get-Date) -gt $deadline) {
            throw "Timed out after $TimeoutSeconds s waiting for session $SessionId to become active (last status: $($session.status)). The sensor may be offline or not checking in."
        }
        Start-Sleep -Seconds $script:PollInterval
    }
}

function Invoke-LRCommand {
    <#
        Issue a Live Response command and poll it to completion.
        Returns the completed command object. Throws on 'error' or timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [Parameter(Mandatory)][string]$Name,
        [string]$Object,
        [hashtable]$Extra,
        [nullable[bool]]$Wait,
        [int]$TimeoutSeconds = 120,
        [string]$Activity
    )

    $body = @{ name = $Name }
    if ($PSBoundParameters.ContainsKey('Object')) { $body.object = $Object }
    if ($null -ne $Wait)                           { $body.wait   = [bool]$Wait }
    if ($Extra) { foreach ($k in $Extra.Keys) { $body[$k] = $Extra[$k] } }

    $cmd   = Invoke-CbApi -Method POST -Path "/api/v1/cblr/session/$SessionId/command" -Body $body
    $cmdId = $cmd.id

    $deadline      = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastKeepAlive = Get-Date
    $delay         = $script:PollInitialDelay   # adaptive: start fast, back off to the ceiling
    while ($true) {
        Start-Sleep -Milliseconds ([int]($delay * 1000))
        $cmd = Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$SessionId/command/$cmdId"

        if ($cmd.status -eq 'complete') { return $cmd }
        if ($cmd.status -eq 'error') {
            $detail = if ($cmd.result_desc) { $cmd.result_desc } else { ($cmd | ConvertTo-Json -Depth 5 -Compress) }
            throw "Live Response command '$Name' failed (code $($cmd.result_code)): $detail"
        }

        if ($Activity) {
            Write-Progress -Activity $Activity -Status "status: $($cmd.status)  (elapsed $([int]((Get-Date) - $lastKeepAlive).TotalSeconds)s since keepalive)"
        }

        if ((Get-Date) -gt $deadline) {
            throw "Timed out after $TimeoutSeconds s waiting for Live Response command '$Name' (last status: $($cmd.status))."
        }
        # Keep the session warm during long-running commands.
        if (((Get-Date) - $lastKeepAlive).TotalSeconds -ge 60) {
            Send-KeepAlive -SessionId $SessionId
            $lastKeepAlive = Get-Date
        }
        $delay = [Math]::Min($delay * 2, $script:PollInterval)   # exponential backoff, capped
    }
}

function Remove-RemoteFile {
    param([string]$SessionId, [string]$Path)
    try {
        Invoke-LRCommand -SessionId $SessionId -Name 'delete file' -Object $Path -TimeoutSeconds $script:CommandTimeout | Out-Null
        Write-Host "  Deleted on endpoint: $Path" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Could not delete '$Path': $($_.Exception.Message)"
    }
}

function Get-RemoteText {
    <# Retrieve a small text file from the endpoint and return its contents. #>
    param([string]$SessionId, [string]$Path)
    $cmd = Invoke-LRCommand -SessionId $SessionId -Name 'get file' -Object $Path -TimeoutSeconds $script:CommandTimeout
    return (Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$SessionId/file/$($cmd.file_id)/content")
}

function Invoke-CleanupPrompt {
    param([string]$SessionId, [string]$BinaryPath, [string]$ImagePath)

    Write-Host ""
    Write-Host "Remote artifacts remaining on the endpoint:" -ForegroundColor Yellow
    Write-Host "  Winpmem binary : $BinaryPath"
    Write-Host "  Memory image   : $ImagePath"
    $choice = Read-Host "Run cleanup? (B)inary only / (I)mage only / (A)ll / (C)ustom path / (N)one [N]"

    switch -Regex ($choice) {
        '^\s*[Bb]' { Remove-RemoteFile -SessionId $SessionId -Path $BinaryPath }
        '^\s*[Ii]' { Remove-RemoteFile -SessionId $SessionId -Path $ImagePath }
        '^\s*[Aa]' {
            Remove-RemoteFile -SessionId $SessionId -Path $BinaryPath
            Remove-RemoteFile -SessionId $SessionId -Path $ImagePath
        }
        '^\s*[Cc]' {
            do {
                $p = Read-Host "  Full remote path to delete (blank to finish)"
                if ($p) { Remove-RemoteFile -SessionId $SessionId -Path $p }
            } while ($p)
        }
        default { Write-Host "No cleanup performed. Artifacts left in place on the endpoint." -ForegroundColor Cyan }
    }
}

# =================================================================================
#  Input gathering (arguments, or interactive prompts as a fallback)
# =================================================================================

if ([string]::IsNullOrWhiteSpace($CbServerUrl)) {
    $CbServerUrl = Read-Default -Prompt 'Carbon Black server base URL (e.g. https://cb.example.local)'
}
if ([string]::IsNullOrWhiteSpace($CbServerUrl)) { throw 'A Carbon Black server URL is required.' }
$script:BaseUrl  = $CbServerUrl.TrimEnd('/')
$script:SkipCert = [bool]$SkipCertificateCheck
$script:PollInterval     = $PollIntervalSeconds   # adaptive-poll ceiling
$script:PollInitialDelay = 0.25                   # first poll delay (seconds), then backs off
$script:CommandTimeout   = $CommandTimeoutSeconds

# API key: ALWAYS prompted, never an argument.
Write-Host "Enter your Carbon Black API token (input hidden)." -ForegroundColor Yellow
$secureToken = Read-Host -Prompt 'API token' -AsSecureString
if (-not $secureToken -or $secureToken.Length -eq 0) { throw 'An API token is required.' }
$bstr        = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
$plainToken  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
$script:Headers = @{ 'X-Auth-Token' = $plainToken }

# Target selection: hostname preferred, Sensor ID as fallback.
if ($PSCmdlet.ParameterSetName -eq 'BySensorId' -or $SensorId) {
    # explicit sensor id supplied
}
elseif ([string]::IsNullOrWhiteSpace($Hostname)) {
    $Hostname = Read-Host 'Target hostname (leave blank to enter a Sensor ID instead)'
    if ([string]::IsNullOrWhiteSpace($Hostname)) {
        $sidInput = Read-Host 'Target Sensor ID'
        if ([string]::IsNullOrWhiteSpace($sidInput)) { throw 'A hostname or Sensor ID is required.' }
        $SensorId = [int]$sidInput
    }
}

$exitCode = 0
$sessionId = $null
try {
    # =============================================================================
    #  STEP 1: Resolve the sensor
    # =============================================================================
    Write-Host "`n[1/8] Resolving target sensor..." -ForegroundColor Cyan

    if ($SensorId) {
        $sensor = Invoke-CbApi -Method GET -Path "/api/v1/sensor/$SensorId"
        if (-not $sensor) { throw "No sensor found with Sensor ID $SensorId." }
    }
    else {
        $encoded = [uri]::EscapeDataString($Hostname)
        $result  = Invoke-CbApi -Method GET -Path "/api/v1/sensor?hostname=$encoded"
        # The hostname filter is a case-insensitive substring search, so it can
        # return several sensors (including re-registered duplicates).
        $candidates = @($result)
        if ($candidates.Count -eq 0) { throw "No sensor matched hostname '$Hostname'." }

        # Prefer an exact computer_name match (strip any DOMAIN\ prefix).
        $exact = @($candidates | Where-Object {
            $cn = ($_.computer_name -split '\\')[-1]
            $cn -ieq $Hostname
        })
        if ($exact.Count -gt 0) { $candidates = $exact }

        if ($candidates.Count -gt 1) {
            Write-Host "  Multiple sensors matched '$Hostname':" -ForegroundColor Yellow
            $candidates |
                Select-Object id, computer_name, status, last_checkin_time |
                Sort-Object last_checkin_time -Descending |
                Format-Table -AutoSize | Out-Host
            # Auto-select the most recently checked-in Online sensor.
            $sensor = $candidates |
                Sort-Object @{ E = { $_.status -ieq 'Online' } }, last_checkin_time -Descending |
                Select-Object -First 1
            Write-Warning "Auto-selected sensor id $($sensor.id) (computer_name '$($sensor.computer_name)', status '$($sensor.status)'). Re-run with -SensorId to target a specific one."
        }
        else {
            $sensor = $candidates[0]
        }
    }

    $resolvedSensorId = if ($sensor.id) { $sensor.id } else { $sensor.sensor_id }
    $computerName     = $sensor.computer_name
    Write-Host "  Sensor id : $resolvedSensorId" -ForegroundColor Green
    Write-Host "  Host      : $computerName" -ForegroundColor Green
    Write-Host "  Status    : $($sensor.status)   Last checkin: $($sensor.last_checkin_time)" -ForegroundColor Green
    if ($sensor.status -and $sensor.status -inotmatch 'online') {
        Write-Warning "Sensor status is '$($sensor.status)'. Live Response requires the sensor to be online; the session may not activate."
    }

    # =============================================================================
    #  Derive default paths now that the host is known
    # =============================================================================
    $stamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostLabel = if ($computerName) { ($computerName -split '\\')[-1] } else { "sensor$resolvedSensorId" }

    if ([string]::IsNullOrWhiteSpace($WinpmemSourcePath)) {
        $WinpmemSourcePath = Read-Default -Prompt 'Local path to the Winpmem binary (source)'
    }
    if (-not (Test-Path -LiteralPath $WinpmemSourcePath -PathType Leaf)) {
        throw "Winpmem binary not found at '$WinpmemSourcePath'."
    }
    $binaryLeaf = Split-Path -Path $WinpmemSourcePath -Leaf

    if ([string]::IsNullOrWhiteSpace($RemoteBinaryPath)) {
        $RemoteBinaryPath = Read-Default -Prompt 'Remote binary path (target on endpoint)' -Default "C:\Windows\Temp\$binaryLeaf"
    }
    if ([string]::IsNullOrWhiteSpace($RemoteImagePath)) {
        $RemoteImagePath = Read-Default -Prompt 'Remote image path (target on endpoint)' -Default "C:\Windows\Temp\${hostLabel}_$stamp.raw"
    }
    if ([string]::IsNullOrWhiteSpace($LocalDestinationPath)) {
        $LocalDestinationPath = Read-Default -Prompt 'Local destination (folder or file) to save the image' -Default (Get-Location).Path
    }
    # If the destination is a directory, derive a file name from the remote image.
    if ((Test-Path -LiteralPath $LocalDestinationPath -PathType Container) -or $LocalDestinationPath.EndsWith('\') -or $LocalDestinationPath.EndsWith('/')) {
        $imageLeaf            = Split-Path -Path $RemoteImagePath -Leaf
        $LocalDestinationPath = Join-Path -Path $LocalDestinationPath -ChildPath $imageLeaf
    }
    $destDir = Split-Path -Path $LocalDestinationPath -Parent
    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
    }

    # Resolve Winpmem argument tokens; retrieval relies on -RemoteImagePath.
    $resolvedArgs = $WinpmemArguments.Replace('{ImagePath}', $RemoteImagePath).Replace('{PagefilePath}', $PagefilePath)
    if ($resolvedArgs -notlike "*$RemoteImagePath*") {
        Write-Warning "The resolved Winpmem arguments do not reference '$RemoteImagePath'. Retrieval reads from -RemoteImagePath, so make sure Winpmem writes the image there (keep the {ImagePath} token)."
    }
    $processCommand = '"{0}" {1}' -f $RemoteBinaryPath, $resolvedArgs

    Write-Host "`n  Plan:" -ForegroundColor Cyan
    Write-Host "    Push binary : $WinpmemSourcePath  ->  $RemoteBinaryPath"
    Write-Host "    Run         : $processCommand"
    Write-Host "    Image (host): $RemoteImagePath"
    Write-Host "    Save (local): $LocalDestinationPath"

    # =============================================================================
    #  STEP 2: Open a Live Response session
    # =============================================================================
    Write-Host "`n[2/8] Opening Live Response session..." -ForegroundColor Cyan
    $newSession = Invoke-CbApi -Method POST -Path '/api/v1/cblr/session' -Body @{
        sensor_id               = [int]$resolvedSensorId
        default_command_timeout = $AcquisitionTimeoutSeconds   # keep the long Winpmem run from timing out server-side
    }
    $sessionId = $newSession.id
    Write-Host "  Session id: $sessionId (status: $($newSession.status))"
    $null = Wait-Session -SessionId $sessionId -TimeoutSeconds $SessionTimeoutSeconds
    Write-Host "  Session is active." -ForegroundColor Green

    # =============================================================================
    #  STEP 3: Upload Winpmem to the CB server, then push it to the endpoint
    # =============================================================================
    Write-Host "`n[3/8] Uploading Winpmem to the CB server..." -ForegroundColor Cyan
    $uploaded = Invoke-CbApi -Method POST -Path "/api/v1/cblr/session/$sessionId/file" -Form @{ file = Get-Item -LiteralPath $WinpmemSourcePath }
    $fileId   = $uploaded.id
    Write-Host "  Uploaded (server file id: $fileId, size: $($uploaded.size))." -ForegroundColor Green

    Write-Host "  Pushing binary to endpoint ($RemoteBinaryPath)..."
    Invoke-LRCommand -SessionId $sessionId -Name 'put file' -Object $RemoteBinaryPath `
        -Extra @{ file_id = $fileId } -TimeoutSeconds $CommandTimeoutSeconds | Out-Null
    Write-Host "  Binary delivered." -ForegroundColor Green

    # =============================================================================
    #  STEP 4: Run Winpmem on the endpoint (create process, no PowerShell shell)
    # =============================================================================
    Write-Host "`n[4/8] Running Winpmem on the endpoint (this can take a while)..." -ForegroundColor Cyan
    $acqLogPath = "$RemoteImagePath.winpmem.log"   # capture Winpmem's console output for diagnostics
    $runStart   = Get-Date
    $runResult  = Invoke-LRCommand -SessionId $sessionId -Name 'create process' -Object $processCommand `
        -Wait $true -Extra @{ working_directory = (Split-Path -Path $RemoteImagePath -Parent); output_file = $acqLogPath } `
        -TimeoutSeconds $AcquisitionTimeoutSeconds -Activity 'Winpmem memory acquisition'
    Write-Progress -Activity 'Winpmem memory acquisition' -Completed
    $runSecs = [int]((Get-Date) - $runStart).TotalSeconds
    $rc      = $runResult.return_code

    # Fail fast: a nonzero (or missing) exit code means Winpmem did not produce a
    # valid image. Pull its captured output so the reason is visible, then abort
    # instead of limping into a confusing "file not found" on the next step.
    if ($null -eq $rc -or $rc -ne 0) {
        Write-Warning "Winpmem exited with code '$rc' after ${runSecs}s."
        try {
            $acqLog = Get-RemoteText -SessionId $sessionId -Path $acqLogPath
            if ($acqLog) {
                Write-Host "  --- Winpmem output (from endpoint) ---" -ForegroundColor DarkYellow
                Write-Host $acqLog
                Write-Host "  --------------------------------------" -ForegroundColor DarkYellow
            }
        }
        catch { Write-Verbose "Could not retrieve Winpmem log: $($_.Exception.Message)" }
        throw "Winpmem failed on the endpoint (exit code '$rc'); no valid image was produced. Verify the Winpmem arguments match your binary's CLI - see the 'Choosing a Winpmem binary' table in the README."
    }
    Write-Host "  Winpmem completed in ${runSecs}s (exit code 0)." -ForegroundColor Green

    # =============================================================================
    #  STEP 5: Confirm the image exists and get its size
    # =============================================================================
    Write-Host "`n[5/8] Confirming image on the endpoint..." -ForegroundColor Cyan
    $dir      = Invoke-LRCommand -SessionId $sessionId -Name 'directory list' -Object $RemoteImagePath -TimeoutSeconds $CommandTimeoutSeconds
    $imageLeaf = Split-Path -Path $RemoteImagePath -Leaf
    $entry    = $dir.files | Where-Object { $_.name -ieq $imageLeaf } | Select-Object -First 1
    if (-not $entry) { $entry = $dir.files | Select-Object -First 1 }
    if (-not $entry) { throw "Image '$RemoteImagePath' was not found on the endpoint after acquisition." }
    $remoteSize = [int64]$entry.size
    if ($remoteSize -le 0) { throw "Image '$RemoteImagePath' exists but is 0 bytes; acquisition likely failed." }
    Write-Host ("  Image present: {0:N0} bytes ({1:N2} GB)." -f $remoteSize, ($remoteSize / 1GB)) -ForegroundColor Green

    # =============================================================================
    #  STEP 6: Export the image to this machine (chunked get file)
    # =============================================================================
    Write-Host "`n[6/8] Exporting image to $LocalDestinationPath ..." -ForegroundColor Cyan
    $chunkBytes    = [int64]$RetrievalChunkSizeMB * 1MB
    $exportStart   = Get-Date
    if ($chunkBytes -le 0) {
        # Single-shot: stream the whole file straight to the destination.
        $getCmd = Invoke-LRCommand -SessionId $sessionId -Name 'get file' -Object $RemoteImagePath -TimeoutSeconds $AcquisitionTimeoutSeconds
        Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$sessionId/file/$($getCmd.file_id)/content" -OutFile $LocalDestinationPath -TimeoutSec $AcquisitionTimeoutSeconds
    }
    else {
        # Chunked: pull offset/get_count ranges and stream each chunk onto the end
        # of the destination file (no whole-chunk buffering in memory).
        $fs = [System.IO.File]::Open($LocalDestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            $offset = [int64]0
            while ($offset -lt $remoteSize) {
                $count  = [Math]::Min($chunkBytes, $remoteSize - $offset)
                $getCmd = Invoke-LRCommand -SessionId $sessionId -Name 'get file' -Object $RemoteImagePath `
                    -Extra @{ offset = $offset; get_count = $count } -TimeoutSeconds $CommandTimeoutSeconds
                $tmp = [System.IO.Path]::GetTempFileName()
                Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$sessionId/file/$($getCmd.file_id)/content" -OutFile $tmp -TimeoutSec $AcquisitionTimeoutSeconds
                $chunkLen = (Get-Item -LiteralPath $tmp).Length
                if ($chunkLen -gt 0) {
                    $in = [System.IO.File]::OpenRead($tmp)
                    try { $in.CopyTo($fs) } finally { $in.Dispose() }
                }
                Remove-Item -LiteralPath $tmp -Force
                if ($chunkLen -eq 0) { break }   # EOF safety
                $offset += $chunkLen
                $elapsed = ((Get-Date) - $exportStart).TotalSeconds
                $mbps    = if ($elapsed -gt 0) { ($offset / 1MB) / $elapsed } else { 0 }
                $pct     = [int](($offset / $remoteSize) * 100)
                Write-Progress -Activity 'Exporting memory image' -PercentComplete $pct `
                    -Status ("{0:N0}/{1:N0} bytes ({2}%) - {3:N1} MB/s" -f $offset, $remoteSize, $pct, $mbps)
            }
            Write-Progress -Activity 'Exporting memory image' -Completed
        }
        finally {
            $fs.Dispose()
        }
    }
    $localSize   = (Get-Item -LiteralPath $LocalDestinationPath).Length
    $exportSecs  = [int]((Get-Date) - $exportStart).TotalSeconds
    Write-Host ("  Wrote {0:N0} bytes locally in {1}s ({2:N1} MB/s)." -f $localSize, $exportSecs, (($localSize / 1MB) / [Math]::Max($exportSecs, 1))) -ForegroundColor Green

    # =============================================================================
    #  STEP 7: Verify and record
    # =============================================================================
    Write-Host "`n[7/8] Verifying local copy..." -ForegroundColor Cyan
    $sizeMatch = ($localSize -eq $remoteSize)
    if ($sizeMatch) { Write-Host "  Size matches the endpoint ($localSize bytes)." -ForegroundColor Green }
    else            { Write-Warning "Size MISMATCH: local $localSize vs endpoint $remoteSize bytes." }

    Write-Host "  Computing local SHA256..."
    $localHash = (Get-FileHash -LiteralPath $LocalDestinationPath -Algorithm SHA256).Hash
    Write-Host "  SHA256: $localHash" -ForegroundColor Green

    $remoteHash = $null
    if ($VerifyRemoteHash) {
        Write-Host "  Hashing the image on the endpoint (certutil)..."
        try {
            Invoke-LRCommand -SessionId $sessionId -Name 'create process' `
                -Object ('certutil -hashfile "{0}" SHA256' -f $RemoteImagePath) -Wait $true `
                -Extra @{ output_file = 'C:\Windows\Temp\winpmem_hash.txt' } -TimeoutSeconds $AcquisitionTimeoutSeconds | Out-Null
            $hashGet = Invoke-LRCommand -SessionId $sessionId -Name 'get file' -Object 'C:\Windows\Temp\winpmem_hash.txt' -TimeoutSeconds $CommandTimeoutSeconds
            $hashRaw = Invoke-CbApi -Method GET -Path "/api/v1/cblr/session/$sessionId/file/$($hashGet.file_id)/content"
            $remoteHash = (($hashRaw -split "`n") | Where-Object { $_ -match '^[0-9a-fA-F ]{40,}$' } | Select-Object -First 1) -replace '\s',''
            Remove-RemoteFile -SessionId $sessionId -Path 'C:\Windows\Temp\winpmem_hash.txt'
            if ($remoteHash) {
                if ($remoteHash -ieq $localHash) { Write-Host "  Endpoint SHA256 matches local copy." -ForegroundColor Green }
                else { Write-Warning "Endpoint SHA256 ($remoteHash) does NOT match local ($localHash)." }
            }
        }
        catch { Write-Warning "Remote hashing failed: $($_.Exception.Message)" }
    }

    # Detect whether the retrieved artifact is compressed (needs go-winpmem extract).
    $compressed     = $resolvedArgs -match '--compression'
    $extractCommand = $null
    if ($compressed) {
        $extractTarget  = if ($LocalDestinationPath -match '\.raw$') { $LocalDestinationPath -replace '\.raw$', '.extracted.raw' } else { "$LocalDestinationPath.extracted.raw" }
        $extractCommand = '{0} extract "{1}" "{2}"' -f (Split-Path -Path $WinpmemSourcePath -Leaf), $LocalDestinationPath, $extractTarget
    }

    # Chain-of-custody sidecar.
    $manifest = [ordered]@{
        acquired_utc      = (Get-Date).ToUniversalTime().ToString('o')
        cb_server         = $script:BaseUrl
        sensor_id         = $resolvedSensorId
        computer_name     = $computerName
        session_id        = $sessionId
        winpmem_source    = $WinpmemSourcePath
        remote_binary     = $RemoteBinaryPath
        winpmem_command   = $processCommand
        remote_image      = $RemoteImagePath
        pagefile_path     = $PagefilePath
        local_image       = $LocalDestinationPath
        remote_size_bytes = $remoteSize
        local_size_bytes  = $localSize
        size_match        = $sizeMatch
        sha256_local      = $localHash
        sha256_remote     = $remoteHash
        winpmem_exit_code = $runResult.return_code
        compressed        = [bool]$compressed
        extract_command   = $extractCommand
    }
    $manifestPath = "$LocalDestinationPath.manifest.json"
    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding UTF8
    "$localHash *$(Split-Path -Path $LocalDestinationPath -Leaf)" | Out-File -FilePath "$LocalDestinationPath.sha256" -Encoding ASCII
    Write-Host "  Manifest: $manifestPath" -ForegroundColor Green

    # =============================================================================
    #  STEP 8: Optional cleanup of remote artifacts
    # =============================================================================
    Write-Host "`n[8/8] Remote cleanup" -ForegroundColor Cyan
    Invoke-CleanupPrompt -SessionId $sessionId -BinaryPath $RemoteBinaryPath -ImagePath $RemoteImagePath

    Write-Host "`n==========================================" -ForegroundColor Cyan
    Write-Host "  MEMORY ACQUISITION COMPLETE" -ForegroundColor Cyan
    Write-Host "  Image : $LocalDestinationPath"
    Write-Host "  SHA256: $localHash  (of the transferred file)"
    if ($compressed) {
        Write-Host "  NOTE  : This is a compressed go-winpmem image. Decompress before analysis:" -ForegroundColor Yellow
        Write-Host "          $extractCommand" -ForegroundColor Yellow
    }
    Write-Host "==========================================" -ForegroundColor Cyan
}
catch {
    $exitCode = 1
    Write-Error "Memory acquisition failed: $($_.Exception.Message)"
}
finally {
    # Always close the Live Response session.
    if ($sessionId) {
        Write-Host "`nClosing Live Response session $sessionId..." -ForegroundColor Yellow
        try { Invoke-CbApi -Method PUT -Path "/api/v1/cblr/session/$sessionId" -Body @{ status = 'close' } | Out-Null }
        catch { Write-Warning "Failed to close session ${sessionId}: $($_.Exception.Message)" }
    }
    # Scrub the plaintext token from memory.
    if ($script:Headers) { $script:Headers['X-Auth-Token'] = $null }
    $plainToken = $null
    [System.GC]::Collect()
}

exit $exitCode
