<#
.SYNOPSIS
    Exports every populated Windows event log filtered to a UTC start time.
.DESCRIPTION
    Enumerates all Windows event logs that have at least one record, then uses
    wevtutil to export each log to its own .evtx file containing only events
    created at or after -StartUtc. After all logs are exported, the output
    directory is compressed to -ZipPath.

    Useful for forensic capture of recent activity across the full local
    event-log landscape without exporting unfiltered (and much larger) full logs.
.EXAMPLE
    .\Get-targetedEvents.ps1 `
        -StartUtc '2026-05-03T00:00:00.000Z' `
        -OutputRoot 'C:\Temp\EventLogs_After_2026-05-03_UTC' `
        -ZipPath   'C:\Temp\EventLogs_After_2026-05-03_UTC.zip'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$StartUtc,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipPath
)

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
Where-Object { $_.RecordCount -gt 0 } |
ForEach-Object {
    $LogName = $_.LogName
    $SafeName = ($LogName -replace '[\\/:*?"<>|]', '_')
    $OutFile = Join-Path $OutputRoot "$SafeName.evtx"

    wevtutil epl "$LogName" "$OutFile" `
        /q:"*[System[TimeCreated[@SystemTime>='$StartUtc']]]" `
        /ow:true 2>$null
}

Compress-Archive -Path "$OutputRoot\*.evtx" -DestinationPath $ZipPath -Force
Write-Host "Saved filtered event logs to: $ZipPath"
