# Get-targetedEvents.ps1

`Get-targetedEvents.ps1` bulk-exports every populated Windows event log on the local machine, filtered to a UTC start time, into a per-log `.evtx` file and then compresses the whole output directory into a single ZIP. It is intended for fast forensic capture of recent activity across the full event-log landscape without dragging along the unfiltered full logs.

## What it does

1. Enumerates every Windows event log via `Get-WinEvent -ListLog *` and keeps only those with at least one record.
2. For each log, calls `wevtutil epl` with an XPath filter selecting events whose `TimeCreated` is at or after `-StartUtc`.
3. Writes the filtered events to `<OutputRoot>\<safe-log-name>.evtx`, sanitizing characters that are illegal in Windows filenames (`\ / : * ? " < > |`) to underscores.
4. Compresses the entire `<OutputRoot>` directory of `.evtx` files into `<ZipPath>` with `Compress-Archive -Force`.
5. Prints a one-line confirmation of the ZIP path.

## Basic usage

```powershell
.\Get-targetedEvents.ps1 `
  -StartUtc   '2026-05-03T00:00:00.000Z' `
  -OutputRoot 'C:\Temp\EventLogs_After_2026-05-03_UTC' `
  -ZipPath    'C:\Temp\EventLogs_After_2026-05-03_UTC.zip'
```

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-StartUtc` | Yes | ISO-8601 UTC timestamp (e.g. `2026-05-03T00:00:00.000Z`). Events with `TimeCreated` at or after this time are exported. |
| `-OutputRoot` | Yes | Directory to receive one `.evtx` per log. Created if it doesn't exist. |
| `-ZipPath` | Yes | Destination path for the compressed archive of all `.evtx` files. Overwritten if it exists. |

## Requirements

- Windows
- PowerShell 5.1+
- `wevtutil.exe` (built into Windows)
- `Compress-Archive` (built-in PowerShell cmdlet)
- **Administrator rights** for any restricted channels (the Security log in particular requires elevation)
- Write access to `-OutputRoot` and `-ZipPath`

## Notes and limitations

- **Local machine only.** There is no `-ComputerName` parameter; the script reads only the local event logs.
- **Locked or access-denied logs are silently skipped.** `wevtutil` stderr is suppressed (`2>$null`) so individual log failures don't clutter the console. If you want a complete capture report, remove that redirection.
- **Empty logs are skipped** to keep the output set small.
- **Filename sanitization is one-way.** Log names containing illegal filename characters (e.g. `Microsoft-Windows-PowerShell/Operational`) become `Microsoft-Windows-PowerShell_Operational.evtx`. Two logs whose sanitized names collide would overwrite each other; in practice the standard Windows channels don't collide.
- **The exported `.evtx` files are still parseable by `Event Viewer`, `wevtutil`, and downstream forensic tools.** They retain the original log's schema and metadata, not just text.
- **`Compress-Archive` is slow** on very large output directories. If the resulting ZIP is hundreds of MB, consider switching to `tar` or `7z` for faster compression.
