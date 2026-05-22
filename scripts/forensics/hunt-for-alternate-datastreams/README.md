# Get-AlternateDataStreams.ps1

`Get-AlternateDataStreams.ps1` lists and prints the contents of NTFS alternate data streams (ADS) attached to a target file, skipping the default unnamed `$DATA` stream. Useful for quickly inspecting whether a file carries hidden payloads (Zone.Identifier metadata, embedded text, hidden executable payloads, etc.).

## What it does

1. Calls `Get-Item -LiteralPath <Path> -Stream *` to enumerate every stream attached to the target file.
2. Filters out the default unnamed data stream (`$DATA`, `::$DATA`, `:$DATA`).
3. For each remaining stream, writes a header line with the stream name and size, then dumps the raw stream contents to the console.

## Basic usage

```powershell
.\Get-AlternateDataStreams.ps1 -Path "C:\path\to\file.exe"
```

Example output:

```text
==== [Zone.Identifier] (123 bytes) ====
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.com/download
HostUrl=https://example.com/installer.exe
```

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-Path` | Yes | Full path to the target file. Passed through `-LiteralPath`, so wildcards are treated as literal characters. |

## Requirements

- Windows
- PowerShell 5.1+
- The target file's volume must be NTFS (alternate data streams are an NTFS feature)
- Read access to the target file

## Notes and limitations

- **Single file only.** No pipeline input, no recursion. To hunt across a directory tree, wrap the script in a loop: `Get-ChildItem -File -Recurse | ForEach-Object { .\Get-AlternateDataStreams.ps1 -Path $_.FullName }`.
- **Binary streams produce console noise.** The script writes the raw contents via `Get-Content -Raw`, which assumes text. Streams that contain binary data (e.g. an embedded executable) will produce garbled output. For binary inspection, pipe the stream to a hex viewer or save it to a file with `Get-Content -Raw -AsByteStream`.
- **For a more comprehensive metadata view** (streams + hashes + ACLs + Authenticode + Office/PDF properties on the same file), see [`get-file-metadata`](../../file-system/get-file-metadata/) — the `Streams` field on its output object lists every stream as well, with the default `$DATA` included for completeness.
