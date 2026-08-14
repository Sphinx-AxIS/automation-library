# Invoke-CBLRMemoryImage.ps1

`Invoke-CBLRMemoryImage.ps1` acquires a live memory image — physical RAM plus the pagefile — from a remote host using the **Carbon Black EDR on-premise Live Response API** (CB Response / EDR 7.9.2) and **Winpmem**. It is intended for incident response and memory forensics, where an analyst needs to capture volatile memory from an endpoint and pull it back to their own workstation for analysis.

The script deliberately avoids running PowerShell inside the Live Response shell (which is fragile). Winpmem is executed directly with the Live Response `create process` command, and all file movement uses the native `put file` / `get file` / `directory list` / `delete file` commands.

## What it does

The workflow runs in eight stages:

1. **Resolve the sensor** — by hostname (preferred) via `GET /api/v1/sensor?hostname=<h>`, or directly by Sensor ID. Because the hostname filter is a case-insensitive substring search, the script prefers an exact `computer_name` match and, if several sensors still match (for example a re-registered host), auto-selects the most recently checked-in Online sensor and prints the candidates.
2. **Open a Live Response session** — `POST /api/v1/cblr/session`, then polls until the session is `active`. The session's `default_command_timeout` is set to `-AcquisitionTimeoutSeconds` so a long Winpmem run is not killed server-side.
3. **Deliver Winpmem** — uploads the binary to the CB server (`POST .../file`, multipart) and pushes it to the endpoint with `put file`.
4. **Run Winpmem** — `create process` with `wait=true`, running Winpmem with your arguments. Progress is polled and the session is kept warm with periodic keepalives.
5. **Confirm the image** — `directory list` verifies the image exists and reads its byte size.
6. **Export the image** — chunked `get file` reads (default 64 MB) streamed to disk on the analyst machine, so arbitrarily large images can be retrieved without exhausting the CB server file store.
7. **Verify and record** — compares local size to the endpoint size, computes a local SHA256, optionally hashes the image on the endpoint with `certutil`, and writes a `.sha256` sidecar plus a `.manifest.json` chain-of-custody record.
8. **Cleanup prompt** — interactively offers to delete the pushed binary and/or the image from the endpoint. Nothing is deleted automatically.

The Live Response session is always closed in a `finally` block, even on error.

## Winpmem and the pagefile

Including the pagefile in a single artifact requires the **full AFF4-capable `winpmem.exe`** and an AFF4 container: the pagefile is stored as an additional stream, which raw/ELF single-stream formats cannot hold, and `winpmem_mini` has no `-p` flag at all.

The Winpmem command line is exposed as the `-WinpmemArguments` parameter so you control the acquisition at run time. Two tokens are substituted before execution:

| Token | Replaced with |
|---|---|
| `{ImagePath}` | `-RemoteImagePath` (where the image is written on the endpoint — also where retrieval reads from) |
| `{PagefilePath}` | `-PagefilePath` (default `C:\pagefile.sys`) |

The default is:

```text
-o "{ImagePath}" -p "{PagefilePath}" -dd
```

Keep the `{ImagePath}` token (or otherwise ensure Winpmem writes to `-RemoteImagePath`) so the export step reads the correct file; the script warns if the resolved arguments do not reference the image path.

## Requirements

- Windows
- PowerShell 7.0+
- A full AFF4-capable Winpmem binary available locally (to push to the endpoint)
- Network reach to the Carbon Black EDR server with the Live Response API enabled
- A Carbon Black API key with Live Response permission (prompted at run time)
- The target sensor must be online for the session to activate

## Basic usage

Fully interactive (prompts for anything not supplied):

```powershell
.\Invoke-CBLRMemoryImage.ps1
```

Typical run by hostname:

```powershell
.\Invoke-CBLRMemoryImage.ps1 `
  -CbServerUrl "https://cb.example.local" `
  -Hostname "WORKSTATION-01" `
  -WinpmemSourcePath "C:\tools\winpmem.exe" `
  -RemoteImagePath "C:\Windows\Temp\WORKSTATION-01.aff4" `
  -LocalDestinationPath "E:\cases\IR-2026-014\memory" `
  -SkipCertificateCheck
```

The API key is always prompted for and read as a `SecureString`; it is never accepted as an argument.

## Parameters

| Parameter | Required | Description |
|---|---:|---|
| `-CbServerUrl` | Yes | Base URL of the CB EDR server, e.g. `https://cb.example.local`. Prompted if omitted. |
| `-Hostname` | One of | Target host name (preferred). Resolved to a Sensor ID. |
| `-SensorId` | One of | Target Sensor ID. Use when hostname resolution is not feasible. |
| `-WinpmemSourcePath` | Yes | Local path to the Winpmem binary to push. Prompted if omitted. |
| `-RemoteBinaryPath` | No | Where the binary lands on the endpoint. Default: `C:\Windows\Temp\<source-file-name>`. |
| `-RemoteImagePath` | No | Where Winpmem writes the image on the endpoint. Default: `C:\Windows\Temp\<host>_<timestamp>.aff4`. |
| `-PagefilePath` | No | Pagefile path on the endpoint. Default: `C:\pagefile.sys`. |
| `-WinpmemArguments` | No | Winpmem argument string with `{ImagePath}` / `{PagefilePath}` tokens. Default: `-o "{ImagePath}" -p "{PagefilePath}" -dd`. |
| `-LocalDestinationPath` | No | Folder or file on this machine for the exported image. Default: current directory. |
| `-RetrievalChunkSizeMB` | No | Chunk size for `get file` retrieval. Default: 64. Set to 0 for a single-shot pull. |
| `-PollIntervalSeconds` | No | Seconds between status polls. Default: 5. |
| `-SessionTimeoutSeconds` | No | Max wait for the session to become active. Default: 300. |
| `-CommandTimeoutSeconds` | No | Timeout for short commands (put/get/dir/delete). Default: 120. |
| `-AcquisitionTimeoutSeconds` | No | Timeout for the Winpmem run and single-shot retrieval. Default: 3600. |
| `-VerifyRemoteHash` | No | Also hash the image on the endpoint with `certutil` and compare to the local SHA256. |
| `-SkipCertificateCheck` | No | Skip TLS validation (self-signed on-prem certificates). |

The API key is intentionally **not** a parameter — it is always prompted.

## Output

Written next to the exported image:

| File | Contents |
|---|---|
| `<image>` | The memory image (default AFF4 with embedded pagefile). |
| `<image>.sha256` | `SHA256 *<filename>` line for integrity checking. |
| `<image>.manifest.json` | Acquisition record: server, sensor, session, sizes, hashes, Winpmem command, timestamps. |

## Notes and limitations

- **Sensor must be online.** Live Response cannot activate a session against an offline sensor; the script warns and will time out if the sensor never checks in.
- **Image size.** Memory images can be tens of GB. Chunked retrieval keeps the CB server file store from filling up, but transfer over Live Response is still slow — plan for it, and confirm the server's `CbLRMaxStoreSizeMB` is large enough for at least one chunk.
- **Full Winpmem required for the pagefile.** `winpmem_mini` cannot capture the pagefile; supply the AFF4-capable build.
- **AFF4 output.** The default produces an AFF4 container. Extract a raw image later with `winpmem -e` (or analyze with AFF4-aware tooling) if your workflow needs raw.
- **Permissions.** The Live Response `create process` runs as SYSTEM on the endpoint, which is sufficient for Winpmem to load its driver.

## Troubleshooting

### Session never becomes active
The sensor is offline or not checking in, or Live Response is not enabled on the server. Confirm the sensor status shown in step 1 is `Online` and that `CbLREnabled=True` on the server.

### HTTP 412 on session create
Live Response is disabled on the CB server. Enable it (`CbLREnabled=True`) and restart services.

### TLS / certificate errors
On-prem CB servers commonly use self-signed certificates. Re-run with `-SkipCertificateCheck`.

### Winpmem returns a non-zero exit code
The image may be incomplete. Check that the supplied binary is the AFF4-capable build, that `-PagefilePath` is correct for the target, and review the arguments echoed in the plan output.
