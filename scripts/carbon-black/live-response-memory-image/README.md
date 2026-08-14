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
6. **Export the image** — chunked `get file` reads (default 256 MB) streamed to disk on the analyst machine, so arbitrarily large images can be retrieved without exhausting the CB server file store. Status polling is adaptive (starts sub-second, backs off) so per-chunk overhead stays minimal rather than paying a fixed poll interval on every chunk.
7. **Verify and record** — compares local size to the endpoint size, computes a local SHA256, optionally hashes the image on the endpoint with `certutil`, and writes a `.sha256` sidecar plus a `.manifest.json` chain-of-custody record.
8. **Cleanup prompt** — interactively offers to delete the pushed binary and/or the image from the endpoint. Nothing is deleted automatically.

The Live Response session is always closed in a `finally` block, even on error.

## Choosing a Winpmem binary

The Winpmem command line is exposed as the `-WinpmemArguments` parameter, so the same script drives any Winpmem build — you supply the arguments that match your binary. Two tokens are substituted before execution:

| Token | Replaced with |
|---|---|
| `{ImagePath}` | `-RemoteImagePath` — where the image is written on the endpoint, and where the export step reads from |
| `{PagefilePath}` | `-PagefilePath` (default `C:\pagefile.sys`) |

Keep the `{ImagePath}` token (or otherwise ensure Winpmem writes to `-RemoteImagePath`) so the export step reads the correct file; the script warns if the resolved arguments do not reference the image path.

Which build you use is a real decision, because **no current Winpmem captures the pagefile with a modern signed driver — the two requirements pull in opposite directions:**

| Build | Pagefile? | Output | Driver / Secure Boot | Example `-WinpmemArguments` |
|---|---|---|---|---|
| Legacy AFF4 winpmem (`winpmem_v3.3.rc3`, `winpmem-2.1.post4`) | **Yes** (`-p`) | AFF4 container (RAM + pagefile streams) | Old driver; **may not load** under Secure Boot / HVCI — test first | `-o "{ImagePath}" -p "{PagefilePath}" -dd` |
| `go-winpmem` (1.0-rc2, Go rewrite) | No | Raw (sparse; optional `--compression snappy\|gzip`, decompress with `go-winpmem extract`) | Modern driver, **signed (Binalyze / GlobalSign)** — loads under Secure Boot | `acquire --compression snappy --progress "{ImagePath}"` |
| WinPMEM 4.x "mini" (`winpmem_mini_x64`, `winpmem64.exe`) | No | Raw only | Modern driver | `"{ImagePath}"` (output is positional) |

The script's **default** is the `go-winpmem` form with **snappy compression** (`acquire --compression snappy --progress "{ImagePath}"`) — a modern signed driver that loads under Secure Boot, and compression shrinks the image before it crosses the (slow, store-and-forward) Live Response transfer. That means the retrieved file is a **compressed** go-winpmem image; the script prints the exact `go-winpmem extract` command to turn it into a raw image, and records that command in the `.manifest.json`. For an uncompressed raw image, drop `--compression snappy`. To capture the **pagefile** instead, switch to the legacy AFF4 build by passing `-WinpmemArguments '-o "{ImagePath}" -p "{PagefilePath}" -dd'` and giving `-RemoteImagePath` an `.aff4` name.

### Why compression is the main speed lever

Live Response `get file` is store-and-forward (endpoint → CB server → analyst), so export is often slower than capture — a real problem when racing a VDI logoff. The default mitigations: snappy compression cuts the bytes crossing that path (RAM images compress well); 256 MB chunks and adaptive polling remove per-chunk overhead. For a small VDI RAM footprint this typically brings capture+export down to a few minutes. See the export discussion in the acquisition strategy notes.

**If you need the pagefile *and* a driver that loads on modern endpoints,** capture RAM with `go-winpmem` and collect `C:\pagefile.sys` as a separate step — it is a locked system file, so it needs a raw-NTFS copy tool run via `create process`, not a plain `get file`. Note that `go-winpmem acquire` installs a `winpmem` driver service on the endpoint; run `go-winpmem uninstall` (via `create process`) afterward to leave a clean footprint.

## Requirements

- Windows
- PowerShell 7.0+
- A Winpmem binary available locally to push to the endpoint (see [Choosing a Winpmem binary](#choosing-a-winpmem-binary); the default arguments assume `go-winpmem`)
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
  -WinpmemSourcePath "C:\tools\go-winpmem_amd64_1.0-rc2_signed.exe" `
  -RemoteImagePath "C:\Windows\Temp\WORKSTATION-01.raw" `
  -LocalDestinationPath "E:\cases\IR-2026-014\memory" `
  -SkipCertificateCheck
```

To capture the pagefile with the legacy AFF4 build instead, add
`-WinpmemArguments '-o "{ImagePath}" -p "{PagefilePath}" -dd'` and use an `.aff4` image name.

The API key is always prompted for and read as a `SecureString`; it is never accepted as an argument.

## Parameters

| Parameter | Required | Description |
|---|---:|---|
| `-CbServerUrl` | Yes | Base URL of the CB EDR server, e.g. `https://cb.example.local`. Prompted if omitted. |
| `-Hostname` | One of | Target host name (preferred). Resolved to a Sensor ID. |
| `-SensorId` | One of | Target Sensor ID. Use when hostname resolution is not feasible. |
| `-WinpmemSourcePath` | Yes | Local path to the Winpmem binary to push. Prompted if omitted. |
| `-RemoteBinaryPath` | No | Where the binary lands on the endpoint. Default: `C:\Windows\Temp\<source-file-name>`. |
| `-RemoteImagePath` | No | Where Winpmem writes the image on the endpoint. Default: `C:\Windows\Temp\<host>_<timestamp>.raw`. |
| `-PagefilePath` | No | Pagefile path on the endpoint, substituted into `{PagefilePath}`. Only used by the legacy AFF4 arguments. Default: `C:\pagefile.sys`. |
| `-WinpmemArguments` | No | Winpmem argument string with `{ImagePath}` / `{PagefilePath}` tokens. Default (go-winpmem, compressed): `acquire --compression snappy --progress "{ImagePath}"`. Uncompressed: drop `--compression snappy`. Legacy AFF4: `-o "{ImagePath}" -p "{PagefilePath}" -dd`. |
| `-LocalDestinationPath` | No | Folder or file on this machine for the exported image. Default: current directory. |
| `-RetrievalChunkSizeMB` | No | Chunk size for `get file` retrieval. Larger means fewer round-trips (faster) but stages more in the CB server file store (`CbLRMaxStoreSizeMB` must hold one chunk). Default: 256. Set to 0 for a single-shot pull. |
| `-PollIntervalSeconds` | No | Ceiling for adaptive status polling — polling starts sub-second and backs off up to this value, so fast commands (get-file chunks) don't wait a fixed interval each time. Default: 5. |
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
| `<image>` | The memory image. By default a **snappy-compressed** go-winpmem image — decompress with the `go-winpmem extract` command the script prints. Drop `--compression` for raw, or use the legacy build for AFF4 with the pagefile. |
| `<image>.sha256` | `SHA256 *<filename>` line for integrity checking. |
| `<image>.manifest.json` | Acquisition record: server, sensor, session, sizes, hashes, Winpmem command, timestamps, whether the image is compressed, and the `go-winpmem extract` command to decompress it. |

## Notes and limitations

- **Sensor must be online.** Live Response cannot activate a session against an offline sensor; the script warns and will time out if the sensor never checks in.
- **Image size and export speed.** Memory images can be tens of GB, and Live Response `get file` is store-and-forward (endpoint → CB server → analyst), so export is often slower than capture. The defaults fight this: **snappy compression** shrinks the bytes on the wire, **256 MB chunks** and **adaptive polling** cut per-chunk overhead. Confirm `CbLRMaxStoreSizeMB` on the server can hold at least one chunk.
- **Compressed output needs `extract`.** With the default (`--compression snappy`), the retrieved file is a compressed go-winpmem image — not directly analyzable. The script prints the exact `go-winpmem extract` command at the end and records it in the manifest. The recorded SHA256 is of the compressed (transferred) file. Drop `--compression snappy` if you'd rather transfer raw.
- **Ephemeral VDI.** For non-persistent VDI, a user logoff destroys the instance and the local image with it. Capture while the user is logged in and export fast (the defaults are tuned for this); for a guaranteed capture, prefer a hypervisor snapshot-with-memory, which freezes live memory out-of-band and sidesteps both the logoff race and the Live Response transfer entirely.
- **Pagefile support depends on the binary.** Only the legacy AFF4 build captures the pagefile; `go-winpmem` and WinPMEM 4.x image RAM only. See [Choosing a Winpmem binary](#choosing-a-winpmem-binary).
- **Driver signing vs. Secure Boot.** Modern endpoints with Secure Boot / HVCI may refuse the legacy AFF4 driver. `go-winpmem` ships a signed driver that loads under Secure Boot but does not capture the pagefile. Validate driver load on a representative endpoint before an engagement.
- **Failure is now fatal by design.** A nonzero Winpmem exit aborts the run and prints Winpmem's captured console output, rather than continuing into the retrieval steps.
- **Permissions.** The Live Response `create process` runs as SYSTEM on the endpoint, which is sufficient for Winpmem to load its driver.

## Troubleshooting

### Session never becomes active
The sensor is offline or not checking in, or Live Response is not enabled on the server. Confirm the sensor status shown in step 1 is `Online` and that `CbLREnabled=True` on the server.

### HTTP 412 on session create
Live Response is disabled on the CB server. Enable it (`CbLREnabled=True`) and restart services.

### TLS / certificate errors
On-prem CB servers commonly use self-signed certificates. Re-run with `-SkipCertificateCheck`.

### Winpmem returns a non-zero exit code
The script aborts immediately on a nonzero exit and prints Winpmem's own console output (captured from the endpoint) so you can see the cause. The most common cause is an argument/binary mismatch — for example passing the AFF4 `-o / -p / -dd` flags to a modern build (`go-winpmem` or WinPMEM 4.x) that uses different syntax. Match `-WinpmemArguments` to your binary using the [Choosing a Winpmem binary](#choosing-a-winpmem-binary) table, and confirm the endpoint has a writable target path (e.g. `C:\Windows\Temp\`).
