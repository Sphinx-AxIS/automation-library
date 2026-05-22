# llm-assisted-investigate

Three PowerShell scripts that automate the initial investigation of a Carbon Black watchlist alert. Given a Carbon Black UI URL and an alert name, the workflow fetches the full process tree from the CB API, validates each observed software product against a software-approval API, and emits a structured LLM prompt summarizing the alert for Tier 2 SOC analyst review. The final prompt is copied to the clipboard.

## What it does

1. Loads two supporting toolkits via dot-sourcing: `Get-CBProcessTree.ps1` (process tree + event data via the CB v1/v4 APIs) and `SoftwareValidation.ps1` (software approval lookups against the SPOC C API).
2. Loads two local lookup files: `whitelist.txt` (internal whitelist, one product per line) and `process_map.csv` (mapping of observed process names to official product names — see *Inputs* below).
3. Accepts a Carbon Black URL (analyze view or search view), extracts the process IDs (or queries the search API and extracts them), and identifies the target processes.
4. For each target process: walks the full child tree, classifies the parent and every unique child against the whitelist and SPOC C API, scrubs noise from the event data (drops signed-binary modload entries, decodes filemod action codes), and builds a markdown prompt for analyst use.
5. Joins all generated prompts and copies them to the clipboard.

## Files in this folder

| File | Role |
|---|---|
| `Start-CBInvestigation.ps1` | Entry point — accepts `-WatchlistUrl` and `-AlertName`, orchestrates the run, builds the LLM prompt, and copies it to the clipboard. |
| `Get-CBProcessTree.ps1` | Function library — defines `Get-CBProcessTreeData`, which retrieves a process and its full child subtree from the CB APIs. |
| `SoftwareValidation.ps1` | Function library — defines `Test-ApprovedSoftware`, which queries the SPOC C software approval API for a product (and optional version) and returns `$true`/`$false`. |
| `whitelist.txt` | Internal whitelist; one product/process name per line. Lines starting with `#` are treated as comments. |
| `process_map.csv` | **Not committed.** Required at runtime. Two columns: `process_name`, `official_product_name`. Used to translate observed process names (e.g. `chrome.exe`) to the canonical product name (e.g. `Google Chrome`) before the SPOC C lookup. See *Inputs* below. |

## Configuration

Edit the placeholders at the top of each script before running.

### `Get-CBProcessTree.ps1`

```powershell
$CBServer        = "<your-cb-server>:<port>"                  # e.g. "cb.example.com:8443"
$CBAPIKey        = Get-Content "<path-to-cb-api-key-file>"    # supports NTFS ADS, e.g. ".\cred.txt:APIKeyStream"
$EventOutputRoot = "<path-to-event-output-directory>"         # where per-process event JSON gets written
```

### `SoftwareValidation.ps1`

```powershell
$script:DefaultApiKey = Get-Content "<path-to-software-validation-api-key-file>"
$apiUrl = "<software-validation-api-url>"   # e.g. "https://your-validation-api.example.com/api/v1/public/product"
```

### `Start-CBInvestigation.ps1` (inside the LLM prompt template)

Replace the `<your-internal-cidr-N>` placeholders in the *Internal IP Address Ranges* section of the prompt with your organization's internal CIDR ranges (e.g. `10.0.0.0/8`, `192.168.0.0/16`). Add or remove rows as needed. The editing instruction is also in a PowerShell comment block above the here-string.

## Basic usage

```powershell
# Interactive prompts for the URL and alert name
.\Start-CBInvestigation.ps1

# Or supply both as parameters
.\Start-CBInvestigation.ps1 `
  -WatchlistUrl 'https://cb.example.com/#/analyze/00000001-0000-0000-0000-000000000000/1' `
  -AlertName    'Suspicious Outbound Beacon'
```

`Start-CBInvestigation.ps1` recognizes two CB URL shapes:

- `/#/analyze/<process-id>/<segment-id>` — extracted directly
- `/#/search?...` or `/#/search/q=...` — rewritten to `/api/v1/process?...` and queried; up to 200 processes returned

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-WatchlistUrl` | No | Carbon Black UI URL (analyze view or search view). Prompted if omitted. |
| `-AlertName` | No | Friendly name of the alert/watchlist; used in the generated prompt header. Prompted if omitted. |

## Inputs

- **`-WatchlistUrl`** and **`-AlertName`** parameters (or interactive prompts)
- **Carbon Black API key** — loaded from the path in `Get-CBProcessTree.ps1`
- **Software-approval API key** — loaded from the path in `SoftwareValidation.ps1`
- **`whitelist.txt`** in the script's working directory (optional but recommended; absence triggers a warning)
- **`process_map.csv`** in the script's working directory (required for accurate approval lookups; absence triggers a warning and reduces the lookup to raw process names)

### `process_map.csv` format

Two columns:

```csv
process_name,official_product_name
chrome.exe,Google Chrome
code.exe,Microsoft Visual Studio Code
firefox.exe,Mozilla Firefox
```

Used to translate the observed process name (with extension stripped and lowercased) to the canonical product name that the SPOC C API expects.

## Outputs

- **Console log** — progress messages, per-process tree retrieval status, approval lookups, etc.
- **Per-process event JSON files** at `$EventOutputRoot\<ProcessID>_<SegmentID>_events.json` (written by `Get-CBProcessTree.ps1`)
- **Generated LLM prompt** — one prompt per matched target process, joined and copied to the clipboard. Each prompt includes:
  - Watchlist name, target PID, target process name
  - Parent process approval status (internal-whitelisted / approved / not approved)
  - Child process approval statuses (per unique child name)
  - The full JSON-serialized initial process summary
  - (The here-string is truncated at the `JSON Formatted Initial Process Summary` block — extend the template to add more sections if needed.)

## Requirements

- Windows
- PowerShell 5.1+
- Network reach to the Carbon Black API server (currently configured via `$CBServer`)
- Network reach to the SPOC C software approval API
- Carbon Black API key
- SPOC C API key
- NTFS volume at the credential file path (the original deployment uses NTFS alternate data streams for key storage)
- Read access to those credential streams

## Status

**WIP.** Required to make this turnkey:

1. Fill in the configuration placeholders for your environment.
2. Provide a `process_map.csv` in the script directory.
3. Replace the `<your-internal-cidr-N>` placeholders in the prompt template's *Internal IP Address Ranges* section.
4. Verify network reach and API key validity before running against a live alert.

Once those four steps are done and you have a successful end-to-end run, bump the status in `manifest.yml` to `Beta` or `Production`.

## Notes and limitations

- **Search URLs are hardcoded to return at most 200 processes.** If you investigate a watchlist with more than 200 matching rows, only the first 200 are analyzed; rerun against a narrower query.
- **Event-tree retrieval writes raw JSON to disk.** Every process and child writes a `<ProcessID>_<SegmentID>_events.json` to `$EventOutputRoot`. The directory is created if missing; ACLs on each file are tightened to grant the current user full control.
- **Software-approval logic is best-effort.** A product is considered "approved" if any version returned by the API has `approval_status -ieq 'Approved'`. Errors from the API short-circuit to `Not Approved`.
- **The clipboard copy uses `Set-Clipboard`.** Multi-prompt runs (multiple target PIDs) are concatenated with `--- (New Prompt) ---` separators.
