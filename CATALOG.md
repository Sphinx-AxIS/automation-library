# Catalog

Per-script index of `automation-library`. Each entry links to the script folder, names the entry point, and gives a one-paragraph summary of what it does. For a feature-by-feature view (capabilities, tags, platforms) see [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md).

---

## carbon-black

### [llm-assisted-investigate](scripts/carbon-black/llm-assisted-investigate/)
Automates the initial investigation of a Carbon Black watchlist alert. Accepts a CB UI search or analyze URL, converts it to an API query, fetches the resulting process tree(s) and event data, validates observed software against an approval API, and emits a structured LLM prompt for downstream analysis.

- **Entry point:** [Start-CBInvestigation.ps1](scripts/carbon-black/llm-assisted-investigate/Start-CBInvestigation.ps1)
- **Components:** `Get-CBProcessTree.ps1` (process tree + event collection), `SoftwareValidation.ps1` (SPOC C software approval lookup), `whitelist.txt`, `process_map.csv`
- **Inputs:** Carbon Black URL, alert/watchlist name, CB API key, SPOC C API key
- **Status:** WIP

### [export-processes-by-host](scripts/carbon-black/export-processes-by-host/)
End-to-end Carbon Black extraction workflow. Queries the CB API for processes filtered by hostname and time range, then converts the raw JSON to structured CSV and finally to an analyst-friendly XLSX report.

- **Entry point:** [Run-FullCBWorkflow.ps1](scripts/carbon-black/export-processes-by-host/Run-FullCBWorkflow.ps1)
- **Components:** `ConvertJSON-ToCSV.ps1`, `Convert-ToXlsx.ps1`
- **Inputs:** Carbon Black API credentials, hostname, start/end time
- **Outputs:** JSON (raw), CSV (structured), XLSX (final)
- **Status:** Production

### [graph-process-tree](scripts/carbon-black/graph-process-tree/)
Three Python scripts that visualize Carbon Black process trees from an Excel export. Includes a forest renderer that emits one styled SVG per root tree across the entire workbook, and two PID-centered renderers (a zero-dependency styled SVG and a Graphviz-based DOT/SVG/PDF/PNG variant) that show ancestors up to the root parent plus all descendants of a target PID.

- **Entry point:** [process_pid_context_svg_styled.py](scripts/carbon-black/graph-process-tree/process_pid_context_svg_styled.py)
- **Components:** `process_trees_svg_indented.py` (forest renderer), `process_pid_context_diagram.py` (Graphviz alternative)
- **Inputs:** Excel workbook (`.xlsx`) with hostname/parent_name/parent_pid/process_name/cmdline/username/process_pid columns; target PID for the PID-centered scripts
- **Outputs:** Styled SVG (or DOT/SVG/PDF/PNG via Graphviz), per-diagram CSV, run-level manifest CSV
- **Language:** Python 3.8+
- **Status:** Beta

---

## elastic

### [query-kibana-api](scripts/elastic/query-kibana-api/)
Starter template for invoking a Kibana API endpoint with HTTP Basic Authentication. Encodes the supplied username and password, builds JSON request headers and a body, sends a POST, and prints the response. Designed to be edited inline for a specific endpoint and payload.

- **Entry point:** [Kibana_API.ps1](scripts/elastic/query-kibana-api/Kibana_API.ps1)
- **Inputs:** `$KibanaUrl`, `$Username`, `$Password`, `$RequestBody` (all edited inline)
- **Outputs:** Console output of the parsed response
- **Status:** WIP

---

## file-system

### [get-file-metadata](scripts/file-system/get-file-metadata/)
Comprehensive single-file or batch metadata collector for forensic triage and file review. Returns a structured object containing filesystem timestamps, NTFS alternate data stream info, owner and ACL, MD5/SHA1/SHA256 hashes, Authenticode signature data, Windows Shell extended properties, Office Open XML metadata, embedded OLE objects (including legacy `.doc` via Word COM), and best-effort PDF XMP metadata. Pipeline-friendly with `Get-ChildItem`.

- **Entry point:** [Get-AllFileMetadata.ps1](scripts/file-system/get-file-metadata/Get-AllFileMetadata.ps1) (function — dot-source before calling `Get-AllFileMetadata`)
- **Inputs:** file path (parameter or pipeline)
- **Outputs:** PSCustomObject; commonly exported to JSON or flattened to CSV
- **Status:** Production

### [search-file-for-keywords](scripts/file-system/search-file-for-keywords/)
Searches a single file (`.txt`, `.docx`, etc.) for a user-supplied keyword list and writes each match to an output file with the line number and the full line of context. Keywords file is one keyword per line.

- **Entry point:** [Search-Keywords.ps1](scripts/file-system/search-file-for-keywords/Search-Keywords.ps1)
- **Inputs:** `-InputPath`, `-KeywordsPath`, `-OutputPath`
- **Status:** Beta

---

## forensics

### [convert-epoch-time](scripts/forensics/convert-epoch-time/)
Reads epoch-millisecond timestamps from a text file (one per line) and writes a two-column CSV (`EpochMS`, `UTC`) mapping each value to its UTC ISO-8601 representation.

- **Entry point:** [ConvertEpoch-toHuman.ps1](scripts/forensics/convert-epoch-time/ConvertEpoch-toHuman.ps1)
- **Inputs:** `-InputPath`, `-OutputPath`
- **Status:** Beta

### [hunt-for-alternate-datastreams](scripts/forensics/hunt-for-alternate-datastreams/)
Lists and prints the contents of NTFS alternate data streams attached to a single target file, skipping the default `$DATA` stream.

- **Entry point:** [Get-AlternateDataStreams.ps1](scripts/forensics/hunt-for-alternate-datastreams/Get-AlternateDataStreams.ps1)
- **Inputs:** `-Path`
- **Status:** Beta

### [search-zeekfeeds](scripts/forensics/search-zeekfeeds/)

Queries 24 IP-specific open-source threat intelligence feeds hosted in the CriticalPathSecurity Zeek repository. Bypasses GitHub API rate limits by pulling raw lists directly from the CDN to rapidly audit Indicators of Compromise (IOCs).

- **Entry point:** [Search-ZeekFeeds.psm1](scripts/forensics/search-zeekfeeds/Search-ZeekFeeds.psm1)
- **Inputs:** `-TargetIP` (supports string array inputs via pipeline)
- **Status:** Active

### [windows-event-logs](scripts/forensics/windows-event-logs/)

Bulk-exports every populated Windows event log on the local machine to a per-log `.evtx` file filtered to events created at or after a specified UTC start time, then compresses the result into a single ZIP. Useful for fast forensic capture of recent activity across the full event-log landscape.

- **Entry point:** [Get-targetedEvents.ps1](scripts/forensics/windows-event-logs/Get-targetedEvents.ps1)
- **Inputs:** `-StartUtc`, `-OutputRoot`, `-ZipPath`
- **Outputs:** One `.evtx` per populated log in `-OutputRoot`; combined ZIP archive at `-ZipPath`
- **Status:** Beta

---

## llm

### [get-codex-usage](scripts/llm/get-codex-usage/)
Parses local Codex (`$HOME\.codex\sessions\*.jsonl`) session logs and reports real-time token usage, context window utilization, burn rate (average and peak), rate-limit status with reset timing, and warnings when context exhaustion or large requests are imminent. Helps decide when to start a fresh session.

- **Entry point:** [Get-CODEXUsage.ps1](scripts/llm/get-codex-usage/Get-CODEXUsage.ps1)
- **Inputs:** `-SessionFile` (optional — defaults to most recent), `-RecentEventsForAverage` (optional, default 5)
- **Status:** Production
