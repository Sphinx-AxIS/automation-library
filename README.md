# automation-library

A collection of automation scripts (primarily PowerShell, with Python where it fits the use case better) for security operations, endpoint triage, and forensic investigation. Each script is self-contained under a category folder with its own README and manifest, so a script can be lifted out and run independently of the rest of the library.

## Repository layout

```
automation-library/
├── README.md              ← you are here
├── CATALOG.md             ← every script with a one-line summary
├── CAPABILITY_MATRIX.md   ← scripts mapped to capabilities and tags
├── scripts/
│   ├── carbon-black/      ← Carbon Black EDR triage and reporting
│   ├── elastic/           ← Elastic Stack queries and detections
│   ├── file-system/       ← file metadata, keyword search, integrity
│   ├── forensics/         ← timestamp conversion, ADS hunting, artifacts
│   └── llm/               ← LLM session and usage diagnostics
└── templates/
    ├── README-template.md ← per-script README starting point
    └── manifest-template.yml
```

## Categories

| Folder | Purpose |
|---|---|
| [scripts/carbon-black/](scripts/carbon-black/) | EDR data extraction, process tree analysis and visualization, JSON → CSV → XLSX conversion |
| [scripts/elastic/](scripts/elastic/) | Elastic Stack queries, detection rules, enumeration tooling |
| [scripts/file-system/](scripts/file-system/) | File metadata collection, keyword searching, content inspection |
| [scripts/forensics/](scripts/forensics/) | Timestamp conversion, alternate data stream hunting, artifact parsing |
| [scripts/llm/](scripts/llm/) | LLM session diagnostics and usage tracking (e.g. Codex) |

For a full per-script index see [CATALOG.md](CATALOG.md). For a feature-by-feature view (which scripts cover which capabilities, tags, and platforms) see [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md).

## Using a script

Every script folder contains its own README with parameters, requirements, and example invocations — read that first.

Typical pattern:

```powershell
cd scripts\file-system\get-file-metadata
. .\Get-AllFileMetadata.ps1
Get-AllFileMetadata -Path "C:\path\to\file.pdf"
```

Some scripts are functions that need to be dot-sourced (`. .\Script.ps1`) before calling. Others are entry-point scripts you invoke directly (`.\Script.ps1 -Param value`). The per-script README will say which.

## Adding a new script

1. Create a folder under the appropriate category: `scripts/<category>/<script-name>/`
2. Drop the `.ps1` (and any supporting scripts) into the folder
3. Copy [templates/README-template.md](templates/README-template.md) into the folder as `README.md` and fill it in
4. Copy [templates/manifest-template.yml](templates/manifest-template.yml) into the folder as `manifest.yml` and fill it in
5. Add a one-line entry to [CATALOG.md](CATALOG.md)
6. If the script introduces a new capability or tag, update [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md)

If no existing category fits, create a new top-level folder under `scripts/` and document its purpose in the table above.

## Requirements

- Most scripts target Windows; a few are cross-platform (see each script's README and the [Platform requirements](CAPABILITY_MATRIX.md#platform-requirements) table)
- PowerShell 5.1+ or PowerShell 7+ for the PowerShell scripts; Python 3.8+ for the Python scripts (currently `scripts/carbon-black/graph-process-tree/`)
- Individual scripts may require additional access or software — API keys, network reach, Microsoft Office for COM-based parsers, Graphviz binaries, etc. See each script's README.

## Status conventions

Each `manifest.yml` declares a status:

| Status | Meaning |
|---|---|
| `Production` | Stable, in active use, safe defaults |
| `Beta` | Functional but rough edges; review before production use |
| `WIP` | Under development; expect breakage |

## License

See [LICENSE](LICENSE) at the repository root, where present. Otherwise scripts are provided as-is for internal use.
