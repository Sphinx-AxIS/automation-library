# ConvertEpoch-toHuman.ps1

`ConvertEpoch-toHuman.ps1` reads epoch-millisecond timestamps from a text file (one per line) and writes a CSV mapping each value to its UTC ISO-8601 representation. Useful for quickly normalizing raw epoch timestamps pulled from logs or APIs during forensic review.

## What it does

For each non-blank line in `-InputPath`:

1. Treats the line as an epoch-millisecond integer.
2. Converts it to a `DateTimeOffset` and formats it as `yyyy-MM-ddTHH:mm:sszzz` (UTC with explicit zone offset).
3. Writes a row to `-OutputPath` with two columns: `EpochMS`, `UTC`.

## Basic usage

```powershell
.\ConvertEpoch-toHuman.ps1 -InputPath .\epochs.txt -OutputPath .\converted.csv
```

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-InputPath` | Yes | Path to a text file containing one epoch-millisecond integer per line. |
| `-OutputPath` | Yes | Path for the output CSV (overwritten if it exists). |

## Input format

One epoch-millisecond integer per line, no header. Example `epochs.txt`:

```text
1714617600000
1714704000000
1714790400000
```

## Output format

CSV with two columns:

```csv
"EpochMS","UTC"
"1714617600000","2024-05-02T00:00:00+00:00"
"1714704000000","2024-05-03T00:00:00+00:00"
"1714790400000","2024-05-04T00:00:00+00:00"
```

## Requirements

- PowerShell 5.1+ or PowerShell 7+ (cross-platform — `DateTimeOffset` is .NET)
- Read access to `-InputPath`
- Write access to `-OutputPath`

## Notes and limitations

- **Epoch milliseconds, not seconds.** If your timestamps are in seconds, multiply by 1000 first, or change the call site from `FromUnixTimeMilliseconds` to `FromUnixTimeSeconds`.
- **No input validation.** Non-numeric lines will throw a `[int64]` parse exception that halts the run. Pre-clean the file or wrap the inner expression in `try/catch` if you expect noisy input.
- **Output uses the default culture's CSV quoting** from `Export-Csv`. Re-import with `Import-Csv` to get the same shape back.
