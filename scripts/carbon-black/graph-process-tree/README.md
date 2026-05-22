# graph-process-tree

Three related Python scripts that visualize Carbon Black process trees from a CB process-event export (Excel workbook). All three share the same input schema and deduplication logic, but differ in scope (forest vs. PID-centered) and renderer (zero-dependency SVG vs. Graphviz).

## Choose a script

| Script | Use when you want to... | Renderer | External binaries |
|---|---|---|---|
| `process_pid_context_svg_styled.py` | Investigate a specific PID — see its lineage up to the root parent and all descendants in one diagram | Hand-written SVG (card-style boxes) | None |
| `process_pid_context_diagram.py` | Same PID-centered analysis, but produce Graphviz DOT and let Graphviz lay out the diagram (also yields PDF/PNG) | Graphviz | Graphviz binaries on PATH |
| `process_trees_svg_indented.py` | Render every root process tree in the workbook as one SVG per tree (forest view, no PID required) | Hand-written SVG (card-style boxes) | None |

## Common input format

All three scripts read the same Excel workbook (`.xlsx`) and require these columns on the chosen worksheet:

| Column | Description |
|---|---|
| `hostname` | Host the process ran on |
| `parent_name` | Process name of the parent |
| `parent_pid` | PID of the parent process |
| `process_name` | Name of the process |
| `cmdline` | Command line for the process |
| `username` | User context the process ran under |
| `process_pid` | PID of the process |

Rows are deduplicated on all seven columns before the tree is built. The values `""`, `-1`, `0`, `None`, `nan`, and `null` in `parent_pid` are treated as "no parent" (root).

## Requirements

- Python 3.8+
- `pip install openpyxl` — required by all three
- `pip install pandas` — required only by `process_pid_context_diagram.py`
- `pip install graphviz` — required only by `process_pid_context_diagram.py`. The Python package alone is not enough for SVG/PDF/PNG output; the Graphviz system binaries (`dot`, etc.) must also be on PATH. Without them the script still writes a `.dot` file you can render later.

## Usage

### Investigate a specific PID (zero-dependency SVG)

```bash
python process_pid_context_svg_styled.py runner_processes.xlsx --pid 1234
python process_pid_context_svg_styled.py runner_processes.xlsx --pid 1234 --hostname myhost --outdir pid_1234
```

Produces one styled SVG per matching deduplicated row (the same PID on multiple hosts yields multiple diagrams), a per-diagram CSV listing nodes by role (`target` / `ancestor` / `descendant`), and a `manifest.csv` summarising the run.

### Investigate a specific PID (Graphviz, with PDF/PNG support)

```bash
python process_pid_context_diagram.py runner_processes.xlsx --pid 1234
python process_pid_context_diagram.py runner_processes.xlsx --pid 1234 --hostname myhost --format pdf --outdir pid_1234
```

Same logical analysis as above but emits Graphviz DOT plus a rendered SVG/PDF/PNG. If Graphviz isn't on PATH, the rendered file is skipped and the `.dot` file is left for manual rendering.

### Render every tree in a workbook (forest view)

```bash
python process_trees_svg_indented.py runner_processes.xlsx
python process_trees_svg_indented.py runner_processes.xlsx --outdir my_trees --box-width 500
```

Builds the forest from the workbook and writes one styled SVG per root tree under `trees/`, plus `process_nodes_deduped.csv`, `tree_manifest.csv`, `summary.txt`, and a `process_tree_svgs_bundle.zip` of the output directory.

## Common arguments

| Argument | Available on | Default | Description |
|---|---|---|---|
| `input_xlsx` | all | — | Positional path to the Excel workbook |
| `--sheet` | all | first sheet | Worksheet index or name |
| `--outdir` | all | per-script | Output directory |
| `--pid` | both PID-centered | — | Target process PID (required) |
| `--hostname` | both PID-centered | none | Optional hostname filter |
| `--format` | `process_pid_context_diagram.py` | `svg` | Render format: `svg`, `pdf`, `png` |
| `--box-width` / `--depth-step` / `--v-gap` | both styled-SVG renderers | various | Layout tuning for SVG cards |
| `--cmdline-wrap-width` / `--cmdline-max-chars` | both styled-SVG renderers | various | Wrap and truncation for long command lines |

## Notes and limitations

- The PID-centered scripts may emit more than one diagram per run if the target PID appears in multiple deduplicated rows (e.g. the same PID seen on different hosts).
- The Excel workbook must contain all seven required columns on the chosen sheet; the scripts exit with `Missing expected columns: ...` otherwise.
- The styled-SVG renderers do their own layout (depth = column, vertical stacking inside a column). For deep or very wide trees, tune `--depth-step` and `--v-gap`.
- The Graphviz renderer is the only path that can produce PDF or PNG.
- Upstream feeder: [export-processes-by-host](../export-processes-by-host/) writes an XLSX with a compatible schema if you generate the workbook end-to-end from the CB API.
