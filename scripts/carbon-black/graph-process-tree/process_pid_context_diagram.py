#!/usr/bin/env python3
"""
Generate a process relationship diagram centered on a target PID.

Behavior:
- Loads an Excel workbook (.xlsx)
- Deduplicates rows using:
    hostname, parent_name, parent_pid, process_name, cmdline, username, process_pid
- Finds rows whose process_pid == target PID (optionally filtered by hostname)
- Walks backwards from each matching row to the root parent
- Walks forwards from the target row to include all descendants
- Renders one diagram per matched starting row

Dependencies:
    pip install pandas openpyxl graphviz

Rendering notes:
- The Python package "graphviz" is not enough by itself for SVG/PDF/PNG rendering.
  You also need the Graphviz system binaries installed and available on PATH.
  If rendering fails, the script will still emit a .dot file you can render later.

Examples:
    python process_pid_context_diagram.py runner_processes.xlsx --pid 1234 --outdir pid_1234
    python process_pid_context_diagram.py runner_processes.xlsx --pid 1234 --hostname myhost --format svg
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pandas as pd

try:
    import graphviz
except Exception:
    graphviz = None


DEDUP_COLS = [
    "hostname",
    "parent_name",
    "parent_pid",
    "process_name",
    "cmdline",
    "username",
    "process_pid",
]


def normalize_pid(value) -> Optional[int]:
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(float(text))
    except Exception:
        return None


def clean_text(value) -> str:
    if pd.isna(value):
        return ""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n").strip()
    return text


def safe_filename(text: str, max_len: int = 120) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text.strip())
    text = text.strip("._")
    if not text:
        text = "item"
    return text[:max_len]


def wrap_text(text: str, width: int = 60) -> str:
    if not text:
        return ""
    out: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        while len(line) > width:
            split_at = line.rfind(" ", 0, width + 1)
            if split_at <= 0:
                split_at = width
            out.append(line[:split_at].rstrip())
            line = line[split_at:].lstrip()
        out.append(line)
    return "\n".join(out)


def stable_node_id(row: pd.Series) -> str:
    joined = "||".join(clean_text(row.get(c, "")) for c in DEDUP_COLS)
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()
    return f"n_{digest[:16]}"


def load_dataframe(excel_path: str, sheet_name: Optional[str] = None) -> pd.DataFrame:
    if sheet_name:
        df = pd.read_excel(excel_path, sheet_name=sheet_name, engine="openpyxl")
    else:
        df = pd.read_excel(excel_path, engine="openpyxl")

    missing = [c for c in DEDUP_COLS if c not in df.columns]
    if missing:
        raise ValueError(
            "Workbook is missing required columns: " + ", ".join(missing)
        )

    df = df.copy()
    for col in DEDUP_COLS:
        df[col] = df[col].apply(clean_text)

    df["process_pid_norm"] = df["process_pid"].apply(normalize_pid)
    df["parent_pid_norm"] = df["parent_pid"].apply(normalize_pid)
    df["node_id"] = df.apply(stable_node_id, axis=1)

    before = len(df)
    df = df.drop_duplicates(subset=DEDUP_COLS, keep="first").reset_index(drop=True)
    after = len(df)
    print(f"Loaded {before} rows; deduplicated to {after} rows ({before - after} removed).")
    return df


def build_indexes(df: pd.DataFrame):
    rows_by_node_id: Dict[str, pd.Series] = {}
    by_host_pid: Dict[Tuple[str, Optional[int]], List[str]] = defaultdict(list)
    children_by_host_parentpid: Dict[Tuple[str, Optional[int]], List[str]] = defaultdict(list)

    for _, row in df.iterrows():
        node_id = row["node_id"]
        host = row["hostname"]
        pid = row["process_pid_norm"]
        ppid = row["parent_pid_norm"]

        rows_by_node_id[node_id] = row
        by_host_pid[(host, pid)].append(node_id)
        children_by_host_parentpid[(host, ppid)].append(node_id)

    return rows_by_node_id, by_host_pid, children_by_host_parentpid


def choose_parent_candidate(
    child_row: pd.Series,
    candidate_ids: Sequence[str],
    rows_by_node_id: Dict[str, pd.Series],
) -> Optional[str]:
    if not candidate_ids:
        return None
    if len(candidate_ids) == 1:
        return candidate_ids[0]

    parent_name = clean_text(child_row.get("parent_name", "")).lower()
    if parent_name:
        exact = []
        partial = []
        for cand_id in candidate_ids:
            cand_name = clean_text(rows_by_node_id[cand_id].get("process_name", "")).lower()
            if cand_name == parent_name:
                exact.append(cand_id)
            elif cand_name and (cand_name in parent_name or parent_name in cand_name):
                partial.append(cand_id)
        if exact:
            return sorted(exact)[0]
        if partial:
            return sorted(partial)[0]

    return sorted(candidate_ids)[0]


def get_parent_id(
    row: pd.Series,
    by_host_pid: Dict[Tuple[str, Optional[int]], List[str]],
    rows_by_node_id: Dict[str, pd.Series],
) -> Optional[str]:
    host = row["hostname"]
    parent_pid = row["parent_pid_norm"]
    if parent_pid is None:
        return None

    candidates = by_host_pid.get((host, parent_pid), [])
    return choose_parent_candidate(row, candidates, rows_by_node_id)


def get_children_ids(
    row: pd.Series,
    children_by_host_parentpid: Dict[Tuple[str, Optional[int]], List[str]],
    rows_by_node_id: Dict[str, pd.Series],
) -> List[str]:
    host = row["hostname"]
    pid = row["process_pid_norm"]
    if pid is None:
        return []

    candidate_ids = children_by_host_parentpid.get((host, pid), [])
    process_name = clean_text(row.get("process_name", "")).lower()

    exact = []
    other = []
    for child_id in candidate_ids:
        child = rows_by_node_id[child_id]
        parent_name = clean_text(child.get("parent_name", "")).lower()
        if process_name and parent_name == process_name:
            exact.append(child_id)
        else:
            other.append(child_id)

    return sorted(exact) + sorted(other)


def collect_context_subgraph(
    start_node_id: str,
    rows_by_node_id: Dict[str, pd.Series],
    by_host_pid: Dict[Tuple[str, Optional[int]], List[str]],
    children_by_host_parentpid: Dict[Tuple[str, Optional[int]], List[str]],
) -> Tuple[Set[str], Set[Tuple[str, str]], List[str]]:
    included_nodes: Set[str] = set()
    edges: Set[Tuple[str, str]] = set()

    lineage: List[str] = []
    current_id: Optional[str] = start_node_id
    seen_up: Set[str] = set()

    while current_id and current_id not in seen_up:
        seen_up.add(current_id)
        included_nodes.add(current_id)
        lineage.append(current_id)

        current_row = rows_by_node_id[current_id]
        parent_id = get_parent_id(current_row, by_host_pid, rows_by_node_id)
        if parent_id:
            included_nodes.add(parent_id)
            edges.add((parent_id, current_id))
        current_id = parent_id

    queue = deque([start_node_id])
    seen_down: Set[str] = {start_node_id}

    while queue:
        node_id = queue.popleft()
        row = rows_by_node_id[node_id]
        child_ids = get_children_ids(row, children_by_host_parentpid, rows_by_node_id)
        for child_id in child_ids:
            included_nodes.add(child_id)
            edges.add((node_id, child_id))
            if child_id not in seen_down:
                seen_down.add(child_id)
                queue.append(child_id)

    return included_nodes, edges, lineage


def node_label(row: pd.Series, highlight: bool = False) -> str:
    host = clean_text(row.get("hostname", ""))
    pname = clean_text(row.get("process_name", ""))
    pid = clean_text(row.get("process_pid", ""))
    parent_name = clean_text(row.get("parent_name", ""))
    parent_pid = clean_text(row.get("parent_pid", ""))
    user = clean_text(row.get("username", ""))
    cmd = wrap_text(clean_text(row.get("cmdline", "")), width=70)

    lines = [
        f"process_name: {pname}",
        f"process_pid: {pid}",
        f"username: {user}",
        f"hostname: {host}",
        f"parent_name: {parent_name}",
        f"parent_pid: {parent_pid}",
        f"cmdline: {cmd}",
    ]

    if highlight:
        lines.insert(0, "*** TARGET PID ***")

    # Graphviz record/Mrecord labels do not behave well with newlines in long text.
    # Use plain text inside a rounded box instead.
    return "\n".join(lines)


def render_graph(
    title: str,
    out_base: Path,
    rows: Iterable[pd.Series],
    edges: Iterable[Tuple[str, str]],
    target_node_id: str,
    fmt: str = "svg",
) -> Tuple[Path, Optional[Path]]:
    rows = list(rows)
    edge_list = list(edges)

    dot_path = out_base.with_suffix(".dot")
    rendered_path: Optional[Path] = None

    dot_lines = [
        "digraph G {",
        '  rankdir="TB";',
        '  graph [pad="0.3", nodesep="0.35", ranksep="0.5", overlap="false", splines="true", labelloc="t", fontsize="18"];',
        '  node [shape="box", style="rounded", fontname="Helvetica", fontsize="10", margin="0.14,0.08"];',
        '  edge [fontname="Helvetica", fontsize="9"];',
        f'  label="{title.replace(chr(34), chr(92)+chr(34))}";',
    ]

    for row in rows:
        node_id = row["node_id"]
        label = node_label(row, highlight=(node_id == target_node_id))
        escaped = label.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        if node_id == target_node_id:
            attrs = 'penwidth="2"'
        else:
            attrs = ''
        if attrs:
            dot_lines.append(f'  "{node_id}" [label="{escaped}", {attrs}];')
        else:
            dot_lines.append(f'  "{node_id}" [label="{escaped}"];')

    for src, dst in sorted(edge_list):
        dot_lines.append(f'  "{src}" -> "{dst}";')

    dot_lines.append("}")
    dot_path.write_text("\n".join(dot_lines), encoding="utf-8")

    if graphviz is not None:
        try:
            g = graphviz.Source(dot_path.read_text(encoding="utf-8"))
            rendered = g.render(filename=str(out_base), format=fmt, cleanup=True)
            rendered_path = Path(rendered)
        except Exception as exc:
            print(f"Warning: Graphviz render failed for {out_base.name}: {exc}")
            print(f"DOT file still written to: {dot_path}")

    return dot_path, rendered_path


def export_subgraph_csv(
    out_csv: Path,
    rows: Iterable[pd.Series],
    target_pid: int,
    target_node_id: str,
):
    export_rows = []
    for row in rows:
        item = {c: row.get(c, "") for c in DEDUP_COLS}
        item["is_target"] = "yes" if row["node_id"] == target_node_id else ""
        item["target_pid_query"] = target_pid
        export_rows.append(item)

    pd.DataFrame(export_rows).to_csv(out_csv, index=False)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a parent-root + child-descendant process diagram for a given PID."
    )
    parser.add_argument("excel_file", help="Input .xlsx file")
    parser.add_argument("--pid", required=True, type=int, help="Target process PID")
    parser.add_argument("--hostname", help="Optional hostname filter")
    parser.add_argument("--sheet", help="Optional sheet name")
    parser.add_argument("--outdir", default="pid_context_output", help="Output directory")
    parser.add_argument("--format", default="svg", choices=["svg", "pdf", "png"], help="Render format")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = load_dataframe(args.excel_file, sheet_name=args.sheet)
    rows_by_node_id, by_host_pid, children_by_host_parentpid = build_indexes(df)

    matches = df[df["process_pid_norm"] == args.pid].copy()
    if args.hostname:
        matches = matches[matches["hostname"].str.lower() == args.hostname.lower()].copy()

    if matches.empty:
        raise SystemExit(
            f"No deduplicated rows found for process_pid={args.pid}"
            + (f" and hostname={args.hostname}" if args.hostname else "")
        )

    summary_rows = []

    for idx, (_, start_row) in enumerate(matches.iterrows(), start=1):
        start_node_id = start_row["node_id"]
        included_node_ids, edges, lineage = collect_context_subgraph(
            start_node_id,
            rows_by_node_id,
            by_host_pid,
            children_by_host_parentpid,
        )

        sub_rows = [rows_by_node_id[nid] for nid in sorted(included_node_ids)]
        host = clean_text(start_row.get("hostname", "")) or "unknown_host"
        pname = clean_text(start_row.get("process_name", "")) or "unknown_process"
        pid_text = clean_text(start_row.get("process_pid", "")) or str(args.pid)

        title = f"PID context for {pname} ({pid_text}) on {host}"
        stem = f"{idx:03d}__{safe_filename(host)}__{safe_filename(pname)}__pid{safe_filename(pid_text)}"

        out_base = outdir / stem
        dot_path, rendered_path = render_graph(
            title=title,
            out_base=out_base,
            rows=sub_rows,
            edges=edges,
            target_node_id=start_node_id,
            fmt=args.format,
        )

        csv_path = outdir / f"{stem}.csv"
        export_subgraph_csv(csv_path, sub_rows, args.pid, start_node_id)

        root_node = rows_by_node_id[lineage[-1]] if lineage else start_row
        summary_rows.append(
            {
                "file_stem": stem,
                "hostname": host,
                "target_process_name": clean_text(start_row.get("process_name", "")),
                "target_process_pid": clean_text(start_row.get("process_pid", "")),
                "target_username": clean_text(start_row.get("username", "")),
                "root_process_name": clean_text(root_node.get("process_name", "")),
                "root_process_pid": clean_text(root_node.get("process_pid", "")),
                "nodes_in_subgraph": len(included_node_ids),
                "edges_in_subgraph": len(edges),
                "svg_or_rendered_path": str(rendered_path) if rendered_path else "",
                "dot_path": str(dot_path),
                "csv_path": str(csv_path),
            }
        )

        print(f"Wrote: {dot_path}")
        if rendered_path:
            print(f"Wrote: {rendered_path}")
        print(f"Wrote: {csv_path}")

    manifest = pd.DataFrame(summary_rows)
    manifest_path = outdir / "manifest.csv"
    manifest.to_csv(manifest_path, index=False)
    print(f"Wrote: {manifest_path}")


if __name__ == "__main__":
    main()
