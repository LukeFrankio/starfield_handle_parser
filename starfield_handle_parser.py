#!/usr/bin/env python3
"""
Parse Starfield DumpPointerHandles logs using real plugin ownership.

This parser intentionally does **not** trust the dump's ``ModIdx`` field as the
primary owner signal. In large Starfield setups, that field often points at an
internal handle owner or pack-in context instead of the plugin that actually
owns the FormID prefix. The reliable source is the FormID itself:

- ``00`` to ``FC`` prefix  -> full plugin slot
- ``FDxx``                 -> medium plugin slot
- ``FExxx``                -> light plugin slot
- ``FFxxxxxx``             -> runtime/temp handle

The script accepts a load-order text file in the format the user provided,
streams the dump without loading it fully into memory, attributes each handle to
its plugin, and can optionally emit JSON/CSV reports for downstream analysis.
"""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

if sys.version_info < (3, 14):
    raise SystemExit(
        f"Python 3.14+ required (you're running {sys.version}). "
        "upgrade immediately, bestie uwu"
    )


type PluginNamespace = str

type PluginKey = tuple[PluginNamespace, int]


dataclass_kwargs = {"frozen": True, "slots": True}


@dataclass(**dataclass_kwargs)
class PluginRecord:
    """Plugin metadata parsed from the real load-order listing.

    ✨ PURE DATA ✨

    Args:
        plugin_name: Display name from the load-order file.
        namespace: One of ``full``, ``medium``, ``light``, ``runtime``, or ``unknown``.
        slot: Numeric slot within that namespace. Runtime rows use ``-1``.
        slot_hex: Uppercase hexadecimal slot representation for display.
        form_id_prefix: Prefix used to identify this plugin from FormIDs.
        load_order_position: 0-based order in the provided load-order file.
        prefix_display: Human-friendly prefix label like ``254 FE 002``.
    """

    plugin_name: str
    namespace: PluginNamespace
    slot: int
    slot_hex: str
    form_id_prefix: str
    load_order_position: int
    prefix_display: str


@dataclass(**dataclass_kwargs)
class PluginStats:
    """Aggregated handle counts for a single plugin.

    ✨ PURE DATA ✨

    Args:
        plugin_name: Display name for the plugin row.
        namespace: Plugin namespace category.
        slot: Numeric slot within the namespace.
        slot_hex: Uppercase hexadecimal slot value.
        form_id_prefix: Prefix used when decoding FormIDs.
        prefix_display: Human-friendly prefix label.
        load_order_position: 0-based order in the supplied load order.
        cell_handles: Count of attributed cell handles.
        reference_handles: Count of attributed reference handles.
        pack_in_cells: Count of cell handles flagged as pack-ins.
        pack_in_references: Count of reference handles inside pack-in cells.
        parent_packin_fallback_handles: Count of handles attributed via parent pack-in fallback.
        total_handles: Convenience total of cell and reference handles.
    """

    plugin_name: str
    namespace: PluginNamespace
    slot: int
    slot_hex: str
    form_id_prefix: str
    prefix_display: str
    load_order_position: int
    cell_handles: int
    reference_handles: int
    pack_in_cells: int
    pack_in_references: int
    parent_packin_fallback_handles: int
    total_handles: int


@dataclass(**dataclass_kwargs)
class DumpTotals:
    """Top-level totals copied from the dump footer.

    ✨ PURE DATA ✨
    """

    cell_handles_used: int | None
    cell_handles_capacity: int | None
    pack_in_cells_total: int | None
    reference_handles_used: int | None
    reference_handles_capacity: int | None
    pack_in_references_total: int | None


LOAD_ORDER_LIGHT_PATTERN = re.compile(
    r"^\s*254\s+FE\s+([0-9A-Fa-f]{1,3})\s+(.+?\.(?:esm|esp|esl))\s*$",
    re.IGNORECASE,
)
LOAD_ORDER_MEDIUM_PATTERN = re.compile(
    r"^\s*253\s+FD\s+([0-9A-Fa-f]{1,2})\s+(.+?\.(?:esm|esp|esl))\s*$",
    re.IGNORECASE,
)
LOAD_ORDER_FULL_PATTERN = re.compile(
    r"^\s*(\d+)\s+([0-9A-Fa-f]{1,2})\s+(.+?\.(?:esm|esp|esl))\s*$",
    re.IGNORECASE,
)
HANDLE_BRACKET_PATTERN = re.compile(r"^\s*\d+\s*--->\s*\[(.*?)\]")
PACKIN_BRACKET_PATTERN = re.compile(r"(?:Parent Cell Pack-In|Pack-In)\s*--->\s*\[(.*?)\]")
CELL_TOTAL_PATTERN = re.compile(
    r"Cell Handle Count:\s*([\d,]+)\s*/\s*([\d,]+)(?:\s*\(of which\s*([\d,]+)\s*are Pack-In Cells\))?",
    re.IGNORECASE,
)
REFERENCE_TOTAL_PATTERN = re.compile(
    r"Reference Handle Count:\s*([\d,]+)\s*/\s*([\d,]+)(?:\s*\(of which\s*([\d,]+)\s*are being in Pack-In Cells\))?",
    re.IGNORECASE,
)
FORMID_PATTERN = re.compile(r"^[0-9A-F]{8}$")


SPECIAL_RUNTIME_RECORD = PluginRecord(
    plugin_name="[runtime/temp]",
    namespace="runtime",
    slot=-1,
    slot_hex="FF",
    form_id_prefix="FFxxxxxx",
    load_order_position=1_000_000,
    prefix_display="FF",
)
SPECIAL_UNRESOLVED_RECORD = PluginRecord(
    plugin_name="[unresolved]",
    namespace="unknown",
    slot=-1,
    slot_hex="??",
    form_id_prefix="unknown",
    load_order_position=1_000_001,
    prefix_display="??",
)


def _parse_int(text: str | None) -> int | None:
    """Convert a dump integer field into ``int`` or ``None``.

    ✨ PURE FUNCTION ✨

    Args:
        text: Raw string that may contain commas.

    Returns:
        Parsed integer value, or ``None`` when the input is empty.
    """

    if text is None:
        return None
    stripped = text.strip()
    if not stripped:
        return None
    return int(stripped.replace(",", ""))


def _build_plugin_record(
    plugin_name: str,
    namespace: PluginNamespace,
    slot: int,
    load_order_position: int,
) -> PluginRecord:
    """Create a plugin descriptor from a parsed load-order entry.

    ✨ PURE FUNCTION ✨

    Args:
        plugin_name: Plugin filename from the load-order file.
        namespace: Plugin namespace category.
        slot: Numeric slot value for the namespace.
        load_order_position: Order in the supplied load-order file.

    Returns:
        Normalised plugin metadata ready for matching against FormIDs.
    """

    match namespace:
        case "full":
            slot_hex = f"{slot:02X}"
            prefix_display = f"{slot:>3} {slot_hex}"
            form_id_prefix = slot_hex
        case "medium":
            slot_hex = f"{slot:02X}"
            prefix_display = f"253 FD {slot_hex}"
            form_id_prefix = f"FD{slot_hex}"
        case "light":
            slot_hex = f"{slot:03X}"
            prefix_display = f"254 FE {slot_hex}"
            form_id_prefix = f"FE{slot_hex}"
        case _:
            raise ValueError(f"Unsupported namespace: {namespace}")

    return PluginRecord(
        plugin_name=plugin_name,
        namespace=namespace,
        slot=slot,
        slot_hex=slot_hex,
        form_id_prefix=form_id_prefix,
        load_order_position=load_order_position,
        prefix_display=prefix_display,
    )


def _parse_load_order_line(line: str, load_order_position: int) -> PluginRecord | None:
    """Parse one line from the provided load-order text.

    ✨ PURE FUNCTION ✨

    Args:
        line: One raw line from the load-order file.
        load_order_position: 0-based plugin order among parsed entries.

    Returns:
        Parsed plugin metadata, or ``None`` if the line is not a plugin entry.
    """

    light_match = LOAD_ORDER_LIGHT_PATTERN.match(line)
    if light_match is not None:
        slot_text, plugin_name = light_match.groups()
        return _build_plugin_record(
            plugin_name.strip(),
            "light",
            int(slot_text, 16),
            load_order_position,
        )

    medium_match = LOAD_ORDER_MEDIUM_PATTERN.match(line)
    if medium_match is not None:
        slot_text, plugin_name = medium_match.groups()
        return _build_plugin_record(
            plugin_name.strip(),
            "medium",
            int(slot_text, 16),
            load_order_position,
        )

    full_match = LOAD_ORDER_FULL_PATTERN.match(line)
    if full_match is not None:
        _, slot_hex, plugin_name = full_match.groups()
        return _build_plugin_record(
            plugin_name.strip(),
            "full",
            int(slot_hex, 16),
            load_order_position,
        )

    return None


def load_plugin_map(load_order_path: Path) -> tuple[dict[PluginKey, PluginRecord], list[PluginRecord]]:
    """Load the user-supplied Starfield load order.

    ⚠️ IMPURE FUNCTION (performs file I/O)

    Args:
        load_order_path: Path to the text file containing the real load order.

    Returns:
        Tuple of ``(plugin_map, plugins_in_order)``.

    Raises:
        ValueError: If duplicate namespace/slot entries exist in the load order.
    """

    plugin_map: dict[PluginKey, PluginRecord] = {}
    plugins_in_order: list[PluginRecord] = []

    with load_order_path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            record = _parse_load_order_line(raw_line.rstrip("\n"), len(plugins_in_order))
            if record is None:
                continue
            key = (record.namespace, record.slot)
            if key in plugin_map:
                raise ValueError(
                    f"Duplicate load-order slot detected for {record.prefix_display}: {record.plugin_name}"
                )
            plugin_map[key] = record
            plugins_in_order.append(record)

    return plugin_map, plugins_in_order


def _plugin_key_from_formid(form_id: str) -> PluginKey | None:
    """Convert a raw FormID string into a plugin namespace key.

    ✨ PURE FUNCTION ✨

    Args:
        form_id: Raw FormID field as read from the dump.

    Returns:
        Namespace/slot tuple, or ``None`` when the FormID is blank or malformed.
    """

    compact = form_id.replace(" ", "").upper()
    if not compact:
        return None
    if FORMID_PATTERN.fullmatch(compact) is None:
        return None

    match compact[:2]:
        case "FF":
            return ("runtime", -1)
        case "FE":
            return ("light", int(compact[2:5], 16))
        case "FD":
            return ("medium", int(compact[2:4], 16))
        case _:
            return ("full", int(compact[:2], 16))


def _extract_bracket_content(line: str, pattern: re.Pattern[str]) -> tuple[str, ...] | None:
    """Extract pipe-delimited bracket fields from a dump line.

    ✨ PURE FUNCTION ✨

    Args:
        line: Raw dump line.
        pattern: Regex that captures the bracket payload.

    Returns:
        Tuple of stripped fields, or ``None`` when no bracket content matches.
    """

    match = pattern.search(line)
    if match is None:
        return None
    return tuple(field.strip() for field in match.group(1).split("|"))


def _unknown_record_for_key(plugin_key: PluginKey) -> PluginRecord:
    """Create a synthetic plugin record when the load-order file lacks a slot.

    ✨ PURE FUNCTION ✨
    """

    namespace, slot = plugin_key
    match namespace:
        case "full":
            slot_hex = f"{slot:02X}"
            prefix_display = f"{slot:>3} {slot_hex}"
            form_id_prefix = slot_hex
        case "medium":
            slot_hex = f"{slot:02X}"
            prefix_display = f"253 FD {slot_hex}"
            form_id_prefix = f"FD{slot_hex}"
        case "light":
            slot_hex = f"{slot:03X}"
            prefix_display = f"254 FE {slot_hex}"
            form_id_prefix = f"FE{slot_hex}"
        case _:
            return SPECIAL_UNRESOLVED_RECORD

    return PluginRecord(
        plugin_name=f"[unknown {namespace} {form_id_prefix}]",
        namespace=namespace,
        slot=slot,
        slot_hex=slot_hex,
        form_id_prefix=form_id_prefix,
        load_order_position=1_000_100 + slot,
        prefix_display=prefix_display,
    )


def _resolve_record(
    primary_form_id: str,
    packin_form_id: str | None,
    plugin_map: dict[PluginKey, PluginRecord],
) -> tuple[PluginRecord, bool]:
    """Resolve the best plugin owner for a handle line.

    ✨ PURE FUNCTION ✨

    Resolution strategy:
    1. Use the primary FormID when it belongs to a full/medium/light plugin.
    2. If the primary FormID is blank or runtime/temp, fall back to the parent pack-in FormID.
    3. Runtime/temp lines without a resolvable fallback stay in the runtime bucket.
    4. Missing namespace entries become synthetic ``unknown`` rows.

    Args:
        primary_form_id: Main record FormID from the line.
        packin_form_id: Parent pack-in FormID when present.
        plugin_map: Real load-order mapping.

    Returns:
        Tuple of ``(plugin_record, used_parent_packin_fallback)``.
    """

    primary_key = _plugin_key_from_formid(primary_form_id)
    packin_key = _plugin_key_from_formid(packin_form_id or "")

    if primary_key is not None and primary_key[0] in {"full", "medium", "light"}:
        return plugin_map.get(primary_key, _unknown_record_for_key(primary_key)), False

    if packin_key is not None and packin_key[0] in {"full", "medium", "light"}:
        return plugin_map.get(packin_key, _unknown_record_for_key(packin_key)), True

    if primary_key == ("runtime", -1):
        return SPECIAL_RUNTIME_RECORD, False

    return SPECIAL_UNRESOLVED_RECORD, False


def summarise_dump(
    dump_path: Path,
    plugin_map: dict[PluginKey, PluginRecord],
    plugins_in_order: list[PluginRecord],
) -> tuple[list[PluginStats], list[PluginStats], DumpTotals]:
    """Stream the dump and aggregate per-plugin handle counts.

    ⚠️ IMPURE FUNCTION (performs file I/O)

    Args:
        dump_path: Path to the Starfield dump file.
        plugin_map: Namespace/slot map built from the supplied load order.
        plugins_in_order: Plugins sorted exactly as they appear in the load order.

    Returns:
        Tuple of ``(rows_in_load_order, top_rows_by_reference_handles, totals)``.
    """

    section: str | None = None
    counts: dict[PluginRecord, dict[str, int]] = defaultdict(
        lambda: {
            "cell_handles": 0,
            "reference_handles": 0,
            "pack_in_cells": 0,
            "pack_in_references": 0,
            "parent_packin_fallback_handles": 0,
        }
    )
    totals = DumpTotals(
        cell_handles_used=None,
        cell_handles_capacity=None,
        pack_in_cells_total=None,
        reference_handles_used=None,
        reference_handles_capacity=None,
        pack_in_references_total=None,
    )

    with dump_path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")

            if line.startswith("Exporting Cell Handles"):
                section = "cell"
                continue
            if line.startswith("Exporting Reference Handles"):
                section = "reference"
                continue

            cell_total_match = CELL_TOTAL_PATTERN.search(line)
            if cell_total_match is not None:
                totals = DumpTotals(
                    cell_handles_used=_parse_int(cell_total_match.group(1)),
                    cell_handles_capacity=_parse_int(cell_total_match.group(2)),
                    pack_in_cells_total=_parse_int(cell_total_match.group(3)),
                    reference_handles_used=totals.reference_handles_used,
                    reference_handles_capacity=totals.reference_handles_capacity,
                    pack_in_references_total=totals.pack_in_references_total,
                )
                section = None
                continue

            reference_total_match = REFERENCE_TOTAL_PATTERN.search(line)
            if reference_total_match is not None:
                totals = DumpTotals(
                    cell_handles_used=totals.cell_handles_used,
                    cell_handles_capacity=totals.cell_handles_capacity,
                    pack_in_cells_total=totals.pack_in_cells_total,
                    reference_handles_used=_parse_int(reference_total_match.group(1)),
                    reference_handles_capacity=_parse_int(reference_total_match.group(2)),
                    pack_in_references_total=_parse_int(reference_total_match.group(3)),
                )
                section = None
                continue

            if section not in {"cell", "reference"} or "--->" not in line:
                continue

            primary_fields = _extract_bracket_content(line, HANDLE_BRACKET_PATTERN)
            if primary_fields is None or not primary_fields:
                continue

            packin_fields = _extract_bracket_content(line, PACKIN_BRACKET_PATTERN)
            primary_form_id = primary_fields[0]
            packin_form_id = packin_fields[0] if packin_fields else None
            record, used_parent_fallback = _resolve_record(primary_form_id, packin_form_id, plugin_map)
            bucket = counts[record]
            is_pack_in_line = "Pack-In  --->" in line or "Parent Cell Pack-In" in line

            match section:
                case "cell":
                    bucket["cell_handles"] += 1
                    if is_pack_in_line:
                        bucket["pack_in_cells"] += 1
                case "reference":
                    bucket["reference_handles"] += 1
                    if is_pack_in_line:
                        bucket["pack_in_references"] += 1
                case _:
                    continue

            if used_parent_fallback:
                bucket["parent_packin_fallback_handles"] += 1

    all_records: list[PluginRecord] = [*plugins_in_order]
    extra_records = sorted(
        (record for record in counts if record not in plugin_map.values()),
        key=lambda record: (record.load_order_position, record.plugin_name.lower()),
    )
    all_records.extend(extra_records)

    rows: list[PluginStats] = []
    for record in all_records:
        bucket = counts.get(record)
        cell_handles = bucket["cell_handles"] if bucket else 0
        reference_handles = bucket["reference_handles"] if bucket else 0
        pack_in_cells = bucket["pack_in_cells"] if bucket else 0
        pack_in_references = bucket["pack_in_references"] if bucket else 0
        parent_packin_fallback_handles = bucket["parent_packin_fallback_handles"] if bucket else 0
        rows.append(
            PluginStats(
                plugin_name=record.plugin_name,
                namespace=record.namespace,
                slot=record.slot,
                slot_hex=record.slot_hex,
                form_id_prefix=record.form_id_prefix,
                prefix_display=record.prefix_display,
                load_order_position=record.load_order_position,
                cell_handles=cell_handles,
                reference_handles=reference_handles,
                pack_in_cells=pack_in_cells,
                pack_in_references=pack_in_references,
                parent_packin_fallback_handles=parent_packin_fallback_handles,
                total_handles=cell_handles + reference_handles,
            )
        )

    top_rows = sorted(
        (row for row in rows if row.total_handles > 0),
        key=lambda row: (
            -row.reference_handles,
            -row.total_handles,
            row.load_order_position,
            row.plugin_name.lower(),
        ),
    )

    return rows, top_rows, totals


def _rows_to_csv(rows: list[PluginStats], output_path: Path) -> None:
    """Write a CSV export for the full row set.

    ⚠️ IMPURE FUNCTION (performs file I/O)
    """

    if not rows:
        output_path.write_text("", encoding="utf-8")
        return

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def _rows_to_json(
    rows: list[PluginStats],
    top_rows: list[PluginStats],
    totals: DumpTotals,
    dump_path: Path,
    load_order_path: Path,
    output_path: Path,
) -> None:
    """Write a JSON export for automation-friendly inspection.

    ⚠️ IMPURE FUNCTION (performs file I/O)
    """

    payload = {
        "dump_path": str(dump_path),
        "load_order_path": str(load_order_path),
        "totals": asdict(totals),
        "rows": [asdict(row) for row in rows],
        "top_by_reference_handles": [asdict(row) for row in top_rows],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def render_report(rows: list[PluginStats], top_rows: list[PluginStats], totals: DumpTotals) -> str:
    """Render the human-readable table report.

    ✨ PURE FUNCTION ✨

    Args:
        rows: Full per-plugin rows in actual load-order order.
        top_rows: Non-zero rows sorted by reference handles.
        totals: Dump-level totals from the file footer.

    Returns:
        Multi-line text report suitable for stdout or a text file.
    """

    top_limit = 30
    non_zero_rows = [row for row in rows if row.total_handles > 0]
    lines = [
        "Starfield DumpPointerHandles ownership report",
        "=" * 78,
        f"Cell handles      : {totals.cell_handles_used or 0:,}/{totals.cell_handles_capacity or 0:,}",
        f"Pack-in cells     : {totals.pack_in_cells_total or 0:,}",
        f"Reference handles : {totals.reference_handles_used or 0:,}/{totals.reference_handles_capacity or 0:,}",
        f"Pack-in refs      : {totals.pack_in_references_total or 0:,}",
        "",
        "Top contributors by reference handles",
        "-" * 78,
        f"{'Rank':<5} {'Prefix':<12} {'Refs':>10} {'Cells':>10} {'PackInRefs':>12} {'Fallback':>10}  Plugin",
        "-" * 78,
    ]

    for rank, row in enumerate(top_rows[:top_limit], start=1):
        lines.append(
            f"{rank:<5} {row.prefix_display:<12} {row.reference_handles:>10,} {row.cell_handles:>10,} "
            f"{row.pack_in_references:>12,} {row.parent_packin_fallback_handles:>10,}  {row.plugin_name}"
        )

    lines.extend(
        [
            "",
            "Non-zero rows in actual load-order order",
            "-" * 78,
            f"{'Prefix':<12} {'Refs':>10} {'Cells':>10} {'PackInRefs':>12} {'PackInCells':>12} {'Total':>10}  Plugin",
            "-" * 78,
        ]
    )
    for row in non_zero_rows:
        lines.append(
            f"{row.prefix_display:<12} {row.reference_handles:>10,} {row.cell_handles:>10,} "
            f"{row.pack_in_references:>12,} {row.pack_in_cells:>12,} {row.total_handles:>10,}  {row.plugin_name}"
        )

    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments.

    ✨ PURE FUNCTION ✨
    """

    parser = argparse.ArgumentParser(
        description="Parse Starfield DumpPointerHandles using real full/medium/light FormID ownership.",
    )
    parser.add_argument("--dump", required=True, type=Path, help="Path to DumpPointerHandles_*.txt")
    parser.add_argument(
        "--load-order",
        required=True,
        type=Path,
        help="Text file containing the real Starfield load order listing.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path for a machine-readable JSON report.",
    )
    parser.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        help="Optional path for a CSV export of the full row set.",
    )
    parser.add_argument(
        "--text-out",
        type=Path,
        default=None,
        help="Optional path for the human-readable text report.",
    )
    return parser.parse_args()


def main() -> int:
    """Run the CLI entry point.

    ⚠️ IMPURE FUNCTION (performs file I/O and prints to stdout)

    Returns:
        Process exit code.
    """

    args = parse_arguments()
    plugin_map, plugins_in_order = load_plugin_map(args.load_order)
    rows, top_rows, totals = summarise_dump(args.dump, plugin_map, plugins_in_order)
    report_text = render_report(rows, top_rows, totals)

    if args.json_out is not None:
        _rows_to_json(rows, top_rows, totals, args.dump, args.load_order, args.json_out)
    if args.csv_out is not None:
        _rows_to_csv(rows, args.csv_out)
    if args.text_out is not None:
        args.text_out.write_text(report_text, encoding="utf-8")

    print(report_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
