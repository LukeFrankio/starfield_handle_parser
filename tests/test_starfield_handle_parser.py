from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "starfield_handle_parser.py"
FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _run_parser(output_path: Path) -> dict[str, object]:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--dump",
            str(FIXTURE_DIR / "sample_dump.txt"),
            "--load-order",
            str(FIXTURE_DIR / "sample_load_order.txt"),
            "--json-out",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    return json.loads(output_path.read_text(encoding="utf-8"))


def _index_rows_by_name(report: dict[str, object]) -> dict[str, dict[str, object]]:
    rows = report["rows"]
    assert isinstance(rows, list)
    return {
        str(row["plugin_name"]): row
        for row in rows
        if isinstance(row, dict)
    }


def test_cli_attributes_handles_by_real_formid_owner(tmp_path: Path) -> None:
    report = _run_parser(tmp_path / "report.json")
    rows = _index_rows_by_name(report)

    assert rows["Starfield.esm"]["cell_handles"] == 1
    assert rows["Starfield.esm"]["reference_handles"] == 1

    assert rows["tankgirlsxenologyexpanded.esm"]["cell_handles"] == 1
    assert rows["tankgirlsxenologyexpanded.esm"]["reference_handles"] == 1

    assert rows["SFBGS004.esm"]["cell_handles"] == 1
    assert rows["SFBGS004.esm"]["reference_handles"] == 1
    assert rows["SFBGS004.esm"]["pack_in_cells"] == 1
    assert rows["SFBGS004.esm"]["pack_in_references"] == 1

    assert rows["sfbgs009.esm"]["reference_handles"] == 1
    assert rows["sfbgs009.esm"]["parent_packin_fallback_handles"] == 1

    assert rows["[runtime/temp]"]["cell_handles"] == 1
    assert rows["[runtime/temp]"]["reference_handles"] == 1


def test_cli_preserves_actual_load_order_rows(tmp_path: Path) -> None:
    report = _run_parser(tmp_path / "report.json")
    rows = report["rows"]
    assert isinstance(rows, list)

    ordered_names = [row["plugin_name"] for row in rows if isinstance(row, dict)]
    assert ordered_names[:5] == [
        "Starfield.esm",
        "ShatteredSpace.esm",
        "tankgirlsxenologyexpanded.esm",
        "SFBGS004.esm",
        "sfbgs009.esm",
    ]
