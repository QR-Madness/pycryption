"""Guard the on-disk notebook format the site build depends on.

Quarto (verified against 1.9.38) silently strips newlines from any markdown
cell after the first whose ``source`` is a single JSON string rather than the
canonical list-of-lines — whole cells collapse into one giant heading on the
rendered site. Notebooks written by Jupyter are always list-of-lines;
programmatically generated ones may not be. Normalize via:

    nbformat.write(nbformat.read(path, as_version=4), path)
"""
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NOTEBOOKS = sorted(REPO_ROOT.glob("*.ipynb"))


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.name)
def test_cell_sources_are_line_lists(path: Path) -> None:
    nb = json.loads(path.read_text())
    offenders = [
        cell.get("id", f"index {i}")
        for i, cell in enumerate(nb["cells"])
        if isinstance(cell.get("source"), str) and "\n" in cell["source"]
    ]
    assert not offenders, (
        f"{path.name} has multiline string-source cells {offenders}; "
        f"Quarto drops their newlines on render. Normalize with nbformat.write()."
    )
