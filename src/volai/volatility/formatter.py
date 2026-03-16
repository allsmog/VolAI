from __future__ import annotations

from datetime import datetime
from typing import Any

from volatility3.framework.interfaces.renderers import (
    BaseAbsentValue,
    TreeGrid,
    TreeNode,
)


def _render_value(value: Any) -> str | int | float | bool | None:
    """Convert a Volatility3 cell value to a JSON-safe Python type."""
    if isinstance(value, BaseAbsentValue):
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (int, float, bool)):
        return value
    return str(value)


def treegrid_to_dict(grid: TreeGrid) -> tuple[list[str], list[dict]]:
    """Convert a Volatility3 TreeGrid to (column_names, list_of_row_dicts).

    Flattens the tree structure — children appear as rows at the same level,
    with an additional '__depth' key for hierarchy.
    """
    column_names = [col.name for col in grid.columns]
    rows: list[dict] = []

    def visitor(node: TreeNode, accumulator: list[dict]) -> list[dict]:
        row: dict[str, Any] = {"__depth": node.path_depth}
        for i, col in enumerate(grid.columns):
            row[col.name] = _render_value(node.values[i])
        accumulator.append(row)
        return accumulator

    grid.populate(visitor, rows)
    return column_names, rows
