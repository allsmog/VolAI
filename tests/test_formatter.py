from datetime import datetime, timezone
from unittest.mock import MagicMock

from volatility3.framework.renderers import (
    NotApplicableValue,
    NotAvailableValue,
    UnreadableValue,
)

from volai.volatility.formatter import _render_value, treegrid_to_dict


class TestRenderValue:
    def test_string(self):
        assert _render_value("hello") == "hello"

    def test_int(self):
        assert _render_value(42) == 42

    def test_float(self):
        assert _render_value(3.14) == 3.14

    def test_bool(self):
        assert _render_value(True) is True
        assert _render_value(False) is False

    def test_none_like_object(self):
        # str(some_object) as fallback
        assert _render_value(None) == "None"

    def test_datetime(self):
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = _render_value(dt)
        assert "2024-01-15" in result
        assert "10:30:00" in result

    def test_bytes(self):
        result = _render_value(b"\xde\xad\xbe\xef")
        assert result == "deadbeef"

    def test_absent_value_unreadable(self):
        assert _render_value(UnreadableValue()) is None

    def test_absent_value_not_available(self):
        assert _render_value(NotAvailableValue()) is None

    def test_absent_value_not_applicable(self):
        assert _render_value(NotApplicableValue()) is None

    def test_custom_object_uses_str(self):
        class Custom:
            def __str__(self):
                return "custom-repr"
        assert _render_value(Custom()) == "custom-repr"


class TestTreegridToDict:
    def _make_mock_grid(self, columns, rows_data):
        """Build a mock TreeGrid with given columns and row data."""
        grid = MagicMock()

        # Mock columns
        mock_cols = []
        for col_name in columns:
            col = MagicMock()
            col.name = col_name
            mock_cols.append(col)
        grid.columns = mock_cols

        # Mock populate — calls visitor for each row
        def populate(visitor, accumulator):
            for depth, values in rows_data:
                node = MagicMock()
                node.path_depth = depth
                node.values = values
                accumulator = visitor(node, accumulator)
            return accumulator

        grid.populate = populate
        return grid

    def test_basic_grid(self):
        grid = self._make_mock_grid(
            ["PID", "Name"],
            [
                (0, [4, "System"]),
                (0, [100, "svchost.exe"]),
            ],
        )
        cols, rows = treegrid_to_dict(grid)
        assert cols == ["PID", "Name"]
        assert len(rows) == 2
        assert rows[0] == {"__depth": 0, "PID": 4, "Name": "System"}
        assert rows[1] == {"__depth": 0, "PID": 100, "Name": "svchost.exe"}

    def test_tree_depth(self):
        grid = self._make_mock_grid(
            ["PID", "Name"],
            [
                (0, [1, "init"]),
                (1, [100, "child"]),
                (2, [200, "grandchild"]),
            ],
        )
        cols, rows = treegrid_to_dict(grid)
        assert rows[0]["__depth"] == 0
        assert rows[1]["__depth"] == 1
        assert rows[2]["__depth"] == 2

    def test_absent_values(self):
        grid = self._make_mock_grid(
            ["PID", "Name"],
            [(0, [UnreadableValue(), "test"])],
        )
        cols, rows = treegrid_to_dict(grid)
        assert rows[0]["PID"] is None
        assert rows[0]["Name"] == "test"

    def test_empty_grid(self):
        grid = self._make_mock_grid(["PID"], [])
        cols, rows = treegrid_to_dict(grid)
        assert cols == ["PID"]
        assert rows == []
