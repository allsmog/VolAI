from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from volai.volatility.runner import PluginResult, VolatilityRunner


class TestPluginResult:
    def test_defaults(self):
        pr = PluginResult(plugin_name="test")
        assert pr.columns == []
        assert pr.rows == []
        assert pr.error is None
        assert pr.row_count == 0

    def test_with_data(self):
        pr = PluginResult(
            plugin_name="windows.pslist.PsList",
            columns=["PID", "Name"],
            rows=[{"PID": 4, "Name": "System"}],
            row_count=1,
        )
        assert pr.row_count == 1


class TestVolatilityRunner:
    def test_init(self):
        runner = VolatilityRunner(Path("/tmp/test.dmp"))
        assert runner.dump_path == Path("/tmp/test.dmp")
        assert not runner._initialized

    def test_initialize_missing_file(self):
        runner = VolatilityRunner(Path("/tmp/this_definitely_does_not_exist.dmp"))
        with pytest.raises(FileNotFoundError, match="Memory dump not found"):
            runner.initialize()

    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_initialize_success(self, mock_import, mock_list, tmp_path):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {
            "windows.pslist.PsList": MagicMock(),
            "windows.netscan.NetScan": MagicMock(),
        }

        runner = VolatilityRunner(dump)
        runner.initialize()
        assert runner._initialized
        assert "windows.pslist.PsList" in runner._plugin_list

    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_initialize_only_once(self, mock_import, mock_list, tmp_path):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {}

        runner = VolatilityRunner(dump)
        runner.initialize()
        runner.initialize()  # second call should be no-op
        mock_import.assert_called_once()

    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_list_available_plugins(self, mock_import, mock_list, tmp_path):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {
            "c.plugin": MagicMock(),
            "a.plugin": MagicMock(),
            "b.plugin": MagicMock(),
        }

        runner = VolatilityRunner(dump)
        plugins = runner.list_available_plugins()
        assert plugins == ["a.plugin", "b.plugin", "c.plugin"]

    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_run_plugin_not_found(self, mock_import, mock_list, tmp_path):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {}

        runner = VolatilityRunner(dump)
        result = runner.run_plugin("nonexistent.Plugin")
        assert result.error == "Plugin 'nonexistent.Plugin' not found"

    @patch("volai.volatility.runner.treegrid_to_dict")
    @patch("volai.volatility.runner.vol_plugins.construct_plugin")
    @patch("volai.volatility.runner.automagic")
    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_run_plugin_success(
        self, mock_import, mock_list, mock_automagic, mock_construct, mock_treegrid, tmp_path
    ):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        plugin_cls = MagicMock()
        mock_import.return_value = {}
        mock_list.return_value = {"test.Plugin": plugin_cls}
        mock_automagic.available.return_value = []
        mock_automagic.choose_automagic.return_value = []

        mock_plugin_instance = MagicMock()
        mock_construct.return_value = mock_plugin_instance
        mock_treegrid.return_value = (["Col1", "Col2"], [{"Col1": "a", "Col2": "b"}])

        runner = VolatilityRunner(dump)
        result = runner.run_plugin("test.Plugin")

        assert result.error is None
        assert result.columns == ["Col1", "Col2"]
        assert result.rows == [{"Col1": "a", "Col2": "b"}]
        assert result.row_count == 1

    @patch("volai.volatility.runner.vol_plugins.construct_plugin")
    @patch("volai.volatility.runner.automagic")
    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_run_plugin_construct_returns_none(
        self, mock_import, mock_list, mock_automagic, mock_construct, tmp_path
    ):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {"test.Plugin": MagicMock()}
        mock_automagic.available.return_value = []
        mock_automagic.choose_automagic.return_value = []
        mock_construct.return_value = None

        runner = VolatilityRunner(dump)
        result = runner.run_plugin("test.Plugin")
        assert result.error is not None
        assert "unsatisfied requirements" in result.error.lower()

    @patch("volai.volatility.runner.vol_plugins.construct_plugin")
    @patch("volai.volatility.runner.automagic")
    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    def test_run_plugin_exception_handled(
        self, mock_import, mock_list, mock_automagic, mock_construct, tmp_path
    ):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {"test.Plugin": MagicMock()}
        mock_automagic.available.return_value = []
        mock_automagic.choose_automagic.return_value = []
        mock_construct.side_effect = RuntimeError("Boom!")

        runner = VolatilityRunner(dump)
        result = runner.run_plugin("test.Plugin")
        assert result.error == "RuntimeError: Boom!"

    @pytest.mark.asyncio
    @patch("volai.volatility.runner.volatility3.framework.list_plugins")
    @patch("volai.volatility.runner.volatility3.framework.import_files")
    async def test_run_plugins_async(self, mock_import, mock_list, tmp_path):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)

        mock_import.return_value = {}
        mock_list.return_value = {}

        runner = VolatilityRunner(dump)
        results = await runner.run_plugins_async(["a.Plugin", "b.Plugin"])

        assert len(results) == 2
        assert all(r.error is not None for r in results)  # both not found
