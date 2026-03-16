from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

import volatility3.framework
import volatility3.plugins
from volatility3.framework import automagic, contexts
from volatility3.framework import plugins as vol_plugins
from volatility3.framework.interfaces.plugins import FileHandlerInterface

from volai.volatility.formatter import treegrid_to_dict

logger = logging.getLogger(__name__)

volatility3.framework.require_interface_version(2, 0, 0)


@dataclass
class PluginResult:
    """Result of running a single Volatility3 plugin."""

    plugin_name: str
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    error: str | None = None
    row_count: int = 0


class VolatilityRunner:
    """Manages Volatility3 framework lifecycle and plugin execution."""

    def __init__(self, dump_path: Path) -> None:
        self.dump_path = dump_path
        self._plugin_list: dict = {}
        self._initialized = False

    def initialize(self) -> None:
        """Initialize the Volatility3 framework and discover plugins."""
        if self._initialized:
            return

        if not self.dump_path.exists():
            raise FileNotFoundError(f"Memory dump not found: {self.dump_path}")

        failures = volatility3.framework.import_files(volatility3.plugins, True)
        if failures:
            logger.warning("Some plugins failed to import: %s", failures)

        self._plugin_list = volatility3.framework.list_plugins()
        self._initialized = True

    def list_available_plugins(self) -> list[str]:
        """Return sorted list of available plugin names."""
        self.initialize()
        return sorted(self._plugin_list.keys())

    def run_plugin(self, plugin_name: str) -> PluginResult:
        """Run a single Volatility3 plugin and return structured results."""
        self.initialize()

        if plugin_name not in self._plugin_list:
            return PluginResult(
                plugin_name=plugin_name,
                error=f"Plugin '{plugin_name}' not found",
            )

        plugin_class = self._plugin_list[plugin_name]

        try:
            ctx = contexts.Context()
            ctx.config[
                "automagic.LayerStacker.single_location"
            ] = "file:///" + str(self.dump_path.resolve())

            available = automagic.available(ctx)
            chosen = automagic.choose_automagic(available, plugin_class)

            constructed = vol_plugins.construct_plugin(
                ctx,
                chosen,
                plugin_class,
                "plugins",
                progress_callback=self._progress_callback,
                open_method=FileHandlerInterface,
            )

            if constructed is None:
                return PluginResult(
                    plugin_name=plugin_name,
                    error=f"Failed to construct plugin '{plugin_name}' "
                    "(unsatisfied requirements)",
                )

            treegrid = constructed.run()
            columns, rows = treegrid_to_dict(treegrid)

            return PluginResult(
                plugin_name=plugin_name,
                columns=columns,
                rows=rows,
                row_count=len(rows),
            )

        except Exception as e:
            logger.exception("Plugin '%s' failed", plugin_name)
            return PluginResult(
                plugin_name=plugin_name,
                error=f"{type(e).__name__}: {e}",
            )

    async def run_plugins_async(
        self, plugin_names: list[str]
    ) -> list[PluginResult]:
        """Run multiple plugins concurrently using thread pool."""
        self.initialize()
        tasks = [
            asyncio.to_thread(self.run_plugin, name) for name in plugin_names
        ]
        return list(await asyncio.gather(*tasks))

    @staticmethod
    def _progress_callback(progress: float, description: str) -> None:
        logger.debug("Progress: %.1f%% - %s", progress * 100, description)
