from volai.volatility.plugins import (
    ALL_TRIAGE_PLUGINS,
    LINUX_TRIAGE_PLUGINS,
    MAC_TRIAGE_PLUGINS,
    WINDOWS_TRIAGE_PLUGINS,
    get_triage_plugins,
)


class TestPluginProfiles:
    def test_windows_plugins_not_empty(self):
        assert len(WINDOWS_TRIAGE_PLUGINS) > 0

    def test_linux_plugins_not_empty(self):
        assert len(LINUX_TRIAGE_PLUGINS) > 0

    def test_mac_plugins_not_empty(self):
        assert len(MAC_TRIAGE_PLUGINS) > 0

    def test_windows_plugins_have_correct_prefix(self):
        for p in WINDOWS_TRIAGE_PLUGINS:
            assert p.startswith("windows."), f"{p} missing windows. prefix"

    def test_linux_plugins_have_correct_prefix(self):
        for p in LINUX_TRIAGE_PLUGINS:
            assert p.startswith("linux."), f"{p} missing linux. prefix"

    def test_mac_plugins_have_correct_prefix(self):
        for p in MAC_TRIAGE_PLUGINS:
            assert p.startswith("mac."), f"{p} missing mac. prefix"


class TestGetTriagePlugins:
    def test_windows_profile(self):
        result = get_triage_plugins("windows")
        assert result == WINDOWS_TRIAGE_PLUGINS

    def test_linux_profile(self):
        result = get_triage_plugins("linux")
        assert result == LINUX_TRIAGE_PLUGINS

    def test_mac_profile(self):
        result = get_triage_plugins("mac")
        assert result == MAC_TRIAGE_PLUGINS

    def test_none_returns_combined_superset(self):
        result = get_triage_plugins(None)
        # Should contain all unique plugins from all profiles
        all_plugins = set()
        for plugins in ALL_TRIAGE_PLUGINS.values():
            all_plugins.update(plugins)
        assert set(result) == all_plugins

    def test_none_has_no_duplicates(self):
        result = get_triage_plugins(None)
        assert len(result) == len(set(result))

    def test_unknown_os_falls_back_to_windows(self):
        result = get_triage_plugins("freebsd")
        assert result == WINDOWS_TRIAGE_PLUGINS
