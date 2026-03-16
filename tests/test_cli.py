from click.testing import CliRunner

from volai.cli import cli


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "VolAI" in result.output
        assert "analyze" in result.output
        assert "chat" in result.output

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_analyze_help(self):
        result = self.runner.invoke(cli, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--provider" in result.output
        assert "--model" in result.output
        assert "--api-key" in result.output
        assert "--base-url" in result.output
        assert "--os-profile" in result.output
        assert "--plugins" in result.output
        assert "--output" in result.output
        assert "--verbose" in result.output

    def test_chat_help(self):
        result = self.runner.invoke(cli, ["chat", "--help"])
        assert result.exit_code == 0
        assert "--provider" in result.output
        assert "--model" in result.output

    def test_analyze_missing_provider(self, tmp_path):
        dump = tmp_path / "test.dmp"
        dump.write_bytes(b"\x00" * 100)
        result = self.runner.invoke(cli, ["analyze", str(dump)])
        assert result.exit_code != 0
        # Click should complain about missing --provider
        assert "provider" in result.output.lower() or "required" in result.output.lower()

    def test_analyze_missing_dump(self):
        result = self.runner.invoke(
            cli, ["analyze", "--provider", "local"]
        )
        assert result.exit_code != 0

    def test_analyze_nonexistent_dump(self):
        result = self.runner.invoke(
            cli, ["analyze", "/tmp/this_does_not_exist_abc123.dmp", "--provider", "local"]
        )
        assert result.exit_code != 0

    def test_chat_missing_provider(self):
        result = self.runner.invoke(cli, ["chat", "/tmp/nonexist.dmp"])
        assert result.exit_code != 0

    def test_invalid_provider_choice(self):
        result = self.runner.invoke(
            cli, ["analyze", "/tmp/x.dmp", "--provider", "gemini"]
        )
        assert result.exit_code != 0
        assert "gemini" in result.output.lower() or "invalid" in result.output.lower()

    def test_invalid_os_profile_choice(self):
        result = self.runner.invoke(
            cli,
            ["analyze", "/tmp/x.dmp", "--provider", "local", "--os-profile", "freebsd"],
        )
        assert result.exit_code != 0
