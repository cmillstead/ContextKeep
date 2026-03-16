import json
import os
import stat
import pytest
from pathlib import Path


class TestInstallConfigPermissions:
    def test_generated_config_has_0600_permissions(self, tmp_path, monkeypatch):
        """generate_config should create mcp_config.json with 0o600 permissions."""
        monkeypatch.chdir(tmp_path)
        # Create a fake python path
        python_path = tmp_path / "venv" / "bin" / "python"
        python_path.parent.mkdir(parents=True)
        python_path.touch()

        from install import generate_config
        generate_config(python_path)

        config_path = tmp_path / "mcp_config.json"
        assert config_path.exists()
        mode = stat.S_IMODE(os.stat(config_path).st_mode)
        assert mode == 0o600

    def test_generated_config_is_valid_json(self, tmp_path, monkeypatch):
        """generate_config should produce valid JSON."""
        monkeypatch.chdir(tmp_path)
        python_path = tmp_path / "venv" / "bin" / "python"
        python_path.parent.mkdir(parents=True)
        python_path.touch()

        from install import generate_config
        generate_config(python_path)

        config_path = tmp_path / "mcp_config.json"
        with open(config_path) as f:
            data = json.load(f)
        assert "mcpServers" in data
