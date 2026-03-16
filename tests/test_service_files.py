import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent

HARDENING_DIRECTIVES = [
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
]


class TestServiceFileHardening:
    @pytest.mark.parametrize("service_file", [
        "contextkeep-server.service",
        "contextkeep-webui.service",
    ])
    def test_service_file_has_hardening(self, service_file):
        content = (PROJECT_ROOT / service_file).read_text()
        for directive in HARDENING_DIRECTIVES:
            assert directive in content, f"Missing {directive} in {service_file}"
