"""Suite-wide safety nets."""

import pytest


@pytest.fixture(autouse=True)
def _audit_to_tmp(tmp_path, monkeypatch):
    # No test may write the real audit log, whatever module it imports.
    monkeypatch.setenv("MCP_AUDIT_LOG", str(tmp_path / "audit" / "audit.jsonl"))
