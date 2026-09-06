"""Read-time retention must never delete outside the configured directory."""

import json
import os
import time

import pytest

from tools.environments.local import LocalEnvironment
from tools.file_operations import ShellFileOperations
from tools.file_tools import read_file_tool
from tools.registry import registry


@pytest.mark.parametrize("dispatch", [False, True])
@pytest.mark.parametrize("linked", [False, True])
def test_local_temp_result_retention_preserves_outside_victim(tmp_path, monkeypatch, linked, dispatch):
    env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
    monkeypatch.setattr(env, "get_temp_dir", lambda: str(tmp_path))
    file_ops = ShellFileOperations(env, cwd=str(tmp_path))
    monkeypatch.setattr("tools.file_tools._get_file_ops", lambda task_id: file_ops)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("outside content must survive", encoding="utf-8")
    stale = time.time() - 8 * 24 * 3600
    os.utime(victim, (stale, stale))
    storage = tmp_path / "hermes-results"
    if linked:
        storage.symlink_to(outside, target_is_directory=True)
    else:
        storage.mkdir()
        artifact = storage / "victim.txt"
        artifact.write_text("expired result", encoding="utf-8")
        os.utime(artifact, (stale, stale))

    requested = str(storage / "victim.txt")
    raw = (
        registry.dispatch("read_file", {"path": requested}, task_id="retention-local")
        if dispatch else read_file_tool(requested, task_id="retention-local")
    )
    result = json.loads(raw)

    assert victim.exists(), "read_file deleted the outside victim"
    assert victim.read_text(encoding="utf-8") == "outside content must survive"
    if linked:
        assert "could not be verified" in result["error"]
    else:
        assert "expired after" in result["error"]
        assert not artifact.exists()
