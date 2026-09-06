"""Public read retention is bounded to storage, never an outside symlink victim."""

import json
import os
import time

import pytest

from tools.environments.local import LocalEnvironment
from tools.file_operations import ShellFileOperations
from tools.file_tools import read_file_tool
from tools.registry import registry
from tools.tool_result_storage import get_spillover_dir


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("dispatch", [False, True])
@pytest.mark.parametrize("kind", ["temp", "alias", "private", "legacy", "unrelated"])
@pytest.mark.parametrize("state", ["expired", "recent", "directory-link", "file-link"])
def test_local_retention_is_scoped(tmp_path, monkeypatch, kind, state, dispatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    alias = tmp_path / "temp-alias"
    alias.symlink_to(temp_root, target_is_directory=True)
    env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(temp_root)})
    monkeypatch.setattr(env, "get_temp_dir", lambda: str(alias if kind == "alias" else temp_root))
    file_ops = ShellFileOperations(env, cwd=str(tmp_path))
    monkeypatch.setattr("tools.file_tools._get_file_ops", lambda task_id: file_ops)
    private = get_spillover_dir()
    directories = {"temp": temp_root / "hermes-results", "alias": temp_root / "hermes-results", "private": private, "legacy": private.parent, "unrelated": tmp_path / "ordinary"}
    directory = directories[kind]
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("outside must survive", encoding="utf-8")
    stale = time.time() - 8 * 24 * 3600
    os.utime(victim, (stale, stale))
    directory.parent.mkdir(parents=True, exist_ok=True)
    artifact = directory / "victim.txt"
    if state == "directory-link":
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory.mkdir()
        if state == "file-link":
            artifact.symlink_to(victim)
        else:
            artifact.write_text("retained content", encoding="utf-8")
        ttl = 24 if kind in {"private", "legacy"} else 7 * 24
        age = ttl - 1 if state == "recent" else ttl + 1
        when = time.time() - age * 3600
        os.utime(artifact, (when, when), follow_symlinks=False)
    raw = (registry.dispatch("read_file", {"path": str(artifact)}, task_id="retention-local") if dispatch else read_file_tool(str(artifact), task_id="retention-local"))
    result = json.loads(raw)
    assert victim.read_text(encoding="utf-8") == "outside must survive"
    if kind == "unrelated" or state == "recent":
        assert not result.get("error"), result
        assert artifact.exists()
    elif state == "directory-link" or (state == "file-link" and kind in {"private", "legacy"}):
        assert "could not be verified" in result.get("error", ""), result
        assert artifact.exists()
    else:
        assert "expired after" in result.get("error", ""), result
        assert not artifact.exists()
        assert not artifact.is_symlink()
