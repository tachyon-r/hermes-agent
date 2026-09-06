"""Remote retention executes real shell probes behind a sandbox transport fixture."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from tools.file_operations import ShellFileOperations
from tools.registry import registry
from tools.tool_result_storage import get_spillover_dir, maybe_persist_tool_result


class SandboxTransport:
    def __init__(self, root):
        self.root = root
        self.cwd = str(root)
        self._remote_home = str(root)
        self._remote_home_detected = True

    def get_temp_dir(self):
        return str(self.root / "temp")

    def execute(self, command, timeout=30, stdin_data=None, cwd=None, **kwargs):
        result = subprocess.run(
            ["/bin/bash", "-c", command], input=stdin_data, text=True,
            capture_output=True, timeout=timeout, cwd=cwd or self.cwd,
            env={**os.environ, "HOME": str(self.root)}, check=False,
        )
        return {"returncode": result.returncode, "output": result.stdout + result.stderr}


@pytest.mark.platforms("posix")
@pytest.mark.parametrize("backend", ["ssh", "daytona", "vercel_sandbox"])
@pytest.mark.parametrize("kind", ["canonical", "temp", "unrelated"])
@pytest.mark.parametrize("state", ["expired", "recent", "directory-link", "file-link", "write-cleanup"])
def test_remote_retention_is_scoped(tmp_path, monkeypatch, backend, kind, state):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "host-hermes"))
    monkeypatch.setenv("TERMINAL_ENV", backend)
    remote_home = tmp_path / "remote-home"
    remote_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "host-home")
    # Container tilde resolution uses the effective subprocess home; SSH must
    # instead use its detected remote home, deliberately different here.
    monkeypatch.setattr("hermes_constants.get_subprocess_home", lambda: str(tmp_path / "host-home" if backend == "ssh" else remote_home))
    env = SandboxTransport(remote_home)
    file_ops = ShellFileOperations(env, cwd=str(remote_home))
    monkeypatch.setattr("tools.file_tools._get_file_ops", lambda task_id: file_ops)
    monkeypatch.setattr("tools.file_tools_paths._terminal_env_type_for_task", lambda task_id="default": backend)
    get_spillover_dir().mkdir(parents=True)
    canonical = remote_home / ".hermes/cache/spillover/tool-results"
    directories = {"canonical": canonical, "temp": remote_home / "temp/hermes-results", "unrelated": remote_home / "project/cache/spillover/tool-results"}
    directory = directories[kind]
    directory.parent.mkdir(parents=True, exist_ok=True)
    outside = remote_home / "outside"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("outside must survive", encoding="utf-8")
    stale = time.time() - 8 * 24 * 3600
    os.utime(victim, (stale, stale))
    target = directory / "victim.txt"
    if state == "directory-link":
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory.mkdir()
        if state == "file-link":
            target.symlink_to(victim)
        else:
            target.write_text("retained content", encoding="utf-8")
        ttl = 24 if kind == "canonical" else 7 * 24
        age = ttl - 1 if state == "recent" else ttl + 1
        when = time.time() - age * 3600
        os.utime(target, (when, when), follow_symlinks=False)
    if state == "write-cleanup":
        # Only temp storage is opportunistically cleaned by a fallback write.
        saved = maybe_persist_tool_result("new result", "terminal", "fresh", env, threshold=0)
        assert "Full output saved to:" in saved
        if kind == "temp":
            assert not target.exists()
        else:
            assert target.exists()
        return
    requested = "~/.hermes/cache/spillover/tool-results/victim.txt" if kind == "canonical" else str(target)
    result = json.loads(registry.dispatch("read_file", {"path": requested}, task_id="retention-remote"))
    assert victim.read_text(encoding="utf-8") == "outside must survive"
    if kind == "unrelated" or state == "recent":
        assert not result.get("error"), result
        assert target.exists()
    elif state == "directory-link":
        assert "could not be verified" in result.get("error", ""), result
        assert target.exists()
    else:
        assert "expired after" in result.get("error", ""), result
        assert not target.exists()
        assert not target.is_symlink()
