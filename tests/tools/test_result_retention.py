"""Retention and read-time safety, stacked on private result writes."""

import os
import ntpath
import stat
import sys
import time
from pathlib import Path, PurePosixPath
import pytest
from unittest.mock import MagicMock, patch
from tools.tool_result_storage import RESULT_TTL_DAYS, _expire_host_spillover_on_access, _expire_persisted_result_on_access, _expire_remote_spillover_on_access, _write_to_sandbox, get_spillover_dir


class TestResultRetention:
    @pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX mode bits not enforced on Windows")
    def test_real_write_is_private_and_enforces_ttl_boundary(self, tmp_path):
        from tools.environments.local import LocalEnvironment

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        storage_dir = tmp_path / "hermes-results"
        storage_dir.mkdir(mode=0o755)
        expired = storage_dir / "expired.txt"
        expired.write_text("old", encoding="utf-8")
        retained = storage_dir / "retained.txt"
        retained.write_text("recent", encoding="utf-8")
        now = time.time()
        expired_at = now - ((RESULT_TTL_DAYS * 24 + 1) * 60 * 60)
        retained_at = now - ((RESULT_TTL_DAYS * 24 - 1) * 60 * 60)
        os.utime(expired, (expired_at, expired_at))
        os.utime(retained, (retained_at, retained_at))

        target = storage_dir / "fresh.txt"
        assert _write_to_sandbox("private content", str(target), env) is True

        assert target.read_text(encoding="utf-8") == "private content"
        assert stat.S_IMODE(storage_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert not expired.exists()
        assert retained.read_text(encoding="utf-8") == "recent"


    @pytest.mark.skipif(
        sys.platform.startswith("win") or not hasattr(os, "symlink"),
        reason="requires POSIX symlink semantics",
    )
    def test_cleanup_removes_expired_symlink_artifact_without_following_it(self, tmp_path):
        from tools.environments.local import LocalEnvironment

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        storage_dir = tmp_path / "hermes-results"
        storage_dir.mkdir(mode=0o700)
        outside = tmp_path / "outside.txt"
        outside.write_text("must remain", encoding="utf-8")
        artifact = storage_dir / "expired.txt"
        artifact.symlink_to(outside)
        expired_at = time.time() - ((RESULT_TTL_DAYS * 24 + 1) * 60 * 60)
        os.utime(artifact, (expired_at, expired_at), follow_symlinks=False)

        target = storage_dir / "fresh.txt"
        assert _write_to_sandbox("private content", str(target), env) is True

        assert not artifact.exists()
        assert not artifact.is_symlink()
        assert outside.read_text(encoding="utf-8") == "must remain"


    @pytest.mark.skipif(sys.platform.startswith("win"), reason="requires POSIX find semantics")
    def test_access_deletes_expired_result_without_a_later_write(self, tmp_path):
        from tools.environments.local import LocalEnvironment

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        target = tmp_path / "expired.txt"
        target.write_text("sensitive", encoding="utf-8")
        expired_at = time.time() - ((RESULT_TTL_DAYS * 24 + 1) * 60 * 60)
        os.utime(target, (expired_at, expired_at))

        assert _expire_persisted_result_on_access(str(target), env) is True
        assert not target.exists()


    @pytest.mark.skipif(
        sys.platform.startswith("win") or not hasattr(os, "symlink"),
        reason="requires POSIX symlink semantics",
    )
    def test_access_deletes_expired_symlink_without_following_it(self, tmp_path):
        from tools.environments.local import LocalEnvironment

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        outside = tmp_path / "outside.txt"
        outside.write_text("must remain", encoding="utf-8")
        artifact = tmp_path / "expired.txt"
        artifact.symlink_to(outside)
        expired_at = time.time() - ((RESULT_TTL_DAYS * 24 + 1) * 60 * 60)
        os.utime(artifact, (expired_at, expired_at), follow_symlinks=False)

        assert _expire_persisted_result_on_access(str(artifact), env) is True
        assert not artifact.is_symlink()
        assert outside.read_text(encoding="utf-8") == "must remain"


    @pytest.mark.skipif(
        sys.platform.startswith("win") or not hasattr(os, "symlink"),
        reason="requires POSIX symlink semantics",
    )
    def test_read_interface_deletes_expired_symlink_without_following_it(self, tmp_path):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        from tools.file_tools import read_file_tool

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        file_ops = ShellFileOperations(env, cwd=str(tmp_path))
        storage_dir = tmp_path / "hermes-results"
        storage_dir.mkdir(mode=0o700)
        outside = tmp_path / "outside.txt"
        outside.write_text("must remain", encoding="utf-8")
        artifact = storage_dir / "expired.txt"
        artifact.symlink_to(outside)
        expired_at = time.time() - ((RESULT_TTL_DAYS * 24 + 1) * 60 * 60)
        os.utime(artifact, (expired_at, expired_at), follow_symlinks=False)

        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch(
                "tools.tool_result_storage._resolve_storage_dir",
                return_value=str(storage_dir),
            ),
        ):
            result = read_file_tool(str(artifact))

        assert "expired after 7 days" in result
        assert not artifact.is_symlink()
        assert outside.read_text(encoding="utf-8") == "must remain"


    @pytest.mark.skipif(
        sys.platform.startswith("win"), reason="requires POSIX lstat semantics"
    )
    def test_read_interface_enforces_canonical_spillover_expiry(
        self, tmp_path, monkeypatch
    ):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        from tools.file_tools import read_file_tool

        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        file_ops = ShellFileOperations(env, cwd=str(tmp_path))
        spill_dir = get_spillover_dir()
        spill_dir.mkdir(parents=True)
        artifact = spill_dir / "expired.txt"
        artifact.write_text("old", encoding="utf-8")
        stale = time.time() - (25 * 3600)
        os.utime(artifact, (stale, stale))

        with patch("tools.file_tools._get_file_ops", return_value=file_ops):
            result = read_file_tool(str(artifact))

        assert "expired after 24 hours" in result
        assert not artifact.exists()


    @pytest.mark.skipif(
        sys.platform.startswith("win") or not hasattr(os, "symlink"),
        reason="requires POSIX directory symlinks",
    )
    def test_read_interface_refuses_symlinked_spillover_directory(
        self, tmp_path, monkeypatch
    ):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        from tools.file_tools import read_file_tool

        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        file_ops = ShellFileOperations(env, cwd=str(tmp_path))
        spill_dir = get_spillover_dir()
        spill_dir.parent.mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "victim.txt"
        victim.write_text("keep", encoding="utf-8")
        stale = time.time() - (25 * 3600)
        os.utime(victim, (stale, stale))
        spill_dir.symlink_to(outside, target_is_directory=True)

        with patch("tools.file_tools._get_file_ops", return_value=file_ops):
            result = read_file_tool(str(spill_dir / "victim.txt"))

        assert "could not be verified" in result
        assert victim.read_text(encoding="utf-8") == "keep"


    @pytest.mark.skipif(
        sys.platform.startswith("win") or not hasattr(os, "symlink"),
        reason="requires POSIX directory symlinks",
    )
    def test_read_interface_refuses_symlinked_shared_root(
        self, tmp_path, monkeypatch
    ):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        from tools.file_tools import read_file_tool

        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        file_ops = ShellFileOperations(env, cwd=str(tmp_path))
        spill_dir = get_spillover_dir()
        spill_dir.parent.parent.mkdir(parents=True)
        outside = tmp_path / "outside-root"
        private_outside = outside / "tool-results"
        private_outside.mkdir(parents=True)
        victim = private_outside / "victim.txt"
        victim.write_text("keep", encoding="utf-8")
        stale = time.time() - (25 * 3600)
        os.utime(victim, (stale, stale))
        spill_dir.parent.symlink_to(outside, target_is_directory=True)

        with patch("tools.file_tools._get_file_ops", return_value=file_ops):
            result = read_file_tool(str(spill_dir / "victim.txt"))

        assert "could not be verified" in result
        assert victim.read_text(encoding="utf-8") == "keep"


    @pytest.mark.skipif(sys.platform.startswith("win"), reason="requires POSIX find semantics")
    def test_access_retains_recent_result(self, tmp_path):
        from tools.environments.local import LocalEnvironment

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        target = tmp_path / "recent.txt"
        target.write_text("sensitive", encoding="utf-8")

        assert _expire_persisted_result_on_access(str(target), env) is False
        assert target.read_text(encoding="utf-8") == "sensitive"


    @pytest.mark.skipif(
        sys.platform.startswith("win") or not hasattr(os, "symlink"),
        reason="requires POSIX directory symlinks",
    )
    @pytest.mark.parametrize(
        "expiry_helper",
        [_expire_persisted_result_on_access, _expire_remote_spillover_on_access],
    )
    def test_remote_expiry_refuses_symlinked_parent(
        self, tmp_path, expiry_helper
    ):
        from tools.environments.local import LocalEnvironment

        env = LocalEnvironment(cwd=str(tmp_path), env={"TMPDIR": str(tmp_path)})
        outside = tmp_path / "outside"
        outside.mkdir()
        victim = outside / "victim.txt"
        victim.write_text("keep", encoding="utf-8")
        stale = time.time() - (8 * 24 * 3600)
        os.utime(victim, (stale, stale))
        alias = tmp_path / "hermes-results"
        alias.symlink_to(outside, target_is_directory=True)

        assert expiry_helper(str(alias / "victim.txt"), env) is None
        assert victim.read_text(encoding="utf-8") == "keep"


    def test_access_expiry_probe_failure_is_indeterminate(self):
        env = MagicMock()
        env.execute.return_value = {"returncode": 1, "output": ""}

        assert _expire_persisted_result_on_access(
            "/tmp/hermes-results/result.txt", env
        ) is None


    def test_remote_spillover_expiry_uses_24_hour_boundary(self):
        env = MagicMock()
        env.execute.return_value = {"returncode": 0, "output": "expired"}

        assert _expire_remote_spillover_on_access(
            "/root/.hermes/cache/spillover/tool-results/result.txt", env
        ) is True
        command = env.execute.call_args.args[0]
        assert "-mmin +1439" in command


    def test_read_interface_enforces_remote_canonical_expiry(self):
        from tools.file_tools import read_file_tool

        env = MagicMock()
        file_ops = MagicMock(env=env)
        visible_path = "/root/.hermes/cache/spillover/tool-results/expired.txt"
        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch("tools.file_tools._file_ops_uses_host_paths", return_value=False),
            patch(
                "tools.file_tools.os.lstat",
                return_value=MagicMock(st_mode=stat.S_IFDIR),
            ),
            patch(
                "tools.file_tools._resolve_path_for_task",
                return_value=PurePosixPath(visible_path),
            ),
            patch(
                "tools.credential_files.to_agent_visible_cache_path",
                return_value="/root/.hermes/cache/spillover/tool-results",
            ),
            patch(
                "tools.tool_result_storage._expire_remote_spillover_on_access",
                return_value=True,
            ) as expire,
        ):
            result = read_file_tool(visible_path)

        assert "expired after 24 hours" in result
        expire.assert_called_once_with(visible_path, env)
        file_ops.read_file.assert_not_called()


    def test_read_interface_remote_canonical_fails_closed_for_invalid_host_root(
        self, monkeypatch
    ):
        from tools.file_tools import read_file_tool

        monkeypatch.setenv("TERMINAL_ENV", "docker")
        env = MagicMock()
        file_ops = MagicMock(env=env)
        visible_path = "/root/.hermes/cache/spillover/tool-results/result.txt"
        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch("tools.file_tools._file_ops_uses_host_paths", return_value=False),
            patch("tools.file_tools.os.lstat", side_effect=FileNotFoundError),
            patch(
                "tools.file_tools._resolve_path_for_task",
                return_value=PurePosixPath(visible_path),
            ),
            patch(
                "tools.credential_files.to_agent_visible_cache_path",
                return_value=os.fspath(get_spillover_dir()),
            ),
            patch(
                "tools.tool_result_storage._expire_remote_spillover_on_access"
            ) as expire,
        ):
            result = read_file_tool(visible_path)

        assert "could not be verified" in result
        expire.assert_not_called()
        file_ops.read_file.assert_not_called()


    def test_read_interface_does_not_classify_matching_suffix_as_canonical(
        self, monkeypatch
    ):
        from tools.file_tools import read_file_tool

        monkeypatch.setenv("TERMINAL_ENV", "docker")
        env = MagicMock()
        file_ops = MagicMock(env=env)
        read_result = MagicMock()
        read_result.content = "ordinary file"
        read_result.error = None
        read_result.to_dict.return_value = {
            "content": "ordinary file",
            "total_lines": 1,
            "file_size": 13,
        }
        file_ops.read_file.return_value = read_result
        unrelated_path = "/workspace/project/cache/spillover/tool-results/notes.txt"
        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch("tools.file_tools._file_ops_uses_host_paths", return_value=False),
            patch(
                "tools.file_tools._resolve_path_for_task",
                return_value=PurePosixPath(unrelated_path),
            ),
            patch(
                "tools.credential_files.to_agent_visible_cache_path",
                return_value="/root/.hermes/cache/spillover/tool-results",
            ),
            patch(
                "tools.tool_result_storage._expire_remote_spillover_on_access"
            ) as expire,
        ):
            result = read_file_tool(unrelated_path)

        assert "ordinary file" in result
        expire.assert_not_called()
        file_ops.read_file.assert_called_once()


    def test_read_interface_enforces_expiry_only_in_active_result_dir(self, tmp_path, monkeypatch):
        from tools.environments.local import LocalEnvironment
        from tools.file_operations import ShellFileOperations
        from tools.file_tools import read_file_tool

        root = tmp_path / "temp-root"
        root.mkdir()
        alias = tmp_path / "temp-alias"
        alias.symlink_to(root, target_is_directory=True)
        storage = root / "hermes-results"
        storage.mkdir()
        target = storage / "expired.txt"
        target.write_text("expired", encoding="utf-8")
        stale = time.time() - 8 * 24 * 3600
        os.utime(target, (stale, stale))
        env = LocalEnvironment(cwd=str(tmp_path))
        monkeypatch.setattr(env, "get_temp_dir", lambda: str(alias))
        file_ops = ShellFileOperations(env, cwd=str(tmp_path))
        monkeypatch.setattr("tools.file_tools._get_file_ops", lambda task_id: file_ops)

        result = read_file_tool(str(target))

        assert "expired after 7 days" in result
        assert not target.exists()


    def test_read_interface_fails_closed_when_expiry_cannot_be_verified(self):
        from tools.file_tools import read_file_tool

        env = MagicMock()
        file_ops = MagicMock(env=env)
        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch("tools.file_tools._file_ops_uses_host_paths", return_value=True),
            patch(
                "tools.file_tools._resolve_path_for_task",
                return_value=Path("/tmp/hermes-results/result.txt"),
            ),
            patch(
                "tools.tool_result_storage._resolve_storage_dir",
                return_value="/tmp/hermes-results",
            ),
            patch(
                "tools.tool_result_storage._expire_persisted_result_on_access",
                return_value=None,
            ),
        ):
            result = read_file_tool("/tmp/hermes-results/result.txt")

        assert "could not be verified" in result
        file_ops.read_file.assert_not_called()


    def test_read_interface_does_not_expire_unrelated_old_file(self):
        from tools.file_tools import read_file_tool

        env = MagicMock()
        file_ops = MagicMock(env=env)
        read_result = MagicMock()
        read_result.content = "still here"
        read_result.error = None
        read_result.to_dict.return_value = {
            "content": "still here",
            "total_lines": 1,
            "file_size": 10,
        }
        file_ops.read_file.return_value = read_result
        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch(
                "tools.file_tools._resolve_path_for_task",
                return_value=Path("/tmp/other/old.txt"),
            ),
            patch(
                "tools.tool_result_storage._resolve_storage_dir",
                return_value="/tmp/hermes-results",
            ),
            patch("tools.tool_result_storage._expire_persisted_result_on_access") as expire,
        ):
            result = read_file_tool("/tmp/other/old.txt")

        assert "still here" in result
        expire.assert_not_called()


    def test_remote_read_keeps_posix_result_path_on_windows_host(self):
        from tools.file_tools import read_file_tool

        env = MagicMock()
        file_ops = MagicMock(env=env)
        remote_path = "/tmp/hermes-results/expired.txt"
        with (
            patch("tools.file_tools._get_file_ops", return_value=file_ops),
            patch("tools.file_tools._file_ops_uses_host_paths", return_value=False),
            patch(
                "tools.file_tools._resolve_path_for_task",
                return_value=Path(remote_path),
            ),
            patch("tools.file_tools.os.path", ntpath),
            patch(
                "tools.tool_result_storage._resolve_storage_dir",
                return_value="/tmp/hermes-results",
            ),
            patch(
                "tools.tool_result_storage._expire_persisted_result_on_access",
                return_value=True,
            ) as expire,
        ):
            result = read_file_tool(remote_path)

        assert "expired after 7 days" in result
        expire.assert_called_once_with(remote_path, env)
        file_ops.read_file.assert_not_called()


    @pytest.fixture(autouse=True)
    def _isolated_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
        # Reset the once-per-process prune flag so each test is independent.
        import tools.tool_result_storage as trs
        monkeypatch.setattr(trs, "_spillover_pruned_once", False)
        yield


    @pytest.mark.skipif(
        sys.platform.startswith("win"), reason="requires POSIX lstat semantics"
    )
    def test_spillover_access_expiry_fails_closed(self):
        spill_dir = get_spillover_dir()
        spill_dir.mkdir(parents=True)

        expired = spill_dir / "expired.txt"
        expired.write_text("old", encoding="utf-8")
        stale = time.time() - (25 * 3600)
        os.utime(expired, (stale, stale))
        assert _expire_host_spillover_on_access(expired) is True
        assert not expired.exists()

        fresh = spill_dir / "fresh.txt"
        fresh.write_text("new", encoding="utf-8")
        assert _expire_host_spillover_on_access(fresh) is False

        outside = spill_dir.parent / "outside.txt"
        outside.write_text("must remain", encoding="utf-8")
        alias = spill_dir / "alias.txt"
        alias.symlink_to(outside)
        assert _expire_host_spillover_on_access(alias) is None
        assert alias.is_symlink()
        assert outside.read_text(encoding="utf-8") == "must remain"

