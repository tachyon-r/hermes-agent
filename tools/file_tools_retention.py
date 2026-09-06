"""Read-time classification and retention of persisted tool results."""

import os
import posixpath
import stat
import sys
from pathlib import Path

from tools.file_tools_paths import _uses_container_paths


def persisted_result_read_error(path, resolved, file_ops, task_id):
    """Return a retention error, or None for a permitted/non-result read."""
    from tools.file_tools import (
        _expand_tilde, _resolve_base_dir, _file_ops_uses_host_paths, tool_error,
    )

    # Keep a lexical host path for the persisted-result expiry gate. The
    # ordinary resolver intentionally dereferences symlinks, but the gate
    # must inspect/delete an expired symlink artifact itself, never its
    # target. Canonicalize only the parent below so /tmp aliases still
    # compare correctly on macOS.
    expiry_candidate = None
    if sys.platform != "win32" and not _uses_container_paths(task_id):
        expanded = _expand_tilde(path)
        candidate = Path(expanded)
        if not candidate.is_absolute():
            candidate = _resolve_base_dir(task_id, container_paths=False) / candidate
        expiry_candidate = os.path.abspath(os.fspath(candidate))

    # Persisted oversized tool results are sensitive, short-lived
    # artifacts. Enforce their TTL when they are served as well as during
    # later writes, so a result with no successor cannot remain readable
    # indefinitely. Scope the mutating check to the active environment's
    # exact storage directory; reading an unrelated old file must stay
    # read-only.
    from tools.tool_result_storage import (
        PERSISTED_SPILLOVER_SUBDIR,
        RESULT_TTL_DAYS,
        SPILLOVER_MAX_AGE_HOURS,
        _expire_host_spillover_on_access,
        _expire_persisted_result_on_access,
        _expire_remote_spillover_on_access,
        _resolve_storage_dir,
        get_spillover_dir,
        get_spillover_root,
    )

    file_env = getattr(file_ops, "env", None)
    raw_persisted_dir = _resolve_storage_dir(file_env)
    if _file_ops_uses_host_paths(file_ops):
        # macOS exposes /tmp through /private/tmp; canonicalize the parent
        # for comparison without dereferencing the leaf symlink before the
        # expiry helper has a chance to remove or reject it.
        path_flavor = os.path
        candidate_path = expiry_candidate or os.fspath(resolved)
        candidate_lexical = os.path.abspath(candidate_path)
        # Resolve only the temp root (e.g. /tmp -> /private/tmp), not the
        # hermes-results leaf. Dereferencing that leaf before validation would
        # hide a preplanted directory symlink from the expiry helper.
        persisted_dir = os.path.join(
            os.path.realpath(os.path.dirname(raw_persisted_dir)),
            os.path.basename(raw_persisted_dir),
        )
        candidate_parent = os.path.dirname(candidate_lexical)
        candidate_parent = os.path.join(
            os.path.realpath(os.path.dirname(candidate_parent)),
            os.path.basename(candidate_parent),
        )
        if candidate_parent == persisted_dir:
            try:
                storage_is_directory = stat.S_ISDIR(os.lstat(persisted_dir).st_mode)
            except OSError:
                storage_is_directory = False
            if not storage_is_directory:
                return tool_error(
                    "Persisted tool result retention could not be verified safely; "
                    "access denied. Check backend permissions and retry."
                )
        resolved_path = os.path.join(
            os.path.realpath(os.path.dirname(candidate_path)),
            os.path.basename(candidate_path),
        )
        is_host_spillover = False
        is_remote_spillover = False
        remote_spillover_invalid = False
        host_spillover_invalid = False
        spillover_root_lexical = os.path.abspath(
            os.fspath(get_spillover_root())
        )
        try:
            root_stat = os.lstat(spillover_root_lexical)
            spillover_root_valid = stat.S_ISDIR(root_stat.st_mode)
        except OSError:
            spillover_root_valid = False
        try:
            candidate_under_root = (
                os.path.commonpath([candidate_lexical, spillover_root_lexical])
                == spillover_root_lexical
            )
        except ValueError:
            candidate_under_root = False
        if not spillover_root_valid and candidate_under_root:
            is_host_spillover = True
            host_spillover_invalid = True
            resolved_path = candidate_lexical
        for configured_path in (() if host_spillover_invalid else (get_spillover_dir(), get_spillover_root())):
            configured_lexical = os.path.abspath(os.fspath(configured_path))
            lexical_match = (
                os.path.dirname(candidate_lexical) == configured_lexical
                and os.path.basename(candidate_lexical).endswith(".txt")
            )
            try:
                configured_stat = os.lstat(configured_lexical)
                configured_is_dir = stat.S_ISDIR(configured_stat.st_mode)
            except OSError:
                configured_is_dir = False
            if not configured_is_dir:
                if lexical_match:
                    is_host_spillover = True
                    host_spillover_invalid = True
                    resolved_path = candidate_lexical
                    break
                continue
            configured_canonical = os.path.realpath(configured_lexical)
            if (
                os.path.dirname(resolved_path) == configured_canonical
                and os.path.basename(resolved_path).endswith(".txt")
            ):
                is_host_spillover = True
                break
    else:
        # Remote/container paths are POSIX even when the Hermes host is
        # Windows; never reinterpret them with the host path module.
        path_flavor = posixpath
        persisted_dir = posixpath.normpath(raw_persisted_dir)
        resolved_path = posixpath.normpath(os.fspath(resolved))
        is_host_spillover = False
        host_spillover_invalid = False
        remote_spillover_invalid = False
        host_spillover_dirs_valid = True
        for configured_path in (get_spillover_root(), get_spillover_dir()):
            try:
                configured_stat = os.lstat(configured_path)
            except OSError:
                host_spillover_dirs_valid = False
                break
            if not stat.S_ISDIR(configured_stat.st_mode):
                host_spillover_dirs_valid = False
                break
        try:
            from tools.credential_files import (
                get_agent_visible_cache_base,
                to_agent_visible_cache_path,
            )

            host_spillover_dir = os.fspath(get_spillover_dir())
            mapped_spillover_dir = posixpath.normpath(
                to_agent_visible_cache_path(host_spillover_dir)
            )
            remote_spillover_dirs = set()
            if mapped_spillover_dir != posixpath.normpath(host_spillover_dir):
                remote_spillover_dirs.add(mapped_spillover_dir)
            visible_cache_base = get_agent_visible_cache_base()
            if visible_cache_base:
                # ``_resolve_path_for_task`` expands ``~`` before this
                # classification, so normalize the backend root the same way.
                resolved_visible_base = _expand_tilde(visible_cache_base)
                remote_spillover_dirs.add(
                    posixpath.normpath(
                        posixpath.join(
                            resolved_visible_base,
                            "cache",
                            "spillover",
                            PERSISTED_SPILLOVER_SUBDIR,
                        )
                    )
                )
        except Exception:
            remote_spillover_dirs = set()
        resolved_parent = posixpath.dirname(resolved_path)
        is_remote_spillover = (
            resolved_parent in remote_spillover_dirs
            and posixpath.basename(resolved_path).endswith(".txt")
        )
        remote_spillover_invalid = (
            is_remote_spillover and not host_spillover_dirs_valid
        )

    if is_host_spillover:
        expiry_status = (
            None
            if host_spillover_invalid
            else _expire_host_spillover_on_access(resolved_path)
        )
        if expiry_status is True:
            return tool_error(
                "Persisted tool result expired after "
                f"{SPILLOVER_MAX_AGE_HOURS} hours and was deleted. Re-run the "
                "original tool call if the output is still needed."
            )
        if expiry_status is None:
            return tool_error(
                "Persisted tool result retention could not be verified safely; "
                "access denied. Check host permissions and retry."
            )
    elif is_remote_spillover:
        expiry_status = (
            None
            if remote_spillover_invalid
            else _expire_remote_spillover_on_access(resolved_path, file_env)
        )
        if expiry_status is True:
            return tool_error(
                "Persisted tool result expired after "
                f"{SPILLOVER_MAX_AGE_HOURS} hours and was deleted. Re-run the "
                "original tool call if the output is still needed."
            )
        if expiry_status is None:
            return tool_error(
                "Persisted tool result retention could not be verified safely; "
                "access denied. Check backend permissions and retry."
            )
    elif (
        path_flavor.dirname(resolved_path) == persisted_dir
        and path_flavor.basename(resolved_path).endswith(".txt")
    ):
        expiry_status = _expire_persisted_result_on_access(resolved_path, file_env)
        if expiry_status is True:
            return tool_error(
                f"Persisted tool result expired after {RESULT_TTL_DAYS} days "
                "and was deleted. Re-run the original tool call if the output "
                "is still needed."
            )
        if expiry_status is None:
            return tool_error(
                "Persisted tool result retention could not be verified safely; "
                "access denied. Check backend permissions and retry."
            )

