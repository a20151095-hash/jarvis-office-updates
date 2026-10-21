"""Actual Windows file/directory symlink boundary test of public v0.3.1.

Only synthetic temporary files are used. Existing security settings and token
privileges are never changed. A blocked link creation is NOT a passing test.
This script neither starts AI tasks nor reads user configuration or records.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
from unittest import mock
from urllib.request import Request, build_opener, HTTPRedirectHandler
import zipfile

VERSION = "0.3.1"
PAYLOAD_URL = "https://a20151095-hash.github.io/jarvis-office-updates/packages/jarvis-0.3.1.zip"
EXPECTED_SHA256 = "d0fae9f6bc27ba11ff6fddf8293f8940357263c84cf348fa9bce91c75ec9e5ed"
EXPECTED_SIZE = 60245
PAYLOAD_NAMES = frozenset({"index.html", "자비스_사무실.py", "codex_adapter.py", "claude_adapter.py",
    "version.json", "assets/chiikawa.svg", "assets/hachiware.svg", "assets/usagi.svg"})
REPORT_NAME = "file-link-boundary-report.json"
SYMLINK_TAG = 0xA000000C
DIRECTORY_ATTRIBUTE = 0x10
sys.dont_write_bytecode = True


class RedirectForbidden(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def download_payload(folder, report):
    opener = build_opener(RedirectForbidden())
    request = Request(PAYLOAD_URL, headers={"User-Agent": "JarvisOffice-Boundary-Verification/0.3.1"})
    # urllib uses normal certificate validation; no HTTP fallback or credentials.
    with opener.open(request, timeout=20) as response:
        require(response.status == 200 and response.geturl() == PAYLOAD_URL, "direct_https_response_required")
        data = response.read(EXPECTED_SIZE + 1)
    require(len(data) == EXPECTED_SIZE, "payload_size_mismatch")
    require(sha(data) == EXPECTED_SHA256, "payload_sha256_mismatch")
    hashes = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.namelist()) == 8 and set(archive.namelist()) == PAYLOAD_NAMES,
                "exact_eight_file_payload_required")
        require(sum(item.file_size for item in archive.infolist()) <= 4 * 1024 * 1024, "payload_unpacked_size_limit")
        for item in archive.infolist():
            require(not item.flag_bits & 1, "encrypted_zip_entry_forbidden")
            require(not ((item.external_attr >> 16) & 0o170000 == 0o120000), "archive_symlink_forbidden")
            content = archive.read(item)
            path = folder / item.filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            hashes[item.filename] = sha(content)
    version = json.loads((folder / "version.json").read_text(encoding="utf-8"))
    require(version.get("version") == VERSION and version.get("bootstrapProtocol") == 1, "unexpected_payload_version")
    report["payload"] = {"url": PAYLOAD_URL, "sha256": sha(data), "bytes": len(data),
        "pinnedHashAndSizeVerified": True, "exactEightFiles": True, "fileSHA256": hashes,
        "trustBasis": "HTTPS plus immutable payload hash/size pinned from locally verified signed release; no mutable latest lookup"}


def run_boundary(payload, fixture, report):
    sys.path.insert(0, str(payload))
    spec = importlib.util.spec_from_file_location("jarvis_public_v031_boundary", payload / "자비스_사무실.py")
    server = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server)
    require(server.VERSION == VERSION, "packaged_server_version_mismatch")
    claude, codex, external = fixture / "claude", fixture / "codex", fixture / "external"
    for folder in (claude, codex, external):
        folder.mkdir()
    outside_file = fixture / "outside.jsonl"
    outside_child = external / "file.jsonl"
    outside_file.write_bytes(b'{"kind":"read","session":"synthetic-outside-file"}\n')
    outside_child.write_bytes(b'{"kind":"write","session":"synthetic-outside-directory"}\n')
    file_link, directory_link = codex / "linked.jsonl", codex / "linked-directory"
    originals = {path: (sha(path.read_bytes()), path.stat().st_mtime_ns) for path in (outside_file, outside_child)}
    try:
        # Standard Python/Windows calls use only rights already present on runner.
        file_link.symlink_to(outside_file, target_is_directory=False)
        directory_link.symlink_to(external, target_is_directory=True)
    except (OSError, NotImplementedError) as error:
        report["linkCreation"] = {"result": "BLOCKED", "errorType": type(error).__name__,
            "winerror": getattr(error, "winerror", None), "securitySettingsChanged": False,
            "privilegesEnabled": False}
        report["result"] = "BLOCKED"
        return
    file_stat, directory_stat = file_link.lstat(), directory_link.lstat()
    require(file_link.is_symlink() and file_link.is_file(), "actual_file_symlink_required")
    require(file_stat.st_reparse_tag == SYMLINK_TAG and not file_stat.st_file_attributes & DIRECTORY_ATTRIBUTE,
            "actual_windows_file_symlink_tag_required")
    require(directory_link.is_symlink() and directory_link.is_dir(), "actual_directory_symlink_required")
    require(directory_stat.st_reparse_tag == SYMLINK_TAG and directory_stat.st_file_attributes & DIRECTORY_ATTRIBUTE,
            "actual_windows_directory_symlink_tag_required")
    report["linkCreation"] = {"result": "CREATED_WITH_EXISTING_RIGHTS", "fileSymlink": True, "directorySymlink": True,
        "fileName": "linked.jsonl", "fileReparseTag": hex(file_stat.st_reparse_tag),
        "directoryReparseTag": hex(directory_stat.st_reparse_tag), "junctionUsedAsSubstitute": False,
        "securitySettingsChanged": False, "privilegesEnabled": False}
    parser_calls, opened_paths, scanned_paths = [], [], []
    def parser(record, context):
        require(record.get("session") == "synthetic-positive-control", "outside_content_reached_parser")
        parser_calls.append(record["session"])
        return [{"session_id": record["session"], "agent_id": record["session"], "parent_id": None,
                 "provider": "codex", "kind": record["kind"], "label": "test", "tool": "Read",
                 "timestamp": "2026-01-01T00:00:00Z"}]
    monitor = server.Monitor(claude, codex, parsers={"claude": parser, "codex": parser})
    original_open, original_scandir = os.open, os.scandir
    forbidden_files = {outside_file, outside_child, file_link}
    def guarded_open(path, *args, **kwargs):
        current = Path(path)
        require(current not in forbidden_files and not current.is_relative_to(directory_link), "external_or_link_open_attempted")
        require(current.parent == codex, "unexpected_file_open_attempted")
        opened_paths.append(current.name)
        return original_open(path, *args, **kwargs)
    def guarded_scandir(path):
        current = Path(path)
        require(current in {claude, codex}, "external_or_link_directory_enumeration_attempted")
        scanned_paths.append(current.name)
        return original_scandir(path)
    def passed(name):
        report["checks"].append({"name": name, "result": "PASS", "kind": "REAL_WINDOWS_FILESYSTEM_SYNTHETIC_CONTENT"})
    try:
        with mock.patch.object(server.os, "open", side_effect=guarded_open), \
             mock.patch.object(server.os, "scandir", side_effect=guarded_scandir):
            monitor.tick(force_scan=True)
            require(monitor.snapshot()["events"] == [] and parser_calls == [] and opened_paths == [],
                    "original_symlink_ignore_semantics_failed")
            passed("original_test_semantics_file_and_directory_symlinks_are_ignored")
            with mock.patch.object(Path, "resolve", side_effect=AssertionError("must_reject_before_resolution")):
                require(not server.within_root(file_link, codex), "file_link_boundary_accepted")
                require(not server.within_root(directory_link / "file.jsonl", codex), "directory_link_component_accepted")
            passed("file_and_intermediate_directory_links_rejected_before_resolution")
            scans_before = len(scanned_paths)
            require(monitor._discover("codex", directory_link) == [] and not monitor.available["codex"], "symlink_root_accepted")
            require(len(scanned_paths) == scans_before, "symlink_root_enumeration_attempted")
            passed("directory_symlink_root_rejected_before_scandir")
            for candidate in (file_link, directory_link / "file.jsonl"):
                cursor = server.FileCursor(candidate, codex, "codex")
                require(monitor._read_cursor(cursor, 4096) == 0 and opened_paths == [], "cached_cursor_followed_link")
            passed("file_and_directory_cached_cursors_rejected_before_open")
            control = codex / "normal.jsonl"
            control.write_bytes(b'{"kind":"read","session":"synthetic-positive-control"}\n')
            before_control = (sha(control.read_bytes()), control.stat().st_mtime_ns)
            monitor.tick(force_scan=True)
            events = monitor.snapshot()["events"]
            require(len(events) == 1 and events[0]["kind"] == "read", "positive_control_event_missing_or_extra")
            require(parser_calls == ["synthetic-positive-control"] and opened_paths == ["normal.jsonl"],
                    "unexpected_parser_or_file_access")
            require((sha(control.read_bytes()), control.stat().st_mtime_ns) == before_control, "positive_control_modified")
            passed("normal_jsonl_positive_control_collected_once_without_modification")
        require(all((sha(path.read_bytes()), path.stat().st_mtime_ns) == initial for path, initial in originals.items()),
                "synthetic_external_targets_modified")
        require((file_link.lstat().st_ino, file_link.lstat().st_mtime_ns, file_link.lstat().st_reparse_tag) ==
                (file_stat.st_ino, file_stat.st_mtime_ns, file_stat.st_reparse_tag), "file_link_metadata_modified")
        require((directory_link.lstat().st_ino, directory_link.lstat().st_mtime_ns, directory_link.lstat().st_reparse_tag) ==
                (directory_stat.st_ino, directory_stat.st_mtime_ns, directory_stat.st_reparse_tag), "directory_link_metadata_modified")
        passed("synthetic_targets_hash_mtime_and_link_metadata_preserved")
        report["accessGuard"] = {"externalTargetOpens": 0, "externalTargetEnumerations": 0,
            "parserCalls": len(parser_calls), "normalFileOpens": len(opened_paths),
            "targetHashing": "Harness directly hashes only the synthetic files it generated, outside scanner guards"}
        report["result"] = "PASS"
    finally:
        monitor.stop()


def main():
    report = {"schemaVersion": 1, "appVersion": VERSION, "result": "NOT_RUN", "checks": [],
        "checkedAtUTC": datetime.now(timezone.utc).isoformat(),
        "runtime": {"python": platform.python_version(), "platform": sys.platform,
                    "windowsRelease": platform.release(), "architecture": platform.machine()},
        "scope": "Packaged server boundary on hosted Windows; synthetic fixtures only. This is separate from the user's PC validation.",
        "preservation": {"userFilesRead": False, "userSettingsRead": False, "aiTasksStarted": False,
            "securitySettingsChanged": False, "privilegesEnabled": False, "adminElevationRequested": False,
            "privateKeysOrCredentialsRead": False, "appSourceModified": False},
        "originalTest": {"name": "test_server.MonitorTests.test_symlinks_are_ignored",
            "scope": "Equivalent file+directory symlink ignore semantics executed against pinned packaged v031 server; original local SKIP evidence remains unchanged"}}
    run_root = None
    try:
        require(sys.platform == "win32" and sys.version_info >= (3, 10), "windows_python_310_or_newer_required")
        owner = Path.cwd().absolute()
        run_root = Path(tempfile.mkdtemp(prefix="jarvis-boundary-", dir=owner))
        payload, fixture = run_root / "payload", run_root / "fixture"
        payload.mkdir()
        fixture.mkdir()
        download_payload(payload, report)
        run_boundary(payload, fixture, report)
    except Exception as error:
        report["result"] = "FAIL"
        report["failure"] = {"type": type(error).__name__,
            "reason": str(error) if isinstance(error, AssertionError) else "dependency_download_or_probe_error",
            "winerror": getattr(error, "winerror", None)}
    finally:
        if run_root is not None:
            try:
                # The only recursive deletion is a verified directory created by this test.
                require(run_root.resolve().parent == Path.cwd().resolve() and run_root.name.startswith("jarvis-boundary-")
                        and not run_root.is_symlink(), "temporary_cleanup_scope_mismatch")
                shutil.rmtree(run_root)
                report["temporaryFixtureCleanup"] = "PASS"
            except Exception:
                report["temporaryFixtureCleanup"] = "FAIL"
                report["result"] = "FAIL"
        report["summary"] = {"pass": sum(item["result"] == "PASS" for item in report["checks"]),
            "requiredChecks": 6, "complete": report["result"] == "PASS" and len(report["checks"]) == 6}
        if not report["summary"]["complete"] and report["result"] == "PASS":
            report["result"] = "FAIL"
        # Report/log contains constants, platform facts, hashes and synthetic outcomes only.
        Path(REPORT_NAME).write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        print("JARVIS_BOUNDARY_RESULT_JSON="+json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return 0 if report["summary"]["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
