"""Symbolic links inside a scan target: allowed, never followed, never a source of evidence.

Fixtures live under pytest's temporary directory. Sources are synthetic text
handed to the scanner; nothing here is executed except a harmless canary script
that only creates a marker file.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer import semgrep_adapter
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.scan_evidence_manifest import EvidenceStatus, parse_scope_evidence
from ai_code_security_analyzer.semgrep_adapter import ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.semgrep_parser import parse_semgrep_json
from ai_code_security_analyzer.services import scan_service as scan_service_module
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService, ServiceError
from test_api_scan import FakeAdapter, _client
from test_untrusted_git_scan_hardening import (
    RULES,
    TOKEN,
    VULNERABLE,
    _build,
    _require_git,
    _require_semgrep,
)


pytestmark = pytest.mark.skipif(os.name != "posix", reason="fixtures use POSIX symbolic links")

HEADERS = {"X-Local-API-Token": TOKEN}
SCAN = {"target_id": "local-project", "rule_profile_id": "baseline"}
POLICY = "adapter_policy_exclusion"
LINK_NOTE = "symbolic_links_not_followed"
HARMLESS = "export const label = 'plain';\n"


def _write(path: Path, text: str = VULNERABLE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _link(link: Path, destination: str | Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(destination, link)


def _outside(tmp_path: Path) -> Path:
    """A folder next to the target whose file would produce a finding if it were scanned."""
    outside = tmp_path / "outside"
    _write(outside / "secret.js")
    return outside


# --- what the pre-scan check accepts and refuses (no Semgrep needed) -------------------------


class CountingAdapter(FakeAdapter):
    calls = 0

    def _scan_with_evidence(self, target: Path, rules_file: Path):
        type(self).calls += 1
        return super()._scan_with_evidence(target, rules_file)


@pytest.fixture
def counted(tmp_path: Path):
    CountingAdapter.calls = 0
    _client_instance, service = _client(tmp_path, CountingAdapter)
    return service, service.settings.target_directory


def test_links_below_the_root_no_longer_reject_the_project_and_are_noted(counted, tmp_path: Path) -> None:
    service, target = counted
    outside = _outside(tmp_path)
    _write(target / "src" / "real.js")
    _link(target / "src" / "alias.js", "real.js")
    _link(target / "mirror", "src")
    _link(target / "leak.js", outside / "secret.js")
    _link(target / "outside-folder", outside)
    _link(target / "gone.js", "missing.js")
    _link(target / "loop", ".")

    response, manifest = service._scan_with_manifest("local-project", "baseline")

    assert response.scan_status is ScanStatus.COMPLETED
    assert CountingAdapter.calls == 1
    assert LINK_NOTE in manifest.scope_evidence.limitations
    assert LINK_NOTE in manifest.limitations


def test_a_target_without_links_carries_no_link_note(counted) -> None:
    service, target = counted
    _write(target / "src" / "real.js")
    # A dependency folder that is itself a link is excluded by name, not walked and not noted.
    _link(target / "node_modules", "elsewhere")

    _response, manifest = service._scan_with_manifest("local-project", "baseline")

    assert LINK_NOTE not in manifest.scope_evidence.limitations


@pytest.mark.parametrize("location", [".semgrepignore", "packages/api/.semgrepignore"])
@pytest.mark.parametrize("kind", ["link_to_outside", "link_to_inside", "dangling_link", "fifo", "directory"])
def test_ignore_file_that_is_not_a_regular_file_is_refused_before_semgrep(
    counted, tmp_path: Path, location: str, kind: str
) -> None:
    service, target = counted
    _write(target / "src" / "real.js")
    ignore_file = target / location
    ignore_file.parent.mkdir(parents=True, exist_ok=True)
    if kind == "link_to_outside":
        _write(tmp_path / "outside-rules", "src/\n")
        _link(ignore_file, tmp_path / "outside-rules")
    elif kind == "link_to_inside":
        _write(target / "rules.txt", "src/\n")
        _link(ignore_file, target / "rules.txt")
    elif kind == "dangling_link":
        _link(ignore_file, "missing")
    elif kind == "fifo":
        os.mkfifo(ignore_file)
    else:
        ignore_file.mkdir()

    with pytest.raises(ServiceError) as error:
        service.scan("local-project", "baseline")

    assert (error.value.status_code, error.value.code) == (400, "target_not_allowed")
    assert CountingAdapter.calls == 0


@pytest.mark.parametrize("folder", ["node_modules", "node_modules/pkg", ".venv", ".venv/lib/python"])
@pytest.mark.parametrize("kind", ["link", "fifo"])
def test_ignore_file_inside_a_dependency_folder_must_also_be_regular(
    counted, tmp_path: Path, folder: str, kind: str
) -> None:
    """Semgrep opens ignore files inside the dependency folders it does not scan."""
    service, target = counted
    _write(target / "src" / "real.js")
    ignore_file = target / folder / ".semgrepignore"
    ignore_file.parent.mkdir(parents=True)
    if kind == "link":
        _write(tmp_path / "outside-rules", "*\n")
        _link(ignore_file, tmp_path / "outside-rules")
    else:
        os.mkfifo(ignore_file)

    with pytest.raises(ServiceError) as error:
        service.scan("local-project", "baseline")

    assert (error.value.status_code, error.value.code) == (400, "target_not_allowed")
    assert CountingAdapter.calls == 0


def test_regular_ignore_files_and_anything_inside_git_metadata_are_accepted(counted, tmp_path: Path) -> None:
    service, target = counted
    _write(target / "src" / "real.js")
    _write(target / ".semgrepignore", "docs/\n")
    _write(target / "node_modules" / "pkg" / ".semgrepignore", "test/\n")
    # Semgrep does not look for ignore files inside .git, so it is not walked.
    _link(target / ".git" / "info" / ".semgrepignore", tmp_path / "anything")
    os.mkfifo(target / ".git" / ".semgrepignore")

    assert service.scan("local-project", "baseline").scan_status is ScanStatus.COMPLETED
    assert CountingAdapter.calls == 1


def test_dependency_folders_do_not_count_toward_the_entry_limit_which_still_applies(
    counted, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, target = counted
    _write(target / "src" / "real.js")
    for index in range(40):
        _write(target / "node_modules" / f"pkg{index}" / "index.js")
        _link(target / "node_modules" / ".bin" / f"tool{index}", f"../pkg{index}/index.js")
        _write(target / ".venv" / "lib" / f"module{index}.py", "x = 1\n")
        _write(target / ".git" / "objects" / f"{index:02d}" / "blob", "x")
    monkeypatch.setattr(scan_service_module, "_MAX_TARGET_ENTRIES", 8)

    # Five entries count: src, real.js and the three excluded names.
    response, manifest = service._scan_with_manifest("local-project", "baseline")
    assert response.scan_status is ScanStatus.COMPLETED
    # Links inside dependency folders are part of the exclusion, not noted separately.
    assert LINK_NOTE not in manifest.scope_evidence.limitations

    for index in range(8):
        _write(target / "src" / f"extra{index}.js")
    with pytest.raises(ServiceError) as error:
        service.scan("local-project", "baseline")
    assert (error.value.status_code, error.value.code) == (400, "target_not_allowed")
    assert CountingAdapter.calls == 1


def test_time_budget_covers_dependency_folders(counted, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    service, target = counted
    _write(target / "real.js")
    _write(target / "node_modules" / "a" / "b" / "c" / "index.js")
    calls = 0

    def monotonic() -> float:
        # Calls: the deadline, then one per visited folder (root, node_modules, a, b, c).
        # Time runs out only once the walk is two levels inside the dependency folder.
        nonlocal calls
        calls += 1
        return 0.0 if calls <= 3 else 99.0

    monkeypatch.setattr(scan_service_module, "time", SimpleNamespace(monotonic=monotonic))

    with pytest.raises(ServiceError) as error:
        service.scan("local-project", "baseline")

    assert (error.value.status_code, error.value.code) == (400, "target_not_allowed")
    assert calls == 4
    assert CountingAdapter.calls == 0


def test_root_replaced_by_a_link_is_still_refused(counted, tmp_path: Path) -> None:
    service, target = counted
    _write(target / "src" / "real.js")
    target.rename(tmp_path / "moved")
    _link(target, tmp_path / "moved")

    with pytest.raises(ServiceError) as error:
        service.scan("local-project", "baseline")

    assert (error.value.status_code, error.value.code) == (400, "target_not_allowed")
    assert CountingAdapter.calls == 0


@pytest.mark.parametrize("which", ["root", "parent"])
def test_linked_root_or_parent_is_refused_at_configuration(tmp_path: Path, which: str) -> None:
    real_parent = tmp_path / "real-parent"
    _write(real_parent / "project" / "src" / "real.js")
    rules = tmp_path / "rules"
    rules.mkdir()
    if which == "root":
        _link(tmp_path / "linked-project", real_parent / "project")
        configured = tmp_path / "linked-project"
    else:
        _link(tmp_path / "linked-parent", real_parent)
        configured = tmp_path / "linked-parent" / "project"

    with pytest.raises(ValueError, match="symlink_path_not_allowed"):
        ApiSettings(configured, rules, TOKEN)


# --- containment of what Semgrep reports (no Semgrep needed) ---------------------------------


def _result(path: str) -> bytes:
    return json.dumps({
        "results": [{
            "check_id": "baseline.javascript-dynamic-eval", "path": path,
            "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 12},
            "extra": {"message": "synthetic", "severity": "ERROR"},
        }],
        "errors": [],
    }).encode()


@pytest.mark.parametrize(
    "reported",
    ["src/alias.js", "mirror/real.js", "leak.js", "outside-folder/secret.js", "a/b/deep.js", "../outside/secret.js"],
)
def test_a_reported_path_that_passes_through_a_link_is_refused_not_rewritten(tmp_path: Path, reported: str) -> None:
    outside = _outside(tmp_path)
    root = tmp_path / "project"
    _write(root / "src" / "real.js")
    _write(root / "a" / "real-b" / "deep.js")
    _link(root / "src" / "alias.js", "real.js")
    _link(root / "mirror", "src")
    _link(root / "leak.js", outside / "secret.js")
    _link(root / "outside-folder", outside)
    _link(root / "a" / "b", "real-b")

    for form in (reported, str(root / reported)):
        parsed = parse_semgrep_json(_result(form), root)
        assert parsed.findings == ()
        assert parsed.issues == ("result_0_invalid_result",)

    direct = parse_semgrep_json(_result(str(root / "src" / "real.js")), root)
    assert [item.file_path for item in direct.findings] == ["src/real.js"]
    assert direct.issues == ()


def test_taint_trace_location_through_a_link_is_refused(tmp_path: Path) -> None:
    from ai_code_security_analyzer import taint_evidence

    outside = _outside(tmp_path)
    root = tmp_path / "project"
    _write(root / "src" / "real.js")
    _link(root / "src" / "alias.js", "real.js")
    _link(root / "leak.js", outside / "secret.js")

    assert taint_evidence._relative_path("src/real.js", root) == "src/real.js"
    assert taint_evidence._relative_path(str(root / "src" / "real.js"), root) == "src/real.js"
    assert taint_evidence._relative_path("src/alias.js", root) is None
    assert taint_evidence._relative_path("leak.js", root) is None
    assert taint_evidence._relative_path("../outside/secret.js", root) is None


def test_adapter_marks_a_scan_partial_when_semgrep_reports_through_a_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Models a Semgrep that follows links: the result is dropped and the scan is not complete."""
    outside = _outside(tmp_path)
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    _link(target / "leak.js", outside / "secret.js")
    trusted = tmp_path / "trusted"
    _write(trusted / "local.yml", "rules: []\n")
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")
    document = json.loads(_result(str(target / "leak.js")))
    document["results"].append(json.loads(_result(str(target / "src" / "real.js")))["results"][0])
    document["paths"] = {"scanned": [str(target / "leak.js"), str(target / "src" / "real.js")]}

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(0, " ".join(semgrep_adapter._REQUIRED_OPTIONS).encode())
        return semgrep_adapter._ProcessResult(0, json.dumps(document).encode())

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    output = SemgrepAdapter(trusted)._scan_with_evidence(target, trusted / "local.yml")

    assert output.result.status is ScanStatus.PARTIAL
    assert output.result.issues == ("result_0_invalid_result",)
    assert [item.file_path for item in output.result.findings] == ["src/real.js"]
    # The scanned list named a link, so none of it is kept as evidence.
    assert output.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE
    assert output.scope_evidence.scanned_paths == ()
    assert "path_value_invalid" in output.scope_evidence.limitations


def test_skipped_excluded_name_may_be_a_link_but_nothing_below_a_link_is_recorded(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _write(tmp_path / "shared" / "pkg" / "index.js")
    _write(root / "src" / "real.js")
    _link(root / "node_modules", tmp_path / "shared")
    _link(root / "other-link", tmp_path / "shared")

    def scope(*skipped: tuple[str, str]):
        return parse_scope_evidence(
            {"results": [], "errors": [], "paths": {
                "scanned": ["src/real.js"], "skipped": [{"path": path, "reason": reason} for path, reason in skipped],
            }},
            root,
        )

    excluded = scope(("node_modules", "cli_exclude_flags_match"))
    assert excluded.skipped_status is EvidenceStatus.OBSERVED
    assert [(item.path, item.reason_code) for item in excluded.skipped_paths] == [("node_modules", POLICY)]

    for path, reason in (
        ("node_modules/pkg", "cli_exclude_flags_match"),
        ("node_modules/pkg/index.js", "semgrepignore_patterns_match"),
        ("other-link", "semgrepignore_patterns_match"),
        ("other-link", "cli_exclude_flags_match"),
    ):
        refused = scope((path, reason))
        assert refused.skipped_status is EvidenceStatus.UNAVAILABLE
        assert refused.skipped_paths == ()


def test_firestore_source_snapshot_skips_excluded_folders(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _write(root / "firestore.rules", "service cloud.firestore {}\n")
    _write(root / "node_modules" / "pkg" / "firestore.rules", "service cloud.firestore {}\n")
    _write(root / ".venv" / "firestore.rules", "service cloud.firestore {}\n")

    snapshot = semgrep_adapter._snapshot_firestore_sources(root, root)

    assert set(snapshot) == {"firestore.rules"}


# --- the real Semgrep subprocess through the real HTTP API -----------------------------------


def _app(target: Path):
    settings = ApiSettings(target, RULES, TOKEN, allowed_hosts=("testserver",))
    return create_app(settings, scan_service=ScanService(settings), investigation_api_enabled=True)


def _investigate(client: TestClient, app) -> tuple[dict, object]:
    response = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
    assert response.status_code == 200, response.text
    body = response.json()
    return body, app.state.investigation_registry.get_run(body["run_handle"]).manifest.scope_evidence


def _node_project(target: Path, tmp_path: Path) -> tuple[set[str], set[tuple[str, str]]]:
    _write(target / "src" / "app.js")
    _write(target / "packages" / "ws" / "index.js")
    _write(target / "node_modules" / "pkg" / "cli.js")
    _link(target / "node_modules" / ".bin" / "tool", "../pkg/cli.js")
    _link(target / "node_modules" / "@scope" / "ws", "../../packages/ws")
    return {"src/app.js", "packages/ws/index.js"}, {("node_modules", POLICY)}


def _python_project(target: Path, tmp_path: Path) -> tuple[set[str], set[tuple[str, str]]]:
    _write(target / "src" / "app.js")
    _write(target / ".venv" / "lib" / "site.js")
    _link(target / ".venv" / "bin" / "python", sys.executable)
    _link(target / ".venv" / "bin" / "python3", "python")
    return {"src/app.js"}, {(".venv", POLICY)}


def _linked_dependency_folders(target: Path, tmp_path: Path) -> tuple[set[str], set[tuple[str, str]]]:
    _write(target / "src" / "app.js")
    _write(tmp_path / "shared-modules" / "pkg" / "index.js")
    _write(tmp_path / "shared-venv" / "lib" / "site.js")
    _link(target / "node_modules", tmp_path / "shared-modules")
    _link(target / ".venv", tmp_path / "shared-venv")
    return {"src/app.js"}, {("node_modules", POLICY), (".venv", POLICY)}


PROJECTS = {
    "node_project": _node_project,
    "python_project": _python_project,
    "linked_dependency_folders": _linked_dependency_folders,
}


@pytest.mark.parametrize("shape", PROJECTS)
def test_ordinary_project_structures_scan_to_completion(shape: str, tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    expected_sources, expected_skips = PROJECTS[shape](target, tmp_path)
    app = _app(target)

    with TestClient(app) as client:
        plain = client.post("/api/v1/scans", headers=HEADERS, json=SCAN)
        investigated, scope = _investigate(client, app)

    assert plain.status_code == 200, plain.text
    assert plain.json()["scan_status"] == "completed"
    assert {item["file_path"] for item in plain.json()["findings"]} == expected_sources
    assert investigated["scan"]["scan_status"] == "completed"
    assert investigated["scan"]["issues"] == []
    assert {item["file_path"] for item in investigated["scan"]["findings"]} == expected_sources
    assert set(scope.scanned_paths) == expected_sources
    assert {(item.path, item.reason_code) for item in scope.skipped_paths} == expected_skips
    assert LINK_NOTE not in scope.limitations
    assert "scan_result_is_not_safety_proof" in plain.json()["limitations"]
    assert str(tmp_path) not in plain.text + json.dumps(investigated)


def _internal_file_link(target: Path, outside: Path) -> None:
    _link(target / "src" / "alias.js", "real.js")


def _internal_folder_link(target: Path, outside: Path) -> None:
    _link(target / "mirror", "src")


def _external_file_link(target: Path, outside: Path) -> None:
    _link(target / "src" / "leak.js", outside / "secret.js")


def _external_folder_link(target: Path, outside: Path) -> None:
    _link(target / "outside-folder", outside)


def _dangling_link(target: Path, outside: Path) -> None:
    _link(target / "src" / "gone.js", "missing.js")


def _cyclic_links(target: Path, outside: Path) -> None:
    _link(target / "src" / "loop", "..")
    _link(target / "a.js", "b.js")
    _link(target / "b.js", "a.js")


def _linked_gitignore(target: Path, outside: Path) -> None:
    _write(outside / "gitignore", "src/\n*.js\n")
    _link(target / ".gitignore", outside / "gitignore")


LINKS = {
    "internal_file_link": _internal_file_link,
    "internal_folder_link": _internal_folder_link,
    "external_file_link": _external_file_link,
    "external_folder_link": _external_folder_link,
    "dangling_link": _dangling_link,
    "cyclic_links": _cyclic_links,
    "linked_gitignore": _linked_gitignore,
}


@pytest.mark.parametrize("kind", LINKS)
def test_links_are_not_followed_and_nothing_outside_the_root_is_reported(kind: str, tmp_path: Path) -> None:
    _require_semgrep()
    outside = _outside(tmp_path)
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    LINKS[kind](target, outside)
    app = _app(target)

    with TestClient(app) as client:
        plain = client.post("/api/v1/scans", headers=HEADERS, json=SCAN)
        investigated, scope = _investigate(client, app)

    for body in (plain.json(), investigated["scan"]):
        assert body["scan_status"] == "completed"
        # The real file is reported once, under its own path. No link, no outside file.
        assert [item["file_path"] for item in body["findings"]] == ["src/real.js"]
    assert list(scope.scanned_paths) == ["src/real.js"]
    assert scope.skipped_status is EvidenceStatus.OBSERVED and scope.skipped_paths == ()
    # The scan is complete for what it covers, and the evidence says links were not followed.
    assert LINK_NOTE in scope.limitations
    assert scope.completeness_status is EvidenceStatus.UNVERIFIED
    assert "secret" not in plain.text + json.dumps(investigated)
    assert "outside" not in plain.text + json.dumps(investigated)


def test_linked_git_metadata_is_excluded_and_its_configuration_never_runs(tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    # A repository outside the target whose configuration names the canary.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _evil_target, evil_repository, marker = _build("own_config", elsewhere, git)
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    _link(target / ".git", evil_repository / ".git")
    app = _app(target)

    with TestClient(app) as client:
        investigated, scope = _investigate(client, app)

    assert not marker.exists()
    assert investigated["scan"]["scan_status"] == "completed"
    assert [item["file_path"] for item in investigated["scan"]["findings"]] == ["src/real.js"]
    assert {(item.path, item.reason_code) for item in scope.skipped_paths} == {(".git", POLICY)}


@pytest.mark.parametrize(
    "location, expected",
    [
        # A blocking ignore file inside a dependency folder stalls Semgrep: it opens it.
        ("node_modules/pkg/.semgrepignore", ScanStatus.TIMED_OUT),
        (".venv/lib/.semgrepignore", ScanStatus.TIMED_OUT),
        # Inside .git it is never opened.
        (".git/info/.semgrepignore", ScanStatus.COMPLETED),
    ],
)
def test_semgrep_opens_ignore_files_inside_dependency_folders_but_not_git_metadata(
    location: str, expected: ScanStatus, tmp_path: Path
) -> None:
    """Pins the measured Semgrep behaviour that the pre-scan ignore-file rule relies on."""
    _require_semgrep()
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    (target / location).parent.mkdir(parents=True)
    os.mkfifo(target / location)

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, RULES / "security-baseline.yml", timeout=15)

    assert output.result.status is expected
    if expected is ScanStatus.COMPLETED:
        assert [item.file_path for item in output.result.findings] == ["src/real.js"]
    else:
        assert output.result.findings == ()
        assert output.scope_evidence.scanned_status is EvidenceStatus.UNAVAILABLE


def test_ignore_rules_nested_in_a_dependency_folder_cannot_hide_other_files(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    _write(target / "lib" / "second.js")
    for folder in ("node_modules", "node_modules/pkg", ".venv"):
        _write(target / folder / ".semgrepignore", "*\n**\n/src/\nsrc/\n../src/\n**/src/**\n*.js\n/../lib/\n")

    output = SemgrepAdapter(RULES)._scan_with_evidence(
        target, RULES / "security-baseline.yml", investigation_verbose=True
    )

    assert output.result.status is ScanStatus.COMPLETED
    assert set(output.scope_evidence.scanned_paths) == {"src/real.js", "lib/second.js"}
    assert {(item.path, item.reason_code) for item in output.scope_evidence.skipped_paths} == {
        ("node_modules", POLICY), (".venv", POLICY),
    }


@pytest.mark.parametrize("link", ["src/linked-folder", "linked-folder", "node_modules/linked-folder"])
def test_ignore_file_discovery_does_not_follow_folder_links(link: str, tmp_path: Path) -> None:
    """A blocking ignore file behind a folder link is never opened."""
    _require_semgrep()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.mkfifo(outside / ".semgrepignore")
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    _link(target / link, outside)

    output = SemgrepAdapter(RULES)._scan_with_evidence(target, RULES / "security-baseline.yml", timeout=30)

    assert output.result.status is ScanStatus.COMPLETED
    assert [item.file_path for item in output.result.findings] == ["src/real.js"]


def _swap_for_link(path: Path, destination: Path) -> None:
    path.unlink()
    os.symlink(destination, path)


@pytest.mark.parametrize("destination", ["outside", "inside"])
def test_file_replaced_by_a_link_after_validation_is_not_followed_by_semgrep(
    destination: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The swap happens after the pre-scan check and before the real Semgrep process starts."""
    _require_semgrep()
    outside = _outside(tmp_path)
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    _write(target / "src" / "swapped.js", HARMLESS)
    _write(target / "lib" / "second.js")
    real_run = semgrep_adapter._run_process
    link_to = outside / "secret.js" if destination == "outside" else target / "lib" / "second.js"

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        if args[1] == "scan" and "--help" not in args:
            _swap_for_link(target / "src" / "swapped.js", link_to)
        return real_run(args, cwd, env, timeout)

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    app = _app(target)
    with TestClient(app) as client:
        investigated, scope = _investigate(client, app)

    assert (target / "src" / "swapped.js").is_symlink()
    assert investigated["scan"]["scan_status"] == "completed"
    assert {item["file_path"] for item in investigated["scan"]["findings"]} == {"src/real.js", "lib/second.js"}
    assert set(scope.scanned_paths) == {"src/real.js", "lib/second.js"}
    assert "secret" not in json.dumps(investigated)


@pytest.mark.parametrize("destination", ["outside", "inside"])
def test_finding_whose_file_became_a_link_after_the_scan_is_dropped_and_the_scan_is_partial(
    destination: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The swap happens after the real Semgrep process ended and before its output is read."""
    _require_semgrep()
    outside = _outside(tmp_path)
    target = tmp_path / "project"
    _write(target / "src" / "real.js")
    _write(target / "src" / "swapped.js")
    _write(target / "lib" / "harmless.js", HARMLESS)
    real_run = semgrep_adapter._run_process
    link_to = outside / "secret.js" if destination == "outside" else target / "lib" / "harmless.js"

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: int) -> semgrep_adapter._ProcessResult:
        completed = real_run(args, cwd, env, timeout)
        if args[1] == "scan" and "--help" not in args:
            _swap_for_link(target / "src" / "swapped.js", link_to)
        return completed

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    app = _app(target)
    with TestClient(app) as client:
        investigated, scope = _investigate(client, app)

    body = investigated["scan"]
    assert body["scan_status"] == "partial"
    assert body["completed"] is False
    assert "scan_partial" in body["limitations"]
    # Neither the link's own path nor the file it now points at is reported.
    assert [item["file_path"] for item in body["findings"]] == ["src/real.js"]
    assert scope.scanned_status is EvidenceStatus.UNAVAILABLE and scope.scanned_paths == ()
    assert "secret" not in json.dumps(investigated)


INVESTIGATIONS = {
    # change between runs: (mutation, comparability, overall, observation for src/old.js)
    "nothing_changes": (None, "COMPARABLE", "UNDETERMINED", None),
    "external_link_added": (
        lambda target, outside: _link(target / "src" / "new-link.js", outside / "secret.js"),
        "COMPARABLE", "UNDETERMINED", None,
    ),
    "finding_file_replaced_by_external_link": (
        lambda target, outside: _swap_for_link(target / "src" / "old.js", outside / "secret.js"),
        "COMPARABLE", "UNDETERMINED", "PATH_NOT_REPORTED",
    ),
    "finding_file_replaced_by_internal_link": (
        lambda target, outside: _swap_for_link(target / "src" / "old.js", target / "src" / "app.js"),
        "COMPARABLE", "UNDETERMINED", "PATH_NOT_REPORTED",
    ),
}


@pytest.mark.parametrize("case", INVESTIGATIONS)
def test_investigation_of_a_project_with_links_keeps_its_comparison_semantics(case: str, tmp_path: Path) -> None:
    _require_semgrep()
    outside = _outside(tmp_path)
    target = tmp_path / "project"
    _node_project(target, tmp_path)
    _write(target / "src" / "old.js")
    _link(target / "docs" / "latest", "../src")
    mutate, comparability, overall, observation = INVESTIGATIONS[case]
    app = _app(target)

    with TestClient(app) as client:
        baseline, _scope = _investigate(client, app)
        assert baseline["scan"]["scan_status"] == "completed"
        old_id = next(item["finding_id"] for item in baseline["scan"]["findings"] if item["file_path"] == "src/old.js")
        if mutate is not None:
            mutate(target, outside)
        current, current_scope = _investigate(client, app)
        assert current["scan"]["scan_status"] == "completed"
        assert LINK_NOTE in current_scope.limitations
        session = client.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": baseline["run_handle"], "current_handle": current["run_handle"],
        })
        assert session.status_code == 201, session.text
        evaluated = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
            "investigation_handle": session.json()["investigation_handle"],
        })

    assert evaluated.status_code == 200, evaluated.text
    evaluation = evaluated.json()
    assert evaluation["comparability"] == comparability
    assert evaluation["overall_assessment"] == overall
    assert evaluation["overall_assessment"] != "EXPLANATION_SUPPORTED"
    assert "scope_completeness_unverified" in evaluation["limitation_codes"]
    old = next(item for item in evaluation["findings"] if item["finding_id"] == old_id)
    if observation is None:
        assert old["category"] == "shared"
    else:
        assert old["category"] == "baselineOnly"
        assert old["path_observation"] == observation
        assert old["skip_hypothesis"] == "UNDETERMINED"
    assert "secret" not in json.dumps(evaluation) + json.dumps(current)
