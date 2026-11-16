"""What a scan says about paths Semgrep left out (A8-R1).

A scan's status describes execution. Whether paths were excluded is a separate
statement, and it must never read "none" unless Semgrep's skip list was actually
collected and validated. These tests use the real Semgrep subprocess wherever the
behaviour depends on the engine; sources are synthetic and are never executed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer import semgrep_adapter
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.reporter import build_json_report, render_text
from ai_code_security_analyzer.review import render_review
from ai_code_security_analyzer.scan_evidence_manifest import (
    EvidenceStatus,
    ScanCoverage,
    SkipEvidenceState,
    classify_reported_skip,
    stored_skip_is_valid,
)
from ai_code_security_analyzer.semgrep_adapter import ScanResult, ScanStatus, SemgrepAdapter
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService
from test_untrusted_git_scan_hardening import (
    BASELINE,
    RULES,
    TOKEN,
    VULNERABLE,
    _eval_files,
    _git,
    _require_git,
    _require_semgrep,
    _scanned,
)


pytestmark = pytest.mark.skipif(os.name != "posix", reason="fixtures use POSIX paths and Git")

ROOT = Path(__file__).resolve().parents[1]
HEADERS = {"X-Local-API-Token": TOKEN}
SCAN = {"target_id": "local-project", "rule_profile_id": "baseline"}
# Every one of these holds the same detectable source as src/app.js. Semgrep's
# default ignore list leaves them out when the project has no .semgrepignore.
DEFAULT_IGNORED = ("dist/bundle.js", "build/out.js", "test/app.test.js", "tests/more.test.js", "vendor/lib.js", "public/lib.min.js")
IGNORE_RULES = "paths_excluded_by_ignore_rules"
SIZE_LIMIT = "paths_excluded_by_size_limit"
UNVERIFIED = "skipped_paths_unverified"
NOT_COLLECTED = "skipped_paths_not_collected"
COVERAGE_CODES = {IGNORE_RULES, SIZE_LIMIT, UNVERIFIED, NOT_COLLECTED}
# A TypeScript file Semgrep 1.182.1 reports as a partial-parsing error.
UNPARSABLE_TS = "eval(x);\nconst = = = ;\nclass { ]]] \n"
HELP = b"--json --metrics --disable-version-check --oss-only --no-autofix --no-git-ignore --exclude --verbose"


def _write(base: Path, *relative_paths: str, text: str = VULNERABLE) -> None:
    for relative in relative_paths:
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _project(tmp_path: Path, *relative_paths: str) -> Path:
    target = tmp_path / "project"
    _write(target, "src/app.js", *relative_paths)
    return target


def _normal(target: Path) -> semgrep_adapter._ScanOutput:
    return SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE)


def _investigation(target: Path) -> semgrep_adapter._ScanOutput:
    return SemgrepAdapter(RULES)._scan_with_evidence(target, BASELINE, investigation_verbose=True)


def _client(target: Path) -> TestClient:
    settings = ApiSettings(target, RULES, TOKEN, allowed_hosts=("testserver",))
    return TestClient(create_app(settings, scan_service=ScanService(settings), investigation_api_enabled=True))


def _coverage_codes(scan: dict) -> set[str]:
    return COVERAGE_CODES & set(scan["limitations"])


# --- the engine: what real Semgrep leaves out, and what the normal scan says about it ---


def test_default_ignored_test_build_and_minified_files_are_reported_not_hidden(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, *DEFAULT_IGNORED)

    output = _normal(target)

    # Execution completed, and only src/app.js was analysed.
    assert output.result.status is ScanStatus.COMPLETED
    assert output.result.issues == ()
    assert _eval_files(output) == {"src/app.js"}
    assert _scanned(output) == {"src/app.js"}
    # The six left-out files are stated, as a count, on the result itself.
    assert output.result.coverage == ScanCoverage(SkipEvidenceState.OBSERVED, ignore_rule_exclusions=6, size_limit_exclusions=0)
    assert output.result.coverage.paths_skipped is True
    assert output.scope_evidence.skipped_status is EvidenceStatus.OBSERVED
    assert {item.path for item in output.scope_evidence.skipped_paths} == set(DEFAULT_IGNORED)


def test_the_left_out_files_are_detectable_once_a_project_ignore_file_replaces_the_default_list(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, *DEFAULT_IGNORED, "docs/example.js")
    (target / ".semgrepignore").write_text("docs/\n", encoding="utf-8")

    output = _normal(target)

    assert output.result.status is ScanStatus.COMPLETED
    # Control for the test above: the same files hold real findings.
    assert _eval_files(output) == {"src/app.js", *DEFAULT_IGNORED}
    # The project's own rule is the one exclusion now, and it is counted.
    assert output.result.coverage == ScanCoverage(SkipEvidenceState.OBSERVED, ignore_rule_exclusions=1, size_limit_exclusions=0)
    assert {item.path for item in output.scope_evidence.skipped_paths} == {"docs/example.js"}


def test_adapter_exclusions_are_recorded_but_are_not_reported_as_excluded_paths(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, "node_modules/pkg/index.js", "packages/a/node_modules/dep/index.js", ".venv/lib/site.js")

    output = _normal(target)

    assert output.result.status is ScanStatus.COMPLETED
    assert _eval_files(output) == {"src/app.js"}
    assert {(item.path, item.reason_code) for item in output.scope_evidence.skipped_paths} == {
        ("node_modules", "adapter_policy_exclusion"),
        ("packages/a/node_modules", "adapter_policy_exclusion"),
        (".venv", "adapter_policy_exclusion"),
    }
    assert output.result.coverage == ScanCoverage(SkipEvidenceState.OBSERVED, ignore_rule_exclusions=0, size_limit_exclusions=0)
    assert output.result.coverage.paths_skipped is False


def test_gitignored_source_with_a_finding_is_scanned_and_is_not_an_exclusion(tmp_path: Path) -> None:
    git = _require_git()
    _require_semgrep()
    target = _project(tmp_path, "local/ignored.js")
    (target / ".gitignore").write_text("local/\n", encoding="utf-8")
    home = tmp_path / "setup-home"
    _git(git, home, "-C", str(target), "init", "-q")
    _git(git, home, "-C", str(target), "add", "-A")
    _git(git, home, "-C", str(target), "commit", "-q", "-m", "synthetic")

    output = _normal(target)

    assert output.result.status is ScanStatus.COMPLETED
    assert _eval_files(output) == {"src/app.js", "local/ignored.js"}
    assert output.result.coverage.paths_skipped is False
    assert {item.path for item in output.scope_evidence.skipped_paths} == {".git"}


def test_a_source_file_above_the_size_limit_is_left_out_and_counted(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path)
    padding = "// " + "x" * 97 + "\n"
    _write(target, "src/large.js", text=padding * 10_500 + VULNERABLE)   # > 1,000,000 bytes, with a real finding
    (target / "package-lock.json").write_text('{"padding": "' + "p" * 1_100_000 + '"}', encoding="utf-8")

    output = _normal(target)

    assert output.result.status is ScanStatus.COMPLETED
    assert _eval_files(output) == {"src/app.js"}
    # The lock file counts as well: Semgrep applies the limit to every file type.
    assert output.result.coverage == ScanCoverage(SkipEvidenceState.OBSERVED, ignore_rule_exclusions=0, size_limit_exclusions=2)
    assert {(item.path, item.reason_code) for item in output.scope_evidence.skipped_paths} == {
        ("src/large.js", "exceeded_size_limit"), ("package-lock.json", "exceeded_size_limit"),
    }


def test_no_supported_files_stays_partial(tmp_path: Path) -> None:
    _require_semgrep()
    target = tmp_path / "project"
    _write(target, "app.py", text="print(eval(input()))\n")

    output = _normal(target)

    assert output.result.status is ScanStatus.PARTIAL
    assert output.result.issues == ("no_files_scanned",)
    assert output.result.findings == ()


def test_a_parser_failure_stays_partial_and_gives_no_exclusion_counts(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path)
    _write(target, "src/broken.ts", text=UNPARSABLE_TS)

    output = _normal(target)

    assert output.result.status is ScanStatus.PARTIAL
    assert output.result.issues == ("semgrep_reported_errors",)
    # Semgrep lists the file it failed on as both scanned and skipped, under a reason
    # this tool does not store. The skip list is therefore not validated, and the
    # result gives no exclusion counts rather than guessing.
    assert output.result.coverage == ScanCoverage(SkipEvidenceState.UNVERIFIED)
    assert output.result.coverage.paths_skipped is None
    assert output.scope_evidence.skipped_status is EvidenceStatus.UNAVAILABLE


def test_a_skip_list_too_large_for_the_output_bound_does_not_fail_the_normal_scan(tmp_path: Path) -> None:
    """Semgrep lists every ignored file with its full path, which can exceed the 2 MB output bound."""
    _require_semgrep()
    target = _project(tmp_path)
    # 3,400 minified files below long folder names: each is listed separately, at about
    # 700 bytes per entry. (An ignored folder is listed once per direct child instead.)
    generated = target / "public" / ("a" * 200) / ("b" * 200) / ("c" * 200)
    generated.mkdir(parents=True)
    for index in range(3_400):
        (generated / f"chunk-{index:04d}.min.js").write_text("var a = 1;\n", encoding="utf-8")

    normal = _normal(target)

    # As before this change, the scan completes and reports its finding ...
    assert normal.result.status is ScanStatus.COMPLETED
    assert _eval_files(normal) == {"src/app.js"}
    # ... and it says that it does not know what was left out.
    assert normal.result.coverage == ScanCoverage(SkipEvidenceState.NOT_COLLECTED)
    assert normal.result.coverage.paths_skipped is None
    assert normal.scope_evidence.skipped_status is EvidenceStatus.NOT_COLLECTED

    # The investigation run needs the list and keeps failing closed.
    investigated = _investigation(target)
    assert investigated.result.status is ScanStatus.OUTPUT_LIMIT_EXCEEDED
    assert investigated.result.issues == ("semgrep_output_limit",)


# --- skip metadata that is missing, malformed or unrecognized (stand-in engine output) ---


def _fake_semgrep(monkeypatch: pytest.MonkeyPatch, document: dict | None, *, scan_error: Exception | None = None) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: float) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1\n")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(0, HELP)
        calls.append(args)
        if scan_error is not None:
            raise scan_error
        return semgrep_adapter._ProcessResult(0, json.dumps(document).encode())

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    return calls


def _document(**paths: object) -> dict:
    return {"results": [], "errors": [], "paths": {"scanned": ["src/app.js"], **paths}}


SKIP_METADATA = {
    # skip list as reported: (expected evidence state, paths_skipped, API code)
    "list_absent": (None, SkipEvidenceState.NOT_COLLECTED, None, NOT_COLLECTED),
    "empty_list": ([], SkipEvidenceState.OBSERVED, False, None),
    "unrecognized_reason": ([{"path": "src/secret.js", "reason": "insufficient_permissions"}], SkipEvidenceState.UNVERIFIED, None, UNVERIFIED),
    "exclude_flag_on_a_path_the_adapter_did_not_exclude": (
        [{"path": "src/other.js", "reason": "cli_exclude_flags_match"}], SkipEvidenceState.UNVERIFIED, None, UNVERIFIED,
    ),
    "size_limit_on_an_adapter_excluded_name": (
        [{"path": "node_modules", "reason": "exceeded_size_limit"}], SkipEvidenceState.UNVERIFIED, None, UNVERIFIED,
    ),
    "not_a_list": ("everything", SkipEvidenceState.UNVERIFIED, None, UNVERIFIED),
    "entry_not_an_object": (["src/other.js"], SkipEvidenceState.UNVERIFIED, None, UNVERIFIED),
    "path_outside_the_project": ([{"path": "../outside.js", "reason": "semgrepignore_patterns_match"}], SkipEvidenceState.UNVERIFIED, None, UNVERIFIED),
    "path_also_reported_scanned": ([{"path": "src/app.js", "reason": "semgrepignore_patterns_match"}], SkipEvidenceState.UNVERIFIED, None, UNVERIFIED),
}


@pytest.mark.parametrize("case", SKIP_METADATA)
def test_missing_or_malformed_skip_metadata_is_never_reported_as_nothing_skipped(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skipped, state, paths_skipped, api_code = SKIP_METADATA[case]
    target = _project(tmp_path)
    _fake_semgrep(monkeypatch, _document() if skipped is None else _document(skipped=skipped))

    result = SemgrepAdapter(RULES).scan(target, BASELINE)

    # The normal scan's status does not depend on the skip list ...
    assert result.status is ScanStatus.COMPLETED
    assert result.issues == ()
    # ... and its coverage says exactly what was established.
    assert result.coverage.skip_evidence is state
    assert result.coverage.paths_skipped is paths_skipped
    report = build_json_report(result, target, BASELINE)
    assert report["coverage"]["paths_skipped"] is paths_skipped
    assert report["coverage"]["skipped_paths"]["evidence"] == state.value
    if state is not SkipEvidenceState.OBSERVED:
        assert report["coverage"]["skipped_paths"]["excluded_by_ignore_rules"] is None
        assert "no excluded paths" not in render_text(result, target, BASELINE)

    with _client(target) as client:
        normal = client.post("/api/v1/scans", headers=HEADERS, json=SCAN).json()
        investigated = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()["scan"]
    assert normal["scan_status"] == "completed"
    assert _coverage_codes(normal) == ({api_code} if api_code else set())
    # The investigation run states the same coverage and, for a list it cannot
    # validate, stays partial as before.
    assert _coverage_codes(investigated) == _coverage_codes(normal)
    assert investigated["scan_status"] == ("partial" if state is SkipEvidenceState.UNVERIFIED else "completed")


def test_a_timed_out_scan_claims_nothing_about_skipped_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _project(tmp_path)
    _fake_semgrep(monkeypatch, None, scan_error=semgrep_adapter._ProcessTimeout())

    result = SemgrepAdapter(RULES).scan(target, BASELINE)

    assert result.status is ScanStatus.TIMED_OUT
    assert result.coverage == ScanCoverage(SkipEvidenceState.NOT_COLLECTED)
    assert build_json_report(result, target, BASELINE)["coverage"]["paths_skipped"] is None
    with _client(target) as client:
        response = client.post("/api/v1/scans", headers=HEADERS, json=SCAN).json()
    assert response["scan_status"] == "timed_out"
    assert "scan_failed" in response["limitations"]


def test_the_output_bound_retry_runs_once_without_the_skip_list_and_only_for_normal_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _project(tmp_path)
    calls: list[list[str]] = []
    timeouts: list[float] = []
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: float) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1\n")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(0, HELP)
        calls.append(args)
        timeouts.append(timeout)
        if "--verbose" in args:
            raise semgrep_adapter._OutputLimitExceeded
        return semgrep_adapter._ProcessResult(0, json.dumps(_document()).encode())

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)
    adapter = SemgrepAdapter(RULES)

    result = adapter.scan(target, BASELINE, timeout=30)

    assert ["--verbose" in args for args in calls] == [True, False]
    assert result.status is ScanStatus.COMPLETED
    assert result.coverage == ScanCoverage(SkipEvidenceState.NOT_COLLECTED)
    # Both runs share one time limit.
    assert timeouts[0] == 30 and 0 < timeouts[1] <= 30

    calls.clear()
    investigated = adapter._scan_with_evidence(target, BASELINE, investigation_verbose=True)
    assert ["--verbose" in args for args in calls] == [True]
    assert investigated.result.status is ScanStatus.OUTPUT_LIMIT_EXCEEDED


def test_a_semgrep_without_the_skip_list_option_still_scans_and_says_the_list_was_not_collected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _project(tmp_path)
    calls: list[list[str]] = []
    monkeypatch.setattr(semgrep_adapter.shutil, "which", lambda _: "/trusted/semgrep")

    def run(args: list[str], cwd: Path, env: dict[str, str], timeout: float) -> semgrep_adapter._ProcessResult:
        if args[1:] == ["--version"]:
            return semgrep_adapter._ProcessResult(0, b"1.182.1\n")
        if args[1:] == ["scan", "--help"]:
            return semgrep_adapter._ProcessResult(0, HELP.replace(b" --verbose", b""))
        calls.append(args)
        return semgrep_adapter._ProcessResult(0, json.dumps(_document()).encode())

    monkeypatch.setattr(semgrep_adapter, "_run_process", run)

    result = SemgrepAdapter(RULES).scan(target, BASELINE)

    assert all("--verbose" not in args for args in calls)
    assert result.status is ScanStatus.COMPLETED
    assert result.coverage == ScanCoverage(SkipEvidenceState.NOT_COLLECTED)


def test_a_result_built_without_coverage_never_claims_that_nothing_was_skipped(tmp_path: Path) -> None:
    result = ScanResult(ScanStatus.COMPLETED)

    assert result.coverage.paths_skipped is None
    report = build_json_report(result, tmp_path, BASELINE)
    assert report["schema_version"] == "1.1"
    assert report["coverage"]["paths_skipped"] is None
    assert report["coverage"]["skipped_paths"] == {
        "evidence": "not_collected", "excluded_by_ignore_rules": None, "excluded_by_size_limit": None,
    }
    assert "skipped-path details were not collected" in render_text(result, tmp_path, BASELINE)
    assert "제외된 경로 정보를 수집하지 못했습니다" in render_review(result)


def test_only_validated_skip_reasons_are_stored() -> None:
    assert classify_reported_skip("src/large.js", "exceeded_size_limit") == "exceeded_size_limit"
    assert stored_skip_is_valid("src/large.js", "exceeded_size_limit")
    # A name the adapter excludes is excluded by the adapter, never by the size limit.
    assert classify_reported_skip("node_modules", "exceeded_size_limit") is None
    assert not stored_skip_is_valid("node_modules", "exceeded_size_limit")
    for reason in ("insufficient_permissions", "analysis_failed_parser_or_internal_error", "wrong_language", "", None, 7):
        assert classify_reported_skip("src/app.js", reason) is None


# --- the same statement on every surface: API, investigation, CLI ---


def test_normal_and_investigation_scans_state_the_same_coverage(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, *DEFAULT_IGNORED)

    with _client(target) as client:
        normal_response = client.post("/api/v1/scans", headers=HEADERS, json=SCAN)
        investigated_response = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
    normal = normal_response.json()
    investigated = investigated_response.json()["scan"]

    # Both observed the same exclusions and reported the same findings.
    assert _coverage_codes(normal) == _coverage_codes(investigated) == {IGNORE_RULES}
    assert [item["file_path"] for item in normal["findings"]] == ["src/app.js"]
    assert [item["finding_id"] for item in normal["findings"]] == [item["finding_id"] for item in investigated["findings"]]
    # The normal scan completed its execution. The investigation run, whose result
    # backs comparison claims, is additionally marked partial, as before.
    assert (normal["scan_status"], normal["completed"], normal["issues"]) == ("completed", True, [])
    assert (investigated["scan_status"], investigated["completed"]) == ("partial", False)
    assert "scan_partial" in investigated["limitations"]
    # Counts stay in the coverage codes; no excluded path name reaches a response.
    for body in (normal_response.text, investigated_response.text):
        assert not any(name in body for name in ("bundle.js", "lib.min.js", "app.test.js", "vendor", str(tmp_path)))


def test_a_project_without_exclusions_carries_no_coverage_limitation_in_either_mode(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, "node_modules/pkg/index.js")

    with _client(target) as client:
        normal = client.post("/api/v1/scans", headers=HEADERS, json=SCAN).json()
        investigated = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()["scan"]

    for scan in (normal, investigated):
        assert scan["scan_status"] == "completed"
        assert _coverage_codes(scan) == set()
        assert scan["limitations"] == ["finding_count_not_confirmed_vulnerability_count", "scan_result_is_not_safety_proof"]


def test_size_limit_and_ignore_rule_exclusions_are_reported_separately(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, "dist/bundle.js")
    _write(target, "src/large.js", text=("// " + "x" * 97 + "\n") * 10_500 + VULNERABLE)

    with _client(target) as client:
        normal = client.post("/api/v1/scans", headers=HEADERS, json=SCAN).json()

    assert normal["scan_status"] == "completed"
    assert _coverage_codes(normal) == {IGNORE_RULES, SIZE_LIMIT}


def _evaluate(client: TestClient, baseline: dict, current: dict) -> dict:
    session = client.post("/api/v2/investigations", headers=HEADERS, json={
        "baseline_handle": baseline["run_handle"], "current_handle": current["run_handle"],
    })
    assert session.status_code == 201, session.text
    evaluated = client.post("/api/v2/investigations/evaluate", headers=HEADERS, json={
        "investigation_handle": session.json()["investigation_handle"],
    })
    assert evaluated.status_code == 200, evaluated.text
    return evaluated.json()


def test_an_ignore_rule_that_hides_a_finding_is_visible_in_both_modes_and_never_reads_as_resolved(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, "src/old.js")
    (target / ".semgrepignore").write_text("docs/\n", encoding="utf-8")

    with _client(target) as client:
        normal_before = client.post("/api/v1/scans", headers=HEADERS, json=SCAN).json()
        baseline = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()
        # The project now tells Semgrep to leave the file with the finding out.
        (target / ".semgrepignore").write_text("docs/\nsrc/old.js\n", encoding="utf-8")
        normal_after = client.post("/api/v1/scans", headers=HEADERS, json=SCAN).json()
        current = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()
        evaluation = _evaluate(client, baseline, current)

    # Before: nothing excluded, two findings, both modes comparable.
    assert normal_before["scan_status"] == baseline["scan"]["scan_status"] == "completed"
    assert _coverage_codes(normal_before) == _coverage_codes(baseline["scan"]) == set()
    assert {item["file_path"] for item in normal_before["findings"]} == {"src/app.js", "src/old.js"}

    # After, normal scan: still a completed execution, and therefore still eligible for
    # the dashboard's comparison. The finding is gone, and the result says a path was excluded.
    assert normal_after["scan_status"] == "completed"
    assert {item["file_path"] for item in normal_after["findings"]} == {"src/app.js"}
    assert _coverage_codes(normal_after) == {IGNORE_RULES}

    # After, investigation: same coverage statement; the comparison is refused and the
    # evidence names the reason. The disappearance is never presented as explained or fixed.
    assert current["scan"]["scan_status"] == "partial"
    assert _coverage_codes(current["scan"]) == {IGNORE_RULES}
    assert evaluation["comparability"] == "INCOMPARABLE"
    assert evaluation["overall_assessment"] == "INCOMPARABLE"
    assert "scan_incomplete" in evaluation["limitation_codes"]
    assert "path_explicitly_skipped" in evaluation["limitation_codes"]
    old = next(item for item in evaluation["findings"] if item["category"] == "baselineOnly")
    assert old["path_observation"] == "PATH_EXPLICITLY_SKIPPED"


def test_a_file_above_the_size_limit_is_named_in_investigation_evidence_and_keeps_the_run_incomparable(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, "src/old.js")

    with _client(target) as client:
        baseline = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()
        # The file with the finding grows past the limit; its finding disappears.
        _write(target, "src/old.js", text=("// " + "x" * 97 + "\n") * 10_500 + VULNERABLE)
        current = client.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN).json()
        evaluation = _evaluate(client, baseline, current)

    assert baseline["scan"]["scan_status"] == "completed"
    assert current["scan"]["scan_status"] == "partial"
    assert _coverage_codes(current["scan"]) == {SIZE_LIMIT}
    assert evaluation["comparability"] == "INCOMPARABLE"
    assert evaluation["overall_assessment"] != "EXPLANATION_SUPPORTED"
    old = next(item for item in evaluation["findings"] if item["category"] == "baselineOnly")
    assert old["path_observation"] == "PATH_EXPLICITLY_SKIPPED"


def _cli(target: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ai_code_security_analyzer", "scan", "--path", str(target), "--rules", str(BASELINE), *arguments],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )


def test_cli_reports_excluded_paths_without_naming_them(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, *DEFAULT_IGNORED)

    as_json = _cli(target, "--format", "json")
    as_text = _cli(target)
    as_review = _cli(target, "--format", "review")
    as_markdown = _cli(target, "--format", "review-md")

    # A completed execution: exit code 0, as before.
    assert (as_json.returncode, as_text.returncode, as_review.returncode, as_markdown.returncode) == (0, 0, 0, 0)
    report = json.loads(as_json.stdout)
    assert report["schema_version"] == "1.1"
    assert (report["status"], report["completed"], report["issues"]) == ("completed", True, [])
    assert [item["file_path"] for item in report["findings"]] == ["src/app.js"]
    assert report["coverage"] == {
        "paths_skipped": True,
        "skipped_paths": {"evidence": "observed", "excluded_by_ignore_rules": 6, "excluded_by_size_limit": 0},
        "rules_skipped": False,
        "no_files_scanned": False,
    }
    assert "Coverage: 6 path(s) were excluded by ignore rules" in as_text.stdout
    assert "제외 규칙(Semgrep 기본 목록 또는 프로젝트 .semgrepignore)으로 경로 6개를 검사하지 않았습니다" in as_review.stdout
    assert "경로 6개를 검사하지 않았습니다" in as_markdown.stdout
    # Counts only: no excluded path, and no absolute path, in any format.
    for output in (as_json.stdout, as_text.stdout, as_review.stdout, as_markdown.stdout):
        assert not any(name in output for name in ("bundle.js", "lib.min.js", "app.test.js", "vendor/", str(tmp_path)))


def test_cli_says_when_nothing_beyond_the_adapter_exclusions_was_left_out(tmp_path: Path) -> None:
    _require_semgrep()
    target = _project(tmp_path, "node_modules/pkg/index.js")

    report = json.loads(_cli(target, "--format", "json").stdout)
    text = _cli(target).stdout

    assert report["coverage"]["paths_skipped"] is False
    assert report["coverage"]["skipped_paths"] == {"evidence": "observed", "excluded_by_ignore_rules": 0, "excluded_by_size_limit": 0}
    assert "Coverage: Semgrep reported no excluded paths beyond .git, node_modules and .venv." in text
