"""A8-R3: two scans of one profile must not look rule-equivalent when the rule file changed.

The API returns an opaque per-process token for the rule file content each scan
used. Equal tokens mean identical bytes; the digest itself is never returned
(ER-D6). Real Semgrep is used for the drift and fix scenarios.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import ai_code_security_analyzer.services.scan_service as scan_service_module
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.api.schemas import ScanResponse
from ai_code_security_analyzer.semgrep_adapter import ScanStatus
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-test-token-" + "x" * 40
HEADER = "x-rule-content-token"
EVAL_RULE = "  - id: baseline.javascript-dynamic-eval\n"
VULNERABLE = 'function run(req) {\n  return eval(req.query.code);\n}\n'


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _project(tmp_path: Path) -> tuple[Path, Path]:
    target, rules = tmp_path / "target", tmp_path / "rules"
    target.mkdir()
    rules.mkdir()
    shutil.copyfile(ROOT / "rules" / "security-baseline.yml", rules / "security-baseline.yml")
    (target / "app.js").write_text(VULNERABLE, encoding="utf-8")
    return target, rules


def _settings(target: Path, rules: Path) -> ApiSettings:
    return ApiSettings(target_directory=target, trusted_rules_directory=rules, api_token=TOKEN, allowed_hosts=("testserver",))


def _scan(client: TestClient) -> tuple[list[str], str | None, dict]:
    response = client.post(
        "/api/v1/scans",
        headers={"X-Local-API-Token": TOKEN},
        json={"target_id": "local-project", "rule_profile_id": "baseline"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_status"] == ScanStatus.COMPLETED.value
    return [item["finding_id"] for item in body["findings"]], response.headers.get(HEADER), body


def _rewrite_rule(rules: Path, extra: str) -> None:
    path = rules / "security-baseline.yml"
    text = path.read_text(encoding="utf-8")
    assert text.count(EVAL_RULE) == 1
    path.write_text(text.replace(EVAL_RULE, EVAL_RULE + extra), encoding="utf-8")


def test_same_rule_id_with_changed_rule_content_is_not_rule_equivalent(tmp_path: Path) -> None:
    _require_semgrep()
    target, rules = _project(tmp_path)
    original = (rules / "security-baseline.yml").read_bytes()
    with TestClient(create_app(_settings(target, rules))) as client:
        first_ids, first_token, first_body = _scan(client)
        assert len(first_ids) == 1 and first_token
        assert re.fullmatch(r"[A-Za-z0-9_-]{22}", first_token)
        # The token is not derived from the content: it reveals no digest.
        digest = hashlib.sha256(original).hexdigest()
        assert first_token not in digest and digest[:12] not in first_token
        assert digest not in str(first_body)

        repeat_ids, repeat_token, _ = _scan(client)
        assert (repeat_ids, repeat_token) == (first_ids, first_token)

        # Same rule ID, same profile, unchanged code: a rule-level path filter hides the finding.
        _rewrite_rule(rules, "    paths:\n      exclude:\n        - app.js\n")
        drift_ids, drift_token, drift_body = _scan(client)
        assert drift_ids == []
        assert drift_token and drift_token != first_token
        # Semgrep does not report rule-level path filters as skipped paths, so scope evidence alone
        # would not reveal why the finding disappeared; only the rule content token does.
        assert "paths_excluded_by_ignore_rules" not in drift_body["limitations"]

        # Restoring the bytes restores the token, within this server process.
        (rules / "security-baseline.yml").write_bytes(original)
        restored_ids, restored_token, _ = _scan(client)
        assert (restored_ids, restored_token) == (first_ids, first_token)

        # A genuine code fix with unchanged rules keeps the token: it is not reported as rule drift.
        (target / "app.js").write_text('function run(req) {\n  return JSON.parse(req.query.code);\n}\n', encoding="utf-8")
        fixed_ids, fixed_token, _ = _scan(client)
        assert fixed_ids == [] and fixed_token == first_token


def test_changed_detection_logic_and_added_rules_change_the_token(tmp_path: Path) -> None:
    _require_semgrep()
    target, rules = _project(tmp_path)
    with TestClient(create_app(_settings(target, rules))) as client:
        _, base_token, _ = _scan(client)
        # A comment-only edit keeps the findings but changes the bytes, so the token changes too:
        # the token tracks rule bytes, not detection semantics (a conservative false alarm).
        _rewrite_rule(rules, "    # reviewed\n")
        ids, comment_token, _ = _scan(client)
        assert len(ids) == 1 and comment_token != base_token
        path = rules / "security-baseline.yml"
        path.write_text(path.read_text(encoding="utf-8") + (
            "  - id: baseline.synthetic-added\n    languages: [javascript]\n    severity: INFO\n"
            "    message: added\n    pattern: JSON.parse($X)\n"
        ), encoding="utf-8")
        _, added_token, _ = _scan(client)
        assert added_token not in (base_token, comment_token)


class _Output:
    def __init__(self) -> None:
        from ai_code_security_analyzer.semgrep_adapter import ScanResult
        self.result = ScanResult(ScanStatus.COMPLETED, semgrep_version="1.182.1")
        self.taint_evidence = ()
        self.scope_evidence = None


class _Adapter:
    """Stand-in engine that can rewrite the rule file while it "runs"."""

    def __init__(self, rules: Path, during=None) -> None:
        self.rules, self.during = rules, during

    def _scan_with_evidence(self, target, rules_file, **_kwargs):
        if self.during:
            self.during(self.rules)
        return _Output()


def _service(tmp_path: Path, during=None) -> ScanService:
    target, rules = tmp_path / "t", tmp_path / "r"
    target.mkdir()
    rules.mkdir()
    (rules / "security-baseline.yml").write_text("rules: []\n", encoding="utf-8")
    return ScanService(_settings(target, rules), adapter_factory=lambda root: _Adapter(root, during))


def test_rule_file_changed_during_the_run_has_no_token(tmp_path: Path) -> None:
    def edit(rules: Path) -> None:
        (rules / "security-baseline.yml").write_text("rules: [] # edited\n", encoding="utf-8")
    response, token = _service(tmp_path, edit).scan_with_rule_content_token("local-project", "baseline")
    assert isinstance(response, ScanResponse) and token is None


def test_unreadable_rule_file_has_no_token(tmp_path: Path) -> None:
    def remove(rules: Path) -> None:
        (rules / "security-baseline.yml").unlink()
    _response, token = _service(tmp_path, remove).scan_with_rule_content_token("local-project", "baseline")
    assert token is None


def test_token_table_is_bounded_and_never_evicts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_service_module, "MAX_RULE_CONTENT_TOKENS", 2)
    service = _service(tmp_path)
    rule = service.settings.trusted_rules_directory / "security-baseline.yml"
    tokens = []
    for index in range(3):
        rule.write_text(f"rules: [] # {index}\n", encoding="utf-8")
        tokens.append(service.scan_with_rule_content_token("local-project", "baseline")[1])
    assert tokens[0] and tokens[1] and tokens[0] != tokens[1] and tokens[2] is None
    rule.write_text("rules: [] # 0\n", encoding="utf-8")
    assert service.scan_with_rule_content_token("local-project", "baseline")[1] == tokens[0]


def test_route_without_token_support_sends_no_header_and_header_is_exposed_to_the_dashboard(tmp_path: Path) -> None:
    class PlainService:
        def scan(self, target_id, rule_profile_id):
            return ScanResponse(
                scan_status=ScanStatus.COMPLETED, completed=True, semgrep_version="1.182.1", finding_count=0,
                displayed_finding_count=0, omitted_finding_count=0, severity_counts={}, issues=(), findings=(), limitations=(),
            )
    target, rules = tmp_path / "t", tmp_path / "r"
    target.mkdir()
    rules.mkdir()
    origin = "http://127.0.0.1:5173"
    settings = ApiSettings(target, rules, TOKEN, allowed_hosts=("testserver",), allowed_origins=(origin,))
    with TestClient(create_app(settings, scan_service=PlainService())) as client:
        response = client.post("/api/v1/scans", headers={"X-Local-API-Token": TOKEN, "Origin": origin},
                               json={"target_id": "local-project", "rule_profile_id": "baseline"})
    assert response.status_code == 200
    assert HEADER not in response.headers
    assert "x-rule-content-token" in response.headers.get("access-control-expose-headers", "").lower()
