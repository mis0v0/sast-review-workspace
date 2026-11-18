"""Every response names the server process that produced it, and nothing about the project.

The identifier lets a client refuse to combine results from two different
server runs. It is random per process and is not project identity.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.api.security import (
    SERVER_INSTANCE_HEADER,
    SecurityHeadersMiddleware,
    new_server_instance_id,
)
from ai_code_security_analyzer.services.scan_service import ApiSettings


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
TOKEN = "synthetic-test-token-" + "x" * 40
HEADERS = {"X-Local-API-Token": TOKEN}
SCAN = {"target_id": "local-project", "rule_profile_id": "baseline"}
ALLOWED_ORIGIN = "http://127.0.0.1:5173"
WELL_FORMED = re.compile(r"\A[A-Za-z0-9_-]{22}\Z")
VULNERABLE = 'const input = "2 + 2";\neval(input);\n'


def _app(target: Path, *, origins: tuple[str, ...] = (), static: Path | None = None, investigation: bool = True):
    settings = ApiSettings(target, RULES, TOKEN, allowed_origins=origins, allowed_hosts=("testserver",))
    return create_app(settings, static_directory=static, investigation_api_enabled=investigation)


def _target(tmp_path: Path, name: str = "project") -> Path:
    target = tmp_path / name
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.js").write_text(VULNERABLE, encoding="utf-8")
    return target


def test_every_kind_of_response_carries_the_same_well_formed_instance_id(tmp_path: Path) -> None:
    static = tmp_path / "ui"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>ui</title>", encoding="utf-8")
    app = _app(_target(tmp_path), origins=(ALLOWED_ORIGIN,), static=static)
    json_headers = {**HEADERS, "Content-Type": "application/json"}

    with TestClient(app) as client:
        responses = {
            "health": client.get("/api/v1/health"),
            "options": client.get("/api/v1/options"),
            "static page": client.get("/"),
            "unknown api route": client.get("/api/v1/nope"),
            "scan without token": client.post("/api/v1/scans", json=SCAN),
            "scan with wrong token": client.post("/api/v1/scans", headers={"X-Local-API-Token": "w" * 43}, json=SCAN),
            "unknown target": client.post("/api/v1/scans", headers=HEADERS, json={**SCAN, "target_id": "other"}),
            "malformed body": client.post("/api/v1/scans", headers=json_headers, content=b"{"),
            "host not allowed": client.get("/api/v1/health", headers={"Host": "attacker.example"}),
            "origin not allowed": client.get("/api/v1/options", headers={"Origin": "http://evil.example"}),
            "v2 without token": client.post("/api/v2/investigation-scans", json=SCAN),
            "v2 unknown handle": client.post(
                "/api/v2/investigations/evaluate", headers=HEADERS, json={"investigation_handle": "h" * 43},
            ),
            "v2 preflight": client.options("/api/v2/investigation-scans", headers={
                "Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-local-api-token",
            }),
        }

    assert {name: response.status_code for name, response in responses.items()} == {
        "health": 200, "options": 200, "static page": 200, "unknown api route": 404, "scan without token": 401,
        "scan with wrong token": 401, "unknown target": 404, "malformed body": 400, "host not allowed": 400,
        "origin not allowed": 403, "v2 without token": 401, "v2 unknown handle": 404, "v2 preflight": 200,
    }
    values = {name: response.headers.get_list(SERVER_INSTANCE_HEADER) for name, response in responses.items()}
    instance = app.state.server_instance_id
    assert WELL_FORMED.fullmatch(instance)
    assert values == {name: [instance] for name in responses}


def test_each_app_instance_gets_its_own_identifier_even_for_the_same_folder(tmp_path: Path) -> None:
    target = _target(tmp_path)
    seen = set()
    for _ in range(5):
        with TestClient(_app(target)) as client:
            first = client.get("/api/v1/options").headers[SERVER_INSTANCE_HEADER]
            assert client.get("/api/v1/health").headers[SERVER_INSTANCE_HEADER] == first
            seen.add(first)
    assert len(seen) == 5
    assert len({new_server_instance_id() for _ in range(100)}) == 100


def test_identifier_reveals_nothing_about_the_project_and_bodies_are_unchanged(tmp_path: Path) -> None:
    target = _target(tmp_path, "customer-secret-project")
    app = _app(target)
    with TestClient(app) as client:
        health, options = client.get("/api/v1/health"), client.get("/api/v1/options")
    info = target.stat()

    instance = health.headers[SERVER_INSTANCE_HEADER]
    for private in ("customer-secret-project", str(tmp_path), str(info.st_ino), str(info.st_dev), TOKEN, str(os.getpid())):
        assert private not in instance
        assert private not in health.text + options.text
    # The public JSON contracts carry no instance or project field.
    assert health.json() == {"status": "ok", "service": "ai-code-security-analyzer"}
    assert sorted(options.json()) == ["rule_profiles", "targets"]
    assert options.json()["targets"] == [{"id": "local-project", "label": "Local Project"}]


def test_cross_origin_pages_can_read_the_identifier_only_from_allowed_origins(tmp_path: Path) -> None:
    app = _app(_target(tmp_path), origins=(ALLOWED_ORIGIN,))
    cross = {"Origin": ALLOWED_ORIGIN}
    with TestClient(app) as client:
        allowed = client.get("/api/v1/options", headers=cross)
        handler_error = client.post("/api/v1/scans", headers={**cross, **HEADERS}, json={**SCAN, "target_id": "other"})
        boundary_denial = client.post("/api/v1/scans", headers=cross, json=SCAN)
        same_origin = client.get("/api/v1/options")
        refused = client.get("/api/v1/options", headers={"Origin": "http://evil.example"})

    # Successful responses and handler errors are readable, with the header exposed.
    assert (allowed.status_code, handler_error.status_code) == (200, 404)
    for response in (allowed, handler_error):
        assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
        assert response.headers["access-control-expose-headers"] == f"{SERVER_INSTANCE_HEADER}, X-Rule-Content-Token"
    # Unchanged boundary: its denials carry no CORS grant, so a cross-origin page
    # cannot read them at all. The header is still there for same-origin clients.
    assert boundary_denial.status_code == 401
    assert "access-control-allow-origin" not in boundary_denial.headers
    assert boundary_denial.headers[SERVER_INSTANCE_HEADER] == allowed.headers[SERVER_INSTANCE_HEADER]
    assert "access-control-expose-headers" not in same_origin.headers
    assert refused.status_code == 403
    assert "access-control-allow-origin" not in refused.headers
    assert "access-control-expose-headers" not in refused.headers


def test_inner_layers_cannot_forge_or_drop_the_identifier() -> None:
    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [
            (b"x-server-instance", b"forged-forged-forged-1"), (b"X-Server-Instance", b"forged-forged-forged-2"),
            (b"content-type", b"text/plain"),
        ]})
        await send({"type": "http.response.body", "body": b"ok"})

    sent: list[dict] = []

    async def run() -> None:
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await SecurityHeadersMiddleware(inner, server_instance_id="R" * 22)({"type": "http"}, receive, send)

    asyncio.run(run())
    values = [value for key, value in sent[0]["headers"] if key.lower() == b"x-server-instance"]
    assert values == [b"R" * 22]


@pytest.mark.parametrize("bad", ["", "short", "a" * 65, "has space " * 3, "né" * 11, None, 12345678901234567890])
def test_middleware_refuses_a_malformed_identifier(bad: object) -> None:
    with pytest.raises(ValueError, match="server_instance_id_invalid"):
        SecurityHeadersMiddleware(lambda *_: None, server_instance_id=bad)  # type: ignore[arg-type]


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")
    version = subprocess.run(["semgrep", "--version"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    if version != "1.182.1":
        pytest.skip(f"requires Semgrep 1.182.1, found {version}")


def test_two_projects_with_identical_scan_bodies_are_told_apart_only_by_the_instance(tmp_path: Path) -> None:
    """The reproduced defect: nothing in the body distinguishes two different projects."""
    _require_semgrep()
    first = _target(tmp_path, "project-one")
    second = _target(tmp_path, "project-two")
    # A different project whose finding sits at the same rule, path and position.
    (second / "src" / "app.js").write_text(VULNERABLE + "\n// unrelated billing service\n", encoding="utf-8")
    (second / "billing.js").write_text("export function invoice() { return 42; }\n", encoding="utf-8")
    app_one, app_two = _app(first), _app(second)

    with TestClient(app_one) as one, TestClient(app_two) as two:
        scan_one, scan_two = (client.post("/api/v1/scans", headers=HEADERS, json=SCAN) for client in (one, two))
        again = one.post("/api/v1/scans", headers=HEADERS, json=SCAN)
        investigated_one = one.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
        investigated_two = two.post("/api/v2/investigation-scans", headers=HEADERS, json=SCAN)
        cross = two.post("/api/v2/investigations", headers=HEADERS, json={
            "baseline_handle": investigated_one.json()["run_handle"],
            "current_handle": investigated_two.json()["run_handle"],
        })

    assert scan_one.status_code == scan_two.status_code == 200
    assert scan_one.json()["finding_count"] == 1
    assert json.dumps(scan_one.json(), sort_keys=True) == json.dumps(scan_two.json(), sort_keys=True)
    instance_one, instance_two = scan_one.headers[SERVER_INSTANCE_HEADER], scan_two.headers[SERVER_INSTANCE_HEADER]
    assert instance_one != instance_two
    # Rescans and investigation scans of one server keep its identifier.
    assert again.headers[SERVER_INSTANCE_HEADER] == investigated_one.headers[SERVER_INSTANCE_HEADER] == instance_one
    assert investigated_two.headers[SERVER_INSTANCE_HEADER] == instance_two
    # Evidence held by one server run cannot be used on another.
    assert cross.status_code == 404
    assert cross.json() == {"error": "evidence_unavailable"}
    assert cross.headers[SERVER_INSTANCE_HEADER] == instance_two
