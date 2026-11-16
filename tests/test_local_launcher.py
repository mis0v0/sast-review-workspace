"""The one-project launcher: ``python -m ai_code_security_analyzer.api PROJECT_DIR``.

Launch tests run the real launcher as a subprocess from a copy of the source
tree, so a missing or present dashboard build can be arranged without touching
the repository.  A stand-in ``semgrep`` lets them run where Semgrep is not
installed; scan journeys use the real Semgrep CLI.
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ai_code_security_analyzer.api import __main__ as launcher


REPOSITORY = Path(__file__).resolve().parents[1]
TOKEN = "L" * 43
REQUIRED_HELP = "--json --metrics --disable-version-check --oss-only --no-autofix --no-git-ignore --exclude --verbose"
# Synthetic source for Semgrep to flag; it is never executed.
EVAL_SOURCE = "function run(input) {\n  return eval(input);\n}\nmodule.exports = run;\n"


def _require_semgrep() -> None:
    if shutil.which("semgrep") is None:
        if os.environ.get("SEMGREP_REQUIRED") == "1":
            pytest.fail("Semgrep required by this job but not installed")
        pytest.skip("Semgrep CLI is not installed")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _tree(tmp_path: Path, *, dashboard: bool = True) -> Path:
    """A copy of the source and rules, laid out like the repository."""
    root = tmp_path / "app"
    shutil.copytree(REPOSITORY / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(REPOSITORY / "rules", root / "rules")
    if dashboard:
        (root / "frontend" / "dist").mkdir(parents=True)
        (root / "frontend" / "dist" / "index.html").write_text("<!doctype html><title>dashboard</title>", encoding="utf-8")
    return root


def _fake_semgrep(directory: Path, *, version: str = "1.182.1", help_text: str = REQUIRED_HELP, broken: bool = False,
                  hang: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "semgrep"
    body = "exit 1" if broken else "exec sleep 60" if hang else (
        f'if [ "$1" = "--version" ]; then echo {version}; exit 0; fi\necho "{help_text}"'
    )
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return directory


def _env(root: Path, *, path: str | None = None, token: str | None = TOKEN, **extra: str) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("AI_CODE_SECURITY_")}
    env["PYTHONPATH"] = str(root / "src")
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    if path is not None:
        env["PATH"] = path
    if token is not None:
        env["AI_CODE_SECURITY_API_TOKEN"] = token
    env.update(extra)
    return env


def _command(project: Path | str, port: int) -> list[str]:
    return [sys.executable, "-m", "ai_code_security_analyzer.api", str(project), "--port", str(port)]


def _fails(root: Path, project: Path | str, env: dict[str, str], port: int | None = None) -> str:
    """Run a launch that must be refused; return its error output."""
    result = subprocess.run(
        _command(project, port or _free_port()), cwd=root, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    assert TOKEN not in result.stderr
    return result.stderr


def _request(port: int, path: str, *, method: str = "GET", token: str | None = None, origin: str | None = None,
             body: dict | None = None, timeout: float = 120) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    if token is not None:
        request.add_header("X-Local-API-Token", token)
    if origin is not None:
        request.add_header("Origin", origin)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def _default_interrupt_handling() -> None:
    # A job started from a terminal receives Ctrl+C with the default disposition. The test
    # runner may itself have been started with SIGINT ignored, which a child would inherit.
    signal.signal(signal.SIGINT, signal.SIG_DFL)


class Launch:
    """A launcher subprocess; stopped by the test fixture."""

    def __init__(self, root: Path, project: Path | None, port: int, env: dict[str, str], *, terminal: bool = False) -> None:
        self.port = port
        self.output = b""
        self._master: int | None = None
        # Without a project the launcher is configured by environment variables only.
        command = _command(project, port) if project is not None else [
            sys.executable, "-m", "ai_code_security_analyzer.api", "--port", str(port),
        ]
        if terminal:
            self._master, slave = pty.openpty()
            self.process = subprocess.Popen(
                command, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=slave,
                stderr=subprocess.PIPE, start_new_session=True, preexec_fn=_default_interrupt_handling,
            )
            os.close(slave)
        else:
            self.process = subprocess.Popen(
                command, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, preexec_fn=_default_interrupt_handling,
            )

    def interrupt(self) -> int:
        """Deliver what Ctrl+C delivers: SIGINT to the launcher's foreground process group."""
        os.killpg(self.process.pid, signal.SIGINT)
        return self.process.wait(timeout=30)

    def read_terminal_until(self, marker: bytes, timeout: float = 60) -> str:
        assert self._master is not None
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            assert time.monotonic() < deadline, self.output
            ready, _, _ = select.select([self._master], [], [], 0.5)
            if ready:
                try:
                    self.output += os.read(self._master, 4096)
                except OSError:
                    break
        return self.output.decode("utf-8", errors="replace")

    def wait_ready(self, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert self.process.poll() is None, self.process.stderr.read().decode() if self.process.stderr else ""
            try:
                status, _, body = _request(self.port, "/api/v1/health", timeout=1)
                if status == 200 and json.loads(body)["status"] == "ok":
                    return
            except OSError:
                pass
            time.sleep(0.2)
        raise AssertionError("launcher did not become ready")

    def stop(self) -> tuple[str, str]:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        stdout = self.process.stdout.read().decode() if self.process.stdout else self.output.decode(errors="replace")
        stderr = self.process.stderr.read().decode() if self.process.stderr else ""
        if self._master is not None:
            os.close(self._master)
            self._master = None
        return stdout, stderr


@pytest.fixture
def launches():
    started: list[Launch] = []
    yield started
    for launch in started:
        launch.stop()


def _node_project(directory: Path) -> Path:
    (directory / "src").mkdir(parents=True)
    (directory / "package.json").write_text('{"name": "web-app", "version": "1.0.0", "main": "src/index.js"}\n')
    (directory / "src" / "index.js").write_text(EVAL_SOURCE)
    (directory / "node_modules" / "left-pad").mkdir(parents=True)
    (directory / "node_modules" / "left-pad" / "index.js").write_text(EVAL_SOURCE)
    return directory


def _python_project(directory: Path) -> Path:
    # Ordinary project files written for Semgrep to read; never imported or run.
    (directory / "service").mkdir(parents=True)
    (directory / "pyproject.toml").write_text('[project]\nname = "service"\nversion = "0.1.0"\n')
    (directory / "service" / "__init__.py").write_text("")
    (directory / "service" / "app.py").write_text(
        "import subprocess\n\n\ndef run(command):\n    return subprocess.run(command, shell=True)\n"
    )
    return directory


def _scan(port: int, token: str = TOKEN) -> tuple[int, dict[str, str], dict]:
    status, headers, body = _request(
        port, "/api/v1/scans", method="POST", token=token, origin=f"http://127.0.0.1:{port}",
        body={"target_id": "local-project", "rule_profile_id": "baseline"},
    )
    return status, headers, json.loads(body)


# --- server configuration -------------------------------------------------------------------------


def _in_process_launch(monkeypatch, dist: Path, run, probe=lambda: (None, "1.182.1")) -> int:
    """Arrange ``launcher.main`` to run in this process with a stand-in for the server loop."""
    monkeypatch.setattr(launcher, "DASHBOARD_DIRECTORY", dist)
    monkeypatch.setattr(launcher, "probe_semgrep", probe)
    monkeypatch.setattr(launcher.uvicorn.Server, "run", run)
    monkeypatch.setattr(launcher.sys.stdout, "isatty", lambda: True, raising=False)
    for name in ("AI_CODE_SECURITY_TARGET", "AI_CODE_SECURITY_TARGETS", "AI_CODE_SECURITY_API_TOKEN",
                 "AI_CODE_SECURITY_ALLOWED_ORIGINS", "AI_CODE_SECURITY_RULES_DIR"):
        monkeypatch.delenv(name, raising=False)
    return _free_port()


def test_project_mode_serves_one_loopback_worker_with_only_the_dashboard_origin(monkeypatch, tmp_path) -> None:
    project = _node_project(tmp_path / "project")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html>")
    captured: dict = {}

    def run(server, sockets=None):
        captured.update(config=server.config, sockets=[sock.getsockname() for sock in sockets])
        server.started = True   # a server that started and was then stopped

    port = _in_process_launch(monkeypatch, dist, run)
    launcher.main([str(project), "--port", str(port)])

    config = captured["config"]
    assert config.workers == 1 and config.reload is False and config.host == "127.0.0.1"
    assert captured["sockets"] == [("127.0.0.1", port)]
    app = config.app
    assert app.state.investigation_api_enabled is True
    settings = app.state.api_settings
    assert settings.allowed_origins == (f"http://127.0.0.1:{port}",)
    assert [target.directory for target in settings.registered_targets] == [project.resolve()]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", settings.api_token)


def test_without_a_project_the_environment_configuration_is_unchanged(monkeypatch) -> None:
    for name in ("AI_CODE_SECURITY_TARGET", "AI_CODE_SECURITY_TARGETS", "AI_CODE_SECURITY_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SystemExit) as stopped:
        launcher.main([])
    assert str(stopped.value).startswith("local_api_configuration_required\n")
    assert "PROJECT_DIR" in str(stopped.value)


# --- refused launches -----------------------------------------------------------------------------


def test_invalid_project_paths_are_refused_with_a_fix(tmp_path) -> None:
    root = _tree(tmp_path)
    env = _env(root, path=str(_fake_semgrep(tmp_path / "bin")))
    project = _node_project(tmp_path / "project")
    (tmp_path / "links").mkdir()
    (tmp_path / "links" / "project-link").symlink_to(project, target_is_directory=True)
    (tmp_path / "parent-link").symlink_to(tmp_path / "links", target_is_directory=True)

    assert "error: project_directory_invalid" in _fails(root, tmp_path / "missing", env)
    assert "error: project_directory_invalid" in _fails(root, project / "src" / "index.js", env)
    assert "error: project_directory_invalid" in _fails(root, "", env)
    for linked in (tmp_path / "links" / "project-link", tmp_path / "parent-link" / "project-link" / "src"):
        message = _fails(root, linked, env)
        assert "error: project_path_has_symlink" in message and "pwd -P" in message
    assert "error: project_overlaps_rules" in _fails(root, root / "rules", env)
    assert "error: project_overlaps_rules" in _fails(root, root, env)


def test_configuration_conflicts_are_refused(tmp_path) -> None:
    root = _tree(tmp_path)
    project = _node_project(tmp_path / "project")
    bin_path = str(_fake_semgrep(tmp_path / "bin"))
    assert "error: target_configured_twice" in _fails(
        root, project, _env(root, path=bin_path, AI_CODE_SECURITY_TARGET=str(project)),
    )
    assert "error: api_token_invalid" in _fails(root, project, _env(root, path=bin_path, token="too-short"))
    assert "error: allowed_origins_invalid" in _fails(
        root, project, _env(root, path=bin_path, AI_CODE_SECURITY_ALLOWED_ORIGINS="https://example.com"),
    )


def test_missing_dashboard_build_is_refused(tmp_path) -> None:
    root = _tree(tmp_path, dashboard=False)
    message = _fails(root, _node_project(tmp_path / "project"), _env(root, path=str(_fake_semgrep(tmp_path / "bin"))))
    assert "error: dashboard_build_missing" in message and "npm run build" in message


def test_missing_or_unsupported_semgrep_is_refused(tmp_path) -> None:
    root = _tree(tmp_path)
    project = _node_project(tmp_path / "project")
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    cases = {
        "semgrep_not_installed": str(empty),
        "version_check_failed": str(_fake_semgrep(tmp_path / "broken", broken=True)),
        "semgrep_unsupported": str(_fake_semgrep(tmp_path / "old", version="0.90.0", help_text="--json --metrics")),
    }
    for code, path in cases.items():
        message = _fails(root, project, _env(root, path=path))
        assert f"error: {code}" in message and "semgrep==1.182.1" in message
    hanging = str(_fake_semgrep(tmp_path / "hang", hang=True))
    message = _fails(root, project, _env(root, path=f"{hanging}:/bin:/usr/bin"))
    assert "error: version_check_timed_out" in message and "semgrep --version" in message


def test_an_occupied_port_is_refused(tmp_path) -> None:
    root = _tree(tmp_path)
    env = _env(root, path=str(_fake_semgrep(tmp_path / "bin")))
    project = _node_project(tmp_path / "project")
    for address in ("127.0.0.1", "0.0.0.0"):
        with socket.socket() as holder:
            holder.bind((address, 0))
            holder.listen()
            port = holder.getsockname()[1]
            message = _fails(root, project, env, port)
        assert "error: port_in_use" in message and f"-iTCP:{port}" in message and "--port" in message


def test_a_generated_token_is_never_written_where_it_is_not_seen(tmp_path) -> None:
    root = _tree(tmp_path)
    project = _node_project(tmp_path / "project")
    message = _fails(root, project, _env(root, path=str(_fake_semgrep(tmp_path / "bin")), token=None))
    assert "error: token_display_unavailable" in message


# --- running launches -----------------------------------------------------------------------------


def test_terminal_launch_shows_a_working_token_kept_out_of_arguments_and_environment(tmp_path, launches) -> None:
    root = _tree(tmp_path)
    project = _node_project(tmp_path / "project")
    port = _free_port()
    launch = Launch(root, project, port, _env(root, path=str(_fake_semgrep(tmp_path / "bin")), token=None), terminal=True)
    launches.append(launch)
    shown = launch.read_terminal_until(b"Press Ctrl+C")
    token = re.search(r"API token  ([A-Za-z0-9_-]{43})\r?\n", shown).group(1)
    assert f"Dashboard  http://127.0.0.1:{port}/" in shown
    launch.wait_ready()

    # The token printed on the terminal is the one the server accepts, and only it.
    assert _request(port, "/api/v1/scans", method="POST", body={"target_id": "x", "rule_profile_id": "baseline"})[0] == 401
    status, _, _ = _request(port, "/api/v1/scans", method="POST", token=token,
                            body={"target_id": "unknown", "rule_profile_id": "baseline"})
    assert status == 404
    # The dashboard is served from the same origin as the API.
    status, headers, body = _request(port, "/")
    assert status == 200 and headers["content-type"].startswith("text/html") and b"dashboard" in body

    process_view = subprocess.run(
        ["ps", "eww", "-o", "command=", "-p", str(launch.process.pid)], capture_output=True, text=True, check=True,
    ).stdout
    assert process_view and token not in process_view
    _, stderr = launch.stop()
    assert token not in stderr


def test_untested_semgrep_version_starts_with_a_warning(tmp_path, launches) -> None:
    root = _tree(tmp_path)
    port = _free_port()
    launch = Launch(root, _node_project(tmp_path / "project"), port,
                    _env(root, path=str(_fake_semgrep(tmp_path / "bin", version="1.150.0"))))
    launches.append(launch)
    launch.wait_ready()
    stdout, _ = launch.stop()
    assert "Warning: Semgrep 1.150.0 is installed; this tool is tested with 1.182.1." in stdout
    assert "(not shown)" in stdout and TOKEN not in stdout


# --- stopping -------------------------------------------------------------------------------------


def _port_is_free(port: int) -> bool:
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


@pytest.mark.parametrize("terminal", [False, True], ids=["token_from_environment", "generated_token_on_a_terminal"])
def test_ctrl_c_stops_the_launcher_without_a_traceback_and_releases_the_port(terminal: bool, tmp_path, launches) -> None:
    root = _tree(tmp_path)
    port = _free_port()
    env = _env(root, path=str(_fake_semgrep(tmp_path / "bin")), token=None if terminal else TOKEN)
    launch = Launch(root, _node_project(tmp_path / "project"), port, env, terminal=terminal)
    launches.append(launch)
    if terminal:
        launch.read_terminal_until(b"Press Ctrl+C")
    launch.wait_ready()

    if terminal:
        # Read the terminal while the launcher stops: output still buffered in a
        # pseudo-terminal can be discarded once its last writer has exited.
        os.killpg(launch.process.pid, signal.SIGINT)
        launch.read_terminal_until(b"Stopped.", timeout=20)
        exit_code = launch.process.wait(timeout=30)
    else:
        exit_code = launch.interrupt()
    stdout, stderr = launch.stop()

    assert exit_code == 0
    assert stderr == ""
    assert "Traceback" not in stdout and "KeyboardInterrupt" not in stdout
    assert stdout.rstrip().endswith("Stopped.")
    assert _port_is_free(port)


def test_ctrl_c_during_the_semgrep_check_exits_without_a_traceback_and_leaves_no_process(tmp_path, launches) -> None:
    root = _tree(tmp_path)
    port = _free_port()
    started = tmp_path / "semgrep-started"
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    # A Semgrep that never answers: records its process ID, then waits.
    (bin_directory / "semgrep").write_text(f'#!/bin/sh\necho $$ > "{started}"\nexec sleep 60\n', encoding="utf-8")
    (bin_directory / "semgrep").chmod(0o755)
    launch = Launch(root, _node_project(tmp_path / "project"), port, _env(root, path=f"{bin_directory}:/bin:/usr/bin"))
    launches.append(launch)
    deadline = time.monotonic() + 30
    while not (started.is_file() and started.read_text().strip()):
        assert time.monotonic() < deadline and launch.process.poll() is None
        time.sleep(0.1)

    exit_code = launch.interrupt()
    stdout, stderr = launch.stop()

    assert exit_code == 130
    assert stdout == ""
    assert "Traceback" not in stderr and "KeyboardInterrupt" not in stderr
    assert _port_is_free(port)
    with pytest.raises(ProcessLookupError):
        for _ in range(50):   # the waiting Semgrep process is stopped with the launcher
            os.kill(int(started.read_text()), 0)
            time.sleep(0.1)


def test_environment_variable_startup_still_serves_and_stops_cleanly(tmp_path, launches) -> None:
    root = _tree(tmp_path)
    project = _node_project(tmp_path / "project")
    port = _free_port()
    env = _env(
        root, path=str(_fake_semgrep(tmp_path / "bin")), AI_CODE_SECURITY_TARGET=str(project),
        AI_CODE_SECURITY_ALLOWED_ORIGINS=f"http://127.0.0.1:{port}",
    )
    launch = Launch(root, None, port, env)
    launches.append(launch)
    launch.wait_ready()

    status, _, body = _request(port, "/api/v1/options")
    assert status == 200 and json.loads(body)["targets"] == [{"id": "local-project", "label": "Local Project"}]
    assert _request(port, "/api/v1/scans", method="POST", body={"target_id": "x", "rule_profile_id": "baseline"})[0] == 401

    exit_code = launch.interrupt()
    stdout, stderr = launch.stop()

    assert exit_code == 0
    assert "Traceback" not in stdout + stderr and "KeyboardInterrupt" not in stdout + stderr
    assert _port_is_free(port)


def test_only_ctrl_c_counts_as_a_normal_stop(monkeypatch, tmp_path, capsys) -> None:
    project = _node_project(tmp_path / "project")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html>")

    def interrupted(server, sockets=None):
        server.started = True
        raise KeyboardInterrupt

    port = _in_process_launch(monkeypatch, dist, interrupted)
    launcher.main([str(project), "--port", str(port)])
    assert capsys.readouterr().out.rstrip().endswith("Stopped.")
    assert _port_is_free(port)

    # Any other failure of the running server is raised, not reported as a stop.
    def crashed(server, sockets=None):
        server.started = True
        raise RuntimeError("synthetic server failure")

    port = _in_process_launch(monkeypatch, dist, crashed)
    with pytest.raises(RuntimeError, match="synthetic server failure"):
        launcher.main([str(project), "--port", str(port)])
    assert "Stopped." not in capsys.readouterr().out
    assert _port_is_free(port)

    # A server that returns without ever starting is an error with its own exit code.
    port = _in_process_launch(monkeypatch, dist, lambda server, sockets=None: None)
    with pytest.raises(SystemExit) as refused:
        launcher.main([str(project), "--port", str(port)])
    captured = capsys.readouterr()
    assert refused.value.code == 2
    assert "error: server_start_failed" in captured.err and "Stopped." not in captured.out

    # Ctrl+C before the server runs (during the Semgrep check) ends quietly as an interrupt.
    def interrupted_check():
        raise KeyboardInterrupt

    port = _in_process_launch(monkeypatch, dist, crashed, probe=interrupted_check)
    with pytest.raises(SystemExit) as stopped:
        launcher.main([str(project), "--port", str(port)])
    assert stopped.value.code == 130
    assert capsys.readouterr().out == ""


def test_boundaries_hold_for_a_launched_project(tmp_path, launches) -> None:
    root = _tree(tmp_path)
    port = _free_port()
    launch = Launch(root, _node_project(tmp_path / "project"), port, _env(root, path=str(_fake_semgrep(tmp_path / "bin"))))
    launches.append(launch)
    launch.wait_ready()
    own_origin = f"http://127.0.0.1:{port}"
    body = {"target_id": "local-project", "rule_profile_id": "baseline"}

    assert _request(port, "/api/v1/scans", method="POST", origin=own_origin, body=body)[0] == 401
    assert _request(port, "/api/v1/scans", method="POST", token="w" * 43, origin=own_origin, body=body)[0] == 401
    assert _request(port, "/api/v1/options", origin="http://127.0.0.1:5173")[0] == 403
    assert _request(port, "/api/v1/options", origin="http://evil.example")[0] == 403
    status, headers, options = _request(port, "/api/v1/options", origin=own_origin)
    assert status == 200 and headers["access-control-allow-origin"] == own_origin
    # The browser sees a fixed label, never the project path.
    assert str(tmp_path) not in options.decode()
    assert json.loads(options)["targets"] == [{"id": "local-project", "label": "Local Project"}]


# --- real scans -----------------------------------------------------------------------------------


def test_node_and_python_projects_scan_end_to_end(tmp_path, launches) -> None:
    _require_semgrep()
    root = _tree(tmp_path)
    env = _env(root)
    node = _node_project(tmp_path / "projects" / "web app — 테스트")
    # A4: repository-controlled Git configuration must not run during the scan.
    canary = tmp_path / "fsmonitor-ran"
    hook = tmp_path / "fsmonitor.sh"
    hook.write_text(f"#!/bin/sh\ntouch '{canary}'\n")
    hook.chmod(0o755)
    if shutil.which("git"):
        subprocess.run(["git", "init", "-q", str(node)], check=True)
        subprocess.run(["git", "-C", str(node), "config", "core.fsmonitor", str(hook)], check=True)
    # A5: a link inside the project to source outside it is not followed.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.js").write_text(EVAL_SOURCE)
    (node / "src" / "linked.js").symlink_to(outside / "secret.js")

    port = _free_port()
    first = Launch(root, node, port, env)
    launches.append(first)
    first.wait_ready()
    status, headers, scan = _scan(port)
    assert status == 200, scan
    assert scan["scan_status"] in {"completed", "partial"}
    paths = {finding["file_path"] for finding in scan["findings"]}
    assert paths == {"src/index.js"}, paths  # not node_modules, not the followed link
    assert scan["findings"][0]["rule_id"] == "baseline.javascript-dynamic-eval"
    assert str(tmp_path) not in json.dumps(scan)
    assert not canary.exists()
    first_instance = headers["x-server-instance"]
    stdout, _ = first.stop()
    assert "web app — 테스트" in stdout

    # Restart on the same port with a Python project: a different server run.
    python = _python_project(tmp_path / "projects" / "py service ünï")
    second = Launch(root, python, port, env)
    launches.append(second)
    second.wait_ready()
    status, headers, scan = _scan(port)
    assert status == 200, scan
    assert headers["x-server-instance"] != first_instance
    # The bundled rules cover JavaScript/TypeScript and Firestore rules only. Semgrep scans
    # no file of a Python-only project, and the result says so instead of looking clean.
    assert scan["scan_status"] == "partial" and scan["completed"] is False, scan
    assert scan["finding_count"] == 0 and scan["issues"] == ["evidence_unavailable"]
    assert "scan_partial" in scan["limitations"]
