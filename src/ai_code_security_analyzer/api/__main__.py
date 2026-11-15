"""Run the local API and dashboard on loopback only.

``python -m ai_code_security_analyzer.api PROJECT_DIR`` registers one local
source directory, generates an API token for this run, allows only the
dashboard's own origin and serves the built dashboard.  Setup problems are
reported, with a fix, before the server starts.

Without ``PROJECT_DIR`` the server is configured only by the
``AI_CODE_SECURITY_*`` environment variables, exactly as before.
"""

from __future__ import annotations

import argparse
import errno
import os
import secrets
import socket
import sys
import unicodedata
from pathlib import Path

import uvicorn

from ai_code_security_analyzer.api.app import (
    DASHBOARD_DIRECTORY,
    DEFAULT_RULES_DIRECTORY,
    create_app,
    create_app_from_env,
)
from ai_code_security_analyzer.semgrep_adapter import probe_semgrep
from ai_code_security_analyzer.services.scan_service import ApiSettings, _strict_directory


DEFAULT_PORT = 8765
TESTED_SEMGREP_VERSION = "1.182.1"
_HOST = "127.0.0.1"
_TARGET_VARIABLES = ("AI_CODE_SECURITY_TARGET", "AI_CODE_SECURITY_TARGETS")
_SEMGREP_INSTALL = f"uv tool install --python 3.12 'semgrep=={TESTED_SEMGREP_VERSION}'"
_TOKEN_RULE = "43-256 characters of A-Z, a-z, 0-9, _ and -"


class LaunchError(Exception):
    """A setup problem found before the server starts, with the fix to show the user."""

    def __init__(self, code: str, message: str, fix: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.fix = fix


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number from 1 to 65535") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be a number from 1 to 65535")
    return port


def _printable(text: str) -> str:
    """Escape control characters so a path cannot drive the terminal."""
    return "".join(f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char for char in text)


def _settings(project: str, token: str, port: int) -> ApiSettings:
    if project == "":
        raise LaunchError(
            "project_directory_invalid", "The project directory is empty.",
            "Pass the directory to scan, for example: python -m ai_code_security_analyzer.api ~/code/my-app",
        )
    rules_value = os.environ.get("AI_CODE_SECURITY_RULES_DIR")
    rules = Path(rules_value) if rules_value else DEFAULT_RULES_DIRECTORY
    try:
        _strict_directory(rules)
    except ValueError:
        raise LaunchError(
            "rules_directory_invalid",
            "The trusted rules directory is missing, relative, or reached through a symbolic link.",
            "Unset AI_CODE_SECURITY_RULES_DIR to use this repository's rules/ directory.",
        ) from None
    directory = Path(project)
    if not directory.is_absolute():
        directory = Path.cwd() / directory
    dashboard_origin = f"http://{_HOST}:{port}"
    extra_origins = [
        item.strip() for item in os.environ.get("AI_CODE_SECURITY_ALLOWED_ORIGINS", "").split(",")
        if item.strip() and item.strip() != dashboard_origin
    ]
    try:
        return ApiSettings(
            target_directory=directory,
            trusted_rules_directory=rules,
            api_token=token,
            allowed_origins=(dashboard_origin, *extra_origins),
        )
    except ValueError as error:
        code = str(error)
    if code == "api_token_configuration_invalid":
        raise LaunchError(
            "api_token_invalid", f"AI_CODE_SECURITY_API_TOKEN must be {_TOKEN_RULE}.",
            "Unset it to have a token generated for this run, or set a valid value.",
        )
    if code == "symlink_path_not_allowed":
        raise LaunchError(
            "project_path_has_symlink",
            "The project path goes through a symbolic link, which this tool never follows."
            " (On macOS, /tmp and /var are such links.)",
            'Pass the real path instead, for example: "$(cd <project> && pwd -P)"',
        )
    if code == "target_rules_overlap":
        raise LaunchError(
            "project_overlaps_rules",
            "The project contains, or is inside, the trusted rules directory.",
            "Choose a project directory outside this repository's rules/ and not above it.",
        )
    if code == "origin_configuration_invalid":
        raise LaunchError(
            "allowed_origins_invalid",
            "AI_CODE_SECURITY_ALLOWED_ORIGINS must list exact http://127.0.0.1:<port> or http://localhost:<port> origins.",
            "Unset it; the dashboard's own origin is allowed automatically.",
        )
    raise LaunchError(
        "project_directory_invalid", "The project directory does not exist or is not a directory.",
        "Check the path; quote it if it contains spaces.",
    )


def _check_dashboard() -> None:
    if not (DASHBOARD_DIRECTORY / "index.html").is_file():
        raise LaunchError(
            "dashboard_build_missing", "The dashboard has not been built (frontend/dist/index.html is missing).",
            "Build it once from the repository root: (cd frontend && npm ci && npm run build)",
        )


def _check_semgrep() -> str:
    issue, version = probe_semgrep()
    if issue == "semgrep_not_installed":
        raise LaunchError(issue, "Semgrep was not found on PATH.", f"Install the tested version: {_SEMGREP_INSTALL}")
    if issue == "version_check_timed_out":
        raise LaunchError(
            issue, "Semgrep did not answer within 10 seconds; its first run after installation can be slow.",
            "Run `semgrep --version` once, then start again.",
        )
    if issue == "version_check_failed":
        raise LaunchError(issue, "Semgrep is on PATH but did not run or report a version.", f"Reinstall it: {_SEMGREP_INSTALL}")
    if issue is not None or version is None:
        raise LaunchError(
            "semgrep_unsupported", f"Semgrep {version} lacks command-line options every scan needs.",
            f"Install the tested version: {_SEMGREP_INSTALL}",
        )
    return version


def _bind(port: int) -> socket.socket:
    in_use = LaunchError(
        "port_in_use", f"Port {port} on {_HOST} is already in use.",
        f"Stop the other program (lsof -nP -iTCP:{port} -sTCP:LISTEN) or choose another port with --port.",
    )
    # A listener on all interfaces can share the port with a loopback bind on some
    # platforms, so check that nothing answers before binding.
    try:
        with socket.create_connection((_HOST, port), timeout=1):
            pass
    except OSError:
        pass
    else:
        raise in_use
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name == "posix":
            # Same as uvicorn's own binding: a quick restart is not blocked by old connections.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((_HOST, port))
        listener.listen(2048)
    except OSError as error:
        listener.close()
        if error.errno == errno.EADDRINUSE:
            raise in_use from None
        raise LaunchError(
            "port_unavailable", f"Port {port} on {_HOST} cannot be used.", "Choose another port with --port.",
        ) from None
    return listener


def _banner(settings: ApiSettings, port: int, token: str, generated: bool, semgrep_version: str) -> str:
    lines = [
        "SAST Review Workspace is running.",
        "",
        f"  Project    {_printable(str(settings.target_directory))}",
        f"  Dashboard  http://{_HOST}:{port}/",
        "  Rules      JavaScript/TypeScript and Firestore rules; files in other languages are not scanned",
    ]
    if generated:
        lines += [
            f"  API token  {token}",
            "",
            'Open the dashboard and paste the API token into "로컬 API 토큰".',
            "The token is created for this run only and is not saved anywhere.",
        ]
    else:
        lines += [
            "  API token  from AI_CODE_SECURITY_API_TOKEN (not shown)",
            "",
            'Open the dashboard and paste that token into "로컬 API 토큰".',
        ]
    if semgrep_version != TESTED_SEMGREP_VERSION:
        lines.append(
            f"Warning: Semgrep {semgrep_version} is installed; this tool is tested with {TESTED_SEMGREP_VERSION}."
        )
    lines.append("Press Ctrl+C to stop.")
    return "\n".join(lines)


def _serve_project(project: str, port: int) -> None:
    if any(name in os.environ for name in _TARGET_VARIABLES):
        raise LaunchError(
            "target_configured_twice",
            "A project directory was given, but AI_CODE_SECURITY_TARGET or AI_CODE_SECURITY_TARGETS is also set.",
            "Unset those variables, or start without a project directory to use them.",
        )
    supplied = os.environ.get("AI_CODE_SECURITY_API_TOKEN")
    token, generated = (supplied, False) if supplied else (secrets.token_urlsafe(32), True)
    settings = _settings(project, token, port)
    _check_dashboard()
    if generated and not sys.stdout.isatty():
        raise LaunchError(
            "token_display_unavailable",
            "Output is not an interactive terminal, so the generated API token is not shown.",
            f"Run the command in a terminal, or set AI_CODE_SECURITY_API_TOKEN yourself ({_TOKEN_RULE}).",
        )
    semgrep_version = _check_semgrep()
    listener = _bind(port)
    try:
        app = create_app(settings, investigation_api_enabled=True)
        print(_banner(settings, port, token, generated, semgrep_version), flush=True)
        config = uvicorn.Config(
            app, host=_HOST, port=port, access_log=False, reload=False, workers=1, log_level="warning",
        )
        uvicorn.Server(config).run(sockets=[listener])
    finally:
        listener.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m ai_code_security_analyzer.api",
        description="Run SAST Review Workspace on 127.0.0.1 for one local source directory.",
        epilog="Without PROJECT_DIR, the server is configured only by the AI_CODE_SECURITY_* environment "
        "variables (see docs/getting-started.md).",
    )
    parser.add_argument(
        "project", nargs="?", metavar="PROJECT_DIR",
        help="local source directory to scan; a real path without symbolic links",
    )
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT, help=f"loopback port (default {DEFAULT_PORT})")
    args = parser.parse_args(argv)
    if args.project is not None:
        try:
            _serve_project(args.project, args.port)
        except LaunchError as error:
            print(f"error: {error.code}\n  {error.message}\n  fix: {error.fix}", file=sys.stderr)
            raise SystemExit(2) from None
        return
    try:
        app = create_app_from_env(investigation_api_enabled=True)
    except RuntimeError as error:
        if str(error) == "local_api_configuration_required":
            raise SystemExit(
                "local_api_configuration_required\n"
                "  To scan one project, pass its directory: python -m ai_code_security_analyzer.api PROJECT_DIR"
            ) from None
        if str(error) == "local_api_configuration_invalid":
            raise SystemExit(str(error)) from None
        raise SystemExit("local_api_start_failed") from None
    uvicorn.run(
        app,
        host=_HOST,
        port=args.port,
        access_log=False,
        reload=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
