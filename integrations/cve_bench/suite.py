"""Run LASP against explicitly selected CVE-Bench zero-day tasks.

The module owns benchmark setup, Docker compatibility, scoring, and artifact
collection.  It deliberately imports LASP only by launching its public CLI, so
the product code has no dependency on CVE-Bench.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from .docker_bridge import DockerTcpBridge
from .target_scoring import score_target_confirmation


_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$")
_DEFAULT_TAG = "2.2.0"


@dataclass(frozen=True)
class TaskMetadata:
    task_id: str
    application_hosts: tuple[tuple[str, int], ...]
    username: str | None = None
    password: str | None = None


def _read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _load_workspace_env(workspace: Path) -> None:
    if os.environ.get("GEMINI_API_KEY", "").strip():
        return
    for key, value in _read_dotenv(workspace / ".env").items():
        os.environ.setdefault(key, value)


def _task_metadata(root: Path, task_id: str) -> TaskMetadata:
    if _CVE_ID.fullmatch(task_id) is None:
        raise ValueError(f"invalid CVE-Bench task id: {task_id}")
    task_dir = root / "src" / "critical" / "challenges" / task_id
    values = _read_dotenv(task_dir / ".env")
    raw_urls = values.get("APPLICATION_URL", "")
    hosts: list[tuple[str, int]] = []
    for raw in raw_urls.split(","):
        authority = raw.strip().split("/", 1)[0]
        if not authority or ":" not in authority:
            continue
        host, raw_port = authority.rsplit(":", 1)
        hosts.append((host, int(raw_port)))
    if not hosts:
        raise ValueError(f"{task_id} has no usable APPLICATION_URL")
    if not (task_dir / "compose.yml").exists():
        raise ValueError(f"{task_id} has no compose.yml")
    eval_text = (task_dir / "eval.yml").read_text(encoding="utf-8")
    metadata_text = eval_text.split("\nmetadata:\n", 1)[-1]

    def metadata_value(name: str) -> str | None:
        match = re.search(rf"(?m)^\s{{2}}{re.escape(name)}:\s*(.*?)\s*$", metadata_text)
        if match is None:
            return None
        value = match.group(1).strip().strip('"').strip("'")
        return value if value and value.casefold() != "null" else None

    return TaskMetadata(
        task_id=task_id,
        application_hosts=tuple(hosts),
        username=metadata_value("default_username"),
        password=metadata_value("default_password"),
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _localize_url(url: str, local_origin: str, aliases: tuple[str, ...]) -> str:
    resolved = urllib.parse.urljoin(local_origin, url)
    parsed = urllib.parse.urlsplit(resolved)
    if parsed.netloc.casefold() not in {alias.casefold() for alias in aliases}:
        return resolved
    local = urllib.parse.urlsplit(local_origin)
    return urllib.parse.urlunsplit(
        (local.scheme, local.netloc, parsed.path, parsed.query, parsed.fragment)
    )


def _open_without_redirects(opener, request, *, aliases: tuple[str, ...], limit: int = 5):
    current = request
    for _ in range(limit):
        try:
            return opener.open(current, timeout=15), current.full_url
        except urllib.error.HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                return error, current.full_url
            location = error.headers.get("Location")
            error.close()
            if not location:
                raise RuntimeError("login redirect omitted Location")
            next_url = _localize_url(location, current.full_url, aliases)
            current = urllib.request.Request(
                next_url,
                headers={"User-Agent": "LASP-CVE-Bench/1.0"},
            )
    raise RuntimeError("login redirect limit exceeded")


def _authenticate_session(
    local_origin: str,
    *,
    aliases: tuple[str, ...],
    username: str,
    password: str,
) -> str | None:
    """Authenticate through an observed password form and return only Cookie pairs."""

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        _NoRedirect,
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
    )
    response, page_url = _open_without_redirects(
        opener,
        urllib.request.Request(
            local_origin + "/", headers={"User-Agent": "LASP-CVE-Bench/1.0"}
        ),
        aliases=aliases,
    )
    body = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    response.close()
    soup = BeautifulSoup(body, "lxml")
    password_input = soup.find("input", attrs={"type": re.compile("password", re.I)})
    if password_input is None or password_input.find_parent("form") is None:
        return None
    form = password_input.find_parent("form")
    fields: list[tuple[str, str]] = []
    username_field: str | None = None
    password_field = password_input.get("name")
    for field in form.find_all("input", attrs={"name": True}):
        name = str(field.get("name"))
        field_type = str(field.get("type") or "text").casefold()
        if field is password_input:
            continue
        if username_field is None and field_type in {"text", "email"}:
            username_field = name
            continue
        value = field.get("value")
        if value is not None and field_type in {"hidden", "submit"}:
            fields.append((name, str(value)))
    if not username_field or not password_field:
        return None
    fields.extend(((username_field, username), (str(password_field), password)))

    action = str(form.get("action") or page_url)
    ajax_urls = re.findall(r"\burl\s*:\s*['\"]([^'\"]+)['\"]", body)
    login_ajax = next((value for value in ajax_urls if "login" in value.casefold()), None)
    if login_ajax:
        action = login_ajax
    action_url = _localize_url(action, page_url, aliases)
    request = urllib.request.Request(
        action_url,
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "LASP-CVE-Bench/1.0",
        },
    )
    login_response, _authenticated_url = _open_without_redirects(
        opener, request, aliases=aliases
    )
    authenticated_body = login_response.read(1024 * 1024).decode(
        "utf-8", errors="replace"
    )
    login_response.close()
    authenticated_page = BeautifulSoup(authenticated_body, "lxml")
    still_has_password = authenticated_page.find(
        "input", attrs={"type": re.compile("password", re.I)}
    ) is not None
    # A session cookie is commonly issued before login.  Count authentication
    # only when the submitted flow leaves the observed password form.
    if still_has_password:
        return None
    cookies = [(cookie.name, cookie.value) for cookie in jar]
    if not cookies:
        return None
    return "; ".join(f"{name}={value}" for name, value in cookies)


def _compose_environment(root: Path, task_id: str, seed: str) -> dict[str, str]:
    task_env = _read_dotenv(
        root / "src" / "critical" / "challenges" / task_id / ".env"
    )
    env = dict(os.environ)
    env.update(task_env)
    env.update(
        {
            "CVEBENCH_TAG": env.get("CVEBENCH_TAG", _DEFAULT_TAG),
            "CVEBENCH_VERSION": "critical",
            "CVEBENCH_VERSION_DIR": str(root / "src" / "critical"),
            "CVEBENCH_METADATA_DIR": str(root / "src" / "critical" / "metadata"),
            "CVEBENCH_CHALLENGE_DIR": str(root / "src" / "critical" / "challenges"),
            "CVEBENCH_DOCKER_DIR": str(root / "src" / "common" / "docker"),
            "CVEBENCH_SANDBOXES_DIR": str(root / "src" / "common" / "sandboxes"),
            "CVEBENCH_ORGANIZATION": env.get("CVEBENCH_ORGANIZATION", "cvebench"),
            "CVEBENCH_KALI_SIZE": "core",
            "CVEBENCH_SECRET_SEED": seed,
            "CVEBENCH_AGENT_INTERNET": "false",
            "CVEBENCH_AGENT_INTERNET_INTERNAL": "true",
            "DOCKER_DEFAULT_PLATFORM": "linux/amd64",
            "CVE": task_id,
            "CVE_LOWER": task_id.casefold(),
            "COMPOSE_PROJECT_NAME": task_id.casefold(),
        }
    )
    return env


def _compatibility_override(root: Path, directory: Path) -> Path:
    """Provide a macOS-safe MariaDB secret-table initialization hook.

    Docker Desktop exposes the upstream bind-mounted hook as executable.  The
    MariaDB entrypoint then launches it in a child shell, where its private
    ``docker_process_sql`` function does not exist.  Calling the client directly
    preserves the upstream behavior without editing the benchmark checkout.
    """

    copied = directory / "zzz-secret-init.sh"
    copied.write_text(
        "#!/bin/bash\n"
        "set -e\n"
        "password=$(cat /run/secrets/mysql/mysql_root_password)\n"
        "for f in /secret-init/*.sql; do\n"
        "  mariadb --protocol=socket -uroot -p\"$password\" "
        "\"$MYSQL_DATABASE\" <\"$f\"\n"
        "done\n",
        encoding="utf-8",
    )
    copied.chmod(copied.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    override = directory / "compose.compat.yml"
    override.write_text(
        "services:\n"
        "  db:\n"
        "    volumes:\n"
        f"      - {copied}:/docker-entrypoint-initdb.d/zzz-secret-init.sh:ro\n",
        encoding="utf-8",
    )
    return override


def _compose_files(root: Path, task_id: str, override: Path) -> list[str]:
    return [
        "-f",
        str(root / "src" / "critical" / "challenges" / task_id / "compose.yml"),
        "-f",
        str(override),
    ]


def _run_logged(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log: Path,
    timeout: int,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        output = result.stdout
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or "") + f"\nTIMEOUT after {timeout}s\n"
        result = subprocess.CompletedProcess(command, 124, output, None)
    log.write_text(
        f"elapsed_seconds={time.monotonic() - started:.3f}\n{output}",
        encoding="utf-8",
    )
    return result


def _compose(
    root: Path,
    task_id: str,
    override: Path,
    env: dict[str, str],
    *args: str,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *_compose_files(root, task_id, override), *args],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def _container_id(
    root: Path, task_id: str, override: Path, env: dict[str, str], service: str
) -> str:
    result = _compose(root, task_id, override, env, "ps", "-q", service, timeout=30)
    container = result.stdout.strip()
    if result.returncode or not container:
        raise RuntimeError(f"cannot resolve {service} container: {result.stdout.strip()}")
    return container


def _missing_images(
    root: Path, task_id: str, override: Path, env: dict[str, str]
) -> tuple[str, ...]:
    configured = _compose(
        root, task_id, override, env, "config", "--images", timeout=30
    )
    if configured.returncode:
        raise RuntimeError(f"cannot resolve Compose images: {configured.stdout.strip()}")
    missing: list[str] = []
    for image in dict.fromkeys(configured.stdout.splitlines()):
        inspected = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if inspected.returncode:
            missing.append(image)
    return tuple(missing)


def _grader(container: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "exec", container, "/evaluator/done.sh"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {"status": False, "raw": result.stdout.strip()}
    payload["command_exit_code"] = result.returncode
    return payload


def _latest_run_result(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    latest = None
    for line in path.read_text(encoding="utf-8").splitlines():
        with suppress(json.JSONDecodeError):
            item = json.loads(line)
            if item.get("event") == "run_result":
                latest = item
    return latest


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _lasp_command(
    workspace: Path,
    *,
    target_url: str,
    code_version: str,
    routing_log: Path,
    report: Path,
    redirect_origin_aliases: tuple[str, ...] = (),
    session_cookie_env: str | None = None,
) -> list[str]:
    """Build the benchmark profile using only LASP's public CLI contract."""

    command = [
        str(workspace / ".venv" / "bin" / "python"),
        str(workspace / "scripts" / "run_juice_shop_baseline.py"),
        target_url,
        "--vuln",
        "sqli",
        "--recon-entry",
        "base-url",
        "--profile",
        "llm",
        "--recon",
        "agentic",
        "--router",
        "agentic",
        "--budget-allocation",
        "hybrid",
        "--llm-provider",
        "gemini",
        "--request-budget",
        "240",
        "--recon-max-pages",
        "64",
        "--approve-state-changing",
        "--code-version",
        code_version,
        "--routing-log",
        str(routing_log),
        "--report-out",
        str(report),
        "--debug",
    ]
    for alias in redirect_origin_aliases:
        command.extend(("--redirect-origin-alias", alias))
    return command


def run_task(
    *,
    workspace: Path,
    root: Path,
    artifact_dir: Path,
    task_id: str,
    seed: str,
    code_version: str,
    setup_timeout: int,
    task_timeout: int,
) -> dict[str, Any]:
    metadata = _task_metadata(root, task_id)
    task_started = time.monotonic()
    result: dict[str, Any] = {
        "task_id": task_id,
        "code_version": code_version,
        "application_endpoints": len(metadata.application_hosts),
        "selected_endpoint_index": 0,
        "setup_success": False,
        "agent_exit_code": None,
        "grader_before": None,
        "grader_after": None,
        "error": None,
    }
    env = _compose_environment(root, task_id, seed)
    prefix = artifact_dir / task_id
    with tempfile.TemporaryDirectory(prefix="lasp-cvebench-") as temporary:
        temporary_path = Path(temporary)
        override = _compatibility_override(root, temporary_path)
        try:
            missing_images = _missing_images(root, task_id, override, env)
            if missing_images:
                docker_config = temporary_path / "docker-config"
                docker_config.mkdir()
                (docker_config / "config.json").write_text(
                    '{"auths":{}}\n', encoding="utf-8"
                )
                pull_env = dict(env)
                pull_env["DOCKER_CONFIG"] = str(docker_config)
                pull_outputs: list[str] = []
                pull_code = 0
                for image in missing_images:
                    pulled = subprocess.run(
                        ["docker", "pull", "--platform", "linux/amd64", image],
                        cwd=root,
                        env=pull_env,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=900,
                        check=False,
                    )
                    pull_outputs.append(pulled.stdout)
                    if pulled.returncode:
                        pull_code = pulled.returncode
                        break
                pull = subprocess.CompletedProcess(
                    ["docker", "pull"], pull_code, "".join(pull_outputs), None
                )
            else:
                pull = subprocess.CompletedProcess(
                    ["docker", "compose", "pull"],
                    0,
                    "all required images already present\n",
                    None,
                )
            (prefix.with_name(prefix.name + "-pull.log")).write_text(
                pull.stdout, encoding="utf-8"
            )
            if pull.returncode:
                raise RuntimeError(f"image pull failed with exit {pull.returncode}")
            setup = _compose(
                root,
                task_id,
                override,
                env,
                "up",
                "--detach",
                "--wait",
                "--wait-timeout",
                str(setup_timeout),
                "--no-build",
                timeout=setup_timeout + 60,
            )
            (prefix.with_name(prefix.name + "-setup.log")).write_text(
                setup.stdout, encoding="utf-8"
            )
            if setup.returncode:
                raise RuntimeError(f"compose setup failed with exit {setup.returncode}")
            result["setup_success"] = True
            target = _container_id(root, task_id, override, env, "target")
            agent_container = _container_id(root, task_id, override, env, "agent")
            result["grader_before"] = _grader(target)
            service, port = metadata.application_hosts[0]
            # The benchmark's agent container has netcat and can resolve every
            # application service on the target network.
            with DockerTcpBridge(
                agent_container, port, remote_host=service
            ) as bridge:
                local_origin = f"http://127.0.0.1:{bridge.local_port}"
                aliases = (
                    f"{service}:{port}",
                    f"127.0.0.1:{port}",
                    f"localhost:{port}",
                )
                session_cookie = None
                if metadata.username and metadata.password:
                    session_cookie = _authenticate_session(
                        local_origin,
                        aliases=aliases,
                        username=metadata.username,
                        password=metadata.password,
                    )
                result["authentication_attempted"] = bool(
                    metadata.username and metadata.password
                )
                result["authentication_success"] = session_cookie is not None
                routing_log = prefix.with_name(prefix.name + "-routing.jsonl")
                report = prefix.with_name(prefix.name + "-report.md")
                console = prefix.with_name(prefix.name + "-console.log")
                command = _lasp_command(
                    workspace,
                    target_url=local_origin + "/",
                    code_version=code_version,
                    routing_log=routing_log,
                    report=report,
                    redirect_origin_aliases=aliases,
                    session_cookie_env=(
                        "LASP_CVEBENCH_SESSION_COOKIE" if session_cookie else None
                    ),
                )
                lasp_env = dict(os.environ)
                lasp_env["PYTHONPATH"] = str(workspace / "src")
                lasp_env["PYTHONUNBUFFERED"] = "1"
                if session_cookie:
                    lasp_env["LASP_CVEBENCH_SESSION_COOKIE"] = session_cookie
                agent = _run_logged(
                    command,
                    cwd=workspace,
                    env=lasp_env,
                    log=console,
                    timeout=task_timeout,
                    input_text="y\n\n",
                )
                result["agent_exit_code"] = agent.returncode
                result["run_result"] = _latest_run_result(routing_log)
                result["target_confirmation"] = score_target_confirmation(
                    task_id, result["run_result"]
                )
            result["grader_after"] = _grader(target)
        except Exception as error:  # preserve per-task evidence and continue suite
            result["error"] = f"{type(error).__name__}: {error}"
            with suppress(Exception):
                service_logs = _compose(
                    root,
                    task_id,
                    override,
                    env,
                    "logs",
                    "--no-color",
                    "--timestamps",
                    timeout=60,
                )
                prefix.with_name(prefix.name + "-services.log").write_text(
                    service_logs.stdout, encoding="utf-8"
                )
        finally:
            with suppress(Exception):
                teardown = _compose(
                    root,
                    task_id,
                    override,
                    env,
                    "down",
                    "--volumes",
                    "--remove-orphans",
                    "--timeout",
                    "0",
                    timeout=120,
                )
                (prefix.with_name(prefix.name + "-teardown.log")).write_text(
                    teardown.stdout, encoding="utf-8"
                )
    result["wall_seconds"] = round(time.monotonic() - task_started, 3)
    _write_json(prefix.with_name(prefix.name + "-result.json"), result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tasks", nargs="+", help="explicit CVE-Bench task IDs")
    parser.add_argument("--cve-bench-root", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--seed", default="lasp-sqli-zero-day-v1")
    parser.add_argument("--code-version", default="baseline")
    parser.add_argument("--setup-timeout", type=int, default=600)
    parser.add_argument("--task-timeout", type=int, default=900)
    args = parser.parse_args(argv)

    workspace = Path(__file__).resolve().parents[2]
    root = args.cve_bench_root.resolve()
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    _load_workspace_env(workspace)
    if not os.environ.get("GEMINI_API_KEY", "").strip():
        parser.error("GEMINI_API_KEY is not configured in the environment or .env")

    # Validate the entire requested set before starting any containers.
    for task_id in args.tasks:
        _task_metadata(root, task_id)

    results: list[dict[str, Any]] = []
    summary_path = artifact_dir / "summary.json"
    for task_id in args.tasks:
        print(f"[{len(results) + 1}/{len(args.tasks)}] {task_id}", flush=True)
        result = run_task(
            workspace=workspace,
            root=root,
            artifact_dir=artifact_dir,
            task_id=task_id,
            seed=args.seed,
            code_version=args.code_version,
            setup_timeout=args.setup_timeout,
            task_timeout=args.task_timeout,
        )
        results.append(result)
        summary = {
            "schema_version": 1,
            "code_version": args.code_version,
            "task_count": len(args.tasks),
            "completed_count": len(results),
            "grader_success_count": sum(
                1
                for item in results
                if (item.get("grader_after") or {}).get("status") is True
            ),
            "agent_success_count": sum(
                1 for item in results if item.get("agent_exit_code") == 0
            ),
            "target_confirmed_count": sum(
                1
                for item in results
                if (item.get("target_confirmation") or {}).get("confirmed") is True
            ),
            "results": results,
        }
        _write_json(summary_path, summary)
        print(
            f"  agent={result['agent_exit_code']} "
            f"grader={bool((result.get('grader_after') or {}).get('status'))} "
            f"seconds={result['wall_seconds']} error={result['error']}",
            flush=True,
        )
    return 0 if all(item["error"] is None for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
