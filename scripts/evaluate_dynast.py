"""Repeat answer-blind Hacklipse scans on freshly reset DynAST vuln/safe twins.

The benchmark CLI owns target lifecycle and scoring. This script only passes its
public target URL to Hacklipse; answer keys and trusted verifier tokens are never
passed to the scanner. No git or software-install commands are used.
"""

from __future__ import annotations

import argparse
import ast
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCH_ROOT = Path(__file__).resolve().parents[2] / "dynast-bench"


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _json_command(command: list[str], *, cwd: Path, env: dict[str, str]) -> dict:
    completed = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0:
        diagnostic = (completed.stderr + "\n" + completed.stdout).casefold()[:8192]
        if any(word in diagnostic for word in ("timed out", "timeout", "deadline exceeded")):
            reason = "timeout"
        elif any(word in diagnostic for word in ("no such image", "image not found", "pull access denied")):
            reason = "image_unavailable"
        elif any(word in diagnostic for word in ("out of memory", "oom", "killed")):
            reason = "resource_exhausted"
        elif "port is already allocated" in diagnostic or "address already in use" in diagnostic:
            reason = "port_conflict"
        else:
            reason = "unspecified"
        raise RuntimeError(
            f"{command[1]} failed: {reason} (exit code {completed.returncode})"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{command[1]} returned invalid JSON") from error
    if not isinstance(result, dict):
        raise RuntimeError(f"{command[1]} returned a non-object result")
    return result


def _local_target(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("benchmark reset did not return a target URL")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"}
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("benchmark target must be a local HTTP URL without credentials or query")
    return value


def _verify_running_stack(
    executable: str, bench_root: Path, env: dict[str, str],
    app: str, variant: str, target: str,
) -> None:
    """Ensure reset's claimed twin is the healthy stack bound to its target.

    A reset result alone is insufficient: an old opposite-variant container can
    retain the port. Persist only a categorical failure, never CLI output.
    """

    status = _json_command(
        [executable, "status", app, "--json"], cwd=bench_root, env=env,
    )
    stacks = status.get("stacks")
    if not isinstance(stacks, list):
        raise ValueError("variant_mismatch")
    active = [
        item for item in stacks
        if isinstance(item, dict) and item.get("app") == app
        and type(item.get("containers_running")) is int
        and item["containers_running"] > 0
    ]
    target_key = target.rstrip("/")
    matching = [
        item for item in active
        if item.get("variant") == variant
        and item.get("healthy") is True
        and isinstance(item.get("target"), str)
        and item["target"].rstrip("/") == target_key
        and item.get("containers_running") == item.get("containers_total")
    ]
    if len(matching) != 1 or any(
        item is not matching[0]
        and isinstance(item.get("target"), str)
        and item["target"].rstrip("/") == target_key
        for item in active
    ):
        raise ValueError("variant_mismatch")


def _scanner_env() -> dict[str, str]:
    # Model credentials may be needed for a separately configured LLM scan, but
    # benchmark answer keys and verifier tokens must never reach the scanner.
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith("DYNAST_BENCH_")
        and key not in {"BENCH_TARGET", "GROUND_TRUTH", "VERIFY_TOKEN"}
    }


def _nextjs_seeded_session(bench_root: Path, variant: str, target: str) -> str:
    """Create a local test session without writing account or Cookie values."""

    seed = bench_root / "vulnerable-apps" / "nextjs" / variant / "prisma" / "seed.mjs"
    source = seed.read_text(encoding="utf-8")
    accounts = re.findall(
        r'\{\s*email:\s*"([^"\n]+)"\s*,\s*pw:\s*"([^"\n]+)"\s*,\s*role:\s*"user"',
        source,
    )
    if not accounts:
        raise RuntimeError("local NextJS test account is unavailable")
    email, password = accounts[0]
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("test login requires a local HTTP target")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.request(
            "POST", "/api/auth/login",
            body=json.dumps({"email": email, "password": password}),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        headers = response.getheaders()
        response.read(1024)
        if response.status != 200:
            raise RuntimeError("local NextJS test login was rejected")
    finally:
        connection.close()
    cookies: dict[str, str] = {}
    for key, value in headers:
        if key.casefold() != "set-cookie":
            continue
        pair = value.split(";", 1)[0]
        if "=" not in pair:
            continue
        name, cookie_value = pair.split("=", 1)
        if name in {"sid", "token"} and cookie_value:
            cookies[name] = cookie_value
    if set(cookies) != {"sid", "token"}:
        raise RuntimeError("local NextJS login did not establish the expected session")
    return "; ".join(f"{name}={cookies[name]}" for name in ("sid", "token"))


def _graphql_seeded_authorization(
    bench_root: Path, variant: str, target: str,
) -> str:
    """Use a non-admin local fixture account; retain its bearer only in memory."""

    source = (
        bench_root / "vulnerable-apps" / "graphql" / variant / "src" / "main.ts"
    ).read_text(encoding="utf-8")
    account = None
    for row in re.finditer(r"\[\s*acme\s*,([^\]\n]+)\]", source):
        if re.search(r",\s*false\s*,", row.group(1)) is None:
            continue
        literals = [value for _, value in re.findall(
            r"(['\"])([^'\"\n]+)\1", row.group(1)
        )]
        if len(literals) >= 2:
            account = (literals[0], literals[1])
            break
    if account is None:
        raise RuntimeError("local GraphQL test account is unavailable")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("test login requires a local HTTP target")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.request(
            "POST", "/graphql",
            body=json.dumps({
                "query": "mutation Login($email: String!, $password: String!) { "
                         "login(email: $email, password: $password) { token } }",
                "variables": {"email": account[0], "password": account[1]},
            }),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        body = response.read(16384)
        if response.status != 200:
            raise RuntimeError("local GraphQL test login was rejected")
        token = json.loads(body).get("data", {}).get("login", {}).get("token")
    finally:
        connection.close()
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9._~-]{1,8000}", token) is None:
        raise RuntimeError("local GraphQL test login did not establish a bearer session")
    return "Bearer " + token


def _llmchat_seeded_session(bench_root: Path, variant: str, target: str) -> str:
    """Use a literal non-admin fixture login without importing challenge code."""

    source = (
        bench_root / "vulnerable-apps" / "llmchat" / variant / "app.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    account = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        if not any(isinstance(target, ast.Name) and target.id == "USERS" for target in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            break
        for value in node.value.values:
            try:
                item = ast.literal_eval(value)
            except (ValueError, TypeError):
                continue
            if (
                isinstance(item, dict) and item.get("role") == "user"
                and item.get("isAdmin") is False
                and isinstance(item.get("email"), str)
                and isinstance(item.get("password"), str)
            ):
                account = (item["email"], item["password"])
                break
        break
    if account is None:
        raise RuntimeError("local LLM chat test account is unavailable")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("test login requires a local HTTP target")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.request(
            "POST", "/api/auth/login",
            body=json.dumps({"email": account[0], "password": account[1]}),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        headers = response.getheaders()
        response.read(1024)
        if response.status != 200:
            raise RuntimeError("local LLM chat test login was rejected")
    finally:
        connection.close()
    for key, value in headers:
        if key.casefold() != "set-cookie":
            continue
        pair = value.split(";", 1)[0]
        if pair.startswith("session=") and len(pair) > len("session="):
            return pair
    raise RuntimeError("local LLM chat login did not establish a session")


def _swagger_test_accounts(
    bench_root: Path, variant: str, *, app: str = "swagger"
) -> tuple[tuple[str, str], ...]:
    """Read only non-admin fixture logins, without importing challenge code."""

    if app not in {"swagger", "fastapi"}:
        raise ValueError("unsupported local Python test fixture")
    seed = bench_root / "vulnerable-apps" / app / variant / "app" / "seed.py"
    tree = ast.parse(seed.read_text(encoding="utf-8"))
    accounts: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "User":
            continue
        fields = {item.arg: item.value for item in node.keywords if item.arg}
        email = fields.get("email")
        password_hash = fields.get("password_hash")
        role = fields.get("role")
        is_admin = fields.get("is_admin")
        if (
            isinstance(email, ast.Constant) and isinstance(email.value, str)
            and isinstance(password_hash, ast.Call)
            and isinstance(password_hash.func, ast.Name)
            and password_hash.func.id == "md5_password"
            and len(password_hash.args) == 1
            and isinstance(password_hash.args[0], ast.Constant)
            and isinstance(password_hash.args[0].value, str)
            and isinstance(role, ast.Constant) and role.value == "user"
            and isinstance(is_admin, ast.Constant) and is_admin.value is False
        ):
            accounts.append((email.value, password_hash.args[0].value))
    if not accounts:
        raise RuntimeError("local Swagger test account is unavailable")
    return tuple(accounts)


def _swagger_login(target: str, account: tuple[str, str]) -> tuple[str, int | None]:
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("test login requires a local HTTP target")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.request(
            "POST", "/api/auth/login",
            body=json.dumps({"email": account[0], "password": account[1]}),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        headers = response.getheaders()
        body = response.read(1024)
        if response.status != 200:
            raise RuntimeError("local Swagger test login was rejected")
    finally:
        connection.close()
    cookies = [
        value.split(";", 1)[0]
        for name, value in headers
        if name.casefold() == "set-cookie" and value.startswith("uid=")
    ]
    if len(cookies) != 1 or not cookies[0].split("=", 1)[1]:
        raise RuntimeError("local Swagger login did not establish a session")
    try:
        principal_id = json.loads(body).get("id")
    except (ValueError, AttributeError):
        principal_id = None
    return cookies[0], principal_id if type(principal_id) is int else None


def _swagger_seeded_session(bench_root: Path, variant: str, target: str) -> str:
    """Log in one non-admin local fixture user; retain no credential in output."""

    return _swagger_login(target, _swagger_test_accounts(bench_root, variant)[0])[0]


def _fastapi_seeded_session(bench_root: Path, variant: str, target: str) -> str:
    """Use the same local uid-cookie login contract for a FastAPI test user."""

    return _swagger_login(
        target, _swagger_test_accounts(bench_root, variant, app="fastapi")[0]
    )[0]


def _gin_seeded_session(bench_root: Path, variant: str, target: str) -> str:
    """Log in a non-admin local Go fixture user without persisting credentials."""

    source = (bench_root / "vulnerable-apps" / "gin" / variant / "main.go").read_text(
        encoding="utf-8"
    )
    accounts = re.findall(
        r'insertUser\("([^"\n]+)",\s*"([^"\n]+)",\s*"user",\s*false,', source
    )
    if not accounts:
        raise RuntimeError("local Gin test account is unavailable")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError("test login requires a local HTTP target")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.request(
            "POST", "/api/auth/login",
            body=json.dumps({"email": accounts[0][0], "password": accounts[0][1]}),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        headers = response.getheaders()
        response.read(1024)
        if response.status != 200:
            raise RuntimeError("local Gin test login was rejected")
    finally:
        connection.close()
    cookies = [
        value.split(";", 1)[0] for name, value in headers
        if name.casefold() == "set-cookie" and value.startswith("session=")
    ]
    if len(cookies) != 1 or not cookies[0].split("=", 1)[1]:
        raise RuntimeError("local Gin login did not establish a session")
    return cookies[0]


def _swagger_access_sessions(
    bench_root: Path, variant: str, target: str
) -> tuple[str, str, str, str]:
    """Prepare two local principals and their own observed object IDs."""

    accounts = _swagger_test_accounts(bench_root, variant)
    if len(accounts) < 2:
        raise RuntimeError("two local Swagger test accounts are unavailable")
    parsed = urlsplit(target)
    sessions: list[tuple[str, str, str]] = []
    for account in accounts[:2]:
        cookie, principal_id = _swagger_login(target, account)
        if principal_id is None:
            raise RuntimeError("local Swagger login did not identify the principal")
        def get_document(path: str) -> dict:
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
            try:
                connection.request("GET", path, headers={"Cookie": cookie})
                response = connection.getresponse()
                body = response.read(256 * 1024)
                if response.status != 200:
                    raise RuntimeError("local Swagger principal cannot inspect test objects")
            finally:
                connection.close()
            try:
                document = json.loads(body)
            except ValueError as error:
                raise RuntimeError("local Swagger test object response is invalid") from error
            if not isinstance(document, dict):
                raise RuntimeError("local Swagger test object response is invalid")
            return document

        own_user = get_document(f"/api/v1/users/{principal_id}")
        own_org = own_user.get("orgSlug")
        if not isinstance(own_org, str) or not own_org:
            raise RuntimeError("local Swagger principal organization is unavailable")
        rows = get_document("/api/v1/posts").get("results")
        if not isinstance(rows, list):
            raise RuntimeError("local Swagger object list is invalid")
        owned_id = None
        for row in rows[:16]:
            object_id = row.get("id") if isinstance(row, dict) else None
            if type(object_id) is not int or object_id < 1:
                continue
            detail = get_document(f"/api/v1/posts/{object_id}")
            if detail.get("orgSlug") == own_org:
                owned_id = str(object_id)
                break
        if owned_id is None:
            raise RuntimeError("local Swagger principal has no accessible own-organization object")
        sessions.append((cookie, owned_id, own_org))
    if sessions[0][1] == sessions[1][1] or sessions[0][2] == sessions[1][2]:
        raise RuntimeError("local Swagger test principals do not have distinct organizations and objects")
    return sessions[0][0], sessions[1][0], sessions[0][1], sessions[1][1]


def _run_summary(log_path: Path) -> dict:
    records = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    results = [item for item in records if item.get("event") == "run_result"]
    if len(results) != 1:
        raise ValueError("scanner log must contain exactly one run_result")
    result = results[0]
    return {
        key: result.get(key) for key in (
            "run_id", "phase", "code_version", "request_budget", "requests_used",
            "finding_count", "candidate_status_counts", "browser_recon",
            "recon_frontier",
            "browser_recon_enabled", "authenticated", "state_changing_approved",
            "stage_funnel", "budget_allocation_mode", "budget_validation_reserve",
            "router_mode", "llm_model",
        )
    }


def _stage_chain(log_path: Path) -> list[dict]:
    """Join sanitized Router inputs and final candidate states by Surface ID."""

    records = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    routing = [item for item in records if item.get("event") == "routing_decision"
               and item.get("status") == "completed"]
    results = [item for item in records if item.get("event") == "run_result"]
    if not routing or len(results) != 1:
        return []
    result = results[0]
    candidates = {
        item["candidate_id"]: item for item in result.get("candidates", [])
        if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
    }
    by_surface: dict[str, dict] = {}
    for decision in routing:
        manifest = decision.get("routing_input_manifest") or {}
        reviews = {
            item["surface_id"]: item for item in decision.get("surface_reviews", [])
            if isinstance(item, dict) and isinstance(item.get("surface_id"), str)
        }
        for surface in manifest.get("surfaces", []):
            if not isinstance(surface, dict) or not isinstance(surface.get("surface_id"), str):
                continue
            review = reviews.get(surface["surface_id"], {})
            candidate_ids = review.get("candidate_ids") or []
            by_surface[surface["surface_id"]] = {
                "surface_key": surface.get("surface_key"),
                "method": surface.get("method"),
                "path_hint": surface.get("path"),
                "discovered_parameter_names": surface.get("parameter_names", []),
                "observation_types": surface.get("observation_types", []),
                "route_reason": review.get("unrouted_reason"),
                "capability_gaps": review.get("capability_gaps", {}),
                "candidates": [{
                    "vulnerability_type": candidates[candidate_id].get("vulnerability_type"),
                    "status": candidates[candidate_id].get("status"),
                    "validation_reason_code": candidates[candidate_id].get(
                        "validation_reason_code"
                    ),
                    "analysis_task_states": candidates[candidate_id].get("analysis_task_states", []),
                    "validation_task_states": candidates[candidate_id].get("validation_task_states", []),
                } for candidate_id in candidate_ids if candidate_id in candidates],
            }
    return sorted(by_surface.values(), key=lambda item: (
        str(item["method"]), str(item["path_hint"]), str(item["surface_key"])
    ))


def _funnel_rates(funnel: object) -> dict[str, float | None]:
    if not isinstance(funnel, dict):
        return {}

    def ratio(numerator: str, denominator: str) -> float | None:
        count = funnel.get(numerator)
        total = funnel.get(denominator)
        if not isinstance(count, int) or not isinstance(total, int) or total <= 0:
            return None
        return round(count / total, 4)

    return {
        "surface_to_candidate": ratio("candidate_surface_count", "discovered_surface_count"),
        "candidate_to_analysis": ratio("analysis_attempted_count", "candidate_count"),
        "analysis_to_validation": ratio("validation_succeeded_count", "analysis_succeeded_count"),
    }


def _score_brief(score: dict) -> dict[str, int]:
    """Read the benchmark's own counts, including findings emitted on its safe twin."""

    counts = score.get("counts")
    runs = score.get("runs")
    if not isinstance(counts, dict) or not isinstance(runs, list):
        raise ValueError("benchmark score lacks counts or runs")
    brief = {}
    for key in ("tp", "fp", "fn"):
        value = counts.get(key)
        if type(value) is not int or value < 0:
            raise ValueError(f"benchmark score has invalid {key}")
        brief[key] = value
    safe_runs = [run for run in runs if isinstance(run, dict) and run.get("variant") == "safe"]
    if len(safe_runs) != 1 or type(safe_runs[0].get("findings")) is not int or safe_runs[0]["findings"] < 0:
        raise ValueError("benchmark score lacks one safe finding count")
    brief["safe_findings"] = safe_runs[0]["findings"]
    return brief


def _print_score_brief(label: str, brief: dict[str, int]) -> None:
    print(
        f"{label}: TP {brief['tp']} | FP {brief['fp']} | FN {brief['fn']}"
        f" | safe Finding {brief['safe_findings']}",
        flush=True,
    )


def _write_json(path: Path, document: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(document, output, ensure_ascii=False, sort_keys=True, indent=2)
        output.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", help="DynAST app name, e.g. nextjs")
    parser.add_argument("--iterations", type=_positive_int, default=3)
    parser.add_argument("--code-version", required=True)
    parser.add_argument("--request-budget", type=_positive_int, default=80)
    parser.add_argument("--router", choices=("heuristic", "agentic"), default="heuristic")
    parser.add_argument("--llm-model", help="fixed model for agentic Router comparison")
    parser.add_argument("--budget-allocation", choices=("off", "heuristic"), default="off",
                        help="candidate ordering and Validation request reservation")
    parser.add_argument("--dynast-cli", default="dynast-bench")
    parser.add_argument("--bench-root", type=Path, default=DEFAULT_BENCH_ROOT)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--no-browser-recon", action="store_true")
    parser.add_argument("--browser-executable", type=Path)
    parser.add_argument("--solo", action="store_true",
                        help="use DynAST's single-container target when compose sidecars are unavailable")
    parser.add_argument("--no-build", action="store_true",
                        help="reuse previously built DynAST images while resetting target data")
    parser.add_argument("--approve-state-changing", action="store_true",
                        help="allow state-changing probes only on the reset local DynAST target")
    parser.add_argument("--nextjs-test-session", action="store_true",
                        help="log in a seeded local NextJS test user in memory for each reset twin")
    parser.add_argument("--swagger-test-session", action="store_true",
                        help="log in a seeded local Swagger test user in memory for each reset twin")
    parser.add_argument("--fastapi-test-session", action="store_true",
                        help="log in a seeded local FastAPI test user in memory for each reset twin")
    parser.add_argument("--gin-test-session", action="store_true",
                        help="log in a seeded local Gin test user in memory for each reset twin")
    parser.add_argument("--graphql-test-session", action="store_true",
                        help="log in a seeded local GraphQL test user in memory for each reset twin")
    parser.add_argument("--llmchat-test-session", action="store_true",
                        help="log in a seeded local LLM chat test user in memory for each reset twin")
    parser.add_argument("--swagger-access-test-sessions", action="store_true",
                        help="prepare two seeded local Swagger users and observed own object IDs")
    args = parser.parse_args(argv)
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.app) is None:
        parser.error("app must be a short lowercase DynAST app name")
    if re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", args.code_version) is None:
        parser.error("code version must be a short label")
    if args.router == "agentic" and not args.llm_model:
        parser.error("--router agentic requires an explicit --llm-model")
    if args.nextjs_test_session and (args.app != "nextjs" or not args.approve_state_changing):
        parser.error("--nextjs-test-session requires nextjs and --approve-state-changing")
    if args.swagger_test_session and (args.app != "swagger" or not args.approve_state_changing):
        parser.error("--swagger-test-session requires swagger and --approve-state-changing")
    if args.fastapi_test_session and (args.app != "fastapi" or not args.approve_state_changing):
        parser.error("--fastapi-test-session requires fastapi and --approve-state-changing")
    if args.gin_test_session and (args.app != "gin" or not args.approve_state_changing):
        parser.error("--gin-test-session requires gin and --approve-state-changing")
    if args.graphql_test_session and (args.app != "graphql" or not args.approve_state_changing):
        parser.error("--graphql-test-session requires graphql and --approve-state-changing")
    if args.llmchat_test_session and (args.app != "llmchat" or not args.approve_state_changing):
        parser.error("--llmchat-test-session requires llmchat and --approve-state-changing")
    if args.swagger_access_test_sessions and (
        args.app != "swagger" or not args.approve_state_changing or args.swagger_test_session
    ):
        parser.error("--swagger-access-test-sessions requires swagger and approval, without --swagger-test-session")
    authenticated_test_session = (
        args.nextjs_test_session or args.swagger_test_session
        or args.swagger_access_test_sessions or args.fastapi_test_session
        or args.gin_test_session or args.graphql_test_session
        or args.llmchat_test_session
    )
    test_session_mode = (
        "swagger_two_principals" if args.swagger_access_test_sessions else
        "swagger_single" if args.swagger_test_session else
        "nextjs_single" if args.nextjs_test_session else
        "fastapi_single" if args.fastapi_test_session else
        "gin_single" if args.gin_test_session else
        "graphql_single" if args.graphql_test_session else
        "llmchat_single" if args.llmchat_test_session else
        "anonymous"
    )
    executable = shutil.which(args.dynast_cli)
    if executable is None:
        parser.error("DynAST CLI is unavailable; provide an existing --dynast-cli path")
    bench_root = args.bench_root.resolve()
    if not (bench_root / "dynast-bench" / "dynast-bench.ts").is_file():
        parser.error("--bench-root does not contain the DynAST checkout")
    if args.browser_executable is not None:
        args.browser_executable = args.browser_executable.expanduser().resolve()
        if not args.browser_executable.is_file() or not os.access(args.browser_executable, os.X_OK):
            parser.error("--browser-executable must be an executable local file")
    label = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    output_dir = (args.output_dir or PROJECT_ROOT / "artifacts" / "dynast-bench" / "evaluations" / label).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    benchmark_env = os.environ.copy()
    scanner_env = _scanner_env()
    results: list[dict] = []
    score_briefs: list[dict[str, int]] = []
    failed = False
    abort = False

    for iteration in range(1, args.iterations + 1):
        pair: dict[str, dict] = {}
        for variant in ("vuln", "safe"):
            print(f"[{iteration}/{args.iterations}] reset {args.app} {variant}", flush=True)
            try:
                reset_command = [executable, "reset", args.app, "--variant", variant, "--json"]
                if args.solo:
                    reset_command.append("--solo")
                if args.no_build:
                    reset_command.append("--no-build")
                reset = _json_command(
                    reset_command,
                    cwd=bench_root, env=benchmark_env,
                )
                target = _local_target(reset.get("target"))
                _verify_running_stack(
                    executable, bench_root, benchmark_env,
                    args.app, variant, target,
                )
                session_authorization = None
                if args.nextjs_test_session:
                    session_cookie = _nextjs_seeded_session(bench_root, variant, target)
                elif args.swagger_test_session:
                    session_cookie = _swagger_seeded_session(bench_root, variant, target)
                elif args.fastapi_test_session:
                    session_cookie = _fastapi_seeded_session(bench_root, variant, target)
                elif args.gin_test_session:
                    session_cookie = _gin_seeded_session(bench_root, variant, target)
                elif args.graphql_test_session:
                    session_authorization = _graphql_seeded_authorization(
                        bench_root, variant, target
                    )
                    session_cookie = None
                elif args.llmchat_test_session:
                    session_cookie = _llmchat_seeded_session(bench_root, variant, target)
                elif args.swagger_access_test_sessions:
                    session_cookie, owner_cookie, actor_id, owner_id = _swagger_access_sessions(
                        bench_root, variant, target
                    )
                else:
                    session_cookie = None
            except (OSError, SyntaxError):
                reset_error = "local_test_fixture_unavailable"
            except (RuntimeError, ValueError) as error:
                # The CLI and fixture may include private response text. Persist
                # only a bounded diagnostic category, including for partial pairs.
                detail = str(error)
                category = (
                    detail.split("failed: ", 1)[1].split(" ", 1)[0]
                    if detail.startswith("reset failed: ")
                    else "variant_mismatch" if detail == "variant_mismatch"
                    else "reset_failed"
                )
                reset_error = (
                    category if category in {
                        "timeout", "image_unavailable", "resource_exhausted",
                        "port_conflict", "unspecified", "variant_mismatch",
                    } else "reset_failed"
                )
            else:
                reset_error = None
            if reset_error is not None:
                leg = {
                    "iteration": iteration, "variant": variant,
                    "test_session_mode": test_session_mode,
                    "error": f"reset_{reset_error}",
                }
                pair[variant] = leg
                results.append(leg)
                failed = abort = True
                print(f"[{iteration}/{args.iterations}] {variant} reset 실패: {leg['error']}", flush=True)
                break

            stem = output_dir / f"{iteration:02d}-{variant}"
            report_path = stem.with_suffix(".md")
            log_path = stem.with_suffix(".jsonl")
            command = [
                sys.executable, str(PROJECT_ROOT / "scripts" / "run_dynast_baseline.py"),
                target, "--app", args.app, "--variant", variant,
                "--code-version", args.code_version,
                "--request-budget", str(args.request_budget),
                "--router", args.router,
                "--budget-allocation", args.budget_allocation,
                "--report-out", str(report_path), "--routing-log", str(log_path),
            ]
            if args.llm_model:
                command.extend(("--llm-model", args.llm_model))
            if session_authorization is not None:
                command.append("--session-authorization-stdin")
            elif session_cookie is None:
                command.append("--anonymous")
            else:
                command.append("--session-cookie-stdin")
            if args.swagger_access_test_sessions:
                command.extend((
                    "--owner-session-cookie-stdin",
                    "--access-actor-object-id", actor_id,
                    "--access-owner-object-id", owner_id,
                ))
            if args.no_browser_recon:
                command.append("--no-browser-recon")
            if args.approve_state_changing:
                command.append("--approve-state-changing")
            if args.browser_executable is not None:
                command.extend(("--browser-executable", str(args.browser_executable)))
            scan_started = time.monotonic()
            scan = subprocess.run(
                command, cwd=PROJECT_ROOT, env=scanner_env,
                input=(
                    "y\n" + (session_cookie + "\n" if session_cookie else "")
                    + (session_authorization + "\n" if session_authorization else "")
                    + (owner_cookie + "\n" if args.swagger_access_test_sessions else "")
                ),
                text=True, capture_output=True, check=False,
            )
            leg = {
                "iteration": iteration, "variant": variant,
                "test_session_mode": test_session_mode,
                "test_principal_count": 2 if args.swagger_access_test_sessions else int(authenticated_test_session),
                "scanner_exit": scan.returncode,
                "scan_elapsed_seconds": round(time.monotonic() - scan_started, 3),
            }
            if scan.returncode == 0:
                try:
                    leg.update(_run_summary(log_path))
                except (OSError, ValueError, json.JSONDecodeError) as error:
                    leg["error"] = type(error).__name__
                if not leg.get("error") and (
                    leg.get("phase") != "done"
                    or leg.get("code_version") != args.code_version
                    or leg.get("request_budget") != args.request_budget
                    or leg.get("authenticated") is not authenticated_test_session
                    or leg.get("state_changing_approved") is not args.approve_state_changing
                    or leg.get("budget_allocation_mode") != args.budget_allocation
                    or (args.router == "agentic" and (
                        leg.get("router_mode") != "agentic"
                        or leg.get("llm_model") != args.llm_model
                    ))
                    or leg.get("browser_recon_enabled") is not (not args.no_browser_recon)
                ):
                    leg["error"] = "run_conditions_mismatch"
                if not leg.get("error") and not args.no_browser_recon:
                    summaries = leg.get("browser_recon") or []
                    if not any(
                        item.get("status") in {"completed", "partial", "bounded"}
                        and isinstance(item.get("page_count"), int)
                        and item["page_count"] > 0
                        and item.get("browser_version")
                        for item in summaries if isinstance(item, dict)
                    ):
                        leg["error"] = "browser_recon_unavailable"
            else:
                leg["error"] = "scanner_failed"
            if leg.get("error"):
                failed = abort = True
                print(f"[{iteration}/{args.iterations}] {variant} 검사 실패: {leg['error']}", flush=True)
            pair[variant] = leg
            results.append(leg)
            if abort:
                break

        if abort:
            break

        if all(pair[variant].get("phase") == "done" for variant in ("vuln", "safe")):
            vuln = output_dir / f"{iteration:02d}-vuln"
            safe = output_dir / f"{iteration:02d}-safe"
            try:
                score = _json_command([
                    executable, "score", args.app, str(vuln.with_suffix(".findings.json")),
                    "--safe", str(safe.with_suffix(".findings.json")),
                    "--endpoints", str(vuln.with_suffix(".endpoints.json")), "--json",
                ], cwd=bench_root, env=benchmark_env)
                brief = _score_brief(score)
                coverage = _json_command([
                    executable, "coverage", args.app, str(vuln.with_suffix(".endpoints.json")),
                    "--findings", str(vuln.with_suffix(".findings.json")), "--json",
                ], cwd=bench_root, env=benchmark_env)
                safe_coverage = _json_command([
                    executable, "coverage", args.app, str(safe.with_suffix(".endpoints.json")),
                    "--findings", str(safe.with_suffix(".findings.json")),
                    "--variant", "safe", "--json",
                ], cwd=bench_root, env=benchmark_env)
                track = coverage.get("tracks", {}).get("coverage", {})
                diagnosis = {
                    "iteration": iteration,
                    "discovery_misses": track.get("discovery_misses", []),
                    "analysis_misses": track.get("analysis_misses", []),
                    "unmapped_vulns": track.get("unmapped_vulns", []),
                    "candidate_status_counts": pair["vuln"].get("candidate_status_counts", {}),
                    "vuln_stage_funnel": pair["vuln"].get("stage_funnel") or {},
                    "safe_stage_funnel": pair["safe"].get("stage_funnel") or {},
                    "vuln_stage_rates": _funnel_rates(pair["vuln"].get("stage_funnel")),
                    "safe_stage_rates": _funnel_rates(pair["safe"].get("stage_funnel")),
                }
                for name, document in (
                    ("score", score), ("vuln-coverage", coverage),
                    ("safe-coverage", safe_coverage), ("diagnosis", diagnosis),
                ):
                    _write_json(output_dir / f"{iteration:02d}-{name}.json", document)
                for variant in ("vuln", "safe"):
                    _write_json(
                        output_dir / f"{iteration:02d}-{variant}-stage-chain.json",
                        {"schema": "hacklipse.surface-stage-chain/v1",
                         "surfaces": _stage_chain(output_dir / f"{iteration:02d}-{variant}.jsonl")},
                    )
                score_briefs.append(brief)
                _print_score_brief(f"[{iteration}/{args.iterations}] 채점", brief)
            except (RuntimeError, OSError, ValueError) as error:
                failed = True
                pair["vuln"]["scoring_error"] = type(error).__name__
                print(f"[{iteration}/{args.iterations}] 채점 실패: {type(error).__name__}", flush=True)

    score_totals = {
        key: sum(brief[key] for brief in score_briefs)
        for key in ("tp", "fp", "fn", "safe_findings")
    }

    summary = {
        "app": args.app, "code_version": args.code_version,
        "request_budget": args.request_budget, "browser_recon": not args.no_browser_recon,
        "budget_allocation_mode": args.budget_allocation,
        "router_mode": args.router, "llm_model": args.llm_model or "",
        "target_mode": "solo" if args.solo else "compose",
        "target_images_reused": args.no_build,
        "state_changing_approved": args.approve_state_changing,
        "authenticated_test_session": authenticated_test_session,
        "test_session_mode": test_session_mode,
        "browser_executable_configured": args.browser_executable is not None,
        "iterations": args.iterations, "legs": results,
        "scored_iterations": len(score_briefs), "score_totals": score_totals,
    }
    _write_json(output_dir / "summary.json", summary)
    if len(score_briefs) > 1:
        _print_score_brief(f"{len(score_briefs)}회 합계 (반복 검사 건수)", score_totals)
    if score_briefs:
        print("safe Finding은 FP에 포함될 수 있으므로 합산하지 마세요.")
    print(f"평가 기록: {output_dir}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
