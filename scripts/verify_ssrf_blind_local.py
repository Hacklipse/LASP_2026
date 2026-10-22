"""Run an answer-blind SSRF callback check against one authorized local target.

Only the starting URL, scope, optional session, and execution budget come from
the caller. Recon and the SSRF router select coordinates from target evidence.
This is a callback reproduction check; it never asserts a forbidden-destination
policy or labels a callback as a confirmed vulnerability.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hacklipse.adapters import (  # noqa: E402
    HttpExecutionRuntime, InMemoryCredentialResolver, StaticApprovalGate,
)
from hacklipse.adapters.local_ssrf_callback import LocalSsrfCallbackService  # noqa: E402
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router  # noqa: E402
from hacklipse.application.errors import WorkflowExecutionError  # noqa: E402
from hacklipse.domain import (  # noqa: E402
    RunExecutionProfile, RunRequest, RunScope, redacted_internal_url_path,
)
from hacklipse.ports.security import FormLoginSpec, ResolvedHttpCredential  # noqa: E402


def _target(raw: str) -> tuple[str, str]:
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
        or parsed.port is None or parsed.username or parsed.password
        or parsed.fragment
    ):
        raise ValueError("local target must be an http://127.0.0.1:<port>/ URL")
    return raw, f"{parsed.scheme}://{parsed.netloc}"


def _credential(args, origin: str) -> tuple[InMemoryCredentialResolver, str | None]:
    resolver = InMemoryCredentialResolver({})
    if not (args.authorization_stdin or args.cookie_stdin or args.form_login_url):
        return resolver, None
    def read_private_line(prompt: str) -> str:
        return (getpass.getpass(prompt) if sys.stdin.isatty()
                else sys.stdin.readline().rstrip("\r\n"))
    if args.form_login_url:
        username = read_private_line("Username: ")
        secret = read_private_line("Password: ")
        if not username or len(username) > 512:
            raise ValueError("form login username line is required on stdin")
        if not secret or len(secret) > 8192:
            raise ValueError("form login password line is required on stdin")
        login = urlsplit(args.form_login_url)
        if f"{login.scheme}://{login.netloc}" != origin or login.username or login.password:
            raise ValueError("form login URL must be on the exact target origin")
        for url in (args.login_preflight_url, args.login_verification_url):
            if url is not None:
                parsed = urlsplit(url)
                if f"{parsed.scheme}://{parsed.netloc}" != origin or parsed.username or parsed.password:
                    raise ValueError("login support URLs must be on the exact target origin")
        if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) is None
               for name in args.login_extra_empty_field):
            raise ValueError("login extra field names must be bounded identifiers")
        credential = ResolvedHttpCredential(form_login=FormLoginSpec(
            login_url=args.form_login_url,
            username=username,
            password=secret,
            username_field=args.username_field,
            password_field=args.password_field,
            csrf_field=args.csrf_field,
            preflight_url=args.login_preflight_url,
            extra_fields=tuple((name, "") for name in args.login_extra_empty_field),
            failure_marker=args.login_failure_marker,
            verification_url=args.login_verification_url,
            approval_ref="local-form-login",
        ))
    else:
        secret = read_private_line("Credential: ")
        if not secret or len(secret) > 8192:
            raise ValueError("a bounded credential line is required on stdin")
    if args.authorization_stdin:
        credential = ResolvedHttpCredential(authorization=secret)
    elif args.cookie_stdin:
        pairs = []
        for part in secret.split(";"):
            name, separator, value = part.strip().partition("=")
            if not separator or not value:
                raise ValueError("cookie stdin must contain name=value pairs")
            pairs.append((name, value))
        credential = ResolvedHttpCredential(cookies=tuple(pairs))
    resolver.add("local-session", credential, allowed_origins=(origin,))
    return resolver, "local-session"


def verify(args) -> dict[str, object]:
    target_url, origin = _target(args.target_url)
    resolver, credential_ref = _credential(args, origin)
    with LocalSsrfCallbackService(
        advertised_host=args.callback_host, bind_host=args.callback_bind_host,
    ) as callback:
        runtime = HttpExecutionRuntime(credential_resolver=resolver)
        try:
            app = build_local_application(
                {}, runtime=runtime, credential_resolver=resolver,
                router=standard_router(("SSRF",), ssrf_callback_service=callback),
                ssrf_callback_service=callback, ssrf_local_test_mode=True,
                approval_gate=StaticApprovalGate((
                    "local-form-login",
                    *(("local-state-change",) if args.approve_state_changing else ()),
                )),
                default_approval_ref=(
                    "local-state-change" if args.approve_state_changing else None
                ),
            )
            register_standard_agents(
                app, recon_max_pages=args.recon_max_pages,
                recon_max_scripts=args.recon_max_scripts,
                recon_browser_enabled=args.browser_recon,
                recon_ssrf_navigation=True,
            )
            run = app.orchestrator.start(RunRequest(
                target_url=target_url,
                scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
                credential_ref=credential_ref,
                request_budget=args.request_budget,
                execution_profile=RunExecutionProfile(
                    state_changing_approved=args.approve_state_changing,
                    ssrf_oast_mode="local_test",
                    browser_recon_enabled=args.browser_recon,
                ),
            ))
            surfaces = {item.surface_id: item for item in app.stores.surfaces.list_by_run(run.run_id)}
            evidence = app.stores.evidence.list_by_run(run.run_id)
            candidates = tuple(item for item in app.stores.candidates.list_by_run(run.run_id)
                               if item.vulnerability_type == "SSRF")
            results = []
            for candidate in candidates:
                surface = surfaces[candidate.surface_id]
                observations = tuple(item.observation for item in evidence
                                     if item.surface_id == surface.surface_id
                                     and item.observation.get("type") == "ssrf_probe_result")
                validation_callbacks = tuple(item for item in evidence
                                             if item.surface_id == surface.surface_id
                                             and item.validation_id is not None
                                             and item.observation.get("type") == "ssrf_callback_http")
                results.append({
                    "method": surface.method,
                    "path": redacted_internal_url_path(urlsplit(surface.url).path),
                    "parameters": sorted({str(item.get("parameter")) for item in observations
                                          if isinstance(item.get("parameter"), str)}),
                    "candidate_status": candidate.status.value,
                    "analysis_callback": any(item.get("status") == "http" for item in observations),
                    "independent_validation_callback": bool(validation_callbacks),
                })
            confirmed = len(app.stores.findings.list_by_run(run.run_id))
            report = {
                "mode": "blind_local_callback",
                "run_phase": run.phase.value,
                "request_budget": args.request_budget,
                "completed_target_requests": sum(
                    item.outcome == "completed"
                    for item in app.audit_log.list_by_run(run.run_id)
                ),
                "surface_count": len(surfaces),
                "ssrf_candidate_count": len(candidates),
                "analysis_callback_count": sum(item["analysis_callback"] for item in results),
                "independently_reproduced_count": sum(
                    item["independent_validation_callback"] and item["analysis_callback"]
                    for item in results
                ),
                "confirmed_policy_violations": confirmed,
                "coordinates": results,
            }
            if args.debug_recon:
                report["browser_recon_summaries"] = [
                    {name: observation.get(name) for name in (
                        "status", "page_count", "action_count", "request_count",
                        "blocked_request_count", "unvisited_page_count", "stop_reason",
                    )}
                    for item in evidence
                    if (observation := item.observation).get("type")
                    == "browser_recon_summary"
                ]
                report["recon_surfaces"] = sorted({
                    (item.method, redacted_internal_url_path(urlsplit(item.url).path),
                     tuple(item.discovery_types),
                     tuple(item.parameters))
                    for item in surfaces.values()
                })
                report["recon_observation_types"] = sorted({
                    str(item.observation.get("type")) for item in evidence
                    if item.created_by in {"recon", "browser_recon"}
                })
                report["fetched_script_paths"] = sorted({
                    redacted_internal_url_path(urlsplit(str(
                        item.observation.get("requested_url")
                    )).path)
                    for item in evidence
                    if item.evidence_type == "http_response"
                    and "javascript" in str(item.observation.get("content_type", "")).casefold()
                })
            return report
        finally:
            runtime.close_session(run.run_id) if "run" in locals() else None
            resolver.clear()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_url", help="authorized local HTTP starting URL")
    parser.add_argument("--request-budget", type=int, default=120)
    parser.add_argument("--recon-max-pages", type=int, default=40)
    parser.add_argument("--recon-max-scripts", type=int, default=16)
    parser.add_argument("--callback-host", choices=("127.0.0.1", "host.docker.internal"),
                        default="127.0.0.1")
    parser.add_argument("--callback-bind-host", default="127.0.0.1")
    parser.add_argument("--browser-recon", action="store_true")
    parser.add_argument("--debug-recon", action="store_true")
    parser.add_argument("--approve-state-changing", action="store_true")
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument("--authorization-stdin", action="store_true")
    credentials.add_argument("--cookie-stdin", action="store_true")
    credentials.add_argument(
        "--form-login-url", help="same-origin login URL; read username and password as two stdin lines",
    )
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    parser.add_argument("--csrf-field")
    parser.add_argument("--login-preflight-url")
    parser.add_argument("--login-extra-empty-field", action="append", default=[])
    parser.add_argument("--login-failure-marker")
    parser.add_argument("--login-verification-url")
    args = parser.parse_args()
    if (args.request_budget < 1 or args.recon_max_pages < 1
            or args.recon_max_scripts < 1):
        parser.error("budgets must be positive")
    try:
        result = verify(args)
    except (OSError, ValueError, RuntimeError) as error:
        detail = ({"phase": error.phase, "reason": error.reason}
                  if isinstance(error, WorkflowExecutionError) else {})
        print(json.dumps({"mode": "blind_local_callback", "result": "ERROR",
                          "error": type(error).__name__, **detail}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
