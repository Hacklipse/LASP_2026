"""Off-origin redirect claims require a separate, bounded validation probe."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qsl, urlsplit

from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    ExecutionResult, HttpRequestKind, HttpRequestSpec, RunPhase, RunRequest,
    RunScope, ValidationProofType,
)
from hacklipse.domain.errors import DomainInvariantError


class _Runtime:
    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable
        self.requests = []

    def execute(self, request):
        self.requests.append(request.resolved_url)
        parsed = urlsplit(request.resolved_url)
        if parsed.path == "/":
            observation = {"type": "http_response", "status": 200, "content_type": "text/html",
                           "body": '<a href="/goto?next=%2F">continue</a>'}
            kind = "http_response"
        else:
            next_url = dict(parse_qsl(parsed.query)).get("next", "/")
            location = next_url if self.vulnerable else "/"
            observation = {"type": "http_redirect", "status": 302,
                           "content_type": "text/html", "location": location, "body": ""}
            kind = "http_redirect"
        observation["requested_url"] = request.resolved_url
        return ExecutionResult(execution_id=request.execution_id,
                               evidence_type=kind, observation=observation)


class _AnchorRuntime:
    def __init__(self, *, mode: str):
        self.mode = mode

    def execute(self, request):
        parsed = urlsplit(request.resolved_url)
        if parsed.path == "/":
            body = '<a href="/out?url=%2F">citation</a>'
        else:
            supplied = dict(parse_qsl(parsed.query)).get("url", "/")
            href = supplied if self.mode == "link" else "/docs/blocked"
            body = (
                f'<a href="{href}">citation</a>' if self.mode != "text" else
                f'<p>{supplied}</p>'
            )
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200,
                "content_type": "text/html", "body": body,
                "requested_url": request.resolved_url,
            },
        )


class OpenRedirectTests(unittest.TestCase):
    def test_external_anchor_requires_independent_control_and_actual_href(self):
        for mode, expected in (("link", 1), ("blocked", 0), ("text", 0)):
            with self.subTest(mode=mode):
                app = build_local_application(
                    {}, runtime=_AnchorRuntime(mode=mode),
                    router=standard_router(("Open Redirect",)),
                )
                register_standard_agents(app, recon_max_pages=2)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), expected)

    def test_probe_kind_rejects_external_destination_and_mutations(self):
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="GET", request_kind=HttpRequestKind.OPEN_REDIRECT_PROBE,
                            query_parameters=(("next", "https://outside.invalid/"),))
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="POST", request_kind=HttpRequestKind.OPEN_REDIRECT_PROBE,
                            query_parameters=(("next", "http://127.0.0.1:9/redirectabcdefgh"),))

    def test_pipeline_requires_independent_redirect_reproduction(self):
        for vulnerable in (True, False):
            with self.subTest(vulnerable=vulnerable):
                runtime = _Runtime(vulnerable)
                app = build_local_application(
                    {}, runtime=runtime, router=standard_router(("Open Redirect",)),
                )
                register_standard_agents(app, recon_max_pages=2)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(vulnerable))
                if vulnerable:
                    self.assertEqual(findings[0].proof_type, ValidationProofType.OPEN_REDIRECT)
                self.assertTrue(all(urlsplit(url).hostname == "local.test" for url in runtime.requests))
                self.assertTrue(all(urlsplit(url).path in {"/", "/goto"} for url in runtime.requests))
