"""CORS claims require independent reflection of two fixed foreign origins."""

from __future__ import annotations

import unittest
from urllib.parse import urlsplit

from hacklipse.adapters.cors_analysis import cors_reflection_signal
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    Evidence, ExecutionResult, HttpRequestKind, HttpRequestSpec,
    RunPhase, RunRequest, RunScope, ValidationProofType,
)
from hacklipse.domain.errors import DomainInvariantError


class _Runtime:
    def __init__(self, vulnerable: bool):
        self.vulnerable = vulnerable
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        origin = dict(request.headers).get("Origin")
        headers = []
        if self.vulnerable and origin and path == "/search":
            headers = [
                ["access-control-allow-origin", origin],
                ["access-control-allow-credentials", "true"],
            ]
        observation = {
            "type": "http_response", "status": 200, "content_type": "text/html",
            "headers": headers, "requested_url": request.resolved_url,
            "body": '<a href="/search?q=one">search</a>' if path == "/" else "results",
        }
        return ExecutionResult(execution_id=request.execution_id,
                               evidence_type="http_response", observation=observation)


class CorsTests(unittest.TestCase):
    def test_probe_kind_rejects_unbounded_origin_and_mutation(self):
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="GET", request_kind=HttpRequestKind.CORS_PROBE,
                            headers=(("Origin", "https://other.example"),))
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="POST", request_kind=HttpRequestKind.CORS_PROBE,
                            headers=(("Origin", "https://probe-a.invalid"),))

    def test_reflection_requires_credentials_and_successful_responses(self):
        def item(headers, status=200):
            return Evidence(evidence_id="e", run_id="r", surface_id="s",
                            created_by="test", evidence_type="http_response",
                            observation={"status": status, "headers": headers})
        control = item([])
        origin = "https://probe-a.invalid"
        self.assertFalse(cors_reflection_signal(control, item([
            ["access-control-allow-origin", origin],
        ]), origin))
        self.assertFalse(cors_reflection_signal(control, item([
            ["access-control-allow-origin", origin],
            ["access-control-allow-credentials", "true"],
        ], 500), origin))

    def test_pipeline_requires_independent_origin_reproduction(self):
        for vulnerable in (True, False):
            with self.subTest(vulnerable=vulnerable):
                runtime = _Runtime(vulnerable)
                app = build_local_application(
                    {}, runtime=runtime, router=standard_router(("CORS",)),
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
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.CORS_ORIGIN_REFLECTION)
                    origins = {dict(request.headers).get("Origin") for request in runtime.requests}
                    self.assertIn("https://probe-a.invalid", origins)
                    self.assertIn("https://probe-b.invalid", origins)
                self.assertTrue(all(urlsplit(request.resolved_url).hostname == "local.test"
                                    for request in runtime.requests))
