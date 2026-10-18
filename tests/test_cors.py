"""CORS claims require independent reflection of two fixed foreign origins."""

from __future__ import annotations

import json
import unittest
from urllib.parse import urlsplit

from hacklipse.adapters.cors_analysis import build_cors_requests, cors_reflection_signal
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    Evidence, ExecutionResult, HttpRequestKind, HttpRequestSpec, Run,
    RunPhase, RunRequest, RunScope, Surface, ValidationProofType,
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


class _OpenApiPostOnlyRuntime:
    def __init__(self):
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        if path == "/openapi.json":
            body = json.dumps({"openapi": "3.0.0", "paths": {"/submit": {"post": {}}}})
            status, media = 200, "application/json"
        elif path == "/":
            body, status, media = "ok", 200, "text/plain"
        else:
            body, status, media = "missing", 404, "text/plain"
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": status,
                         "content_type": media, "headers": [],
                         "requested_url": request.resolved_url, "body": body},
        )


class CorsTests(unittest.TestCase):
    def test_schema_observed_graphql_endpoint_routes_to_read_only_cors_check(self):
        router = standard_router(("CORS",))
        run = Run(
            run_id="run-graphql-cors", target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=20,
        )
        surface = Surface(
            surface_id="surface-graphql", run_id=run.run_id,
            url="http://local.test/graphql", method="GET",
            discovery_types=("graphql_introspection",),
        )
        observation = Evidence(
            evidence_id="evi-operation", run_id=run.run_id,
            surface_id=surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={"type": "graphql_schema_operation",
                         "graphql_kind": "query", "operation": "viewer"},
        )
        decisions = router.route(run, (surface,), (observation,))
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].candidate.vulnerability_type, "CORS")
        self.assertEqual(decisions[0].candidate.assigned_agent, "cors_analyzer")

    def test_probe_kind_rejects_unbounded_origin_and_mutation(self):
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="GET", request_kind=HttpRequestKind.CORS_PROBE,
                            headers=(("Origin", "https://other.example"),))
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="POST", request_kind=HttpRequestKind.CORS_PROBE,
                            headers=(("Origin", "https://probe-a.invalid"),))
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(method="GET", request_kind=HttpRequestKind.CORS_PROBE,
                            query_parameters=(("q", "unbounded-input"),),
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

    def test_graphql_cors_requires_successful_read_query_data(self):
        requests = build_cors_requests("surface-gql", "https://probe-a.invalid",
                                       "graphql cors", graphql_query=True)
        self.assertEqual(
            [request.http_request.query_parameters for request in requests],
            [(('query', 'query { __typename }'),)] * 2,
        )
        def item(body, headers):
            return Evidence(
                evidence_id="e", run_id="r", surface_id="s", created_by="test",
                evidence_type="http_response",
                observation={"status": 200, "body": body, "headers": headers},
            )
        control = item('{"data":{"__typename":"Query"}}', [])
        reflected = [
            ["access-control-allow-origin", "https://probe-a.invalid"],
            ["access-control-allow-credentials", "true"],
        ]
        self.assertFalse(cors_reflection_signal(
            control, item('{"errors":[{"message":"query required"}]}', reflected),
            "https://probe-a.invalid", require_graphql_data=True,
        ))
        self.assertTrue(cors_reflection_signal(
            control, item('{"data":{"__typename":"Query"}}', reflected),
            "https://probe-a.invalid", require_graphql_data=True,
        ))

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
                cors_requests = [request for request in runtime.requests
                                 if urlsplit(request.resolved_url).path == "/search"
                                 and dict(request.headers).get("Origin")]
                self.assertTrue(cors_requests)
                self.assertTrue(all(request.query_parameters == (("q", "hacklipse-control"),)
                                    for request in cors_requests))
                self.assertTrue(all(urlsplit(request.resolved_url).hostname == "local.test"
                                    for request in runtime.requests))

    def test_openapi_post_declaration_does_not_enable_cors_auto_probe(self):
        runtime = _OpenApiPostOnlyRuntime()
        app = build_local_application(
            {}, runtime=runtime, router=standard_router(("CORS",)),
        )
        register_standard_agents(app, recon_max_pages=6)
        run = app.orchestrator.start(RunRequest(
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=30,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertTrue(any(surface.method == "POST"
                            for surface in app.stores.surfaces.list_by_run(run.run_id)))
        self.assertFalse(any(request.method in {"POST", "OPTIONS"}
                             for request in runtime.requests))
        self.assertFalse(app.stores.findings.list_by_run(run.run_id))
