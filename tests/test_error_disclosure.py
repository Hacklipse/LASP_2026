"""Only repeatable internal error frames become a public exposure finding."""

from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from hacklipse.adapters.error_disclosure import exposed_error_stack, error_route_candidate
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import ExecutionResult, RunPhase, RunRequest, RunScope, ValidationProofType


_TRACE = (
    "Traceback (most recent call last):\n"
    '  File "/srv/app/handlers.py", line 38, in read\n'
    "    raise RuntimeError('fixture')\n"
    "RuntimeError: fixture\n"
)


class _Runtime:
    def __init__(self, *, exposed: bool):
        self.exposed = exposed
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        if path == "/":
            status, body = 200, '<a href="/api/error">diagnostics</a>'
        elif path == "/api/error":
            status, body = 500, _TRACE if self.exposed else "Internal error"
        else:
            status, body = 404, "missing"
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": status,
                "content_type": "text/html" if path == "/" else "text/plain",
                "body": body, "requested_url": request.resolved_url,
            },
        )


class _GraphqlRuntime:
    def __init__(self, *, exposed: bool):
        self.exposed = exposed
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        parsed = urlsplit(request.resolved_url)
        query = parse_qs(parsed.query).get("query", [""])[0]
        status, media, body = 404, "text/plain", "missing"
        if parsed.path == "/":
            status, body = 200, "API"
        elif parsed.path == "/graphql":
            status, media = 200, "application/json"
            if "IntrospectionQuery" in query:
                body = json.dumps({"data": {"__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"kind": "OBJECT", "name": "Query",
                               "fields": [{"name": "viewer", "args": []}]}],
                }}})
            else:
                extensions = ({"stack": (
                    "Error: parse failed\n"
                    "    at parse (/srv/graphql/parser.js:10:2)\n"
                    "    at handle (/srv/graphql/http.js:20:3)\n"
                )} if self.exposed else {"code": "GRAPHQL_PARSE_FAILED"})
                body = json.dumps({"errors": [{"message": "syntax error",
                                               "extensions": extensions}]})
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": status, "content_type": media,
                "body": body, "requested_url": request.resolved_url,
            },
        )


class ErrorDisclosureTests(unittest.TestCase):
    def test_signature_requires_real_stack_frames_in_server_error(self):
        self.assertEqual(exposed_error_stack({"status": 500, "body": _TRACE}), "python")
        self.assertIsNone(exposed_error_stack({"status": 200, "body": _TRACE}))
        self.assertIsNone(exposed_error_stack({"status": 500, "body": "Traceback (most recent call last):"}))
        self.assertIsNone(exposed_error_stack({"status": 500, "body": _TRACE, "truncated": True}))
        self.assertTrue(error_route_candidate("http://local.test/api/errors/langchain"))
        self.assertFalse(error_route_candidate("http://local.test/static/errors.js"))
        graphql = _GraphqlRuntime(exposed=True).execute(type("Request", (), {
            "resolved_url": "http://local.test/graphql?query=query+%7B",
            "execution_id": "test",
        })())
        self.assertEqual(exposed_error_stack(graphql.observation), "graphql_javascript")

    def test_pipeline_confirms_only_reproducible_error_frames(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _Runtime(exposed=exposed)
                app = build_local_application({}, runtime=runtime, router=standard_router())
                register_standard_agents(app, recon_max_pages=3)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.ERROR_DETAIL_EXPOSURE)
                    signals = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                               if item.created_by == "error_disclosure_analyzer"]
                    self.assertEqual(len(signals), 1)
                    self.assertEqual(signals[0]["stack_kind"], "python")
                    self.assertNotIn("/srv/app/", str(signals))
                    self.assertGreaterEqual(sum(
                        urlsplit(item.resolved_url).path == "/api/error"
                        for item in runtime.requests
                    ), 2)

    def test_graphql_syntax_errors_require_independent_public_stack(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _GraphqlRuntime(exposed=exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Error Detail Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=6)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.ERROR_DETAIL_EXPOSURE)
                    signals = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                               if item.created_by == "error_disclosure_analyzer"]
                    self.assertEqual(signals[0]["probe_mode"], "graphql")
                    self.assertNotIn("/srv/graphql", str(signals))
                parser_queries = [
                    parse_qs(urlsplit(item.resolved_url).query)["query"][0]
                    for item in runtime.requests
                    if urlsplit(item.resolved_url).path == "/graphql"
                    and parse_qs(urlsplit(item.resolved_url).query).get("query")
                    in (["query {"], ["query { )"])
                ]
                self.assertIn("query {", parser_queries)
                if exposed:
                    self.assertIn("query { )", parser_queries)


if __name__ == "__main__":
    unittest.main()
