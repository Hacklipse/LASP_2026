"""GraphQL schema claims require independent, successful read-only responses."""

from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from hacklipse.adapters.graphql_introspection import INTROSPECTION_DOCUMENT, schema_name
from hacklipse.adapters.graphql_suggestions import suggestion_plan, suggested_field
from hacklipse.application.execution import _credential_for
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    AccessPrincipalRole, EvidenceRequest, ExecutionResult, Run, RunPhase,
    RunRequest, RunScope, ValidationProofType,
)
from hacklipse.domain.errors import DomainInvariantError


class _Runtime:
    def __init__(self, *, available: bool, fail_reproduction: bool = False,
                 suggestions: bool = False, fail_suggestion_reproduction: bool = False):
        self.available = available
        self.fail_reproduction = fail_reproduction
        self.suggestions = suggestions
        self.fail_suggestion_reproduction = fail_suggestion_reproduction
        self.requests = []
        self.short_queries = 0
        self.suggestion_queries = 0

    def execute(self, request):
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        status, media, body = 404, "text/plain", "missing"
        if path == "/":
            status, body = 200, "API"
        elif path == "/graphql":
            status, media = 200, "application/json"
            query = parse_qs(urlsplit(request.resolved_url).query).get("query", [""])[0]
            available = self.available
            if query == INTROSPECTION_DOCUMENT:
                self.short_queries += 1
                if self.fail_reproduction and self.short_queries >= 2:
                    available = False
            if query == "query { viewe }":
                self.suggestion_queries += 1
                disclose = self.suggestions and not (
                    self.fail_suggestion_reproduction and self.suggestion_queries >= 2
                )
                message = 'Cannot query field "viewe" on type "Query".'
                if disclose:
                    message += ' Did you mean "viewer"?'
                body = json.dumps({"errors": [{"message": message}]})
            elif available and query == INTROSPECTION_DOCUMENT:
                body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
            elif available and "IntrospectionQuery" in query:
                body = json.dumps({"data": {"__schema": {
                    "queryType": {"name": "Query"}, "mutationType": None,
                    "subscriptionType": None,
                    "types": [{"kind": "OBJECT", "name": "Query",
                               "fields": [{"name": "viewer", "args": []}]},
                              {"kind": "SCALAR", "name": "String"}],
                }}})
            else:
                body = json.dumps({"errors": [{"message": "introspection disabled"}]})
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": status,
                         "content_type": media, "headers": [],
                         "requested_url": request.resolved_url, "body": body},
        )


class GraphqlIntrospectionTests(unittest.TestCase):
    def test_error_response_does_not_count_as_schema(self):
        self.assertIsNone(schema_name({"status": 200, "body": json.dumps({
            "errors": [{"message": "disabled"}],
            "data": {"__schema": {"queryType": {"name": "Query"}}},
        })}))

    def test_anonymous_schema_request_drops_authorized_run_credential(self):
        run = Run(
            run_id="run-auth", target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=10,
            credential_ref="authorized-test-session",
        )
        self.assertIsNone(_credential_for(
            run, None, run.credential_ref, anonymous=True
        ))
        with self.assertRaises(DomainInvariantError):
            EvidenceRequest(
                evidence_type="http_response", surface_id="surface",
                reason="conflicting principals", suggested_tool="http_get",
                principal_role=AccessPrincipalRole.ACTOR, anonymous=True,
            )

    def test_suggestion_plan_uses_observed_query_and_requires_actual_name(self):
        self.assertEqual(suggestion_plan((("query", "viewer"),)), ("viewer", "viewe"))
        self.assertIsNone(suggestion_plan((("query", "viewer"), ("query", "viewe"))))
        self.assertTrue(suggested_field({"status": 200, "body": json.dumps({
            "errors": [{"message": 'Cannot query field "viewe" on type "Query". Did you mean "viewer"?'}],
        })}, "viewe", "viewer"))
        self.assertFalse(suggested_field({"status": 200, "body": json.dumps({
            "errors": [{"message": 'Cannot query field "viewe" on type "Query".'}],
        })}, "viewe", "viewer"))

    def test_suggestion_pipeline_requires_independent_anonymous_reproduction(self):
        for suggestions, fail_reproduction in ((True, False), (False, False), (True, True)):
            with self.subTest(suggestions=suggestions, fail_reproduction=fail_reproduction):
                runtime = _Runtime(available=True, suggestions=suggestions,
                                   fail_suggestion_reproduction=fail_reproduction)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("GraphQL Field Suggestion Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=6)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(suggestions and not fail_reproduction))
                if findings:
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.GRAPHQL_FIELD_SUGGESTION_EXPOSURE)
                self.assertTrue(all(request.credential_ref is None for request in runtime.requests
                                    if parse_qs(urlsplit(request.resolved_url).query).get("query")
                                    == ["query { viewe }"]))

    def test_pipeline_requires_independent_schema_reproduction(self):
        for available, fail_reproduction in ((True, False), (False, False), (True, True)):
            with self.subTest(available=available, fail_reproduction=fail_reproduction):
                runtime = _Runtime(available=available, fail_reproduction=fail_reproduction)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("GraphQL Introspection Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=6)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=30,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(available and not fail_reproduction))
                if findings:
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.GRAPHQL_INTROSPECTION_EXPOSURE)
                    self.assertEqual(runtime.short_queries, 2)
                self.assertTrue(all(request.method == "GET" for request in runtime.requests))
                self.assertTrue(all(
                    request.credential_ref is None for request in runtime.requests
                    if parse_qs(urlsplit(request.resolved_url).query).get("query")
                    == [INTROSPECTION_DOCUMENT]
                ))
                self.assertTrue(all(urlsplit(request.resolved_url).hostname == "local.test"
                                    for request in runtime.requests))


if __name__ == "__main__":
    unittest.main()
