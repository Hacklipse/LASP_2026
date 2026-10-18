"""GraphQL discovery accepts a bounded schema and never invents operations."""

from __future__ import annotations

import json
import unittest

from hacklipse.adapters.graphql_discovery import (
    graphql_auth_blocked_response, graphql_schema_operations,
    graphql_schema_query_inputs, graphql_query_requests,
)
from hacklipse.domain import DomainInvariantError, Evidence, HttpRequestKind, HttpRequestSpec


class GraphqlDiscoveryTests(unittest.TestCase):
    def test_auth_block_is_structured_and_not_inferred_from_free_text(self):
        def evidence(body):
            return Evidence(
                evidence_id="e1", run_id="r1", surface_id="s1",
                created_by="execution_runtime:http_get", evidence_type="http_response",
                observation={"status": 200, "body": body},
            )
        self.assertTrue(graphql_auth_blocked_response(evidence(
            '{"errors":[{"extensions":{"code":"UNAUTHENTICATED"}}]}'
        )))
        self.assertFalse(graphql_auth_blocked_response(evidence(
            '{"errors":[{"message":"Authentication required"}]}'
        )))

    def test_read_query_plan_excludes_mutations_and_required_extra_inputs(self):
        scalar = {"kind": "SCALAR", "name": "String"}
        object_type = {"kind": "OBJECT", "name": "Result"}
        body = {"data": {"__schema": {
            "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "search", "args": [{"name": "term", "type": scalar}],
                     "type": object_type},
                    {"name": "dependent", "args": [
                        {"name": "term", "type": scalar},
                        {"name": "id", "type": {"kind": "NON_NULL", "ofType": scalar}},
                    ], "type": object_type},
                    {"name": "linkPreview", "args": [{"name": "url", "type": scalar}],
                     "type": object_type},
                    {"name": "reportRun", "args": [{"name": "id", "type": scalar}],
                     "type": object_type},
                ]},
                {"kind": "OBJECT", "name": "Mutation", "fields": [
                    {"name": "delete", "args": [{"name": "term", "type": scalar}],
                     "type": object_type},
                ]},
            ],
        }}}
        plans = graphql_schema_query_inputs({
            "status": 200, "content_type": "application/json", "body": json.dumps(body),
        })
        self.assertEqual([(item.field, item.argument) for item in plans],
                         [("search", "term"), ("dependent", "id")])
        control, probe = graphql_query_requests("surface-1", plans[0], "hacklipseabc", "test")
        self.assertIs(control.http_request.request_kind, HttpRequestKind.GRAPHQL_QUERY_CONTROL)
        self.assertIs(probe.http_request.request_kind, HttpRequestKind.GRAPHQL_QUERY_PROBE)
        self.assertEqual(probe.http_request.query_parameters[0][1],
                         control.http_request.query_parameters[0][1].replace('abc"', 'abc\'"'))
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(
                query_parameters=(("query", 'mutation { delete(term: "hacklipseabc") }'),),
                request_kind=HttpRequestKind.GRAPHQL_QUERY_PROBE,
            )

    def test_rejects_errors_non_json_and_unbounded_schema(self):
        schema = {"data": {"__schema": {"queryType": {"name": "Query"},
                "types": [{"kind": "OBJECT", "name": "Query", "fields": [{"name": "posts"}]}]}}}
        observation = {"status": 200, "content_type": "application/json", "body": json.dumps(schema)}
        self.assertEqual(graphql_schema_operations(observation),
                         (("query", "__schema"), ("query", "posts")))
        self.assertEqual(graphql_schema_operations({**observation, "status": 403}), ())
        self.assertEqual(graphql_schema_operations({**observation, "truncated": True}), ())
        self.assertEqual(graphql_schema_operations({**observation, "body": '{"errors":[]}' }), ())
        self.assertEqual(graphql_schema_operations({**observation, "content_type": "text/html"}), ())

    def test_operation_names_are_bounded_and_do_not_include_values(self):
        body = {"data": {"__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "posts"}, {"name": "invalid-name"}, {"name": "__private"}
                ]},
                {"kind": "OBJECT", "name": "Post", "fields": [{"name": "title"}]},
            ],
        }}}
        result = graphql_schema_operations({
            "status": 200, "content_type": "application/json", "body": json.dumps(body),
        })
        self.assertEqual(result, (("query", "__schema"), ("query", "posts")))


if __name__ == "__main__":
    unittest.main()
