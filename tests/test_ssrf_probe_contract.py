"""SSRF 첫 단계는 callback origin과 관측 입력 밖 탐침을 거부한다."""

from __future__ import annotations

import unittest
import json
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.adapters.ssrf_analysis import (
    SSRF_GRAPHQL_QUERY_STRUCTURE, SSRF_OPENAPI_SINGLE_JSON_STRUCTURE,
    build_ssrf_owned_receiver_requests, build_ssrf_requests,
    ssrf_graphql_query_inputs,
    ssrf_parameter_sources, ssrf_parameters,
)
from hacklipse.adapters.routing import SsrfSurfaceRoutingRule
from hacklipse.domain import (
    DestinationPolicy, Evidence, ExecutionRequest, HttpRequestKind, HttpRequestSpec,
    Run, RunScope, SsrfCanaryProofTarget, SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfPolicyAssertion, SsrfPolicyEvidenceStatus, SsrfPolicySource, Surface,
)
from hacklipse.domain.models import ssrf_request_parameters
from hacklipse.domain.errors import DomainInvariantError
from hacklipse.ports.errors import PolicyViolation


class SsrfProbeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.surface = Surface(
            surface_id="surface-1", run_id="run-1",
            url="https://target.example/preview?url=sample&mode=small",
            method="GET", parameters=("url", "mode"),
        )
        self.run = Run(
            run_id="run-1", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=3,
        )

    def _execution(self, spec: HttpRequestSpec) -> ExecutionRequest:
        return ExecutionRequest(
            execution_id="exec-1", run_id=self.run.run_id, task_id="task-1",
            tool="http_get", target_url=self.surface.url,
            surface_id=self.surface.surface_id, purpose="SSRF fixture",
            method=spec.method, query_parameters=spec.query_parameters,
            request_kind=spec.request_kind,
        )

    @staticmethod
    def _destination_policy(surface_id: str = "surface-1") -> DestinationPolicy:
        return DestinationPolicy(
            policy_id=f"policy:{surface_id}",
            surface_id=surface_id,
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:forbidden",
            approved_by="operator:security-team",
            created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
            destination_origin="http://canary.internal",
            assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
            evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
        )

    def test_only_observed_url_like_get_parameters_are_selected(self) -> None:
        self.assertEqual(ssrf_parameters(self.surface), ("url",))
        self.assertEqual(ssrf_parameters(Surface(
            surface_id="client", run_id="run-1", url="https://target.example/#/preview",
            method="GET", parameters=("url",),
        )), ())
        self.assertEqual(ssrf_parameters(Surface(
            surface_id="schema-only", run_id="run-1",
            url="https://target.example/preview", method="GET",
            parameters=("url",), discovery_types=("openapi_schema",),
        )), ())
        with self.assertRaises(ValueError):
            build_ssrf_requests(self.surface, "invented", "https://callback.example/a")
        with self.assertRaises(ValueError):
            build_ssrf_requests(self.surface, "url", "http://127.0.0.1/a")
        with self.assertRaises(ValueError):
            build_ssrf_requests(
                self.surface, "url", "https://callback.example/a?redirect=/admin",
            )

    def test_observed_http_url_can_identify_nonstandard_field(self) -> None:
        surface = Surface(
            surface_id="remote-image", run_id="run-1",
            url="https://target.example/fetch?file%5B%5D=https%3A%2F%2Fimages.example%2Fa"
                "&other=https%3A%2F%2Fimages.example%2Fb&mode=small",
            method="GET", parameters=("file[]", "other", "mode"),
        )
        self.assertEqual(
            ssrf_parameter_sources(surface),
            (("file[]", "observed_query"), ("other", "observed_query")),
        )
        rule = SsrfSurfaceRoutingRule(
            "SSRF", "ssrf_analyzer", parameter_hints=("url",),
            requires_observed_query=True,
        )
        self.assertTrue(rule.matches(surface))
        control, probe = build_ssrf_requests(
            surface, "file[]", "https://callback.example/ssrf/proof",
        )
        self.assertEqual(dict(control.http_request.query_parameters), {
            "file[]": "hacklipse-control", "other": "hacklipse-control",
            "mode": "small",
        })
        self.assertEqual(dict(probe.http_request.query_parameters)["other"],
                         "hacklipse-control")
        non_url = Surface(
            surface_id="non-url", run_id="run-1",
            url="https://target.example/fetch?file%5B%5D=sample",
            method="GET", parameters=("file[]",),
        )
        self.assertFalse(rule.matches(non_url))

    def test_control_and_probe_change_one_field_only(self) -> None:
        control, probe = build_ssrf_requests(
            self.surface, "url", "https://callback.example/token-a",
        )
        self.assertEqual(control.http_request.query_parameters, (
            ("url", "hacklipse-control"), ("mode", "small"),
        ))
        self.assertEqual(probe.http_request.query_parameters, (
            ("url", "https://callback.example/token-a"),
            ("mode", "small"),
        ))
        self.assertEqual(
            tuple((name, value) for name, value in control.http_request.query_parameters
                  if name != "url"),
            tuple((name, value) for name, value in probe.http_request.query_parameters
                  if name != "url"),
        )
        self.assertEqual(probe.http_request.request_kind, HttpRequestKind.SSRF_PROBE)
        self.assertEqual(control.http_request.request_kind, HttpRequestKind.SSRF_CONTROL)
        for request in (control, probe):
            resolved = self._execution(request.http_request).resolved_url
            self.assertEqual(len(parse_qsl(urlsplit(resolved).query)), 2)

    def test_declared_single_json_url_field_uses_scoped_post(self) -> None:
        surface = Surface(
            surface_id="json-preview", run_id="run-1",
            url="https://target.example/api/preview", method="POST",
            parameters=("url",),
        )
        shape = Evidence(
            evidence_id="evi-json", run_id="run-1", surface_id=surface.surface_id,
            created_by="recon", evidence_type="observation",
            observation={
                "type": "javascript_json_request_structure", "method": "POST",
                "content_type": "application/json", "body_parameter_names": ["url"],
            },
        )
        self.assertEqual(ssrf_parameter_sources(surface, (shape,)),
                         (("url", "declared_json_body"),))
        control, probe = build_ssrf_requests(
            surface, "url", "https://callback.example/one", (shape,),
        )
        self.assertEqual((control.suggested_tool, probe.suggested_tool),
                         ("http_post", "http_post"))
        self.assertEqual(json.loads(control.http_request.body),
                         {"url": "hacklipse-control"})
        self.assertEqual(json.loads(probe.http_request.body),
                         {"url": "https://callback.example/one"})
        self.assertEqual(probe.http_request.query_parameters, ())
        self.assertEqual(probe.http_request.headers,
                         (("Content-Type", "application/json"),))
        class PermitPost:
            def is_approved(self, run, request):
                return True

        def execution(spec):
            return ExecutionRequest(
                execution_id="json-exec", run_id=self.run.run_id,
                task_id="json-task", tool="http_post", target_url=surface.url,
                surface_id=surface.surface_id, purpose="JSON SSRF proof",
                method=spec.method, headers=spec.headers, body=spec.body,
                request_kind=spec.request_kind, scope=self.run.scope,
            )

        AllowlistPolicyGate(
            approval_gate=PermitPost(),
            ssrf_callback_origin="https://callback.example",
        ).validate_execution(self.run, execution(probe.http_request))
        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate(
                approval_gate=PermitPost(),
                ssrf_callback_origin="https://other.example",
            ).validate_execution(self.run, execution(probe.http_request))
        for body, headers in (
            ('{"url":"https://callback.example/one","other":"x"}',
             (("Content-Type", "application/json"),)),
            ('{"url":"https://callback.example/one","url":"https://other.example/"}',
             (("Content-Type", "application/json"),)),
            ('{"url":"https://callback.example/one"}',
             (("Content-Type", "text/plain"),)),
        ):
            with self.assertRaises(DomainInvariantError):
                HttpRequestSpec(
                    method="POST", body=body, headers=headers,
                    request_kind=HttpRequestKind.SSRF_PROBE,
                )
        schema_only = Evidence(
            evidence_id="evi-schema", run_id="run-1", surface_id=surface.surface_id,
            created_by="recon", evidence_type="observation",
            observation={
                "type": "openapi_request_structure", "method": "POST",
                "content_type": "application/json", "body_parameter_names": ["url"],
            },
        )
        self.assertEqual(ssrf_parameter_sources(surface, (schema_only,)), ())
        bounded_schema = Evidence(
            evidence_id="evi-bounded-schema", run_id="run-1",
            surface_id=surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={
                "type": SSRF_OPENAPI_SINGLE_JSON_STRUCTURE,
                "method": "POST", "content_type": "application/json",
                "body_parameter_names": ["url"],
            },
        )
        self.assertEqual(
            ssrf_parameter_sources(surface, (bounded_schema,)),
            (("url", "declared_openapi_single_json_body"),),
        )

    def test_graphql_url_query_uses_schema_shape_and_one_bound_variable(self) -> None:
        scalar = {"kind": "SCALAR", "name": "String"}
        object_type = {"kind": "OBJECT", "name": "Preview"}
        schema = {"data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "linkPreview", "args": [
                        {"name": "url", "type": scalar},
                    ], "type": object_type},
                    {"name": "needsOther", "args": [
                        {"name": "url", "type": scalar},
                        {"name": "id", "type": scalar},
                    ], "type": object_type},
                ]},
                {"kind": "OBJECT", "name": "Mutation", "fields": [
                    {"name": "sendWebhook", "args": [
                        {"name": "url", "type": scalar},
                    ], "type": object_type},
                ]},
            ],
        }}}
        plans = ssrf_graphql_query_inputs({
            "status": 200, "content_type": "application/json",
            "body": json.dumps(schema),
        })
        self.assertEqual(plans, (("linkPreview", "url", True),))
        surface = Surface(
            surface_id="graphql", run_id="run-1",
            url="https://target.example/graphql", method="POST",
            parameters=("url",),
        )
        shape = Evidence(
            evidence_id="evi-graphql", run_id="run-1", surface_id="graphql",
            created_by="recon", evidence_type="observation",
            observation={"type": SSRF_GRAPHQL_QUERY_STRUCTURE,
                         "method": "POST", "field": plans[0][0],
                         "argument": plans[0][1], "select_typename": plans[0][2]},
        )
        control, probe = build_ssrf_requests(
            surface, "url", "https://callback.example/fresh", (shape,),
        )
        for request, expected in (
            (control, "hacklipse-control"),
            (probe, "https://callback.example/fresh"),
        ):
            spec = request.http_request
            self.assertEqual(spec.method, "POST")
            self.assertEqual(spec.query_parameters, ())
            self.assertEqual(json.loads(spec.body)["variables"], {"probe": expected})
            self.assertEqual(
                ssrf_request_parameters(spec.method, spec.query_parameters,
                                        spec.headers, spec.body),
                (("url", expected),),
            )
        class PermitPost:
            def is_approved(self, run, request):
                return True

        probe_spec = probe.http_request
        execution = ExecutionRequest(
            execution_id="graphql-exec", run_id=self.run.run_id,
            task_id="graphql-task", tool="http_post", target_url=surface.url,
            surface_id=surface.surface_id, purpose="GraphQL SSRF proof",
            method="POST", headers=probe_spec.headers, body=probe_spec.body,
            request_kind=HttpRequestKind.SSRF_PROBE, scope=self.run.scope,
        )
        AllowlistPolicyGate(
            approval_gate=PermitPost(),
            ssrf_callback_origin="https://callback.example",
        ).validate_execution(self.run, execution)
        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate(
                approval_gate=PermitPost(),
                ssrf_callback_origin="https://other.example",
            ).validate_execution(self.run, execution)
        with self.assertRaises(DomainInvariantError):
            HttpRequestSpec(
                method="POST", headers=(("Content-Type", "application/json"),),
                body=json.dumps({"query": "mutation($probe:String!){sendWebhook(url:$probe){__typename}}",
                                 "variables": {"probe": "https://callback.example/fresh"}}),
                request_kind=HttpRequestKind.SSRF_PROBE,
            )
        receiver_control, receiver_probe = build_ssrf_owned_receiver_requests(
            surface, "url", "http://host.docker.internal:18080/fresh", (shape,),
        )
        self.assertEqual(
            receiver_probe.http_request.request_kind,
            HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
        )
        self.assertEqual(
            ssrf_request_parameters(
                receiver_probe.http_request.method,
                receiver_probe.http_request.query_parameters,
                receiver_probe.http_request.headers,
                receiver_probe.http_request.body,
            ),
            (("url", "http://host.docker.internal:18080/fresh"),),
        )
        self.assertEqual(
            json.loads(receiver_control.http_request.body)["variables"],
            {"probe": "hacklipse-control"},
        )

    def test_canary_requires_operator_rule_and_exact_runtime_url(self) -> None:
        with self.assertRaises(DomainInvariantError):
            SsrfCanaryProofTarget(
                url="http://canary.internal/proof",
                marker="unsafe<marker>&value",
                surface_id=self.surface.surface_id,
                operator_approved=True,
            )
        with self.assertRaises(DomainInvariantError):
            SsrfCanaryProofTarget(
                url="http://169.254.169.254/latest/meta-data/",
                marker="harmless-canary-marker-12345",
                destination_policy=self._destination_policy(),
                operator_approved=True,
            )
        with self.assertRaises(DomainInvariantError):
            SsrfCanaryProofTarget(
                url="http://canary.internal/",
                marker="harmless-canary-marker-12345",
                destination_policy="operator:forbidden",  # type: ignore[arg-type]
                operator_approved=True,
            )
        canary = SsrfCanaryProofTarget(
            url="http://canary.internal/proof",
            marker="harmless-canary-marker-12345",
            destination_policy=self._destination_policy(), operator_approved=True,
        )
        self.assertEqual(canary.policy_reference, "operator:forbidden")
        canary.require_surface(self.surface.surface_id)
        with self.assertRaises(DomainInvariantError):
            canary.require_surface("surface-2")
        good = HttpRequestSpec(
            method="GET", request_kind=HttpRequestKind.SSRF_CANARY_PROBE,
            query_parameters=(("url", canary.url), ("mode", "small")),
        )
        gate = AllowlistPolicyGate(
            ssrf_callback_origin="https://callback.example",
            ssrf_canary_proof=canary,
        )
        gate.validate_execution(self.run, self._execution(good))
        resolved = self._execution(good).resolved_url
        self.assertEqual(
            parse_qsl(urlsplit(resolved).query),
            [("url", canary.url), ("mode", "small")],
        )
        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate().validate_execution(self.run, self._execution(good))
        wrong = HttpRequestSpec(
            method="GET", request_kind=HttpRequestKind.SSRF_CANARY_PROBE,
            query_parameters=(("url", "http://other.internal/proof"),),
        )
        with self.assertRaises(PolicyViolation):
            gate.validate_execution(self.run, self._execution(wrong))

    def test_destination_policy_requires_closed_enums_and_exact_surface(self) -> None:
        policy = self._destination_policy()
        policy.require_surface("surface-1")
        with self.assertRaises(DomainInvariantError):
            policy.require_surface("surface-2")

        common = {
            "surface_id": "surface-1",
            "source_reference": "operator:forbidden",
            "approved_by": "operator:security-team",
            "created_at": datetime(2026, 10, 21, tzinfo=timezone.utc),
        }
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                policy_id="policy:invalid-rule",
                destination_rule="forbidden",  # type: ignore[arg-type]
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                **common,
            )
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                policy_id="policy:invalid-source",
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type="operator_attestation",  # type: ignore[arg-type]
                **common,
            )
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                policy_id="policy:empty-reference",
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference="",
                surface_id="surface-1",
                approved_by="operator:security-team",
                created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
            )
        with self.assertRaisesRegex(
            DomainInvariantError, "policy_reference is no longer accepted"
        ):
            SsrfCanaryProofTarget(
                url="http://canary.internal/proof",
                marker="harmless-canary-marker-12345",
                policy_reference="operator:forbidden",
                operator_approved=True,
            )

    def test_secret_like_opaque_policy_and_approval_references_are_rejected(self) -> None:
        with self.assertRaisesRegex(DomainInvariantError, "secret material"):
            DestinationPolicy(
                policy_id="policy:secret-ref",
                surface_id="surface-1",
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference="operator:sk-THISISALONGSECRETKEY1234567890",
                approved_by="operator:security-team",
                created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
            )
        with self.assertRaisesRegex(DomainInvariantError, "secret material"):
            SsrfExecutionApproval(
                approval_id="approval-secret-ref",
                surface_id="surface-1",
                verification_endpoint_ref="token-SUPERSECRETVALUE1234567890",
                approved_by="operator:security-team",
                approved_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
            )
        with self.assertRaisesRegex(DomainInvariantError, "secret material"):
            SsrfExecutionApproval(
                approval_id="approval-secret-principal",
                surface_id="surface-1",
                verification_endpoint_ref="verification-service:v1",
                approved_by="sk-THISISALONGSECRETKEY1234567890",
                approved_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
            )

    def test_confirmation_policy_requires_exact_origin_and_trusted_evidence(self) -> None:
        policy = self._destination_policy()
        self.assertTrue(policy.confirms_for(
            "surface-1", "http://canary.internal/proof",
        ))
        self.assertFalse(policy.confirms_for(
            "surface-1", "http://other.internal/proof",
        ))
        self.assertFalse(policy.confirms_for(
            "surface-2", "http://canary.internal/proof",
        ))

        legacy = DestinationPolicy(
            policy_id="policy:legacy",
            surface_id="surface-1",
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:legacy",
            approved_by="operator:security-team",
            created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
        )
        self.assertFalse(legacy.confirms_for(
            "surface-1", "http://canary.internal/proof",
        ))
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                policy_id="policy:any-string",
                surface_id="surface-1",
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference="any-string",
                approved_by="operator:security-team",
                created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
                destination_origin="http://canary.internal",
                assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
                evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
            )
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                policy_id="policy:partial",
                surface_id="surface-1",
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference="operator:partial",
                approved_by="operator:security-team",
                created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
                destination_origin="http://canary.internal",
            )
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                policy_id="policy:unknown-assertion",
                surface_id="surface-1",
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference="operator:unknown-assertion",
                approved_by="operator:security-team",
                created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
                destination_origin="http://canary.internal",
                assertion="arbitrary",  # type: ignore[arg-type]
                evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
            )

    def test_canary_execution_approval_does_not_require_destination_policy(self) -> None:
        canary = SsrfCanaryProofTarget(
            url="http://canary.internal/proof",
            marker="harmless-canary-marker-12345",
            surface_id="surface-1",
            operator_approved=True,
        )
        self.assertIsNone(canary.destination_policy)
        self.assertEqual(canary.policy_reference, "")
        canary.require_surface("surface-1")

    def test_policy_source_values_and_attestation_status_are_closed(self) -> None:
        self.assertEqual(
            {item.value for item in SsrfPolicySource},
            {"operator_attestation", "config_allowlist", "openapi_allowlist"},
        )
        base = {
            "policy_id": "policy:config",
            "surface_id": "surface-1",
            "destination_rule": SsrfDestinationRule.FORBIDDEN,
            "source_type": SsrfPolicySource.CONFIG_ALLOWLIST,
            "source_reference": "config:outbound-deny-v1",
            "approved_by": "operator:security-team",
            "created_at": datetime(2026, 10, 21, tzinfo=timezone.utc),
            "destination_origin": "http://canary.internal",
            "assertion": SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
        }
        with self.assertRaises(DomainInvariantError):
            DestinationPolicy(
                **base,
                evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
            )
        verified = DestinationPolicy(
            **base,
            evidence_status=SsrfPolicyEvidenceStatus.VERIFIED,
        )
        self.assertTrue(verified.confirms_for(
            "surface-1", "http://canary.internal/health",
        ))

        allowed = DestinationPolicy(
            policy_id="policy:allowed",
            surface_id="surface-1",
            destination_rule=SsrfDestinationRule.ALLOWED,
            source_type=SsrfPolicySource.OPENAPI_ALLOWLIST,
            source_reference="openapi:allowed-callback-hosts",
            approved_by="operator:security-team",
            created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
            destination_origin="http://canary.internal",
            assertion=SsrfPolicyAssertion.TARGET_MAY_REACH_DESTINATION,
            evidence_status=SsrfPolicyEvidenceStatus.VERIFIED,
        )
        self.assertFalse(allowed.confirms_for(
            "surface-1", "http://canary.internal/health",
        ))

    def test_docker_host_callback_requires_exact_registered_origin(self) -> None:
        _, probe = build_ssrf_requests(
            self.surface, "url", "http://host.docker.internal:39788/ssrf/token-a",
        )
        scope = RunScope(allowed_hosts=frozenset({"127.0.0.1"}))
        run = Run(
            run_id=self.run.run_id, target_url="http://127.0.0.1:13311/",
            scope=scope, policy_profile="safe", request_budget=3,
        )
        execution = ExecutionRequest(
            execution_id="docker-probe", run_id=run.run_id, task_id="task-1",
            tool="http_get", target_url=run.target_url, surface_id="surface-1",
            purpose="Docker callback", query_parameters=probe.http_request.query_parameters,
            request_kind=HttpRequestKind.SSRF_PROBE, scope=scope,
        )
        AllowlistPolicyGate(
            ssrf_callback_origin="http://host.docker.internal:39788",
            ssrf_local_test_mode=True,
        ).validate_execution(run, execution)
        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate(
                ssrf_callback_origin="http://host.docker.internal:39789",
                ssrf_local_test_mode=True,
            ).validate_execution(run, execution)

    def test_openapi_get_declaration_is_separate_from_observed_request(self) -> None:
        surface = Surface(
            surface_id="schema", run_id="run-1",
            url="https://target.example/api/fetch", method="GET",
            parameters=("url", "mode"), discovery_types=("openapi_schema",),
        )
        shape = Evidence(
            evidence_id="shape", run_id="run-1", surface_id="schema",
            created_by="recon", evidence_type="observation",
            observation={"type": "openapi_request_structure", "method": "GET",
                         "query_parameter_names": ["url", "mode"],
                         "body_parameter_names": []},
        )
        self.assertEqual(ssrf_parameters(surface), ())
        self.assertEqual(ssrf_parameter_sources(surface, (shape,)),
                         (("url", "openapi_declaration"),))
        control, probe = build_ssrf_requests(
            surface, "url", "https://callback.example/token", (shape,),
        )
        self.assertEqual(control.http_request.query_parameters,
                         (("url", "hacklipse-control"),))
        self.assertEqual(probe.http_request.query_parameters,
                         (("url", "https://callback.example/token"),))

        post_shape = Evidence(
            evidence_id="post-shape", run_id="run-1", surface_id="schema",
            created_by="recon", evidence_type="observation",
            observation={"type": "openapi_request_structure", "method": "POST",
                         "query_parameter_names": [], "body_parameter_names": ["url"]},
        )
        self.assertEqual(ssrf_parameters(surface, (post_shape,)), ())

    def test_probe_requires_registered_public_callback_origin(self) -> None:
        _, probe = build_ssrf_requests(
            self.surface, "url", "https://callback.example/token-a",
        )
        execution = self._execution(probe.http_request)
        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate().validate_execution(self.run, execution)
        AllowlistPolicyGate(
            ssrf_callback_origin="https://callback.example"
        ).validate_execution(self.run, execution)
        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate(
                ssrf_callback_origin="https://other.example"
            ).validate_execution(self.run, execution)
        for origin in ("https://127.0.0.1", "https://10.0.0.1", "https://cb.local"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                AllowlistPolicyGate(ssrf_callback_origin=origin)

    def test_interactsh_ticket_subdomain_is_allowed_but_lookalikes_are_not(self) -> None:
        policy = AllowlistPolicyGate(ssrf_callback_origin="https://oast.example")
        for host, allowed in (
            ("a1.oast.example", True),
            ("a1.oast.example.evil.test", False),
            ("a1oast.example", False),
        ):
            with self.subTest(host=host):
                _, probe = build_ssrf_requests(
                    self.surface, "url", f"https://{host}/",
                )
                if allowed:
                    policy.validate_execution(self.run, self._execution(probe.http_request))
                else:
                    with self.assertRaises(PolicyViolation):
                        policy.validate_execution(self.run, self._execution(probe.http_request))

    def test_other_url_fields_are_neutralized_not_fetched(self) -> None:
        surface = Surface(
            surface_id="surface-many", run_id="run-1",
            url="https://target.example/preview?url=old&feed=https%3A%2F%2Foutside.example%2Fx&mode=small",
            method="GET", parameters=("url", "feed", "mode"),
        )
        control, probe = build_ssrf_requests(
            surface, "url", "https://callback.example/token-a",
        )
        self.assertEqual(dict(control.http_request.query_parameters)["feed"], "hacklipse-control")
        self.assertEqual(dict(probe.http_request.query_parameters)["feed"], "hacklipse-control")
        self.assertEqual(dict(probe.http_request.query_parameters)["mode"], "small")

    def test_probe_kind_rejects_post_header_and_multiple_urls(self) -> None:
        for kwargs in (
            {"method": "POST", "query_parameters": (("url", "https://callback.example/a"),)},
            {"headers": (("X-Test", "1"),), "query_parameters": (("url", "https://callback.example/a"),)},
            {"query_parameters": (("a", "https://callback.example/a"),
                                  ("b", "https://callback.example/b"))},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(DomainInvariantError):
                HttpRequestSpec(request_kind=HttpRequestKind.SSRF_PROBE, **kwargs)


if __name__ == "__main__":
    unittest.main()
