"""Callback 수신은 실행된 probe에 묶여 중앙 Evidence로 저장돼야 한다."""

from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timezone
from urllib.parse import quote

from hacklipse.adapters import InMemoryBudgetManager, MemoryStoreBundle
from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.adapters.ssrf_analysis import (
    build_ssrf_canary_requests,
    build_ssrf_canary_request,
    build_ssrf_requests,
    has_http_callback,
)
from hacklipse.application.errors import AgentContractError
from hacklipse.application.execution import RuntimeEvidenceCollector
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    Evidence,
    EvidenceRequest,
    ExecutionResult,
    HttpRequestKind,
    HttpRequestSpec,
    Run,
    RunExecutionProfile,
    RunScope,
    SsrfCanaryProofTarget,
    Surface,
)
from hacklipse.ports import SsrfCallbackHit, SsrfCallbackTicket
from hacklipse.ports.errors import ExternalExecutionDisabled


class _CallbackService:
    origin = "https://callback.example"
    public_oast = False

    def __init__(self) -> None:
        self.tickets: dict[str, SsrfCallbackTicket] = {}
        self.hits: dict[str, list[SsrfCallbackHit]] = {}
        self.sequence = 0

    def issue(self, key: str) -> SsrfCallbackTicket:
        if key not in self.tickets:
            self.sequence += 1
            number = self.sequence
            self.tickets[key] = SsrfCallbackTicket(
                token=f"token-{number}",
                url=f"{self.origin}/token-{number}",
                issued_at=datetime.now(timezone.utc),
            )
        return self.tickets[key]

    def poll(self, token: str, *, timeout_seconds: float) -> tuple[SsrfCallbackHit, ...]:
        if not 0 < timeout_seconds <= 2.0:
            raise ValueError("unexpected poll deadline")
        return tuple(self.hits.get(token, ()))

    def record(self, token: str, *, protocol: str = "http") -> None:
        self.hits.setdefault(token, []).append(SsrfCallbackHit(
            event_id=f"event-{len(self.hits[token]) + 1}",
            token=token, protocol=protocol,
            method="GET" if protocol == "http" else "",
            received_at=datetime.now(timezone.utc),
            source="192.0.2.42 test-agent",
        ))


class _PublicCallbackService(_CallbackService):
    public_oast = True


class _Runtime:
    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200},
        )


class _ReflectingRuntime:
    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200,
                "body": request.resolved_url,
            },
            artifact_refs={"debug": request.resolved_url},
        )


class _HashedRuntime:
    content_hash = hashlib.sha256(b"runtime-secret-response").hexdigest()

    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200,
                "body": "ordinary response", "truncated": False,
            },
            content_hash=self.content_hash,
        )


class _ReflectingCanaryRuntime:
    def __init__(self, canary_url: str, marker: str) -> None:
        self.canary_url = canary_url
        self.marker = marker

    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": self.marker,
                "headers": {"X-Canary": self.marker},
                "location": self.canary_url,
                "encoded_location": quote(self.canary_url, safe=""),
                "truncated": False,
            },
            artifact_refs={
                "debug": f"{self.canary_url} marker={self.marker}",
            },
        )


class _HeaderOnlyCanaryRuntime:
    def __init__(self, location: str, header_value: str) -> None:
        self.location = location
        self.header_value = header_value

    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": "ordinary response",
                "headers": {"X-Verification": self.header_value},
                "location": self.location,
                "truncated": False,
            },
        )


class SsrfCallbackEvidenceTests(unittest.TestCase):
    def test_public_oast_ticket_requires_recorded_run_consent(self) -> None:
        service = _PublicCallbackService()
        stores = MemoryStoreBundle()
        budget = InMemoryBudgetManager()

        def collector_for(run: Run) -> RuntimeEvidenceCollector:
            stores.runs.add(run)
            budget.open_run(run.run_id, run.request_budget)
            return RuntimeEvidenceCollector(
                run_store=stores.runs,
                evidence_store=stores.evidence,
                policy_gate=AllowlistPolicyGate(
                    ssrf_callback_origin=service.origin,
                ),
                budget_manager=budget,
                runtime=_Runtime(),
                ssrf_callback_service=service,
            )

        denied = Run(
            run_id="run-public-denied",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=4,
        )
        with self.assertRaisesRegex(
            ExternalExecutionDisabled, "recorded Run consent",
        ):
            collector_for(denied).issue_ssrf_ticket(
                denied.run_id, "candidate-1", "url",
            )
        self.assertEqual(service.sequence, 0)
        self.assertEqual(service.tickets, {})

        allowed = Run(
            run_id="run-public-allowed",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=4,
            execution_profile=RunExecutionProfile(
                ssrf_oast_mode="public_interactsh",
                ssrf_public_oast_consented=True,
            ),
        )
        ticket = collector_for(allowed).issue_ssrf_ticket(
            allowed.run_id, "candidate-1", "url",
        )
        self.assertEqual(ticket.url, "https://callback.example/token-1")

    def test_browser_created_callback_record_is_not_server_callback_evidence(self) -> None:
        browser_record = Evidence(
            evidence_id="evi-browser-callback",
            run_id="run-1",
            surface_id="surface-1",
            created_by="browser_runtime",
            evidence_type="observation",
            observation={
                "type": "ssrf_callback_http",
                "probe_evidence_id": "evi-probe",
            },
        )
        self.assertFalse(has_http_callback((browser_record,), "evi-probe"))

    def test_bootstrap_uses_provider_origin_and_rejects_mismatch(self) -> None:
        service = _CallbackService()
        app = build_local_application({}, ssrf_callback_service=service)
        app.stores.runs.add(self.run)
        self.assertEqual(
            app.collector.issue_ssrf_ticket(self.run.run_id, "candidate-1", "url").url,
            "https://callback.example/token-1",
        )
        with self.assertRaises(ValueError):
            build_local_application(
                {}, ssrf_callback_service=service,
                ssrf_callback_origin="https://other.example",
            )

    def setUp(self) -> None:
        self.service = _CallbackService()
        self.stores = MemoryStoreBundle()
        self.run = Run(
            run_id="run-1", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=10,
        )
        self.stores.runs.add(self.run)
        self.surface = Surface(
            surface_id="surface-1", run_id=self.run.run_id,
            url="https://target.example/preview?url=old", method="GET",
            parameters=("url",),
        )
        self.budget = InMemoryBudgetManager()
        self.budget.open_run(self.run.run_id, 10)
        self.collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs, evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(
                ssrf_callback_origin=self.service.origin,
            ),
            budget_manager=self.budget, runtime=_Runtime(),
            ssrf_callback_service=self.service,
        )

    def _probe(self, *, validation_id: str | None = None):
        ticket = self.collector.issue_ssrf_ticket(
            self.run.run_id, "candidate-1", "url", validation_id=validation_id,
        )
        _, request = build_ssrf_requests(self.surface, "url", ticket.url)
        probe_id = self.collector.collect(
            self.run.run_id, self.surface.url, request,
            task_id="collection-1", validation_id=validation_id,
            candidate_id="candidate-1",
        )
        return ticket, request, probe_id

    def test_http_hit_is_centrally_stored_without_raw_token_or_source(self) -> None:
        ticket, request, probe_id = self._probe()
        self.service.record(ticket.token)
        ids = self.collector.collect_ssrf_callbacks(
            self.run.run_id, "candidate-1", self.surface.url, request,
            probe_id, task_id="analysis-1",
        )
        self.assertEqual(len(ids), 1)
        item = self.stores.evidence.get(self.run.run_id, ids[0])
        self.assertEqual(item.created_by, "execution_runtime:ssrf_callback")
        self.assertEqual(item.observation["type"], "ssrf_callback_http")
        self.assertEqual(item.observation["probe_evidence_id"], probe_id)
        self.assertEqual(item.observation["attribution"], "unverified")
        self.assertNotIn(ticket.token, str(item.observation))
        self.assertNotIn("192.0.2.42", str(item.observation))
        self.assertNotIn("token_hash", item.observation)
        self.assertNotIn("source_hash", item.observation)
        old_plain_id = "evi-ssrf-" + hashlib.sha256(
            "\0".join((
                self.run.run_id, "candidate-1", ticket.token, probe_id, "event-1",
            )).encode()
        ).hexdigest()[:32]
        self.assertNotEqual(ids[0], old_plain_id)
        self.assertEqual(ids, self.collector.collect_ssrf_callbacks(
            self.run.run_id, "candidate-1", self.surface.url, request,
            probe_id, task_id="analysis-retry",
        ))

    def test_ssrf_runtime_content_hash_is_dropped_but_ordinary_hash_is_kept(self) -> None:
        runtime = _HashedRuntime()
        collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs, evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(
                ssrf_callback_origin=self.service.origin,
            ),
            budget_manager=self.budget, runtime=runtime,
            ssrf_callback_service=self.service,
        )
        ticket = collector.issue_ssrf_ticket(
            self.run.run_id, "candidate-hash", "url",
        )
        control, probe = build_ssrf_requests(self.surface, "url", ticket.url)
        control_id = collector.collect(
            self.run.run_id, self.surface.url, control,
            task_id="control-hash", candidate_id="candidate-hash",
        )
        probe_id = collector.collect(
            self.run.run_id, self.surface.url, probe,
            task_id="probe-hash", candidate_id="candidate-hash",
        )

        canary = SsrfCanaryProofTarget(
            url="http://owned-canary.internal:8025/health",
            marker="owned-harmless-marker-2026",
            surface_id=self.surface.surface_id,
            operator_approved=True,
        )
        canary_collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs, evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(ssrf_canary_proof=canary),
            budget_manager=self.budget, runtime=runtime,
            ssrf_canary_proof=canary,
        )
        _, canary_probe = build_ssrf_canary_requests(
            self.surface, "url", canary.url,
        )
        canary_id = canary_collector.collect(
            self.run.run_id, self.surface.url, canary_probe,
            task_id="canary-hash", candidate_id="candidate-canary-hash",
        )
        ordinary_id = collector.collect(
            self.run.run_id,
            self.surface.url,
            EvidenceRequest(
                evidence_type="http_response",
                surface_id=self.surface.surface_id,
                reason="ordinary GET",
                suggested_tool="http_get",
                http_request=HttpRequestSpec(
                    method="GET", request_kind=HttpRequestKind.CONTROL,
                ),
            ),
            task_id="ordinary-hash",
        )

        for evidence_id in (control_id, probe_id, canary_id):
            self.assertIsNone(
                self.stores.evidence.get(self.run.run_id, evidence_id).content_hash,
            )
        self.assertEqual(
            self.stores.evidence.get(self.run.run_id, ordinary_id).content_hash,
            runtime.content_hash,
        )

    def test_probe_http_evidence_never_stores_callback_url_or_token(self) -> None:
        collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs, evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(
                ssrf_callback_origin=self.service.origin,
            ),
            budget_manager=self.budget, runtime=_ReflectingRuntime(),
            ssrf_callback_service=self.service,
        )
        ticket = collector.issue_ssrf_ticket(
            self.run.run_id, "candidate-secret", "url",
        )
        _, request = build_ssrf_requests(self.surface, "url", ticket.url)
        evidence_id = collector.collect(
            self.run.run_id, self.surface.url, request,
            task_id="collection-secret", candidate_id="candidate-secret",
        )
        stored = self.stores.evidence.get(self.run.run_id, evidence_id)
        serialized = repr((stored.observation, stored.artifact_refs))
        self.assertNotIn(ticket.token, serialized)
        self.assertNotIn(ticket.url, serialized)
        self.assertIn("redacted-ssrf-verification", serialized)

    def test_canary_response_never_stores_endpoint_marker_or_encoded_endpoint(self) -> None:
        canary = SsrfCanaryProofTarget(
            url="http://owned-canary.internal:8025/private/proof",
            marker="owned-harmless-marker-2026",
            surface_id=self.surface.surface_id,
            operator_approved=True,
        )
        collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs,
            evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(ssrf_canary_proof=canary),
            budget_manager=self.budget,
            runtime=_ReflectingCanaryRuntime(canary.url, canary.marker),
            ssrf_canary_proof=canary,
        )
        request = build_ssrf_canary_request(self.surface, "url", canary.url)
        evidence_id = collector.collect(
            self.run.run_id,
            self.surface.url,
            request,
            task_id="collection-canary-secret",
            candidate_id="candidate-canary-secret",
        )
        stored = self.stores.evidence.get(self.run.run_id, evidence_id)
        serialized = repr((stored.observation, stored.artifact_refs))
        self.assertNotIn(canary.url, serialized)
        self.assertNotIn(quote(canary.url, safe=""), serialized)
        self.assertNotIn(canary.marker, serialized)
        self.assertTrue(stored.observation["ssrf_canary_marker_present"])
        self.assertEqual(stored.observation["ssrf_canary_marker_channel"], "body")
        self.assertIn("redacted-ssrf-verification", serialized)

    def test_exact_response_header_marker_is_a_closed_canary_signal(self) -> None:
        canary = SsrfCanaryProofTarget(
            url="http://owned-canary.internal:8025/health",
            marker="owned-harmless-marker-2026",
            surface_id=self.surface.surface_id,
            operator_approved=True,
        )
        collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs,
            evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(ssrf_canary_proof=canary),
            budget_manager=self.budget,
            runtime=_HeaderOnlyCanaryRuntime(
                "https://unrelated.example/redirect", canary.marker,
            ),
            ssrf_canary_proof=canary,
        )
        request = build_ssrf_canary_request(self.surface, "url", canary.url)
        evidence_id = collector.collect(
            self.run.run_id, self.surface.url, request,
            task_id="collection-canary-header",
            candidate_id="candidate-canary-header",
        )
        stored = self.stores.evidence.get(self.run.run_id, evidence_id)
        self.assertTrue(stored.observation["ssrf_canary_marker_present"])
        self.assertEqual(
            stored.observation["ssrf_canary_marker_channel"], "response_header",
        )
        self.assertNotIn(canary.marker, repr(stored.observation))

    def test_location_or_generic_headers_without_marker_are_not_fetch_proof(self) -> None:
        canary = SsrfCanaryProofTarget(
            url="http://owned-canary.internal:8025/health",
            marker="owned-harmless-marker-2026",
            surface_id=self.surface.surface_id,
            operator_approved=True,
        )
        collector = RuntimeEvidenceCollector(
            run_store=self.stores.runs,
            evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(ssrf_canary_proof=canary),
            budget_manager=self.budget,
            runtime=_HeaderOnlyCanaryRuntime(canary.url, "redirected-by-target"),
            ssrf_canary_proof=canary,
        )
        request = build_ssrf_canary_request(self.surface, "url", canary.url)
        evidence_id = collector.collect(
            self.run.run_id, self.surface.url, request,
            task_id="collection-canary-location",
            candidate_id="candidate-canary-location",
        )
        stored = self.stores.evidence.get(self.run.run_id, evidence_id)
        self.assertFalse(stored.observation["ssrf_canary_marker_present"])
        self.assertNotIn("ssrf_canary_marker_channel", stored.observation)
        self.assertNotIn(canary.url, repr(stored.observation))

    def test_validation_uses_a_new_ticket_and_session_provenance(self) -> None:
        analysis = self.collector.issue_ssrf_ticket(self.run.run_id, "candidate-1", "url")
        ticket, request, probe_id = self._probe(validation_id="validation-1")
        self.assertNotEqual(ticket.token, analysis.token)
        self.service.record(ticket.token)
        ids = self.collector.collect_ssrf_callbacks(
            self.run.run_id, "candidate-1", self.surface.url, request,
            probe_id, task_id="validation-1", validation_id="validation-1",
        )
        item = self.stores.evidence.get(self.run.run_id, ids[0])
        self.assertEqual(item.validation_id, "validation-1")
        with self.assertRaises(AgentContractError):
            self.collector.collect_ssrf_callbacks(
                self.run.run_id, "candidate-1", self.surface.url, request,
                probe_id, task_id="validation-2", validation_id="validation-2",
            )

    def test_two_observed_coordinates_get_distinct_tickets(self) -> None:
        first = self.collector.issue_ssrf_ticket(self.run.run_id, "candidate-1", "url")
        second = self.collector.issue_ssrf_ticket(
            self.run.run_id, "candidate-1", "image_url",
        )
        self.assertNotEqual(first.token, second.token)
        self.assertEqual(first, self.collector.issue_ssrf_ticket(
            self.run.run_id, "candidate-1", "url",
        ))

    def test_dns_only_is_not_http_evidence(self) -> None:
        ticket, request, probe_id = self._probe()
        self.service.record(ticket.token, protocol="dns")
        ids = self.collector.collect_ssrf_callbacks(
            self.run.run_id, "candidate-1", self.surface.url, request,
            probe_id, task_id="analysis-1",
        )
        self.assertEqual(
            self.stores.evidence.get(self.run.run_id, ids[0]).observation["type"],
            "ssrf_callback_dns",
        )

    def test_missing_service_and_unissued_probe_are_rejected(self) -> None:
        ticket, request, probe_id = self._probe()
        self.service.tickets.clear()
        with self.assertRaises(AgentContractError):
            self.collector.collect_ssrf_callbacks(
                self.run.run_id, "candidate-1", self.surface.url, request,
                probe_id, task_id="analysis-1",
            )
        no_service = RuntimeEvidenceCollector(
            run_store=self.stores.runs, evidence_store=self.stores.evidence,
            policy_gate=AllowlistPolicyGate(), budget_manager=self.budget,
            runtime=_Runtime(),
        )
        with self.assertRaises(ExternalExecutionDisabled):
            no_service.issue_ssrf_ticket(self.run.run_id, "candidate-1", "url")

    def test_probe_send_requires_the_issued_ticket(self) -> None:
        ticket = self.collector.issue_ssrf_ticket(self.run.run_id, "candidate-1", "url")
        _, request = build_ssrf_requests(
            self.surface, "url", f"{self.service.origin}/unissued",
        )
        with self.assertRaises(AgentContractError):
            self.collector.collect(
                self.run.run_id, self.surface.url, request,
                task_id="collection-1", candidate_id="candidate-1",
            )
        _, valid_request = build_ssrf_requests(self.surface, "url", ticket.url)
        with self.assertRaises(AgentContractError):
            self.collector.collect(
                self.run.run_id, self.surface.url, valid_request,
                task_id="collection-1",
            )


if __name__ == "__main__":
    unittest.main()
