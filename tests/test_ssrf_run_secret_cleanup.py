"""Terminal Runs must not retain exact SSRF endpoints in process memory."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from urllib.parse import urlsplit

from hacklipse.application.errors import AgentContractError, WorkflowExecutionError
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    Evidence,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunPhase,
    RunRequest,
    RunScope,
    SsrfCanaryProofTarget,
    SsrfExecutionApproval,
    Surface,
)
from hacklipse.application.orchestrator import OrchestratorConfig
from hacklipse.ports import SsrfCallbackHit, SsrfCallbackTicket


class _DiscardingCallbackService:
    origin = "https://callback.example"

    def __init__(self) -> None:
        self.tickets: dict[str, SsrfCallbackTicket] = {}
        self.hits: dict[str, tuple[SsrfCallbackHit, ...]] = {}
        self.discarded: list[str] = []
        self._sequence = 0

    def issue(self, key: str) -> SsrfCallbackTicket:
        if key not in self.tickets:
            self._sequence += 1
            token = f"terminal-secret-{self._sequence}"
            self.tickets[key] = SsrfCallbackTicket(
                token=token,
                url=f"{self.origin}/{token}",
                issued_at=datetime.now(timezone.utc),
            )
        return self.tickets[key]

    def poll(self, token: str, *, timeout_seconds: float):
        return self.hits.get(token, ())

    def discard(self, token: str) -> None:
        self.discarded.append(token)
        self.hits.pop(token, None)
        for key, ticket in tuple(self.tickets.items()):
            if ticket.token == token:
                self.tickets.pop(key, None)


class _CallbackRuntime:
    def __init__(self, service: _DiscardingCallbackService) -> None:
        self.service = service

    def execute(self, request):
        body = (
            '<a href="/preview?url=old">preview</a>'
            if urlsplit(request.resolved_url).path == "/"
            else "ok"
        )
        if request.request_kind is HttpRequestKind.SSRF_PROBE:
            callback = next(
                value for _, value in request.query_parameters
                if value.startswith(self.service.origin)
            )
            token = callback.rsplit("/", 1)[-1]
            self.service.hits[token] = (SsrfCallbackHit(
                event_id=f"event-{token}",
                token=token,
                protocol="http",
                received_at=datetime.now(timezone.utc),
                method="GET",
                source="192.0.2.10",
            ),)
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": body},
        )


class SsrfRunSecretCleanupTests(unittest.TestCase):
    def test_successful_run_discards_analysis_and_validation_tickets(self) -> None:
        service = _DiscardingCallbackService()
        app = build_local_application(
            {},
            runtime=_CallbackRuntime(service),
            ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, recon_max_pages=4)

        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))

        self.assertEqual(len(service.discarded), 2)
        self.assertEqual(service.tickets, {})
        self.assertEqual(app.collector._ssrf_issued, {})
        self.assertEqual(app.collector._ssrf_issued_by_run, {})
        self.assertEqual(app.collector._ssrf_run_hash_keys, {})
        self.assertEqual(app.ssrf_reviews.get_for_run(run.run_id), None)

    def test_failed_run_also_discards_ticket_issued_before_failure(self) -> None:
        service = _DiscardingCallbackService()
        app = None
        issued_token = ""

        def fail_after_issue(run: Run) -> None:
            nonlocal issued_token
            assert app is not None
            issued_token = app.collector.issue_ssrf_ticket(
                run.run_id, "candidate-before-failure", "url",
            ).token
            raise RuntimeError("post-Recon gate failed")

        app = build_local_application(
            {},
            runtime=_CallbackRuntime(service),
            ssrf_callback_service=service,
            config=OrchestratorConfig(post_recon_gate=fail_after_issue),
        )
        register_standard_agents(app, recon_max_pages=1)

        with self.assertRaises(WorkflowExecutionError) as caught:
            app.orchestrator.start(RunRequest(
                target_url="https://target.example/",
                scope=RunScope(allowed_hosts=frozenset({"target.example"})),
                request_budget=8,
            ))

        self.assertTrue(issued_token)
        self.assertEqual(service.discarded, [issued_token])
        self.assertEqual(service.tickets, {})
        self.assertEqual(app.collector._ssrf_issued, {})
        self.assertEqual(app.collector._ssrf_run_hash_keys, {})
        self.assertEqual(
            app.stores.runs.get(caught.exception.run_id).phase.value, "failed",
        )

    def test_explicit_cleanup_removes_canary_marker_url_and_review_memory(self) -> None:
        secret_url = "http://owned-canary.internal:8025/private/proof"
        secret_marker = "owned-canary-marker-terminal-2026"
        canary = SsrfCanaryProofTarget(
            url=secret_url,
            marker=secret_marker,
            surface_id="surface-1",
            operator_approved=True,
        )
        app = build_local_application({}, ssrf_canary_proof=canary)
        run = Run(
            run_id="run-cleanup",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=8,
            surface_ids=("surface-1",),
        )
        surface = Surface(
            surface_id="surface-1",
            run_id=run.run_id,
            url="https://target.example/preview?url=old",
            method="GET",
            parameters=("url",),
        )
        review = Evidence(
            evidence_id="evi-review",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={"type": "ssrf_url_fetch_review", "parameter_names": ["url"]},
        )
        app.stores.runs.add(run)
        app.stores.surfaces.add(surface)
        app.stores.evidence.append(review)
        app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id=review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-cleanup",
                surface_id=surface.surface_id,
                verification_endpoint_ref=app.ssrf_verification_endpoint_ref(
                    run.run_id, secret_url,
                ),
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
        )
        app.register_ssrf_canary_proof(run.run_id, canary)

        with self.assertRaisesRegex(
            AgentContractError, "cannot be discarded before termination",
        ):
            app.discard_ssrf_run_secrets(run.run_id)
        app.stores.runs.save(run.with_updates(phase=RunPhase.DONE))
        app.discard_ssrf_run_secrets(run.run_id)
        app.discard_ssrf_run_secrets(run.run_id)

        self.assertIsNone(app.collector.ssrf_canary_proof_for_run(run.run_id))
        self.assertIsNone(app.ssrf_reviews.get_for_run(run.run_id))
        protected_memory = repr((app.collector.__dict__, app.policy_gate.__dict__))
        self.assertNotIn(secret_url, protected_memory)
        self.assertNotIn(secret_marker, protected_memory)


if __name__ == "__main__":
    unittest.main()
