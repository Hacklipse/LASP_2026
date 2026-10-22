"""Bounded callback-to-internal-canary Orchestrator state regressions."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from urllib.parse import urlsplit

from hacklipse.adapters.ssrf_analysis import (
    SSRF_CALLBACK_CAPABILITY,
    SSRF_CANARY_CAPABILITY,
)
from hacklipse.application import OrchestratorConfig, RunStateMachine
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    CandidateStatus,
    DomainInvariantError,
    Evidence,
    ExecutionResult,
    HttpRequestKind,
    ReportArtifact,
    Run,
    RunPhase,
    RunScope,
    SsrfCanaryProofTarget,
    SsrfExecutionApproval,
    SsrfVerificationStrategy,
    Surface,
    ValidationReasonCode,
    ValidationResult,
    ValidationVerdict,
)
from hacklipse.ports import SsrfCallbackHit, SsrfCallbackTicket


class _CallbackOnlyValidator:
    def handle(self, task):
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=ValidationResult(
                validation_id=task.validation_id or "",
                run_id=task.run_id,
                candidate_id=task.candidate_id or "",
                verdict=ValidationVerdict.SUSPECTED,
                evidence_ids=(),
                reason="independent callback A/B observed",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_ONLY,
            ),
        )


class _Reporter:
    def handle(self, task):
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            reports=(ReportArtifact(
                report_id=f"report-{task.run_id}",
                run_id=task.run_id,
                format="markdown",
                content="# staged SSRF test\n",
            ),),
        )


class _CallbackService:
    origin = "https://callback.example"
    public_oast = False

    def __init__(self):
        self.tickets = {}
        self.hits = {}

    def issue(self, key):
        if key not in self.tickets:
            token = f"token-{len(self.tickets) + 1}"
            self.tickets[key] = SsrfCallbackTicket(
                token=token,
                url=f"{self.origin}/ssrf/{token}",
                issued_at=datetime.now(timezone.utc),
            )
        return self.tickets[key]

    def poll(self, token, *, timeout_seconds):
        return tuple(self.hits.get(token, ()))

    def discard(self, token):
        self.hits.pop(token, None)

    def observe(self, url):
        token = urlsplit(url).path.rsplit("/", 1)[-1]
        self.hits.setdefault(token, []).append(SsrfCallbackHit(
            event_id=f"event-{token}",
            token=token,
            protocol="http",
            received_at=datetime.now(timezone.utc),
            method="GET",
            source="target-server",
        ))


class _StagedRuntime:
    marker = "owned-harmless-marker-2026"

    def __init__(self, callback):
        self.callback = callback
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        if request.request_kind is HttpRequestKind.SSRF_PROBE:
            value = next(
                value for _, value in request.query_parameters
                if value.startswith(self.callback.origin)
            )
            self.callback.observe(value)
        body = (
            self.marker
            if request.request_kind is HttpRequestKind.SSRF_CANARY_PROBE
            else "ordinary control"
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "content_type": "text/plain",
                "body": body,
                "truncated": False,
            },
        )


def _application(*, budget: int, gate, planned: bool = False):
    app = build_local_application(
        {"validation": _CallbackOnlyValidator(), "report": _Reporter()},
        config=OrchestratorConfig(post_ssrf_callback_gate=gate),
        agent_allowed_tools={"validation": ("http_get",)},
    )
    candidate_id = "candidate-callback"
    run = Run(
        run_id="run-staged-ssrf",
        target_url="http://localhost/",
        scope=RunScope(allowed_hosts=frozenset({"localhost"})),
        policy_profile="safe",
        request_budget=budget,
        phase=RunPhase.VALIDATE,
        surface_ids=("surface-fetch",),
        candidate_ids=(candidate_id,),
        budget_candidate_order=(candidate_id,) if planned else (),
        budget_candidate_weights=(1,) if planned else (),
        budget_validation_reserve=1 if planned else 0,
        budget_allocation_source="heuristic" if planned else "",
    )
    app.stores.runs.add(run)
    app.stores.surfaces.add(Surface(
        surface_id="surface-fetch",
        run_id=run.run_id,
        url="http://localhost/fetch?url=old",
        method="GET",
        parameters=("url",),
        observed_query=(("url", "old"),),
    ))
    app.stores.candidates.add(Candidate(
        candidate_id=candidate_id,
        run_id=run.run_id,
        surface_id="surface-fetch",
        vulnerability_type="SSRF",
        hypothesis="server may fetch an observed URL",
        assigned_agent="ssrf_analyzer",
        evidence_ids=(),
        status=CandidateStatus.ANALYZED,
    ))
    app.budget_manager.open_run(run.run_id, budget)
    return app, run


class SsrfStagedOrchestrationTests(unittest.TestCase):
    def test_callback_ab_adds_distinct_internal_canary_candidate(self):
        callback = _CallbackService()
        runtime = _StagedRuntime(callback)
        app = None
        gate_calls = []

        def gate(current):
            gate_calls.append(current.phase)
            canary = SsrfCanaryProofTarget(
                url="http://service.internal:8025/proof",
                marker=runtime.marker,
                surface_id="surface-fetch",
                operator_approved=True,
            )
            app.collector.register_ssrf_review(
                run_id=current.run_id,
                parameter="url",
                hint_evidence_id="evi-review",
                approval=SsrfExecutionApproval(
                    approval_id="approval-canary",
                    surface_id="surface-fetch",
                    verification_endpoint_ref=app.ssrf_verification_endpoint_ref(
                        current.run_id, canary.url,
                    ),
                    approved_by="operator-test",
                    approved_at=datetime.now(timezone.utc),
                ),
                destination_policy=None,
                approved_destination_url=canary.url,
                verification_strategy=SsrfVerificationStrategy.INTERNAL_CANARY,
            )
            app.register_ssrf_canary_proof(current.run_id, canary)
            return True

        app = build_local_application(
            {},
            runtime=runtime,
            ssrf_callback_service=callback,
            router=standard_router(
                ("SSRF",), ssrf_callback_service=callback,
            ),
            config=OrchestratorConfig(post_ssrf_callback_gate=gate),
        )
        register_standard_agents(app)
        run = Run(
            run_id="run-staged-e2e",
            target_url="http://localhost/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe",
            request_budget=12,
            phase=RunPhase.ROUTE,
            surface_ids=("surface-fetch",),
            evidence_ids=("evi-review",),
        )
        surface = Surface(
            surface_id="surface-fetch",
            run_id=run.run_id,
            url="http://localhost/fetch?url=old",
            method="GET",
            parameters=("url",),
            observed_query=(("url", "old"),),
        )
        review = Evidence(
            evidence_id="evi-review",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        )
        app.stores.runs.add(run)
        app.stores.surfaces.add(surface)
        app.stores.evidence.append(review)
        app.budget_manager.open_run(run.run_id, run.request_budget)
        app.collector.register_ssrf_review(
            run_id=run.run_id,
            parameter="url",
            hint_evidence_id=review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-callback",
                surface_id=surface.surface_id,
                verification_endpoint_ref="callback-local-test",
                approved_by="operator-test",
                approved_at=datetime.now(timezone.utc),
            ),
            destination_policy=None,
            verification_strategy=SsrfVerificationStrategy.CALLBACK,
        )

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertEqual(gate_calls, [RunPhase.SSRF_REVIEW])
        self.assertEqual(completed.ssrf_followup_rounds, 1)
        candidates = app.stores.candidates.list_by_run(run.run_id)
        by_capability = {
            candidate.routing_capability_id: candidate for candidate in candidates
        }
        self.assertEqual(
            set(by_capability),
            {SSRF_CALLBACK_CAPABILITY, SSRF_CANARY_CAPABILITY},
        )
        self.assertIs(
            by_capability[SSRF_CALLBACK_CAPABILITY].status,
            CandidateStatus.SUSPECTED,
        )
        self.assertIs(
            by_capability[SSRF_CANARY_CAPABILITY].status,
            CandidateStatus.SUSPECTED,
        )
        self.assertEqual(
            sum(request.request_kind is HttpRequestKind.SSRF_PROBE
                for request in runtime.requests),
            2,
        )
        self.assertEqual(
            sum(request.request_kind is HttpRequestKind.SSRF_CANARY_PROBE
                for request in runtime.requests),
            2,
        )

    def test_callback_only_enters_one_review_stage_then_reports_on_skip(self):
        calls = []

        def gate(run):
            calls.append(run.phase)
            return False

        app, run = _application(budget=4, gate=gate)

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertEqual(calls, [RunPhase.SSRF_REVIEW])
        self.assertEqual(completed.ssrf_followup_rounds, 1)
        candidate = app.stores.candidates.get(run.run_id, "candidate-callback")
        self.assertIs(candidate.status, CandidateStatus.SUSPECTED)
        self.assertIs(
            candidate.validation_reason_code,
            ValidationReasonCode.SSRF_CALLBACK_ONLY,
        )

    def test_followup_budget_floor_is_checked_before_prompt(self):
        calls = []
        app, run = _application(
            budget=3,
            gate=lambda current: calls.append(current.run_id) or True,
        )

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertEqual(calls, [])
        self.assertEqual(completed.ssrf_followup_rounds, 0)

    def test_resumed_followup_route_checks_proof_readiness_before_routing(self):
        calls = []
        app, run = _application(
            budget=4,
            gate=lambda current: calls.append(current.phase) or False,
        )
        resumed = run.with_updates(
            phase=RunPhase.ROUTE,
            ssrf_followup_rounds=1,
        )
        app.stores.runs.save(resumed)

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertEqual(calls, [RunPhase.ROUTE])
        self.assertIs(
            app.stores.candidates.get(run.run_id, "candidate-callback").status,
            CandidateStatus.ANALYZED,
        )

    def test_resumed_followup_analysis_and_validation_restore_proof_first(self):
        for phase, status in (
            (RunPhase.ANALYZE, CandidateStatus.ROUTED),
            (RunPhase.VALIDATE, CandidateStatus.ANALYZED),
        ):
            with self.subTest(phase=phase.value):
                calls = []
                app, run = _application(
                    budget=4,
                    gate=lambda current: calls.append(current.phase) or False,
                )
                canary_id = f"candidate-canary-{phase.value}"
                app.stores.candidates.add(Candidate(
                    candidate_id=canary_id,
                    run_id=run.run_id,
                    surface_id="surface-fetch",
                    vulnerability_type="SSRF",
                    hypothesis="approved internal canary follow-up",
                    assigned_agent="ssrf_analyzer",
                    evidence_ids=(),
                    status=status,
                    exploration_parameters=("url",),
                    routing_capability_id=SSRF_CANARY_CAPABILITY,
                ))
                resumed = run.with_updates(
                    phase=phase,
                    candidate_ids=(*run.candidate_ids, canary_id),
                    ssrf_followup_rounds=1,
                )
                app.stores.runs.save(resumed)

                completed = app.orchestrator.resume(run.run_id)

                self.assertIs(completed.phase, RunPhase.DONE)
                self.assertEqual(calls, [phase])
                self.assertIs(
                    app.stores.candidates.get(run.run_id, canary_id).status,
                    status,
                )

    def test_unknown_or_mixed_candidate_type_does_not_open_followup_gate(self):
        cases = (
            ("ssrf.internal_canary_lookalike", ""),
            (SSRF_CALLBACK_CAPABILITY, "observed_url_internal_canary_probe"),
        )
        for capability, analysis_strategy in cases:
            with self.subTest(
                capability=capability, analysis_strategy=analysis_strategy,
            ):
                app, run = _application(budget=4, gate=lambda current: True)
                candidate_id = "candidate-invalid-typed-contract"
                app.stores.candidates.add(Candidate(
                    candidate_id=candidate_id,
                    run_id=run.run_id,
                    surface_id="surface-fetch",
                    vulnerability_type="SSRF",
                    hypothesis="unsupported typed contract",
                    assigned_agent="ssrf_analyzer",
                    evidence_ids=(),
                    status=CandidateStatus.ROUTED,
                    exploration_parameters=("url",),
                    routing_capability_id=capability,
                    analysis_strategy_id=analysis_strategy,
                ))
                resumed = run.with_updates(
                    phase=RunPhase.ANALYZE,
                    candidate_ids=(*run.candidate_ids, candidate_id),
                    ssrf_followup_rounds=1,
                )

                self.assertFalse(
                    app.orchestrator._ssrf_followup_requires_readiness(resumed)
                )

    def test_resumed_followup_analysis_without_gate_reports_safely(self):
        app, run = _application(budget=4, gate=None)
        canary_id = "candidate-canary-no-gate"
        app.stores.candidates.add(Candidate(
            candidate_id=canary_id,
            run_id=run.run_id,
            surface_id="surface-fetch",
            vulnerability_type="SSRF",
            hypothesis="approved internal canary follow-up",
            assigned_agent="ssrf_analyzer",
            evidence_ids=(),
            status=CandidateStatus.ROUTED,
            exploration_parameters=("url",),
            routing_capability_id=SSRF_CANARY_CAPABILITY,
        ))
        resumed = run.with_updates(
            phase=RunPhase.ANALYZE,
            candidate_ids=(*run.candidate_ids, canary_id),
            ssrf_followup_rounds=1,
        )
        app.stores.runs.save(resumed)

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertIs(
            app.stores.candidates.get(run.run_id, canary_id).status,
            CandidateStatus.ROUTED,
        )

    def test_approved_gate_clears_stale_plan_and_does_not_revalidate_terminal_candidate(self):
        calls = []
        app, run = _application(
            budget=4,
            gate=lambda current: calls.append(current.phase) or True,
            planned=True,
        )

        completed = app.orchestrator.resume(run.run_id)

        self.assertIs(completed.phase, RunPhase.DONE)
        self.assertEqual(calls, [RunPhase.SSRF_REVIEW])
        self.assertEqual(completed.ssrf_followup_rounds, 1)
        self.assertEqual(completed.budget_candidate_order, ())
        self.assertEqual(completed.budget_candidate_weights, ())
        self.assertEqual(completed.budget_validation_reserve, 0)

    def test_state_machine_allows_only_bounded_review_edges(self):
        machine = RunStateMachine()
        validating = Run(
            run_id="run-state",
            target_url="http://localhost/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe",
            request_budget=4,
            phase=RunPhase.VALIDATE,
        )
        review = machine.transition(validating, RunPhase.SSRF_REVIEW)
        self.assertIs(machine.transition(review, RunPhase.ROUTE).phase, RunPhase.ROUTE)
        with self.assertRaises(DomainInvariantError):
            machine.transition(review, RunPhase.ANALYZE)


if __name__ == "__main__":
    unittest.main()
