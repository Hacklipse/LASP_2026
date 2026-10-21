"""Operator-owned blind receiver A/B verification regressions."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from urllib.parse import urlsplit

from hacklipse.adapters import InMemoryBudgetManager
from hacklipse.adapters.ssrf_analysis import SSRF_OWNED_RECEIVER_CAPABILITY
from hacklipse.application.task_factory import TaskFactory
from hacklipse.bootstrap import build_local_application, register_standard_agents
from hacklipse.domain import (
    AgentResultStatus,
    Evidence,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunScope,
    SsrfDestinationPolicy,
    SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    Surface,
    ValidationReasonCode,
    ValidationVerdict,
)
from hacklipse.ports import SsrfCallbackHit, SsrfCallbackTicket


class _OwnedReceiver:
    origin = "http://owned-receiver.internal:8025"
    operator_owned = True

    def __init__(self) -> None:
        self.tickets = {}
        self.hits = {}

    def issue(self, key):
        if key not in self.tickets:
            token = f"ticket-{len(self.tickets) + 1}"
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
            source="192.0.2.10 private-source",
        ))


class _TargetRuntime:
    def __init__(self, receiver):
        self.receiver = receiver

    def execute(self, request):
        if request.request_kind is HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE:
            self.receiver.observe(next(
                value for _, value in request.query_parameters
                if value.startswith(self.receiver.origin)
            ))
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200},
        )


class SsrfOwnedReceiverTests(unittest.TestCase):
    def _run(self, *, with_policy: bool):
        receiver = _OwnedReceiver()
        budget = InMemoryBudgetManager()
        app = build_local_application(
            {}, budget_manager=budget, runtime=_TargetRuntime(receiver),
            ssrf_owned_receiver_service=receiver,
        )
        register_standard_agents(app)
        run = Run(
            run_id="run-owned", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=12,
            surface_ids=("surface-owned",),
        )
        surface = Surface(
            surface_id="surface-owned", run_id=run.run_id,
            url="https://target.example/fetch?url=old", method="GET",
            parameters=("url",),
        )
        review = Evidence(
            evidence_id="evi-owned-review", run_id=run.run_id,
            surface_id=surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={"type": "ssrf_url_fetch_review", "parameter_names": ["url"]},
        )
        app.stores.runs.add(run)
        app.stores.surfaces.add(surface)
        app.stores.evidence.append(review)
        budget.open_run(run.run_id, run.request_budget)
        policy = None
        if with_policy:
            policy = SsrfDestinationPolicy(
                policy_id="policy-owned", surface_ids=(surface.surface_id,),
                destination_origin=receiver.origin,
                destination_rule=SsrfDestinationRule.FORBIDDEN,
                assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
                source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
                source_reference="operator:owned-receiver",
                approved_by="operator-security",
                created_at=datetime.now(timezone.utc),
                evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
            )
        app.collector.register_ssrf_review(
            run_id=run.run_id, parameter="url", hint_evidence_id=review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-owned", surface_id=surface.surface_id,
                verification_endpoint_ref=app.ssrf_owned_receiver_endpoint_ref(run.run_id),
                approved_by="operator-security", approved_at=datetime.now(timezone.utc),
            ),
            destination_policy=policy,
        )
        candidate = next(
            item.candidate for item in app.orchestrator._router.route(
                run, (surface,), (review,),
            )
            if item.candidate.routing_capability_id == SSRF_OWNED_RECEIVER_CAPABILITY
        )
        app.stores.candidates.add(candidate)
        factory = TaskFactory()
        analysis = app.dispatcher.dispatch(factory.analysis(
            run, candidate, target_url=surface.url, request_budget=4,
        ))
        self.assertEqual(analysis.status, AgentResultStatus.NEEDS_EVIDENCE)
        ids = tuple(app.collector.collect(
            run.run_id, surface.url, request, task_id="collect-analysis",
            candidate_id=candidate.candidate_id,
        ) for request in analysis.evidence_requests)
        candidate = candidate.add_evidence(ids)
        app.stores.candidates.save(candidate)
        analysis = app.dispatcher.dispatch(factory.analysis(
            run, candidate, target_url=surface.url, request_budget=2,
        ))
        candidate = candidate.add_evidence(analysis.new_evidence_ids)
        app.stores.candidates.save(candidate)
        validation_id = "validation-owned"
        validation = app.dispatcher.dispatch(factory.validation(
            run, candidate, validation_id=validation_id,
            agent_type="validation", request_budget=2,
        ))
        self.assertEqual(validation.status, AgentResultStatus.NEEDS_EVIDENCE)
        ids = tuple(app.collector.collect(
            run.run_id, surface.url, request, task_id="collect-validation",
            validation_id=validation_id, candidate_id=candidate.candidate_id,
        ) for request in validation.evidence_requests)
        candidate = candidate.add_evidence(ids)
        app.stores.candidates.save(candidate)
        result = app.dispatcher.dispatch(factory.validation(
            run, candidate, validation_id=validation_id,
            agent_type="validation", request_budget=1,
        ))
        return app, receiver, result

    def test_fresh_ab_without_policy_remains_suspected_and_secret_free(self):
        app, receiver, result = self._run(with_policy=False)
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            result.validation.reason_code,
            ValidationReasonCode.SSRF_OWNED_RECEIVER_ONLY,
        )
        self.assertEqual(len({ticket.token for ticket in receiver.tickets.values()}), 2)
        serialized = repr(app.stores.evidence.list_by_run("run-owned"))
        self.assertNotIn("private-source", serialized)
        self.assertNotIn("/ssrf/ticket-", serialized)

    def test_exact_forbidden_policy_confirms_independent_owned_receiver(self):
        _, _, result = self._run(with_policy=True)
        self.assertEqual(result.validation.verdict, ValidationVerdict.CONFIRMED)
        self.assertIsNotNone(result.validation.proof)


if __name__ == "__main__":
    unittest.main()
