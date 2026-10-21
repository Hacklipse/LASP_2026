"""Network-free callback/internal-canary strategy separation regressions."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from hacklipse.adapters import (
    InMemoryBudgetManager,
    InMemorySsrfReviewRegistry,
    MemoryStoreBundle,
)
from hacklipse.adapters.ssrf_analysis import (
    SSRF_CALLBACK_CAPABILITY,
    SSRF_CANARY_CAPABILITY,
    SSRF_RESULT_TYPE,
)
from hacklipse.application.task_factory import TaskFactory
from hacklipse.application.errors import AgentContractError
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application, register_standard_agents
from hacklipse.domain import (
    AgentResultStatus,
    Evidence,
    ExecutionResult,
    HttpRequestKind,
    Run,
    RunScope,
    SsrfCanaryProofTarget, SsrfDestinationPolicy, SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfPolicyAssertion, SsrfPolicyEvidenceStatus, SsrfPolicySource,
    SsrfReviewRegistration,
    Surface,
    ValidationReasonCode, ValidationVerdict,
)
from hacklipse.ports.errors import BudgetExceeded


class _CanaryRuntime:
    marker = "owned-harmless-marker-2026"

    def __init__(self) -> None:
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        body = self.marker if (
            request.request_kind is HttpRequestKind.SSRF_CANARY_PROBE
        ) else "ordinary control"
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


class _IssueFailingCallback:
    origin = "https://callback.example"

    def issue(self, key):
        raise OSError("callback provider unavailable")

    def poll(self, token, *, timeout_seconds):
        raise AssertionError("canary strategy must not poll callback provider")


class _ErrorMarkerRuntime(_CanaryRuntime):
    def execute(self, request):
        result = super().execute(request)
        if request.request_kind is not HttpRequestKind.SSRF_CANARY_PROBE:
            return result
        return ExecutionResult(
            execution_id=result.execution_id,
            evidence_type="http_response",
            observation={**result.observation, "status": 500},
        )


class SsrfStrategySeparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = _CanaryRuntime()
        self.budget = InMemoryBudgetManager()
        self.canary = SsrfCanaryProofTarget(
            url="http://owned-canary.internal:8025/proof",
            marker=self.runtime.marker,
            surface_id="surface-1",
            operator_approved=True,
        )
        self.run = Run(
            run_id="run-1",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=12,
            surface_ids=("surface-1",),
        )
        self.surface = Surface(
            surface_id="surface-1",
            run_id=self.run.run_id,
            url="https://target.example/preview?url=old",
            method="GET",
            parameters=("url",),
        )
        self.review = Evidence(
            evidence_id="evi-review",
            run_id=self.run.run_id,
            surface_id=self.surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        )

    def _app(
        self, callback=None, *, policy=None, verification_endpoint_ref=None,
    ):
        app = build_local_application(
            {},
            budget_manager=self.budget,
            runtime=self.runtime,
            ssrf_callback_service=callback,
            ssrf_canary_proof=self.canary,
        )
        register_standard_agents(app)
        app.stores.runs.add(self.run)
        app.stores.surfaces.add(self.surface)
        app.stores.evidence.append(self.review)
        self.budget.open_run(self.run.run_id, self.run.request_budget)
        app.collector.register_ssrf_review(
            run_id=self.run.run_id,
            parameter="url",
            hint_evidence_id=self.review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-1",
                surface_id=self.surface.surface_id,
                verification_endpoint_ref=(
                    verification_endpoint_ref
                    or app.ssrf_verification_endpoint_ref(
                        self.run.run_id, self.canary.url,
                    )
                ),
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            destination_policy=policy,
        )
        return app

    def _policy(
        self, *, origin="http://owned-canary.internal:8025",
        rule=SsrfDestinationRule.FORBIDDEN,
    ):
        return SsrfDestinationPolicy(
            policy_id="policy-1",
            surface_ids=(self.surface.surface_id,),
            destination_origin=origin,
            destination_rule=rule,
            assertion=(
                SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION
                if rule is SsrfDestinationRule.FORBIDDEN
                else SsrfPolicyAssertion.TARGET_MAY_REACH_DESTINATION
            ),
            source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:policy-1",
            approved_by="operator-security",
            created_at=datetime.now(timezone.utc),
            evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
        )

    def _complete_canary(self, app):
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)
        factory = TaskFactory()
        analysis = app.dispatcher.dispatch(factory.analysis(
            self.run, candidate, target_url=self.surface.url, request_budget=4,
        ))
        candidate = candidate.add_evidence(self._collect(
            app, candidate, analysis.evidence_requests,
        ))
        app.stores.candidates.save(candidate)
        analysis = app.dispatcher.dispatch(factory.analysis(
            self.run, candidate, target_url=self.surface.url, request_budget=2,
        ))
        candidate = candidate.add_evidence(analysis.new_evidence_ids)
        app.stores.candidates.save(candidate)
        validation_id = "validation-1"
        validation = app.dispatcher.dispatch(factory.validation(
            self.run, candidate, validation_id=validation_id,
            agent_type="validation", request_budget=2,
        ))
        candidate = candidate.add_evidence(self._collect(
            app, candidate, validation.evidence_requests,
            validation_id=validation_id,
        ))
        app.stores.candidates.save(candidate)
        return app.dispatcher.dispatch(factory.validation(
            self.run, candidate, validation_id=validation_id,
            agent_type="validation", request_budget=0,
        ))

    def _canary_candidate(self, app):
        decisions = app.orchestrator._router.route(
            self.run, (self.surface,), (self.review,),
        )
        return next(
            item.candidate for item in decisions
            if item.candidate.routing_capability_id == SSRF_CANARY_CAPABILITY
        )

    def _collect(self, app, candidate, requests, *, validation_id=None):
        ids = []
        for request in requests:
            ids.append(app.collector.collect(
                self.run.run_id,
                self.surface.url,
                request,
                task_id="collection-task",
                candidate_id=candidate.candidate_id,
                validation_id=validation_id,
            ))
        return tuple(ids)

    def test_callback_and_canary_route_as_distinct_candidates(self) -> None:
        app = self._app(_IssueFailingCallback())
        decisions = app.orchestrator._router.route(
            self.run, (self.surface,), (self.review,),
        )
        ids = {
            item.candidate.routing_capability_id
            for item in decisions
            if item.candidate.vulnerability_type == "SSRF"
        }
        self.assertEqual(ids, {SSRF_CALLBACK_CAPABILITY, SSRF_CANARY_CAPABILITY})

    def test_canary_analysis_and_validation_need_no_callback_provider(self) -> None:
        app = self._app()
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)
        factory = TaskFactory()

        first = app.dispatcher.dispatch(factory.analysis(
            self.run, candidate, target_url=self.surface.url, request_budget=4,
        ))
        self.assertEqual(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(
            tuple(item.http_request.request_kind for item in first.evidence_requests),
            (HttpRequestKind.SSRF_CONTROL, HttpRequestKind.SSRF_CANARY_PROBE),
        )
        candidate = candidate.add_evidence(self._collect(
            app, candidate, first.evidence_requests,
        ))
        app.stores.candidates.save(candidate)
        second = app.dispatcher.dispatch(factory.analysis(
            self.run, candidate, target_url=self.surface.url, request_budget=2,
        ))
        candidate = candidate.add_evidence(second.new_evidence_ids)
        app.stores.candidates.save(candidate)
        result = next(
            item for item in app.stores.evidence.get_many(
                self.run.run_id, second.new_evidence_ids,
            )
            if item.observation.get("type") == SSRF_RESULT_TYPE
        )
        self.assertEqual(result.observation["strategy_id"],
                         "observed_url_internal_canary_probe")

        validation_id = "validation-1"
        validation = app.dispatcher.dispatch(factory.validation(
            self.run,
            candidate,
            validation_id=validation_id,
            agent_type="validation",
            request_budget=2,
        ))
        self.assertEqual(validation.status, AgentResultStatus.NEEDS_EVIDENCE)
        candidate = candidate.add_evidence(self._collect(
            app, candidate, validation.evidence_requests,
            validation_id=validation_id,
        ))
        app.stores.candidates.save(candidate)
        validation = app.dispatcher.dispatch(factory.validation(
            self.run,
            candidate,
            validation_id=validation_id,
            agent_type="validation",
            request_budget=0,
        ))
        self.assertEqual(validation.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            validation.validation.reason_code,
            ValidationReasonCode.SSRF_DESTINATION_POLICY_MISSING,
        )
        self.assertEqual(app.collector.ssrf_callback_usage, (0, 0))

    def test_callback_failure_does_not_touch_canary_strategy(self) -> None:
        app = self._app(_IssueFailingCallback())
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)
        result = app.dispatcher.dispatch(TaskFactory().analysis(
            self.run, candidate, target_url=self.surface.url, request_budget=4,
        ))
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(app.collector.ssrf_callback_usage, (0, 0))

    def test_canary_analysis_reserves_two_validation_requests(self) -> None:
        app = self._app()
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)
        with self.assertRaises(BudgetExceeded):
            app.dispatcher.dispatch(TaskFactory().analysis(
                self.run, candidate, target_url=self.surface.url, request_budget=3,
            ))

    def test_central_validation_reserve_is_not_reserved_twice(self) -> None:
        app = self._app()
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)
        result = app.dispatcher.dispatch(TaskFactory().analysis(
            self.run,
            candidate,
            target_url=self.surface.url,
            request_budget=2,
            validation_request_reserve=2,
        ))
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(result.evidence_requests), 2)

    def test_canary_endpoint_must_match_the_exact_execution_approval(self) -> None:
        app = self._app(verification_endpoint_ref="endpoint-another-service")
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)
        with self.assertRaises(AgentContractError):
            app.dispatcher.dispatch(TaskFactory().analysis(
                self.run, candidate, target_url=self.surface.url, request_budget=4,
            ))
        self.assertEqual(self.runtime.requests, [])

    def test_default_canary_requires_exact_approved_endpoint_reference(self) -> None:
        registry = InMemorySsrfReviewRegistry()
        registry.register(SsrfReviewRegistration(
            run_id=self.run.run_id,
            parameter="url",
            hint_evidence_id=self.review.evidence_id,
            execution_approval=SsrfExecutionApproval(
                approval_id="approval-1",
                surface_id=self.surface.surface_id,
                verification_endpoint_ref="endpoint-approved-for-another-canary",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
        ))
        app = build_local_application(
            {}, budget_manager=self.budget, runtime=self.runtime,
            ssrf_canary_proof=self.canary,
            ssrf_review_registry=registry,
        )
        register_standard_agents(app)
        app.stores.runs.add(self.run)
        app.stores.surfaces.add(self.surface)
        app.stores.evidence.append(self.review)
        self.budget.open_run(self.run.run_id, self.run.request_budget)
        candidate = self._canary_candidate(app)
        app.stores.candidates.add(candidate)

        with self.assertRaises(AgentContractError):
            app.dispatcher.dispatch(TaskFactory().analysis(
                self.run, candidate, target_url=self.surface.url,
                request_budget=4,
            ))

        self.assertEqual(self.runtime.requests, [])

    def test_exact_forbidden_policy_is_required_for_confirmation(self) -> None:
        exact = self._complete_canary(self._app(policy=self._policy()))
        self.assertEqual(exact.validation.verdict, ValidationVerdict.CONFIRMED)
        self.assertEqual(
            exact.validation.reason_code,
            ValidationReasonCode.SSRF_CONFIRMED_DESTINATION_POLICY_VIOLATION,
        )
        self.assertNotIn(self.canary.url, exact.validation.proof.summary)

    def test_wrong_origin_policy_does_not_confirm(self) -> None:
        result = self._complete_canary(self._app(policy=self._policy(
            origin="http://different-canary.internal:8025",
        )))
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            result.validation.reason_code,
            ValidationReasonCode.SSRF_DESTINATION_POLICY_ORIGIN_MISMATCH,
        )

    def test_allowed_destination_policy_is_normal_behavior(self) -> None:
        result = self._complete_canary(self._app(policy=self._policy(
            rule=SsrfDestinationRule.ALLOWED,
        )))
        self.assertEqual(result.validation.verdict, ValidationVerdict.REJECTED)
        self.assertEqual(
            result.validation.reason_code,
            ValidationReasonCode.SSRF_DESTINATION_POLICY_ALLOWS_ACCESS,
        )

    def test_marker_on_server_error_page_never_confirms(self) -> None:
        self.runtime = _ErrorMarkerRuntime()
        result = self._complete_canary(self._app(policy=self._policy()))
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            result.validation.reason_code,
            ValidationReasonCode.SSRF_CANARY_ANALYSIS_NOT_ESTABLISHED,
        )
        self.assertIsNone(result.validation.proof)

    def test_structured_policy_registration_round_trips_all_bindings(self) -> None:
        stores = MemoryStoreBundle()
        app = build_local_application(
            {}, stores=stores, runtime=self.runtime,
            ssrf_canary_proof=self.canary,
        )
        stores.runs.add(self.run)
        stores.surfaces.add(self.surface)
        stores.evidence.append(self.review)
        policy = self._policy()
        app.collector.register_ssrf_review(
            run_id=self.run.run_id,
            parameter="url",
            hint_evidence_id=self.review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-1",
                surface_id=self.surface.surface_id,
                verification_endpoint_ref=app.ssrf_verification_endpoint_ref(
                    self.run.run_id, self.canary.url,
                ),
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            destination_policy=policy,
        )
        persisted = next(
            item for item in stores.evidence.list_by_run(self.run.run_id)
            if item.observation.get("type") == "ssrf_review_registration"
        )
        self.assertEqual(persisted.observation["policy_surface_ids"], ["surface-1"])
        self.assertEqual(
            persisted.observation["destination_origin"],
            "http://owned-canary.internal:8025",
        )
        self.assertEqual(
            persisted.observation["policy_assertion"],
            "target_must_not_reach_destination",
        )
        self.assertEqual(persisted.observation["policy_evidence_status"], "attested")

        restarted = build_local_application(
            {}, stores=stores, runtime=self.runtime,
            ssrf_canary_proof=self.canary,
        )
        restored = restarted.collector.restore_ssrf_review(self.run.run_id)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.destination_policy, policy)


if __name__ == "__main__":
    unittest.main()
