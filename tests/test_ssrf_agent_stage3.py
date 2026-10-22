"""SSRF routing and two fresh callback tokens never imply a confirmed Finding."""

from __future__ import annotations

import unittest
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from hacklipse.adapters import (
    InMemoryBudgetManager,
    InMemoryServerRequestObservationProvider,
    MemoryStoreBundle,
)
from hacklipse.adapters.analyzer_capabilities import (
    OPTIONAL_SSRF_CAPABILITIES, capability_missing_requirements,
)
from hacklipse.adapters.ssrf_analysis import SSRF_ANALYZER
from hacklipse.application import OrchestratorConfig
from hacklipse.application.task_factory import TaskFactory
from hacklipse.bootstrap import (
    build_local_application, register_standard_agents, standard_router,
)
from hacklipse.domain import (
    AgentResultStatus, CandidateStatus, ExecutionResult, HttpRequestKind,
    DestinationPolicy, Evidence, Run, RunPhase, RunRequest, RunScope,
    SsrfCanaryProofTarget, SsrfDestinationRule, SsrfPolicySource, Surface,
    SsrfExecutionApproval, SsrfVerificationStrategy,
    ValidationProofType, ValidationReasonCode, ValidationVerdict,
)
from hacklipse.ports import SsrfCallbackHit, SsrfCallbackTicket
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.ports.llm import LlmResponse


class _Service:
    origin = "https://callback.example"
    public_oast = False

    def __init__(self) -> None:
        self.tickets: dict[str, SsrfCallbackTicket] = {}
        self.hits: dict[str, list[SsrfCallbackHit]] = {}
        self.poll_deadlines: list[float] = []

    def issue(self, key: str) -> SsrfCallbackTicket:
        if key not in self.tickets:
            number = len(self.tickets) + 1
            self.tickets[key] = SsrfCallbackTicket(
                token=f"token-{number}", url=f"{self.origin}/token-{number}",
                issued_at=datetime.now(timezone.utc),
            )
        return self.tickets[key]

    def poll(self, token: str, *, timeout_seconds: float):
        self.poll_deadlines.append(timeout_seconds)
        return tuple(self.hits.get(token, ()))

    def record(self, token: str, *, protocol: str = "http") -> None:
        self.hits.setdefault(token, []).append(SsrfCallbackHit(
            event_id=f"event-{len(self.hits[token]) + 1}", token=token,
            protocol=protocol, method="GET" if protocol == "http" else "",
            received_at=datetime.now(timezone.utc), source="192.0.2.10",
        ))


class _FailingService(_Service):
    def poll(self, token: str, *, timeout_seconds: float):
        raise TimeoutError("callback provider unavailable")


class _IssueFailingService(_Service):
    def issue(self, key: str) -> SsrfCallbackTicket:
        raise OSError("callback provider unavailable")


class _Runtime:
    def __init__(self, service: _Service, *, reproduce: bool = True) -> None:
        self.service = service
        self.reproduce = reproduce
        self.protocol = "http"
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        body = (
            '<a href="/preview?url=old&mode=small">Preview</a>'
            if urlsplit(request.resolved_url).path == "/" else "ok"
        )
        if request.request_kind is HttpRequestKind.SSRF_PROBE:
            value = next(value for name, value in request.query_parameters if name == "url")
            token = value.rsplit("/", 1)[-1]
            if self.reproduce or len([item for item in self.requests
                                      if item.request_kind is HttpRequestKind.SSRF_PROBE]) == 1:
                self.service.record(token, protocol=self.protocol)
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": body},
        )


class _TwoFieldRuntime(_Runtime):
    def execute(self, request):
        self.requests.append(request)
        body = (
            '<a href="/preview?url=old&image_url=old&mode=small">Preview</a>'
            if urlsplit(request.resolved_url).path == "/" else "ok"
        )
        if request.request_kind is HttpRequestKind.SSRF_PROBE:
            callback = next((value for name, value in request.query_parameters
                             if name == "image_url"), "")
            if callback.startswith(self.service.origin):
                self.service.record(callback.rsplit("/", 1)[-1])
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": body},
        )


class _CanaryRuntime(_Runtime):
    marker = "harmless-canary-marker-8d77f0a9"

    def __init__(self, service: _Service, *, can_reach_canary: bool) -> None:
        super().__init__(service)
        self.can_reach_canary = can_reach_canary

    def execute(self, request):
        result = super().execute(request)
        if request.request_kind is not HttpRequestKind.SSRF_CANARY_PROBE:
            return result
        return ExecutionResult(
            execution_id=result.execution_id, evidence_type="http_response",
            observation={**result.observation,
                         "body": (self.marker if self.can_reach_canary else "denied"),
                         "truncated": False},
        )


class _LeakyControlRuntime(_CanaryRuntime):
    def execute(self, request):
        result = super().execute(request)
        if request.request_kind is not HttpRequestKind.SSRF_CONTROL:
            return result
        return ExecutionResult(
            execution_id=result.execution_id, evidence_type="http_response",
            observation={**result.observation, "body": self.marker, "truncated": False},
        )


class _ToolLlm:
    def __init__(self, *, invented: bool = False) -> None:
        self.calls = []
        self.invented = invented

    def complete(self, request):
        self.calls.append(request)
        context = json.loads(request.messages[0].content)
        if self.invented:
            action = ({"tool": "get_surface_context"}
                      if len(self.calls) == 1 else
                      {"tool": "probe_observed_url_input", "parameter": "invented"})
        elif context["attempted_count"] == 0:
            action = ({"tool": "get_surface_context"}
                      if context["tool_result"] is None else
                      {"tool": "probe_observed_url_input", "parameter": "url"})
        elif context["tool_result"] is None:
            action = {"tool": "read_probe_result",
                      "evidence_id": context["last_result_evidence_id"]}
        else:
            action = {"tool": "probe_observed_url_input", "parameter": "image_url"}
        return LlmResponse(payload=action, model="fake-ssrf")


class SsrfStage3Tests(unittest.TestCase):
    @staticmethod
    def _destination_policy(surface_id: str = "surface-1") -> DestinationPolicy:
        return DestinationPolicy(
            policy_id=f"policy:{surface_id}",
            surface_id=surface_id,
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:ssrf-canary-denied-v1",
            approved_by="operator:security-team",
            created_at=datetime(2026, 10, 21, tzinfo=timezone.utc),
        )

    def setUp(self) -> None:
        self.service = _Service()
        self.runtime = _Runtime(self.service)
        self.stores = MemoryStoreBundle()
        self.budget = InMemoryBudgetManager()
        self.app = build_local_application(
            {}, stores=self.stores, budget_manager=self.budget,
            runtime=self.runtime, ssrf_callback_service=self.service,
        )
        register_standard_agents(self.app)
        self.run = Run(
            run_id="run-1", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=10,
        )
        self.surface = Surface(
            surface_id="surface-1", run_id=self.run.run_id,
            url="https://target.example/preview?url=old&mode=small",
            method="GET", parameters=("url", "mode"),
        )
        self.stores.runs.add(self.run)
        self.stores.surfaces.add(self.surface)
        self.budget.open_run(self.run.run_id, 10)
        self.factory = TaskFactory()
        decisions = standard_router(ssrf_callback_service=self.service).route(
            self.run, (self.surface,), (),
        )
        self.candidate = next(item.candidate for item in decisions
                              if item.candidate.assigned_agent == SSRF_ANALYZER)
        self.stores.candidates.add(self.candidate)

    def _collect(self, requests, *, validation_id=None):
        ids = []
        for request in requests:
            task = self.factory.evidence_collection(
                self.run, self.candidate, request, target_url=self.surface.url,
                agent_type="evidence_collector", request_budget=10,
                validation_id=validation_id,
            )
            ids.extend(self.app.dispatcher.dispatch(task).new_evidence_ids)
        self.candidate = self.candidate.add_evidence(ids)
        self.stores.candidates.save(self.candidate)

    def _analysis(self):
        task = self.factory.analysis(
            self.run, self.candidate, target_url=self.surface.url,
            request_budget=10,
        )
        result = self.app.dispatcher.dispatch(task)
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(result.evidence_requests), 2)
        self._collect(result.evidence_requests)
        task = self.factory.analysis(
            self.run, self.candidate, target_url=self.surface.url,
            request_budget=8,
        )
        result = self.app.dispatcher.dispatch(task)
        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        self.candidate = self.candidate.add_evidence(result.new_evidence_ids)
        self.stores.candidates.save(self.candidate)
        return result

    def _validation(self):
        validation_id = "validation-1"
        task = self.factory.validation(
            self.run, self.candidate, validation_id=validation_id,
            agent_type="validation", request_budget=8,
        )
        result = self.app.dispatcher.dispatch(task)
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(result.evidence_requests), 2)
        self._collect(result.evidence_requests, validation_id=validation_id)
        task = self.factory.validation(
            self.run, self.candidate, validation_id=validation_id,
            agent_type="validation", request_budget=6,
        )
        return self.app.dispatcher.dispatch(task)

    def test_router_is_off_without_service(self) -> None:
        decisions = standard_router().route(self.run, (self.surface,), ())
        self.assertFalse(any(item.candidate.assigned_agent == SSRF_ANALYZER
                             for item in decisions))

    def test_provider_issue_failure_blocks_candidate_without_failing_run(self) -> None:
        service = _IssueFailingService()
        app = build_local_application(
            {}, runtime=_Runtime(service), ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, CandidateStatus.BLOCKED)
        self.assertEqual(run.finding_ids, ())

    def test_schema_only_name_is_not_a_replayable_ssrf_coordinate(self) -> None:
        surface = Surface(
            surface_id="schema-only", run_id=self.run.run_id,
            url="https://target.example/preview", method="GET",
            parameters=("url",), discovery_types=("openapi_schema",),
        )
        decisions = standard_router(("SSRF",), ssrf_callback_service=self.service).route(
            self.run, (surface,), (),
        )
        self.assertEqual(decisions, ())
        self.assertIn("observed_query_parameter", capability_missing_requirements(
            OPTIONAL_SSRF_CAPABILITIES[0], surface,
        ))

    def test_untrusted_legacy_workflow_label_cannot_route_probe(self) -> None:
        surface = Surface(
            surface_id="legacy-flow", run_id=self.run.run_id,
            url="https://target.example/operations/execute", method="POST",
            parameters=("url",),
        )
        claimed = Evidence(
            evidence_id="claimed-flow", run_id=self.run.run_id,
            surface_id=surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={"type": "javascript_model_download_workflow",
                         "method": "POST", "body_parameter_names": ["url"]},
        )
        decisions = standard_router(
            ("SSRF",), ssrf_owned_receiver_enabled=True,
        ).route(self.run, (surface,), (claimed,))
        self.assertEqual(decisions, ())

    def test_declared_get_query_routes_and_reproduces_without_claiming_proof(self) -> None:
        surface = Surface(
            surface_id="schema-only", run_id=self.run.run_id,
            url="https://target.example/api/fetch", method="GET",
            parameters=("url", "token"), discovery_types=("openapi_schema",),
        )
        shape = Evidence(
            evidence_id="schema-shape", run_id=self.run.run_id,
            surface_id=surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={"type": "openapi_request_structure", "method": "GET",
                         "query_parameter_names": ["url"],
                         "body_parameter_names": ["token"],
                         "request_template_available": False},
        )
        self.stores.surfaces.add(surface)
        self.stores.evidence.append(shape)
        router = standard_router(("SSRF",), ssrf_callback_service=self.service)
        decisions = router.route(self.run, (surface,), (shape,))
        self.assertEqual(len(decisions), 1)
        self.assertEqual(
            next(item.status for item in router.last_analyzer_coverage
                 if item.capability_id == "ssrf.callback_declared_url_query"),
            "routable",
        )
        self.surface = surface
        self.candidate = decisions[0].candidate
        self.stores.candidates.add(self.candidate)
        self._analysis()
        result = next(
            item for item in self.stores.evidence.list_by_run(self.run.run_id)
            if item.observation.get("type") == "ssrf_probe_result"
            and item.surface_id == surface.surface_id
        )
        self.assertEqual(result.observation["coordinate_source"], "openapi_declaration")
        validation = self._validation()
        self.assertEqual(validation.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(len(self.runtime.requests), 4)
        self.assertTrue(all(
            {name for name, _ in request.query_parameters} == {"url"}
            for request in self.runtime.requests
        ))

    def test_body_only_declaration_does_not_route(self) -> None:
        surface = Surface(
            surface_id="body-only", run_id=self.run.run_id,
            url="https://target.example/api/fetch", method="GET",
            parameters=("url",), discovery_types=("openapi_schema",),
        )
        shape = Evidence(
            evidence_id="body-shape", run_id=self.run.run_id,
            surface_id=surface.surface_id, created_by="recon",
            evidence_type="observation",
            observation={"type": "openapi_request_structure", "method": "GET",
                         "query_parameter_names": [], "body_parameter_names": ["url"]},
        )
        router = standard_router(("SSRF",), ssrf_callback_service=self.service)
        self.assertEqual(router.route(self.run, (surface,), (shape,)), ())

    def test_analysis_and_validation_use_fresh_tokens_but_do_not_confirm(self) -> None:
        analysis = self._analysis()
        self.assertEqual(len(analysis.new_evidence_ids), 2)
        validation = self._validation()
        self.assertEqual(validation.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertIsNone(validation.validation.proof)
        self.assertEqual(validation.validation.reason_code,
                         ValidationReasonCode.SSRF_CALLBACK_ONLY)
        self.assertEqual(len(validation.new_evidence_ids), 1)
        self.assertEqual(len(self.service.tickets), 2)
        self.assertEqual(len(self.runtime.requests), 4)
        self.assertTrue(all(timeout <= 2.0 for timeout in self.service.poll_deadlines))
        for item in self.stores.evidence.get_many(self.run.run_id, validation.validation.evidence_ids):
            self.assertEqual(item.validation_id, "validation-1")

    def test_review_registration_without_observation_provider_keeps_callback_path(self) -> None:
        self.run = self.run.with_updates(surface_ids=(self.surface.surface_id,))
        self.stores.runs.save(self.run)
        review = Evidence(
            evidence_id="evi-review", run_id=self.run.run_id,
            surface_id=self.surface.surface_id, created_by="recon",
            evidence_type="observation", observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        )
        self.stores.evidence.append(review)
        self.app.collector.register_ssrf_review(
            run_id=self.run.run_id, parameter="url",
            hint_evidence_id="evi-review",
            approval=SsrfExecutionApproval(
                approval_id="approval-1", surface_id=self.surface.surface_id,
                verification_endpoint_ref="operator-endpoint-1",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.CALLBACK,
        )
        decisions = self.app.orchestrator._router.route(
            self.run, (self.surface,), (review,),
        )
        self.candidate = next(
            item.candidate for item in decisions
            if item.candidate.vulnerability_type == "SSRF"
        )
        self.assertEqual(self.candidate.exploration_parameters, ("url",))
        self.stores.candidates.add(self.candidate)

        self._analysis()
        validation = self._validation()

        self.assertEqual(validation.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            validation.validation.reason_code,
            ValidationReasonCode.SSRF_CALLBACK_ONLY,
        )

    def test_empty_observation_provider_does_not_intercept_callback_strategy(self) -> None:
        self.run = self.run.with_updates(surface_ids=(self.surface.surface_id,))
        self.stores.runs.save(self.run)
        app = build_local_application(
            {},
            stores=self.stores,
            budget_manager=self.budget,
            runtime=self.runtime,
            ssrf_callback_service=self.service,
            ssrf_observation_provider=InMemoryServerRequestObservationProvider(),
        )
        register_standard_agents(app)
        review = Evidence(
            evidence_id="evi-review-provider",
            run_id=self.run.run_id,
            surface_id=self.surface.surface_id,
            created_by="recon",
            evidence_type="observation",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        )
        self.stores.evidence.append(review)
        app.collector.register_ssrf_review(
            run_id=self.run.run_id,
            parameter="url",
            hint_evidence_id=review.evidence_id,
            approval=SsrfExecutionApproval(
                approval_id="approval-provider-test",
                surface_id=self.surface.surface_id,
                verification_endpoint_ref="callback-provider-test",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.CALLBACK,
        )

        result = app.dispatcher.dispatch(self.factory.analysis(
            self.run,
            self.candidate,
            target_url=self.surface.url,
            request_budget=10,
        ))

        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(
            tuple(item.http_request.request_kind for item in result.evidence_requests),
            (HttpRequestKind.SSRF_CONTROL, HttpRequestKind.SSRF_PROBE),
        )

    def test_post_recon_review_runs_only_selected_callback_coordinate(self) -> None:
        service = _Service()
        runtime = _TwoFieldRuntime(service)
        selected: list[str] = []
        app = None

        def review(run: Run) -> None:
            assert app is not None
            review_evidence = next(
                item for item in app.stores.evidence.list_by_run(run.run_id)
                if item.observation.get("type") == "ssrf_url_fetch_review"
                and "image_url" in item.observation.get("parameter_names", ())
            )
            selected.append(review_evidence.surface_id)
            app.collector.register_ssrf_review(
                run_id=run.run_id,
                parameter="image_url",
                hint_evidence_id=review_evidence.evidence_id,
                approval=SsrfExecutionApproval(
                    approval_id="approval-cli-test",
                    surface_id=review_evidence.surface_id,
                    verification_endpoint_ref="callback-local_callback",
                    approved_by="operator-cli-test",
                    approved_at=datetime.now(timezone.utc),
                ),
                verification_strategy=SsrfVerificationStrategy.CALLBACK,
            )

        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(("SSRF",)),
            config=OrchestratorConfig(post_recon_gate=review),
        )
        register_standard_agents(app, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))

        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertEqual(len(selected), 1)
        ssrf_candidates = tuple(
            item for item in app.stores.candidates.list_by_run(run.run_id)
            if item.vulnerability_type == "SSRF"
        )
        self.assertEqual(len(ssrf_candidates), 1)
        self.assertEqual(ssrf_candidates[0].surface_id, selected[0])
        self.assertEqual(ssrf_candidates[0].exploration_parameters, ("image_url",))
        self.assertEqual(ssrf_candidates[0].status, CandidateStatus.SUSPECTED)
        probes = tuple(
            item for item in runtime.requests
            if item.request_kind is HttpRequestKind.SSRF_PROBE
        )
        self.assertEqual(len(probes), 2)
        self.assertTrue(all(
            next(name for name, value in probe.query_parameters
                 if value.startswith(service.origin)) == "image_url"
            for probe in probes
        ))
        self.assertEqual(run.finding_ids, ())

    def test_skipped_callback_review_cannot_auto_route_available_oast(self) -> None:
        service = _Service()
        runtime = _Runtime(service)
        reviewed: list[str] = []
        app = None

        def skip_callback(run: Run) -> None:
            assert app is not None
            self.assertTrue(any(
                item.observation.get("type") == "ssrf_url_fetch_review"
                for item in app.stores.evidence.list_by_run(run.run_id)
            ))
            reviewed.append(run.run_id)
            app.ssrf_reviews.skip(
                run.run_id, SsrfVerificationStrategy.CALLBACK,
            )

        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(
                ("SSRF",), ssrf_callback_service=service,
            ),
            config=OrchestratorConfig(post_recon_gate=skip_callback),
        )
        register_standard_agents(app, recon_max_pages=4)

        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))

        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertEqual(reviewed, [run.run_id])
        self.assertFalse(any(
            item.vulnerability_type == "SSRF"
            for item in app.stores.candidates.list_by_run(run.run_id)
        ))
        self.assertEqual(service.tickets, {})
        self.assertFalse(any(
            item.request_kind is HttpRequestKind.SSRF_PROBE
            for item in runtime.requests
        ))

    def test_failed_second_callback_stays_suspected(self) -> None:
        self.runtime.reproduce = False
        self._analysis()
        validation = self._validation()
        self.assertEqual(validation.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(validation.new_evidence_ids, ())

    def test_dns_only_does_not_trigger_independent_http_reproduction(self) -> None:
        self.runtime.protocol = "dns"
        self._analysis()
        task = self.factory.validation(
            self.run, self.candidate, validation_id="validation-1",
            agent_type="validation", request_budget=8,
        )
        result = self.app.dispatcher.dispatch(task)
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(result.evidence_requests, ())
        self.assertEqual(len(self.runtime.requests), 2)

    def test_orchestrator_reaches_independent_validation_without_finding(self) -> None:
        service = _Service()
        runtime = _Runtime(service)
        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        candidates = app.stores.candidates.list_by_run(run.run_id)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].status, CandidateStatus.SUSPECTED)
        self.assertEqual(run.finding_ids, ())
        callbacks = [item for item in app.stores.evidence.list_by_run(run.run_id)
                     if item.created_by == "execution_runtime:ssrf_callback"]
        self.assertEqual(len(callbacks), 2)
        self.assertEqual(len({item.validation_id for item in callbacks}), 2)

    def test_legacy_global_canary_is_not_chained_to_callback_candidate(self) -> None:
        canary = SsrfCanaryProofTarget(
            url="http://controlled-canary.internal:8025/proof",
            marker=_CanaryRuntime.marker,
            destination_policy=self._destination_policy(),
            operator_approved=True,
        )
        for reachable in (True, False):
            with self.subTest(can_reach_canary=reachable):
                service = _Service()
                runtime = _CanaryRuntime(service, can_reach_canary=reachable)
                app = build_local_application(
                    {}, runtime=runtime, ssrf_callback_service=service,
                    ssrf_canary_proof=canary,
                    router=standard_router(("SSRF",), ssrf_callback_service=service),
                )
                register_standard_agents(app, recon_max_pages=4)
                run = app.orchestrator.start(RunRequest(
                    target_url="https://target.example/",
                    scope=RunScope(allowed_hosts=frozenset({"target.example"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                candidate = app.stores.candidates.list_by_run(run.run_id)[0]
                self.assertEqual(candidate.status, CandidateStatus.SUSPECTED)
                self.assertEqual(run.finding_ids, ())
                canary_requests = [item for item in runtime.requests
                                   if item.request_kind is HttpRequestKind.SSRF_CANARY_PROBE]
                self.assertEqual(canary_requests, [])

    def test_canary_marker_in_control_is_not_a_finding(self) -> None:
        service = _Service()
        canary = SsrfCanaryProofTarget(
            url="http://controlled-canary.internal:8025/proof",
            marker=_CanaryRuntime.marker,
            destination_policy=self._destination_policy(),
            operator_approved=True,
        )
        app = build_local_application(
            {}, runtime=_LeakyControlRuntime(service, can_reach_canary=True),
            ssrf_callback_service=service, ssrf_canary_proof=canary,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertEqual(run.finding_ids, ())
        self.assertEqual(app.stores.candidates.list_by_run(run.run_id)[0].status,
                         CandidateStatus.SUSPECTED)

    def test_llm_callback_candidate_cannot_activate_global_canary(self) -> None:
        service = _Service()
        llm = _ToolLlm()
        canary = SsrfCanaryProofTarget(
            url="http://controlled-canary.internal:8025/proof",
            marker=_CanaryRuntime.marker,
            destination_policy=self._destination_policy(),
            operator_approved=True,
        )
        app = build_local_application(
            {}, runtime=_CanaryRuntime(service, can_reach_canary=True),
            ssrf_callback_service=service, ssrf_canary_proof=canary,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, llm_client=llm, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertEqual(run.finding_ids, ())
        self.assertFalse(any(
            item.request_kind is HttpRequestKind.SSRF_CANARY_PROBE
            for item in app.runtime.requests
        ))
        self.assertTrue(llm.calls)

    def test_heuristic_tries_second_observed_input_and_validates_it(self) -> None:
        service = _Service()
        runtime = _TwoFieldRuntime(service)
        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, CandidateStatus.SUSPECTED)
        probes = [item for item in runtime.requests
                  if item.request_kind is HttpRequestKind.SSRF_PROBE]
        self.assertEqual([
            next(name for name, value in probe.query_parameters
                 if value.startswith(service.origin)) for probe in probes
        ], ["url", "image_url", "image_url"])
        self.assertEqual(run.finding_ids, ())

    def test_llm_tool_loop_tries_second_observed_input_and_validates_it(self) -> None:
        service = _Service()
        runtime = _TwoFieldRuntime(service)
        llm = _ToolLlm()
        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, llm_client=llm, recon_max_pages=4)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, CandidateStatus.SUSPECTED)
        self.assertEqual(run.finding_ids, ())
        probes = [item for item in runtime.requests
                  if item.request_kind is HttpRequestKind.SSRF_PROBE]
        self.assertEqual(len(probes), 3)
        self.assertEqual([next(name for name, value in probe.query_parameters
                               if value.startswith(service.origin)) for probe in probes],
                         ["url", "image_url", "image_url"])
        calls = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                 if item.observation.get("type") == "ssrf_tool_call"]
        self.assertTrue({"get_surface_context", "read_probe_result",
                         "probe_observed_url_input"}.issubset(
                             {item["tool"] for item in calls}))
        self.assertEqual(len(llm.calls), 4)

    def test_llm_invented_parameter_is_denied_then_falls_back_to_observed(self) -> None:
        llm = _ToolLlm(invented=True)
        app = build_local_application(
            {}, runtime=self.runtime, ssrf_callback_service=self.service,
        )
        register_standard_agents(app, llm_client=llm)
        app.stores.runs.add(self.run)
        app.stores.surfaces.add(self.surface)
        app.stores.candidates.add(self.candidate)
        task = self.factory.analysis(
            self.run, self.candidate, target_url=self.surface.url,
            request_budget=6,
        )
        result = app.dispatcher.dispatch(task)
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(result.evidence_requests), 2)
        calls = app.stores.evidence.get_many(self.run.run_id, result.new_evidence_ids)
        self.assertTrue(any(item.observation.get("decision") == "denied"
                            and item.observation.get("reason") ==
                            "parameter_not_available_or_already_tried" for item in calls))
        self.assertTrue(any(item.observation.get("source") == "deterministic_fallback"
                            for item in calls))

    def test_llm_initial_probe_reports_insufficient_proof_budget(self) -> None:
        app = build_local_application(
            {}, runtime=self.runtime, ssrf_callback_service=self.service,
        )
        register_standard_agents(app, llm_client=_ToolLlm())
        app.stores.runs.add(self.run)
        app.stores.surfaces.add(self.surface)
        app.stores.candidates.add(self.candidate)

        with self.assertRaises(BudgetExceeded) as raised:
            app.dispatcher.dispatch(self.factory.analysis(
                self.run,
                self.candidate,
                target_url=self.surface.url,
                request_budget=3,
            ))

        self.assertEqual(raised.exception.required_requests, 4)

    def test_llm_context_gets_hint_metadata_without_internal_destination(self) -> None:
        llm = _ToolLlm()
        app = build_local_application(
            {}, runtime=self.runtime, ssrf_callback_service=self.service,
        )
        register_standard_agents(app, llm_client=llm)
        app.stores.runs.add(self.run)
        app.stores.surfaces.add(self.surface)
        app.stores.candidates.add(self.candidate)
        app.stores.evidence.append(Evidence(
            evidence_id="evi-hint", run_id=self.run.run_id,
            surface_id=self.surface.surface_id, created_by="recon",
            evidence_type="observation", observation={
                "type": "ssrf_destination_hint",
                "source": "openapi_document",
                "destination_origin": "http://private-service:8025",
                "path_hint": "/private/token/{redacted}",
                "destination_fingerprint": "a" * 64,
                "host_kind": "single_label_dns",
                "probe_authorized": False,
            },
        ))
        result = app.dispatcher.dispatch(self.factory.analysis(
            self.run, self.candidate, target_url=self.surface.url,
            request_budget=6,
        ))
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        context = json.loads(llm.calls[1].messages[0].content)["tool_result"]
        self.assertEqual(context["observed_destination_hint_count"], 1)
        self.assertEqual(context["observed_destination_hint_sources"], ["openapi_document"])
        self.assertEqual(
            context["observed_destination_hint_host_kinds"], ["single_label_dns"],
        )
        self.assertEqual(
            context["observed_destination_path_hints"],
            ["/private/token/{redacted}"],
        )
        self.assertFalse(context["destination_probe_authorized"])
        self.assertNotIn("private-service", str(context))
        self.assertNotIn("a" * 64, str(context))

    def test_non_object_llm_action_falls_back_to_observed_coordinate(self) -> None:
        class _InvalidLlm:
            def complete(self, request):
                return LlmResponse(payload=[], model="fake-ssrf")

        app = build_local_application(
            {}, runtime=self.runtime, ssrf_callback_service=self.service,
        )
        register_standard_agents(app, llm_client=_InvalidLlm())
        app.stores.runs.add(self.run)
        app.stores.surfaces.add(self.surface)
        app.stores.candidates.add(self.candidate)
        task = self.factory.analysis(
            self.run, self.candidate, target_url=self.surface.url,
            request_budget=6,
        )
        result = app.dispatcher.dispatch(task)
        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        calls = app.stores.evidence.get_many(self.run.run_id, result.new_evidence_ids)
        self.assertTrue(any(item.observation.get("reason") == "LlmResponseFormatError"
                            for item in calls))

    def test_second_coordinate_is_skipped_when_validation_budget_would_be_lost(self) -> None:
        service = _Service()
        runtime = _TwoFieldRuntime(service)
        llm = _ToolLlm()
        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app, llm_client=llm)
        run = Run(
            run_id="budget-run", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=5,
        )
        surface = Surface(
            surface_id="budget-surface", run_id=run.run_id,
            url="https://target.example/preview?url=old&image_url=old",
            method="GET", parameters=("url", "image_url"),
        )
        app.stores.runs.add(run)
        app.stores.surfaces.add(surface)
        app.budget_manager.open_run(run.run_id, 5)
        candidate = next(item.candidate for item in
                         standard_router(("SSRF",), ssrf_callback_service=service).route(
                             run, (surface,), ()))
        app.stores.candidates.add(candidate)
        first = app.dispatcher.dispatch(TaskFactory().analysis(
            run, candidate, target_url=surface.url, request_budget=5,
        ))
        self.assertEqual(len(first.evidence_requests), 2)
        candidate = candidate.add_evidence(first.new_evidence_ids)
        app.stores.candidates.save(candidate)
        for request in first.evidence_requests:
            app.collector.collect(
                run.run_id, surface.url, request, task_id="budget-collect",
                candidate_id=candidate.candidate_id,
            )
        runtime_ids = tuple(item.evidence_id for item in app.stores.evidence.list_by_run(run.run_id)
                            if item.created_by == "execution_runtime:http_get")
        candidate = candidate.add_evidence(runtime_ids)
        app.stores.candidates.save(candidate)
        second = app.dispatcher.dispatch(TaskFactory().analysis(
            run, candidate, target_url=surface.url, request_budget=3,
        ))
        self.assertEqual(second.status, AgentResultStatus.COMPLETED)
        self.assertEqual(second.evidence_requests, ())
        self.assertEqual(len([item for item in runtime.requests
                              if item.request_kind is HttpRequestKind.SSRF_PROBE]), 1)

    def test_llm_resume_uses_saved_plan_without_repeating_first_probe(self) -> None:
        service = _Service()
        runtime = _TwoFieldRuntime(service)
        stores = MemoryStoreBundle()
        budget = InMemoryBudgetManager()
        app = build_local_application(
            {}, stores=stores, budget_manager=budget, runtime=runtime,
            ssrf_callback_service=service,
        )
        register_standard_agents(app, llm_client=_ToolLlm())
        run = Run(
            run_id="resume-run", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=6,
        )
        surface = Surface(
            surface_id="resume-surface", run_id=run.run_id,
            url="https://target.example/preview?url=old&image_url=old",
            method="GET", parameters=("url", "image_url"),
        )
        stores.runs.add(run)
        stores.surfaces.add(surface)
        budget.open_run(run.run_id, 6)
        candidate = next(item.candidate for item in
                         standard_router(("SSRF",), ssrf_callback_service=service).route(
                             run, (surface,), ()))
        stores.candidates.add(candidate)
        first = app.dispatcher.dispatch(TaskFactory().analysis(
            run, candidate, target_url=surface.url, request_budget=6,
        ))
        candidate = candidate.add_evidence(first.new_evidence_ids)
        stores.candidates.save(candidate)
        for request in first.evidence_requests:
            item_id = app.collector.collect(
                run.run_id, surface.url, request, task_id="resume-collect",
                candidate_id=candidate.candidate_id,
            )
            candidate = candidate.add_evidence((item_id,))
            stores.candidates.save(candidate)
        restarted = build_local_application(
            {}, stores=stores, budget_manager=budget, runtime=runtime,
            ssrf_callback_service=service,
        )
        register_standard_agents(restarted, llm_client=_ToolLlm())
        next_step = restarted.dispatcher.dispatch(TaskFactory().analysis(
            run, candidate, target_url=surface.url, request_budget=4,
        ))
        self.assertEqual(next_step.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(next_step.evidence_requests), 2)
        self.assertEqual(len(runtime.requests), 2)
        selected = next(value for name, value in
                        next_step.evidence_requests[1].http_request.query_parameters
                        if name == "image_url")
        self.assertTrue(selected.startswith(service.origin))
        self.assertEqual(len(service.tickets), 2)

    def test_provider_timeout_is_blocked_not_negative_or_confirmed(self) -> None:
        service = _FailingService()
        runtime = _Runtime(service)
        app = build_local_application(
            {}, runtime=runtime, ssrf_callback_service=service,
            router=standard_router(("SSRF",), ssrf_callback_service=service),
        )
        register_standard_agents(app)
        run = app.orchestrator.start(RunRequest(
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            request_budget=20,
        ))
        self.assertEqual(run.finding_ids, ())
        candidate = next(item for item in app.stores.candidates.list_by_run(run.run_id)
                         if item.assigned_agent == SSRF_ANALYZER)
        self.assertEqual(candidate.status, CandidateStatus.BLOCKED)


if __name__ == "__main__":
    unittest.main()
