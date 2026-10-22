"""Structured SSRF reviews must enter Findings only through central Evidence."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from hacklipse.adapters import (
    InMemoryServerRequestObservationProvider,
    InMemorySsrfReviewRegistry,
    MemoryStoreBundle,
    SsrfReviewAwareRouter,
)
from hacklipse.adapters.routing import RuleBasedVulnerabilityRouter
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    Candidate,
    CandidateStatus,
    DestinationPolicy,
    Evidence,
    Run,
    RunScope,
    ServerRequestObservation,
    SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfObservationPhase,
    SsrfObservationProviderStatus,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    SsrfReviewRegistration,
    SsrfVerificationStrategy,
    Surface,
    ValidationProofType,
    ValidationResult,
    ValidationVerdict,
)
from hacklipse.ports.errors import RecordNotFound


class SsrfObservationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        now = datetime.now(timezone.utc) - timedelta(minutes=2)
        self.approval = SsrfExecutionApproval(
            approval_id="approval-1",
            surface_id="surface-1",
            verification_endpoint_ref="endpoint-owned-1",
            approved_by="operator-security",
            approved_at=now,
        )
        self.policy = DestinationPolicy(
            policy_id="policy-1",
            surface_id="surface-1",
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:policy-1",
            approved_by="operator-security",
            created_at=now,
            destination_origin="https://owned-callback.example",
            assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
            evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
        )
        self.observations = (
            ServerRequestObservation(
                observation_id="provider-observation-a",
                run_id="run-1",
                surface_id="surface-1",
                parameter="url",
                verification_endpoint_ref="endpoint-owned-1",
                verification_session_id="analysis-a",
                phase=SsrfObservationPhase.ANALYSIS,
                observed_at=now + timedelta(seconds=10),
                source_verified=True,
                destination_origin="https://owned-callback.example",
            ),
            ServerRequestObservation(
                observation_id="provider-observation-b",
                run_id="run-1",
                surface_id="surface-1",
                parameter="url",
                verification_endpoint_ref="endpoint-owned-1",
                verification_session_id="validation-1",
                phase=SsrfObservationPhase.VALIDATION,
                observed_at=now + timedelta(seconds=20),
                source_verified=True,
                destination_origin="https://owned-callback.example",
            ),
        )
        self.provider = InMemoryServerRequestObservationProvider(self.observations)
        self.stores = MemoryStoreBundle()
        self.run = Run(
            run_id="run-1",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=10,
            surface_ids=("surface-1",),
            candidate_ids=("candidate-1",),
        )
        self.surface = Surface(
            surface_id="surface-1",
            run_id="run-1",
            url="https://target.example/fetch?url=sample",
            method="GET",
            parameters=("url",),
            observed_query=(("url", "sample"),),
        )
        self.stores.runs.add(self.run)
        self.stores.surfaces.add(self.surface)
        self.stores.evidence.append(Evidence(
            evidence_id="evi-review",
            run_id="run-1",
            surface_id="surface-1",
            created_by="recon",
            evidence_type="observation",
            source_task_id="recon-1",
            observation={
                "type": "ssrf_url_fetch_review",
                "parameter_names": ["url"],
            },
        ))
        self.app = build_local_application(
            {},
            stores=self.stores,
            ssrf_observation_provider=self.provider,
        )
        self.registration = self.app.collector.register_ssrf_review(
            run_id="run-1",
            parameter="url",
            hint_evidence_id="evi-review",
            approval=self.approval,
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
            destination_policy=self.policy,
        )

    def test_provider_records_become_idempotent_sanitized_central_evidence(self) -> None:
        status, observations, mapping = (
            self.app.collector.collect_server_request_observations(
                run_id="run-1",
                surface_id="surface-1",
                parameter="url",
                task_id="validation-task-1",
                validation_id="validation-1",
            )
        )
        self.assertEqual(status, SsrfObservationProviderStatus.AVAILABLE)
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(
            item.observation_id.startswith("provider:") for item in observations
        ))
        self.assertFalse({
            "provider-observation-a", "provider-observation-b",
        } & set(mapping))
        self.assertEqual(set(mapping), {
            item.observation_id for item in observations
        })
        analysis_observation = next(
            item for item in observations
            if item.phase is SsrfObservationPhase.ANALYSIS
        )
        validation_observation = next(
            item for item in observations
            if item.phase is SsrfObservationPhase.VALIDATION
        )
        analysis = self.stores.evidence.get(
            "run-1", mapping[analysis_observation.observation_id],
        )
        validation = self.stores.evidence.get(
            "run-1", mapping[validation_observation.observation_id],
        )
        self.assertIsNone(analysis.validation_id)
        self.assertEqual(validation.validation_id, "validation-1")
        self.assertEqual(
            validation.created_by,
            "execution_runtime:ssrf_observation_provider",
        )
        rendered = str(validation.observation)
        self.assertEqual(
            validation.observation["destination_origin"],
            "https://owned-callback.example",
        )
        self.assertNotIn("?", rendered)
        self.assertNotIn("#", rendered)
        self.assertNotIn("token", rendered.casefold())
        self.assertNotIn("provider-observation-b", rendered)
        self.assertTrue(
            str(validation.observation["provider_observation_id"]).startswith(
                "provider:"
            )
        )

        self.provider.set_status(SsrfObservationProviderStatus.UNAVAILABLE)
        repeated = self.app.collector.collect_server_request_observations(
            run_id="run-1",
            surface_id="surface-1",
            parameter="url",
            task_id="validation-task-retry",
            validation_id="validation-1",
        )
        self.assertEqual(repeated[0], SsrfObservationProviderStatus.AVAILABLE)
        self.assertEqual(repeated[2], mapping)

        restarted = build_local_application(
            {}, stores=self.stores,
            ssrf_observation_provider=InMemoryServerRequestObservationProvider(
                status=SsrfObservationProviderStatus.UNAVAILABLE,
            ),
        )
        restored = restarted.collector.collect_server_request_observations(
            run_id="run-1",
            surface_id="surface-1",
            parameter="url",
            task_id="validation-task-after-restart",
            validation_id="validation-1",
        )
        self.assertEqual(restored[0], SsrfObservationProviderStatus.AVAILABLE)
        self.assertEqual(restored[1], observations)
        self.assertEqual(restored[2], mapping)

    def test_config_or_openapi_policy_requires_matching_trusted_source_evidence(self) -> None:
        policy = DestinationPolicy(
            policy_id="policy-config-1",
            surface_id="surface-1",
            destination_rule=SsrfDestinationRule.FORBIDDEN,
            source_type=SsrfPolicySource.CONFIG_ALLOWLIST,
            source_reference="config:evi-config-policy-1",
            approved_by="operator-security",
            created_at=datetime.now(timezone.utc),
            destination_origin="https://owned-callback.example",
            assertion=SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION,
            evidence_status=SsrfPolicyEvidenceStatus.VERIFIED,
        )
        registration = SsrfReviewRegistration(
            run_id="run-1",
            parameter="url",
            hint_evidence_id="evi-review",
            execution_approval=self.approval,
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
            destination_policy=policy,
        )
        with self.assertRaisesRegex(AgentContractError, "source Evidence is unavailable"):
            self.app.collector._validate_ssrf_review_registration(registration)

        self.stores.evidence.append(Evidence(
            evidence_id="evi-config-policy-1",
            run_id="run-1",
            surface_id="surface-1",
            created_by="execution_runtime:ssrf_config_policy_loader",
            evidence_type="observation",
            observation={
                "type": "ssrf_destination_policy_evidence",
                "source_type": "config_allowlist",
                "surface_ids": ["surface-1"],
                "destination_origin": "https://owned-callback.example",
                "destination_rule": "forbidden",
                "assertion": "target_must_not_reach_destination",
                "evidence_status": "verified",
            },
        ))
        validated = self.app.collector._validate_ssrf_review_registration(registration)
        self.assertEqual(validated.run_id, "run-1")

        mismatched = replace(
            policy,
            source_reference="config:evi-config-policy-other",
        )
        self.stores.evidence.append(Evidence(
            evidence_id="evi-config-policy-other",
            run_id="run-1",
            surface_id="surface-1",
            created_by="execution_runtime:ssrf_config_policy_loader",
            evidence_type="observation",
            observation={
                "type": "ssrf_destination_policy_evidence",
                "source_type": "config_allowlist",
                "surface_ids": ["surface-2"],
                "destination_origin": "https://owned-callback.example",
                "destination_rule": "forbidden",
                "assertion": "target_must_not_reach_destination",
                "evidence_status": "verified",
            },
        ))
        with self.assertRaisesRegex(AgentContractError, "does not match"):
            self.app.collector._validate_ssrf_review_registration(replace(
                registration, destination_policy=mismatched,
            ))

    def test_confirmed_assessment_uses_standard_validation_and_finding_path(self) -> None:
        register_standard_agents(self.app)
        candidate = Candidate(
            candidate_id="candidate-1",
            run_id="run-1",
            surface_id="surface-1",
            vulnerability_type="SSRF",
            hypothesis="approved URL-handling coordinate requires independent review",
            assigned_agent="ssrf_analyzer",
            evidence_ids=("evi-review",),
            status=CandidateStatus.ANALYZED,
            exploration_parameters=("url",),
        )
        self.stores.candidates.add(candidate)
        self.app.budget_manager.open_run("run-1", 10)
        self.app.orchestrator._id_factory = lambda: "1"

        _, finding_id = self.app.orchestrator._validate_candidate(self.run, candidate)

        self.assertEqual(finding_id, "finding-1")
        finding = self.stores.findings.get("run-1", "finding-1")
        self.assertEqual(
            finding.proof_type, ValidationProofType.SSRF_UNAUTHORIZED_FETCH,
        )
        evidence = self.stores.evidence.get_many("run-1", finding.evidence_ids)
        self.assertEqual(
            {item.observation.get("type") for item in evidence},
            {"ssrf_server_request_observation", "ssrf_assessment_result"},
        )
        self.assertTrue(all(item.validation_id == "validation-1" for item in evidence))
        self.assertNotIn("provider-observation-a", finding.evidence_ids)
        self.assertNotIn("provider-observation-b", finding.evidence_ids)

    def test_policy_is_required_for_a_finding(self) -> None:
        stores = MemoryStoreBundle()
        stores.runs.add(self.run)
        stores.surfaces.add(self.surface)
        stores.evidence.append(self.stores.evidence.get("run-1", "evi-review"))
        app = build_local_application(
            {}, stores=stores, ssrf_observation_provider=self.provider,
        )
        app.collector.register_ssrf_review(
            run_id="run-1", parameter="url", hint_evidence_id="evi-review",
            approval=self.approval,
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
        )
        register_standard_agents(app)
        candidate = Candidate(
            candidate_id="candidate-1", run_id="run-1", surface_id="surface-1",
            vulnerability_type="SSRF", hypothesis="review", assigned_agent="ssrf_analyzer",
            evidence_ids=("evi-review",), status=CandidateStatus.ANALYZED,
            exploration_parameters=("url",),
        )
        stores.candidates.add(candidate)
        app.budget_manager.open_run("run-1", 10)
        app.orchestrator._id_factory = lambda: "1"

        _, finding_id = app.orchestrator._validate_candidate(self.run, candidate)

        self.assertIsNone(finding_id)
        self.assertEqual(stores.findings.list_by_run("run-1"), ())
        self.assertEqual(
            stores.candidates.get("run-1", "candidate-1").status,
            CandidateStatus.SUSPECTED,
        )

    def test_provider_observation_ids_are_not_validation_evidence_ids(self) -> None:
        candidate = Candidate(
            candidate_id="candidate-1", run_id="run-1", surface_id="surface-1",
            vulnerability_type="SSRF", hypothesis="review",
            assigned_agent="ssrf_analyzer", evidence_ids=(),
            status=CandidateStatus.ANALYZED,
            exploration_parameters=("url",),
        )
        forged = ValidationResult(
            validation_id="validation-1",
            run_id="run-1",
            candidate_id="candidate-1",
            verdict=ValidationVerdict.SUSPECTED,
            evidence_ids=("provider-observation-b",),
            reason="provider id was used without central collection",
            reproduction_count=1,
        )

        with self.assertRaises(RecordNotFound):
            self.app.orchestrator._validate_validation_contract(
                self.run, candidate, forged, "validation-1",
            )

    def test_available_provider_without_a_started_session_is_blocked(self) -> None:
        assessment = self._run_empty_observation_case(
            InMemoryServerRequestObservationProvider(),
        )
        self.assertEqual(
            assessment.observation["reason_code"],
            "verification_session_missing",
        )

    def test_configured_unavailable_provider_is_blocked(self) -> None:
        assessment = self._run_empty_observation_case(
            InMemoryServerRequestObservationProvider(
                status=SsrfObservationProviderStatus.UNAVAILABLE,
            ),
        )
        self.assertEqual(
            assessment.observation["reason_code"],
            "provider_unavailable",
        )

    def test_review_without_provider_or_callback_stays_metadata_only(self) -> None:
        stores = MemoryStoreBundle()
        stores.runs.add(self.run)
        stores.surfaces.add(self.surface)
        stores.evidence.append(self.stores.evidence.get("run-1", "evi-review"))
        app = build_local_application({}, stores=stores)
        app.collector.register_ssrf_review(
            run_id="run-1", parameter="url", hint_evidence_id="evi-review",
            approval=self.approval,
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
            destination_policy=self.policy,
        )

        decisions = app.orchestrator._router.route(
            stores.runs.get("run-1"), (self.surface,),
            stores.evidence.list_by_run("run-1"),
        )

        self.assertFalse(any(
            item.candidate.vulnerability_type == "SSRF" for item in decisions
        ))
        self.assertFalse(any(
            item.observation.get("type") == "ssrf_assessment_result"
            for item in stores.evidence.list_by_run("run-1")
        ))

    def test_review_registration_is_restored_from_central_evidence(self) -> None:
        registrations = tuple(
            item for item in self.stores.evidence.list_by_run("run-1")
            if item.observation.get("type") == "ssrf_review_registration"
        )
        self.assertEqual(len(registrations), 1)
        self.assertEqual(
            registrations[0].observation["destination_origin"],
            "https://owned-callback.example",
        )
        self.assertNotIn("?", str(registrations[0].observation))

        restarted = build_local_application(
            {}, stores=self.stores, ssrf_observation_provider=self.provider,
        )
        restored = restarted.collector.ssrf_review_for_surface(
            "run-1", "surface-1",
        )

        self.assertEqual(restored, self.registration)
        decisions = restarted.orchestrator._router.route(
            self.stores.runs.get("run-1"), (self.surface,),
            self.stores.evidence.list_by_run("run-1"),
        )
        ssrf = tuple(
            item for item in decisions
            if item.candidate.vulnerability_type == "SSRF"
        )
        self.assertEqual(len(ssrf), 1)
        self.assertEqual(ssrf[0].candidate.exploration_parameters, ("url",))

    def test_reapproval_cannot_reuse_older_central_observations(self) -> None:
        self.app.collector.collect_server_request_observations(
            run_id="run-1", surface_id="surface-1", parameter="url",
            task_id="validation-task-1", validation_id="validation-1",
        )
        registry = InMemorySsrfReviewRegistry()
        registry.register(SsrfReviewRegistration(
            run_id="run-1", parameter="url", hint_evidence_id="evi-review",
            execution_approval=replace(
                self.approval,
                approval_id="approval-2",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
            destination_policy=self.policy,
        ))
        restarted = build_local_application(
            {}, stores=self.stores, ssrf_observation_provider=self.provider,
            ssrf_review_registry=registry,
        )

        with self.assertRaises(AgentContractError):
            restarted.collector.collect_server_request_observations(
                run_id="run-1", surface_id="surface-1", parameter="url",
                task_id="validation-task-2", validation_id="validation-1",
            )

    def test_review_references_cannot_persist_urls_or_reuse_hint_ids(self) -> None:
        with self.assertRaises(AgentContractError):
            self.app.collector.register_ssrf_review(
                run_id="run-1", parameter="url", hint_evidence_id=None,
                verification_strategy=SsrfVerificationStrategy.CALLBACK,
                approval=replace(
                    self.approval,
                    verification_endpoint_ref="https://owned.example/verify",
                ),
            )
        with self.assertRaises(AgentContractError):
            self.app.collector.register_ssrf_review(
                run_id="run-1", parameter="url", hint_evidence_id="evi-review",
                verification_strategy=SsrfVerificationStrategy.CALLBACK,
                approval=replace(
                    self.approval, verification_endpoint_ref="evi-review",
                ),
            )

    def _run_empty_observation_case(self, provider):
        stores = MemoryStoreBundle()
        stores.runs.add(self.run)
        stores.surfaces.add(self.surface)
        stores.evidence.append(self.stores.evidence.get("run-1", "evi-review"))
        app = build_local_application(
            {}, stores=stores, ssrf_observation_provider=provider,
        )
        app.collector.register_ssrf_review(
            run_id="run-1", parameter="url", hint_evidence_id="evi-review",
            approval=self.approval,
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
            destination_policy=self.policy,
        )
        register_standard_agents(app)
        candidate = Candidate(
            candidate_id="candidate-1", run_id="run-1", surface_id="surface-1",
            vulnerability_type="SSRF", hypothesis="review",
            assigned_agent="ssrf_analyzer", evidence_ids=("evi-review",),
            status=CandidateStatus.ANALYZED, exploration_parameters=("url",),
        )
        stores.candidates.add(candidate)
        app.budget_manager.open_run("run-1", 10)
        app.orchestrator._id_factory = lambda: "1"

        _, finding_id = app.orchestrator._validate_candidate(self.run, candidate)

        self.assertIsNone(finding_id)
        self.assertEqual(
            stores.candidates.get("run-1", "candidate-1").status,
            CandidateStatus.BLOCKED,
        )
        assessments = tuple(
            item for item in stores.evidence.list_by_run("run-1")
            if item.observation.get("type") == "ssrf_assessment_result"
        )
        self.assertEqual(len(assessments), 1)
        return assessments[0]


class SsrfReviewRouterTests(unittest.TestCase):
    def test_registry_releases_once_for_registration_or_skip(self) -> None:
        registry = InMemorySsrfReviewRegistry()
        registration = SsrfReviewRegistration(
            run_id="run-registered", parameter="url", hint_evidence_id=None,
            execution_approval=SsrfExecutionApproval(
                approval_id="approval-1", surface_id="surface-1",
                verification_endpoint_ref="endpoint-owned-1",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
        )
        registry.register(registration)
        registry.register(registration)
        self.assertEqual(
            registry.wait_for_review("run-registered", timeout_seconds=0.01),
            "registered",
        )

        registry.skip("run-skipped", SsrfVerificationStrategy.PASSIVE)
        self.assertEqual(
            registry.wait_for_review("run-skipped", timeout_seconds=0.01),
            "skipped",
        )
        with self.assertRaises(ValueError):
            registry.register(replace(registration, run_id="run-skipped"))

    def test_only_exact_registered_coordinate_is_routed(self) -> None:
        registry = InMemorySsrfReviewRegistry()
        manual = standard_router(("SSRF",), ssrf_review_registry=registry)
        router = SsrfReviewAwareRouter(
            RuleBasedVulnerabilityRouter(), manual, registry,
        )
        run = Run(
            run_id="run-1", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=10,
        )
        surfaces = (
            Surface(
                surface_id="surface-1", run_id="run-1",
                url="https://target.example/fetch?url=a&image_url=b", method="GET",
                parameters=("url", "image_url"),
                observed_query=(("url", "a"), ("image_url", "b")),
            ),
            Surface(
                surface_id="surface-2", run_id="run-1",
                url="https://target.example/other?url=c", method="GET",
                parameters=("url",), observed_query=(("url", "c"),),
            ),
        )
        before = router.route(run, surfaces, ())
        self.assertFalse(any(
            item.candidate.vulnerability_type == "SSRF" for item in before
        ))
        registry.register(SsrfReviewRegistration(
            run_id="run-1", parameter="image_url", hint_evidence_id=None,
            execution_approval=SsrfExecutionApproval(
                approval_id="approval-1", surface_id="surface-1",
                verification_endpoint_ref="endpoint-owned-1",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
        ))

        decisions = router.route(run, surfaces, ())

        ssrf_decisions = tuple(
            item for item in decisions
            if item.candidate.vulnerability_type == "SSRF"
        )
        self.assertEqual(len(ssrf_decisions), 1)
        self.assertEqual(ssrf_decisions[0].candidate.surface_id, "surface-1")
        self.assertEqual(
            ssrf_decisions[0].candidate.exploration_parameters, ("image_url",),
        )

    def test_registered_review_drops_callback_candidates_for_other_surfaces(self) -> None:
        registry = InMemorySsrfReviewRegistry()
        callback_router = standard_router(
            ("SSRF",), ssrf_callback_service=object(),
        )
        reviewed_router = standard_router(
            ("SSRF",), ssrf_review_registry=registry, ssrf_canary_enabled=True,
        )
        router = SsrfReviewAwareRouter(
            callback_router, reviewed_router, registry,
            preserve_unregistered_ssrf=True,
        )
        run = Run(
            run_id="run-1", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=10,
        )
        surfaces = tuple(
            Surface(
                surface_id=f"surface-{index}", run_id="run-1",
                url=f"https://target.example/fetch-{index}?url=value", method="GET",
                parameters=("url",), observed_query=(("url", "value"),),
            )
            for index in (1, 2)
        )
        registry.register(SsrfReviewRegistration(
            run_id="run-1", parameter="url", hint_evidence_id=None,
            execution_approval=SsrfExecutionApproval(
                approval_id="approval-1", surface_id="surface-1",
                verification_endpoint_ref="endpoint-owned-1",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
        ))

        decisions = router.route(run, surfaces, ())

        ssrf_decisions = tuple(
            item for item in decisions
            if item.candidate.vulnerability_type == "SSRF"
        )
        self.assertEqual(len(ssrf_decisions), 1)
        self.assertEqual(ssrf_decisions[0].candidate.routing_capability_id, "")
        self.assertEqual(ssrf_decisions[0].candidate.analysis_strategy_id, "")
        self.assertEqual(
            {item.candidate.surface_id for item in ssrf_decisions}, {"surface-1"},
        )
        self.assertTrue(all(
            item.candidate.exploration_parameters == ("url",)
            for item in ssrf_decisions
        ))

    def test_registration_without_an_execution_provider_does_not_route(self) -> None:
        registry = InMemorySsrfReviewRegistry()
        manual = standard_router(("SSRF",), ssrf_review_registry=registry)
        router = SsrfReviewAwareRouter(
            RuleBasedVulnerabilityRouter(), manual, registry,
            enable_registered_ssrf=False,
        )
        run = Run(
            run_id="run-1", target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe", request_budget=10,
        )
        surface = Surface(
            surface_id="surface-1", run_id="run-1",
            url="https://target.example/fetch?url=a", method="GET",
            parameters=("url",), observed_query=(("url", "a"),),
        )
        registry.register(SsrfReviewRegistration(
            run_id="run-1", parameter="url", hint_evidence_id=None,
            execution_approval=SsrfExecutionApproval(
                approval_id="approval-1", surface_id="surface-1",
                verification_endpoint_ref="endpoint-owned-1",
                approved_by="operator-security",
                approved_at=datetime.now(timezone.utc),
            ),
            verification_strategy=SsrfVerificationStrategy.PASSIVE,
        ))

        decisions = router.route(run, (surface,), ())

        self.assertFalse(any(
            item.candidate.vulnerability_type == "SSRF" for item in decisions
        ))


if __name__ == "__main__":
    unittest.main()
