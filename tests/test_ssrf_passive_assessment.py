"""Network-free SSRF policy and observation assessment contracts."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from hacklipse.adapters import (
    InMemoryServerRequestObservationProvider,
    assess_ssrf_observations,
    resolve_ssrf_assessment,
)
from hacklipse.domain import (
    DestinationPolicy,
    ServerRequestObservation,
    SsrfAssessmentReason,
    SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfObservationPhase,
    SsrfObservationProviderStatus,
    SsrfPolicyAssertion,
    SsrfPolicyEvidenceStatus,
    SsrfPolicySource,
    ValidationVerdict,
)


class SsrfPassiveAssessmentTests(unittest.TestCase):
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)

    def approval(self, *, surface_id: str = "surface-1") -> SsrfExecutionApproval:
        return SsrfExecutionApproval(
            approval_id="approval-1",
            surface_id=surface_id,
            verification_endpoint_ref="endpoint-owned-1",
            approved_by="operator-security",
            approved_at=self.now,
        )

    def policy(
        self, rule: SsrfDestinationRule = SsrfDestinationRule.FORBIDDEN,
        *, surface_id: str = "surface-1",
    ) -> DestinationPolicy:
        return DestinationPolicy(
            policy_id="policy-1",
            surface_id=surface_id,
            destination_rule=rule,
            source_type=SsrfPolicySource.OPERATOR_ATTESTATION,
            source_reference="operator:policy-reference-1",
            approved_by="operator-security",
            created_at=self.now,
            destination_origin="https://owned-callback.example",
            assertion=(
                SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION
                if rule is SsrfDestinationRule.FORBIDDEN
                else SsrfPolicyAssertion.TARGET_MAY_REACH_DESTINATION
            ),
            evidence_status=SsrfPolicyEvidenceStatus.ATTESTED,
        )

    def observation(
        self, phase: SsrfObservationPhase, session: str, *,
        observation_id: str, endpoint_ref: str = "endpoint-owned-1",
        source_verified: bool = True,
    ) -> ServerRequestObservation:
        return ServerRequestObservation(
            observation_id=observation_id,
            run_id="run-1",
            surface_id="surface-1",
            parameter="url",
            verification_endpoint_ref=endpoint_ref,
            verification_session_id=session,
            phase=phase,
            observed_at=self.now,
            source_verified=source_verified,
            destination_origin="https://owned-callback.example",
        )

    def resolve(self, observations=(), **changes):
        arguments = {
            "provider_status": SsrfObservationProviderStatus.AVAILABLE,
            "run_id": "run-1",
            "surface_id": "surface-1",
            "parameter": "url",
            "execution_approval": self.approval(),
            "destination_policy": None,
            "request_budget_available": True,
            "analysis_verification_session_id": "analysis-a",
            "validation_verification_session_id": "validation-b",
        }
        arguments.update(changes)
        return resolve_ssrf_assessment(observations, **arguments)

    def independent_observations(self):
        return (
            self.observation(
                SsrfObservationPhase.ANALYSIS,
                "analysis-a",
                observation_id="observation-a",
            ),
            self.observation(
                SsrfObservationPhase.VALIDATION,
                "validation-b",
                observation_id="observation-b",
            ),
        )

    def test_independent_observations_need_a_surface_bound_policy(self) -> None:
        observations = self.independent_observations()
        suspected = self.resolve(observations)
        self.assertEqual(suspected.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            suspected.reason_code,
            SsrfAssessmentReason.SERVER_REQUEST_OBSERVED_WITHOUT_DESTINATION_POLICY,
        )

        confirmed = self.resolve(
            observations, destination_policy=self.policy(),
        )
        self.assertEqual(confirmed.verdict, ValidationVerdict.CONFIRMED)
        self.assertEqual(confirmed.policy_id, "policy-1")
        self.assertEqual(
            confirmed.observation_ids, ("observation-a", "observation-b")
        )

        allowed = self.resolve(
            observations,
            destination_policy=self.policy(SsrfDestinationRule.ALLOWED),
        )
        self.assertEqual(allowed.verdict, ValidationVerdict.REJECTED)
        self.assertEqual(
            allowed.reason_code,
            SsrfAssessmentReason.DESTINATION_POLICY_ALLOWS_ACCESS,
        )

    def test_wrong_surface_policy_never_confirms(self) -> None:
        result = self.resolve(
            self.independent_observations(),
            destination_policy=self.policy(surface_id="surface-2"),
        )
        self.assertEqual(result.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            result.reason_code,
            SsrfAssessmentReason.DESTINATION_POLICY_SURFACE_MISMATCH,
        )

    def test_wrong_destination_origin_never_confirms(self) -> None:
        observations = tuple(
            replace(item, destination_origin="https://other.example")
            for item in self.independent_observations()
        )
        result = self.resolve(
            observations, destination_policy=self.policy(),
        )
        self.assertEqual(result.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            result.reason_code,
            SsrfAssessmentReason.DESTINATION_POLICY_ORIGIN_MISMATCH,
        )

    def test_endpoint_reference_must_match_execution_approval(self) -> None:
        observations = tuple(
            replace(item, verification_endpoint_ref="endpoint-other")
            for item in self.independent_observations()
        )
        result = self.resolve(observations)
        self.assertEqual(result.verdict, ValidationVerdict.BLOCKED)
        self.assertEqual(
            result.reason_code,
            SsrfAssessmentReason.VERIFICATION_ENDPOINT_MISMATCH,
        )

    def test_missing_or_unverified_inputs_do_not_confirm(self) -> None:
        analysis = self.independent_observations()[0]
        analysis_only = self.resolve((analysis,))
        self.assertEqual(analysis_only.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(
            analysis_only.reason_code,
            SsrfAssessmentReason.INDEPENDENT_OBSERVATION_MISSING,
        )
        unverified = replace(analysis, source_verified=False)
        result = self.resolve((unverified,))
        self.assertEqual(result.verdict, ValidationVerdict.BLOCKED)
        self.assertEqual(
            result.reason_code,
            SsrfAssessmentReason.OBSERVATION_SOURCE_UNVERIFIED,
        )
        same_session = self.resolve(
            self.independent_observations(),
            validation_verification_session_id="analysis-a",
        )
        self.assertEqual(
            same_session.reason_code,
            SsrfAssessmentReason.VERIFICATION_SESSION_MISSING,
        )

    def test_provider_wrapper_is_read_only_and_idempotent(self) -> None:
        observations = self.independent_observations()
        provider = InMemoryServerRequestObservationProvider(observations)
        provider.add(observations[0])
        self.assertEqual(len(provider.list_observations(
            run_id="run-1", surface_id="surface-1", parameter="url",
        )), 2)
        result = assess_ssrf_observations(
            provider,
            run_id="run-1",
            surface_id="surface-1",
            parameter="url",
            execution_approval=self.approval(),
            destination_policy=self.policy(),
            request_budget_available=True,
            analysis_verification_session_id="analysis-a",
            validation_verification_session_id="validation-b",
        )
        self.assertEqual(result.verdict, ValidationVerdict.CONFIRMED)
        provider.set_status(SsrfObservationProviderStatus.UNAVAILABLE)
        blocked = assess_ssrf_observations(
            provider,
            run_id="run-1",
            surface_id="surface-1",
            parameter="url",
            execution_approval=self.approval(),
            request_budget_available=True,
            analysis_verification_session_id="analysis-a",
            validation_verification_session_id="validation-b",
        )
        self.assertEqual(blocked.reason_code, SsrfAssessmentReason.PROVIDER_UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
