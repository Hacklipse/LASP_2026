"""Deterministic, network-free assessment of manual SSRF observations."""

from __future__ import annotations

from collections.abc import Sequence

from hacklipse.domain import (
    ServerRequestObservation,
    SsrfAssessment,
    SsrfAssessmentReason,
    SsrfDestinationPolicy,
    SsrfDestinationRule,
    SsrfExecutionApproval,
    SsrfObservationPhase,
    SsrfObservationProviderStatus,
    ValidationVerdict,
)
from hacklipse.ports import ServerRequestObservationProvider


def assess_ssrf_observations(
    provider: ServerRequestObservationProvider,
    *,
    run_id: str,
    surface_id: str,
    parameter: str,
    execution_approval: SsrfExecutionApproval | None,
    destination_policy: SsrfDestinationPolicy | None = None,
    request_budget_available: bool,
    analysis_verification_session_id: str | None,
    validation_verification_session_id: str | None,
) -> SsrfAssessment:
    """Read one provider snapshot, then apply the network-free resolver."""

    observations = tuple(provider.list_observations(
        run_id=run_id, surface_id=surface_id, parameter=parameter,
    ))
    return resolve_ssrf_assessment(
        observations,
        provider_status=provider.status,
        run_id=run_id,
        surface_id=surface_id,
        parameter=parameter,
        execution_approval=execution_approval,
        destination_policy=destination_policy,
        request_budget_available=request_budget_available,
        analysis_verification_session_id=analysis_verification_session_id,
        validation_verification_session_id=validation_verification_session_id,
    )


def resolve_ssrf_assessment(
    observations: Sequence[ServerRequestObservation],
    *,
    provider_status: SsrfObservationProviderStatus,
    run_id: str,
    surface_id: str,
    parameter: str,
    execution_approval: SsrfExecutionApproval | None,
    destination_policy: SsrfDestinationPolicy | None = None,
    request_budget_available: bool,
    analysis_verification_session_id: str | None,
    validation_verification_session_id: str | None,
) -> SsrfAssessment:
    """Resolve supplied sanitized observations without I/O or mutable state."""

    if provider_status is SsrfObservationProviderStatus.UNAVAILABLE:
        return _assessment(ValidationVerdict.BLOCKED, SsrfAssessmentReason.PROVIDER_UNAVAILABLE)
    if execution_approval is None:
        return _assessment(
            ValidationVerdict.BLOCKED, SsrfAssessmentReason.EXECUTION_APPROVAL_MISSING
        )
    if execution_approval.surface_id != surface_id:
        return _assessment(
            ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.EXECUTION_APPROVAL_SURFACE_MISMATCH,
        )
    if type(request_budget_available) is not bool:
        raise TypeError("request budget availability must be boolean")
    if not request_budget_available:
        return _assessment(
            ValidationVerdict.BLOCKED, SsrfAssessmentReason.REQUEST_BUDGET_UNAVAILABLE
        )
    if (
        not analysis_verification_session_id
        or not validation_verification_session_id
        or analysis_verification_session_id == validation_verification_session_id
    ):
        return _assessment(
            ValidationVerdict.BLOCKED, SsrfAssessmentReason.VERIFICATION_SESSION_MISSING
        )

    scoped = tuple(
        item for item in observations
        if item.run_id == run_id
        and item.surface_id == surface_id
        and item.parameter == parameter
    )
    approved = tuple(
        item for item in scoped
        if item.verification_endpoint_ref
        == execution_approval.verification_endpoint_ref
    )
    if scoped and not approved:
        return _assessment(
            ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.VERIFICATION_ENDPOINT_MISMATCH,
        )
    analysis = tuple(
        item for item in approved
        if item.phase is SsrfObservationPhase.ANALYSIS
        and item.verification_session_id == analysis_verification_session_id
    )
    validation = tuple(
        item for item in approved
        if item.phase is SsrfObservationPhase.VALIDATION
        and item.verification_session_id == validation_verification_session_id
    )
    for phase_observations in (analysis, validation):
        if phase_observations and not any(item.source_verified for item in phase_observations):
            return _assessment(
                ValidationVerdict.BLOCKED,
                SsrfAssessmentReason.OBSERVATION_SOURCE_UNVERIFIED,
                phase_observations,
            )

    verified_analysis = tuple(item for item in analysis if item.source_verified)
    verified_validation = tuple(item for item in validation if item.source_verified)
    if not verified_analysis:
        return _assessment(
            ValidationVerdict.REJECTED,
            SsrfAssessmentReason.NO_SERVER_REQUEST_OBSERVED,
            verified_validation,
        )
    if not verified_validation:
        return _assessment(
            ValidationVerdict.SUSPECTED,
            SsrfAssessmentReason.INDEPENDENT_OBSERVATION_MISSING,
            verified_analysis,
        )

    evidence = verified_analysis + verified_validation
    if destination_policy is None:
        return _assessment(
            ValidationVerdict.SUSPECTED,
            SsrfAssessmentReason.SERVER_REQUEST_OBSERVED_WITHOUT_DESTINATION_POLICY,
            evidence,
        )
    if surface_id not in destination_policy.surface_ids:
        return _assessment(
            ValidationVerdict.SUSPECTED,
            SsrfAssessmentReason.DESTINATION_POLICY_SURFACE_MISMATCH,
            evidence,
        )
    observed_origins = {
        item.destination_origin for item in evidence if item.destination_origin
    }
    if (
        len(observed_origins) != 1
        or destination_policy.destination_origin not in observed_origins
    ):
        return _assessment(
            ValidationVerdict.SUSPECTED,
            SsrfAssessmentReason.DESTINATION_POLICY_ORIGIN_MISMATCH,
            evidence,
        )
    if destination_policy.destination_rule is SsrfDestinationRule.ALLOWED:
        return _assessment(
            ValidationVerdict.REJECTED,
            SsrfAssessmentReason.DESTINATION_POLICY_ALLOWS_ACCESS,
            evidence,
            policy_id=destination_policy.policy_id,
        )
    observed_origin = next(iter(observed_origins))
    if not destination_policy.confirms_for(surface_id, observed_origin):
        return _assessment(
            ValidationVerdict.SUSPECTED,
            SsrfAssessmentReason.DESTINATION_POLICY_EVIDENCE_INVALID,
            evidence,
        )
    return _assessment(
        ValidationVerdict.CONFIRMED,
        SsrfAssessmentReason.CONFIRMED_DESTINATION_POLICY_VIOLATION,
        evidence,
        policy_id=destination_policy.policy_id,
    )


def _assessment(
    verdict: ValidationVerdict,
    reason: SsrfAssessmentReason,
    observations: tuple[ServerRequestObservation, ...] = (),
    *,
    policy_id: str | None = None,
) -> SsrfAssessment:
    observation_ids = tuple(dict.fromkeys(
        item.observation_id for item in observations
    ))
    return SsrfAssessment(
        verdict=verdict,
        reason_code=reason,
        observation_ids=observation_ids,
        policy_id=policy_id,
    )
