"""Analysis 결론 없이 Evidence만으로 Candidate를 독립 판정하는 결정적 Validation Agent."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    EvidenceRequest,
    SsrfAssessmentReason,
    SsrfDestinationRule,
    SsrfObservationPhase,
    SsrfVerificationStrategy,
    TaskEnvelope,
    ValidationProof,
    ValidationProofType,
    ValidationReasonCode,
    ValidationResult,
    ValidationVerdict,
    ssrf_destination_origin,
)
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import (
    build_probe_requests,
    build_sqli_boolean_requests,
    matching_evidence,
    probe_marker,
)
from .path_traversal_analysis import (
    HIDDEN_BODY_CAPABILITY,
    PATH_TRAVERSAL_BYPASS_OBSERVATION,
    PATH_TRAVERSAL_OBSERVATION,
    PATH_TRAVERSAL_TOOL,
    build_path_traversal_bypass_requests,
    build_path_traversal_requests,
    is_restricted_file_surface,
    path_parameter_candidates,
    path_traversal_bypass_signal,
    path_traversal_signal,
)
from .access_control_analysis import (
    ACCESS_CONTROL_TOOL,
    build_access_control_requests,
    unauthorized_object_exposed,
)
from .routing import DEFAULT_RULES, OPTIONAL_SOURCE_MAP_RULES
from .sqli_analysis import sql_boolean_signal, sql_error_signal
from .graphql_discovery import (
    graphql_auth_blocked_response, graphql_query_plans, graphql_query_requests,
)
from .graphql_introspection import (
    INTROSPECTION_TYPE, INTROSPECTION_OBSERVATION,
    introspection_request, schema_name,
)
from .graphql_suggestions import (
    SUGGESTION_TYPE, SUGGESTION_OBSERVATION,
    suggestion_request, suggested_field,
)
from .ssti_analysis import (
    SSTI_OBSERVATION,
    SSTI_TOOL,
    build_ssti_requests,
    matching_ssti_evidence,
    ssti_execution_signal,
)
from .xss_execution import (
    BROWSER_XSS_TOOL, XSS_EXECUTION_MARKER_PREFIX, attribute_execution_marker,
)
from .postmessage_plan import POSTMESSAGE_ANALYZER
from .postmessage_xss_analysis import message_request
from hacklipse.domain import HttpRequestKind
from .sensitive_exposure import EXPOSURE_TYPE, EXPOSURE_OBSERVATION, exposed_json_field_paths
from .public_login_credentials import (
    PUBLIC_LOGIN_TYPE, PUBLIC_LOGIN_VERIFIED, PUBLIC_LOGIN_UNVERIFIABLE,
    observed_login_target, replay_public_login,
)
from .source_map_exposure import (
    SOURCE_MAP_TYPE, SOURCE_MAP_OBSERVATION, exposed_source_map_signature,
)
from .error_disclosure import (
    ERROR_DISCLOSURE_TYPE, ERROR_TRACE_OBSERVATION, exposed_error_stack,
    error_detail_request,
)
from .open_redirect_analysis import (
    REDIRECT_TYPE, REDIRECT_OBSERVATION, build_redirect_requests,
    redirect_probe_url, redirected_to_probe,
)
from .cors_analysis import (
    CORS_TYPE, CORS_OBSERVATION, CORS_VALIDATION_ORIGIN,
    build_cors_requests, cors_reflection_signal, cors_probe_shape,
)
from .ssrf_analysis import (
    SSRF_RESULT_TYPE, SSRF_TYPE, build_ssrf_canary_requests,
    build_ssrf_owned_receiver_requests, build_ssrf_requests,
    canary_marker_signal, has_http_callback, has_owned_receiver_observation,
    poll_ssrf_callbacks, ssrf_candidate_verification_strategy, ssrf_parameters,
)
from .ssrf_assessment import resolve_ssrf_assessment

# Router가 Candidate를 만들 때 쓴 것과 같은 taxonomy. Candidate가 알려진 취약점
# 유형을 벗어나면(Router가 만들 수 없는 값) 계약 위반으로 간주한다. Analysis
# Agent의 자유 서술 결론(hypothesis)은 여기서도 참고하지 않는다.
_EXPECTED_SIGNAL = {
    rule.vulnerability_type: rule.observation_type
    for rule in (*DEFAULT_RULES, *OPTIONAL_SOURCE_MAP_RULES)
}
_EXPECTED_SIGNAL[SSRF_TYPE] = "ssrf_callback_http"

# HttpExecutionRuntime(및 그 대역)이 실제 재현 요청 결과에 붙이는 Observation 유형.
# 최초 Recon이 남긴 신호 관측(예: "url_or_file_parameter")과는 구분되는, Validator
# 자신이 직접 수행을 요청한 독립적인 재요청의 결과만 재현 근거로 인정한다.
_REPRODUCTION_EVIDENCE_TYPES = frozenset(
    {
        "http_response",
        "http_error",
        "http_redirect",
        "browser_execution",
        "browser_error",
    }
)

_REPRODUCTION_TOOL = "http_get"
_SQLI_SYNTAX_BREAKER = "'"


class ValidationAgent:
    """현재 Validation 세션의 Evidence만으로 보수적인 baseline 판정을 내린다.

    SQLi는 독립 control/probe에서 오류 차이를 재현해야만 SQLI_EFFECT proof로 확정한다.
    아직 전용 proof가 없는 취약점은 범용 HTTP 응답만으로 확정하지 않고 SUSPECTED 또는
    BLOCKED를 반환한다.
    """

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        evidence_store: EvidenceStore,
        surface_store: SurfaceStore,
        collector=None,
    ) -> None:
        self._candidates = candidate_store
        self._evidence = evidence_store
        self._surfaces = surface_store
        self._collector = collector

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """독립 재현 Evidence가 있으면 판정하고, 없으면 재현 요청을 반환한다."""

        if task.candidate_id is None or task.validation_id is None:
            raise AgentContractError(
                "validation task is missing a candidate or validation session"
            )
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        if task.surface_id != candidate.surface_id:
            raise AgentContractError(
                "validation candidate and task reference different surfaces"
            )
        if candidate.vulnerability_type not in _EXPECTED_SIGNAL:
            raise AgentContractError(
                "validation agent has no reproduction rule for "
                f"vulnerability type: {candidate.vulnerability_type}"
            )
        specialized_path_validation = (
            candidate.vulnerability_type == "Path Traversal"
            and PATH_TRAVERSAL_TOOL in task.allowed_tools
        )
        specialized_access_validation = (
            candidate.vulnerability_type == "Access Control"
            and ACCESS_CONTROL_TOOL in task.allowed_tools
        )
        specialized_ssti_validation = (
            candidate.vulnerability_type == "SSTI" and SSTI_TOOL in task.allowed_tools
        )
        specialized_login_validation = candidate.vulnerability_type == PUBLIC_LOGIN_TYPE
        if candidate.vulnerability_type == "SQLi":
            surface = self._surfaces.get(task.run_id, candidate.surface_id)
            required_tool = (
                "http_post" if surface.method.upper() == "POST" else _REPRODUCTION_TOOL
            )
        elif specialized_path_validation:
            required_tool = PATH_TRAVERSAL_TOOL
        elif specialized_access_validation:
            required_tool = ACCESS_CONTROL_TOOL
        elif specialized_ssti_validation:
            required_tool = SSTI_TOOL
        elif specialized_login_validation:
            required_tool = "http_post"
        else:
            required_tool = _REPRODUCTION_TOOL
        if required_tool not in task.allowed_tools:
            raise AgentContractError(
                f"validation tool is not allowed by the task: {required_tool}"
            )

        evidence_ids = tuple(dict.fromkeys(task.evidence_ids))
        evidence = self._evidence.get_many(task.run_id, evidence_ids)
        reproduction = [
            item
            for item in evidence
            if _is_reproduction_evidence(item, task.validation_id)
        ]

        if candidate.vulnerability_type == "SQLi":
            return self._validate_sqli(task, candidate, evidence, reproduction)
        if candidate.vulnerability_type == SSRF_TYPE:
            return self._validate_ssrf(task, candidate, evidence)
        if candidate.vulnerability_type == EXPOSURE_TYPE:
            return self._validate_sensitive_exposure(task, candidate, evidence, reproduction)
        if specialized_login_validation:
            return self._validate_public_login(task, candidate, evidence)
        if candidate.vulnerability_type == INTROSPECTION_TYPE:
            return self._validate_graphql_introspection(task, candidate, evidence, reproduction)
        if candidate.vulnerability_type == SUGGESTION_TYPE:
            return self._validate_graphql_suggestion(task, candidate, evidence, reproduction)
        if candidate.vulnerability_type == SOURCE_MAP_TYPE:
            return self._validate_source_map_exposure(task, candidate, evidence, reproduction)
        if candidate.vulnerability_type == ERROR_DISCLOSURE_TYPE:
            return self._validate_error_detail_exposure(task, candidate, evidence, reproduction)
        if candidate.vulnerability_type == REDIRECT_TYPE:
            return self._validate_open_redirect(task, candidate, evidence, reproduction)
        if candidate.vulnerability_type == CORS_TYPE:
            return self._validate_cors(task, candidate, evidence, reproduction)
        if specialized_path_validation:
            return self._validate_path_traversal(
                task, candidate, evidence, reproduction
            )
        if specialized_access_validation:
            return self._validate_access_control(task, candidate, evidence)
        if specialized_ssti_validation:
            return self._validate_ssti(task, candidate, evidence, reproduction)
        if (
            candidate.vulnerability_type == "XSS"
            and BROWSER_XSS_TOOL in task.allowed_tools
        ):
            if candidate.assigned_agent == POSTMESSAGE_ANALYZER:
                return self._validate_postmessage_xss(
                    task, candidate, evidence, reproduction,
                )
            return self._validate_xss(task, candidate, evidence, reproduction)

        if not reproduction:
            return self._needs_evidence(task, candidate.surface_id, EXPOSURE_TYPE)
        return self._decide(task, reproduction)

    def _validate_ssrf(
        self, task: TaskEnvelope, candidate: Candidate, evidence: Sequence[Evidence],
    ) -> AgentResult:
        if self._collector is None:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="SSRF validation collector is unavailable",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        surface_evidence = tuple(item for item in self._evidence.list_by_run(task.run_id)
                                 if item.surface_id == surface.surface_id)
        available_parameters = ssrf_parameters(surface, surface_evidence)
        canary = self._collector.ssrf_canary_proof_for_run(task.run_id)
        try:
            strategy = ssrf_candidate_verification_strategy(candidate)
        except AgentContractError:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="unsupported or mixed SSRF verification strategy",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        registration = self._collector.ssrf_review_for_surface(
            task.run_id, candidate.surface_id, strategy,
        )
        callback_candidate = strategy is SsrfVerificationStrategy.CALLBACK
        canary_candidate = strategy is SsrfVerificationStrategy.INTERNAL_CANARY
        owned_receiver_candidate = strategy is SsrfVerificationStrategy.OWNED_RECEIVER
        passive_candidate = strategy is SsrfVerificationStrategy.PASSIVE
        if (canary_candidate or owned_receiver_candidate) and registration is None:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="SSRF verification requires a Surface-bound execution approval",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        if owned_receiver_candidate:
            if not self._collector.ssrf_owned_receiver_enabled:
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                    reason="operator-owned SSRF receiver is unavailable",
                    reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_UNAVAILABLE,
                )
            assert registration is not None
            return self._validate_registered_ssrf_owned_receiver(
                task,
                candidate,
                evidence,
                surface,
                surface_evidence,
                available_parameters,
                registration,
            )
        if canary_candidate and registration is not None and canary is not None:
            return self._validate_registered_ssrf_canary(
                task, candidate, evidence, surface, surface_evidence,
                available_parameters, registration, canary,
            )
        if (
            passive_candidate
            and registration is not None
            and self._collector.ssrf_observation_enabled
        ):
            return self._validate_registered_ssrf_review(
                task, candidate, available_parameters, registration,
            )
        if passive_candidate:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="passive SSRF review provider or registration is unavailable",
                reason_code=ValidationReasonCode.SSRF_MANUAL_REVIEW_REQUIRED,
            )
        if canary_candidate:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="approved internal canary endpoint is unavailable",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        if registration is not None:
            available_parameters = tuple(
                item for item in available_parameters
                if item == registration.parameter
            )
        if not self._collector.ssrf_enabled:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="SSRF callback service is unavailable",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_PROVIDER_UNAVAILABLE,
            )
        if not available_parameters:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="observed or declared URL input is unavailable",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        analysis_evidence = tuple(item for item in evidence if item.validation_id is None)
        results = tuple(
            item for item in analysis_evidence
            if item.created_by == "ssrf_analyzer"
            and item.observation.get("type") == SSRF_RESULT_TYPE
            and item.observation.get("candidate_id") == candidate.candidate_id
        )
        if any(item.observation.get("status") == "provider_error" for item in results):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="SSRF callback provider failed during analysis",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_PROVIDER_UNAVAILABLE,
            )
        first_probe = None
        parameter = None
        first_hits = tuple(item for item in analysis_evidence
                           if item.created_by == "execution_runtime:ssrf_callback")
        for outcome in results:
            selected = outcome.observation.get("parameter")
            if selected not in available_parameters or outcome.observation.get("status") != "http":
                continue
            try:
                analysis_ticket = self._collector.issue_ssrf_ticket(
                    task.run_id, candidate.candidate_id, selected,
                )
            except (OSError, TimeoutError):
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                    reason="SSRF callback provider could not reload the analysis ticket",
                    reason_code=ValidationReasonCode.SSRF_CALLBACK_PROVIDER_UNAVAILABLE,
                )
            _, analysis_probe = build_ssrf_requests(
                surface, selected, analysis_ticket.url, surface_evidence,
            )
            candidate_probe = matching_evidence(analysis_evidence, surface.url, analysis_probe)
            if candidate_probe is not None and has_http_callback(first_hits, candidate_probe.evidence_id):
                first_probe, parameter = candidate_probe, selected
                break
        if first_probe is None or parameter is None:
            dns_seen = any(item.observation.get("status") == "dns" for item in results)
            return self._validation_result(
                task,
                verdict=ValidationVerdict.SUSPECTED,
                evidence=(),
                reason=("analysis observed DNS only" if dns_seen
                        else "no HTTP callback arrived within the bounded wait"),
                reason_code=ValidationReasonCode.SSRF_CALLBACK_NOT_OBSERVED,
            )
        assert task.validation_id is not None
        try:
            ticket = self._collector.issue_ssrf_ticket(
                task.run_id, candidate.candidate_id, parameter,
                validation_id=task.validation_id,
            )
        except (OSError, TimeoutError):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="SSRF callback provider could not issue a validation ticket",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_PROVIDER_UNAVAILABLE,
            )
        requests = build_ssrf_requests(surface, parameter, ticket.url, surface_evidence)
        session_evidence = tuple(item for item in evidence
                                 if item.validation_id == task.validation_id)
        collected = tuple(matching_evidence(session_evidence, surface.url, request)
                          for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                    reason="independent SSRF control/probe budget is unavailable",
                    reason_code=ValidationReasonCode.SSRF_PROOF_BUDGET_EXHAUSTED,
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )
        probe = collected[1]
        assert probe is not None
        try:
            callback_ids = poll_ssrf_callbacks(
                self._collector, self._evidence, task, surface, requests[1], probe.evidence_id,
            )
        except (OSError, TimeoutError):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=collected,
                reason="SSRF callback provider failed during validation",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_PROVIDER_UNAVAILABLE,
            )
        callback_evidence = self._evidence.get_many(task.run_id, callback_ids)
        reproduced = tuple(item for item in collected if item is not None) + callback_evidence
        if has_http_callback(callback_evidence, probe.evidence_id):
            result = self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="independent HTTP callback reproduced; server attribution and "
                       "destination rule violation remain unproven",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_ONLY,
            )
        else:
            result = self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="analysis HTTP callback was not independently reproduced",
                reason_code=ValidationReasonCode.SSRF_CALLBACK_NOT_OBSERVED,
            )
        return replace(result, new_evidence_ids=callback_ids)

    def _validate_registered_ssrf_owned_receiver(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        evidence: Sequence[Evidence],
        surface,
        surface_evidence: tuple[Evidence, ...],
        available_parameters: Sequence[str],
        registration,
    ) -> AgentResult:
        """Reproduce a trusted receiver hit with a fresh Validation ticket."""

        parameter = registration.parameter
        if (
            parameter not in available_parameters
            or candidate.exploration_parameters != (parameter,)
        ):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=(),
                reason="owned receiver coordinate does not match this Candidate",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        analysis_evidence = tuple(
            item for item in evidence if item.validation_id is None
        )
        results = tuple(
            item
            for item in analysis_evidence
            if item.created_by == "ssrf_analyzer"
            and item.observation.get("type") == SSRF_RESULT_TYPE
            and item.observation.get("candidate_id") == candidate.candidate_id
            and item.observation.get("parameter") == parameter
        )
        if any(item.observation.get("status") == "provider_error" for item in results):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=(),
                reason="operator-owned SSRF receiver failed during Analysis",
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_UNAVAILABLE,
            )
        try:
            analysis_ticket = self._collector.issue_ssrf_owned_receiver_ticket(
                task.run_id,
                candidate.candidate_id,
                candidate.surface_id,
                parameter,
            )
        except (AgentContractError, OSError, TimeoutError):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=(),
                reason="operator-owned SSRF receiver could not restore ticket A",
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_UNAVAILABLE,
            )
        analysis_requests = build_ssrf_owned_receiver_requests(
            surface, parameter, analysis_ticket.url, surface_evidence,
        )
        analysis_probe = matching_evidence(
            analysis_evidence, surface.url, analysis_requests[1],
        )
        analysis_observations = tuple(
            item
            for item in analysis_evidence
            if item.created_by == "execution_runtime:ssrf_observation_provider"
        )
        result_seen = any(
            item.observation.get("status") == "owned_request_observed"
            and item.observation.get("probe_evidence_id")
            == (analysis_probe.evidence_id if analysis_probe is not None else None)
            for item in results
        )
        if (
            analysis_probe is None
            or not result_seen
            or not has_owned_receiver_observation(
                analysis_observations, analysis_probe.evidence_id,
            )
        ):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.SUSPECTED,
                evidence=analysis_observations,
                reason="operator-owned receiver did not establish request A",
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_NOT_OBSERVED,
            )
        assert task.validation_id is not None
        try:
            validation_ticket = self._collector.issue_ssrf_owned_receiver_ticket(
                task.run_id,
                candidate.candidate_id,
                candidate.surface_id,
                parameter,
                validation_id=task.validation_id,
            )
        except (AgentContractError, OSError, TimeoutError):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=analysis_observations,
                reason="operator-owned SSRF receiver could not issue fresh ticket B",
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_UNAVAILABLE,
            )
        requests = build_ssrf_owned_receiver_requests(
            surface, parameter, validation_ticket.url, surface_evidence,
        )
        session_evidence = tuple(
            item for item in evidence if item.validation_id == task.validation_id
        )
        collected = tuple(
            matching_evidence(session_evidence, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                return self._validation_result(
                    task,
                    verdict=ValidationVerdict.BLOCKED,
                    evidence=(),
                    reason="independent owned-receiver request budget is unavailable",
                    reason_code=ValidationReasonCode.SSRF_PROOF_BUDGET_EXHAUSTED,
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )
        probe = collected[1]
        assert probe is not None
        try:
            observation_ids = self._collector.collect_ssrf_owned_receiver_observations(
                task.run_id,
                candidate.candidate_id,
                surface.url,
                requests[1],
                probe.evidence_id,
                task_id=task.task_id,
                validation_id=task.validation_id,
                poll_timeout_seconds=(
                    self._collector.ssrf_owned_receiver_poll_wait_seconds
                ),
            )
        except (AgentContractError, OSError, TimeoutError):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=tuple(item for item in collected if item is not None),
                reason="operator-owned SSRF receiver failed during Validation",
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_UNAVAILABLE,
            )
        validation_observations = self._evidence.get_many(
            task.run_id, observation_ids,
        )
        if not has_owned_receiver_observation(
            validation_observations, probe.evidence_id,
        ):
            result = self._validation_result(
                task,
                verdict=ValidationVerdict.SUSPECTED,
                evidence=tuple(item for item in collected if item is not None),
                reason="request A was observed but fresh request B was not reproduced",
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_NOT_OBSERVED,
            )
            return replace(result, new_evidence_ids=observation_ids)
        return self._validate_registered_ssrf_review(
            task,
            candidate,
            available_parameters,
            registration,
            owned_receiver=True,
        )

    def _validate_registered_ssrf_canary(
        self, task: TaskEnvelope, candidate: Candidate, evidence: Sequence[Evidence],
        surface, surface_evidence: tuple[Evidence, ...],
        available_parameters: Sequence[str], registration, canary,
    ) -> AgentResult:
        """Reproduce the approved, exact endpoint independently of Analysis."""

        parameter = registration.parameter
        if (
            canary.surface_id != candidate.surface_id
            or registration.execution_approval.verification_endpoint_ref
            != self._collector.ssrf_verification_endpoint_ref(task.run_id, canary.url)
            or parameter not in available_parameters
            or candidate.exploration_parameters != (parameter,)
        ):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="approved SSRF coordinate or policy does not match",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        requests = build_ssrf_canary_requests(
            surface, parameter, canary.url, surface_evidence,
        )
        analysis_evidence = tuple(
            item for item in evidence if item.validation_id is None
        )
        analysis_control, analysis_probe = tuple(
            matching_evidence(analysis_evidence, surface.url, request)
            for request in requests
        )
        result_seen = any(
            item.created_by == "ssrf_analyzer"
            and item.observation.get("type") == SSRF_RESULT_TYPE
            and item.observation.get("candidate_id") == candidate.candidate_id
            and item.observation.get("parameter") == parameter
            and item.observation.get("probe_evidence_id") == (
                analysis_probe.evidence_id if analysis_probe is not None else None
            )
            and item.observation.get("status") == "controlled_marker"
            for item in analysis_evidence
        )
        if (
            analysis_control is None or analysis_probe is None or not result_seen
            or not canary_marker_signal(analysis_control, analysis_probe)
        ):
            return self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=(),
                reason="approved endpoint marker was not established during Analysis",
                reason_code=ValidationReasonCode.SSRF_CANARY_ANALYSIS_NOT_ESTABLISHED,
            )
        assert task.validation_id is not None
        session_evidence = tuple(
            item for item in evidence if item.validation_id == task.validation_id
        )
        collected = tuple(
            matching_evidence(session_evidence, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                    reason="independent SSRF verification request budget is unavailable",
                    reason_code=ValidationReasonCode.SSRF_PROOF_BUDGET_EXHAUSTED,
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )
        control, probe = collected
        assert control is not None and probe is not None
        reproduced = (control, probe)
        if not canary_marker_signal(control, probe):
            return self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="approved endpoint marker was not independently reproduced",
                reason_code=ValidationReasonCode.SSRF_CANARY_NOT_REPRODUCED,
            )
        policy = registration.destination_policy
        if policy is None:
            return self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="internal canary was independently reproduced, but no destination "
                       "policy was registered",
                reason_code=ValidationReasonCode.SSRF_DESTINATION_POLICY_MISSING,
            )
        if (
            canary.destination_policy is not None
            and canary.destination_policy != policy
        ):
            return self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="internal canary policy does not match the Run-bound policy",
                reason_code=ValidationReasonCode.SSRF_DESTINATION_POLICY_MISMATCH,
            )
        if candidate.surface_id not in policy.surface_ids:
            return self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="destination policy is not bound to this Surface",
                reason_code=ValidationReasonCode.SSRF_DESTINATION_POLICY_SURFACE_MISMATCH,
            )
        if policy.destination_rule is not SsrfDestinationRule.FORBIDDEN:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=reproduced,
                reason="destination policy explicitly allows this access",
                reason_code=ValidationReasonCode.SSRF_DESTINATION_POLICY_ALLOWS_ACCESS,
            )
        if not policy.confirms_for(candidate.surface_id, canary.url):
            if policy.destination_origin != ssrf_destination_origin(canary.url):
                return self._validation_result(
                    task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                    reason="internal canary was reproduced, but policy origin does not "
                           "match the approved endpoint",
                    reason_code=(
                        ValidationReasonCode.SSRF_DESTINATION_POLICY_ORIGIN_MISMATCH
                    ),
                )
            return self._validation_result(
                task, verdict=ValidationVerdict.SUSPECTED, evidence=reproduced,
                reason="internal canary was reproduced, but policy assertion or evidence "
                       "status is insufficient",
                reason_code=(
                    ValidationReasonCode.SSRF_DESTINATION_POLICY_EVIDENCE_INVALID
                ),
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.SSRF_UNAUTHORIZED_FETCH,
            evidence_ids=(control.evidence_id, probe.evidence_id),
            summary=(
                "approved endpoint marker independently reproduced; policy "
                f"source={policy.source_type.value}, reference={policy.source_reference}, "
                f"surface={candidate.surface_id}, assertion={policy.assertion.value}, "
                f"status={policy.evidence_status.value}"
            ),
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=reproduced,
            reason="approved endpoint response was independently reproduced",
            reason_code=(
                ValidationReasonCode.SSRF_CONFIRMED_DESTINATION_POLICY_VIOLATION
            ),
            proof=proof,
        )

    def _validate_registered_ssrf_review(
        self, task: TaskEnvelope, candidate: Candidate,
        available_parameters: Sequence[str], registration,
        *, owned_receiver: bool = False,
    ) -> AgentResult:
        """Map sanitized provider observations into the normal Validation contract."""

        parameter = registration.parameter
        if (
            parameter not in available_parameters
            or candidate.exploration_parameters != (parameter,)
        ):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="registered SSRF coordinate is not available to this Candidate",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        assert task.validation_id is not None
        review_strategy = (
            SsrfVerificationStrategy.OWNED_RECEIVER
            if owned_receiver else SsrfVerificationStrategy.PASSIVE
        )
        try:
            provider_status, observations, mapping = (
                self._collector.collect_server_request_observations(
                    run_id=task.run_id,
                    surface_id=candidate.surface_id,
                    parameter=parameter,
                    task_id=task.task_id,
                    validation_id=task.validation_id,
                    strategy=review_strategy,
                )
            )
        except (AgentContractError, OSError, TimeoutError):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="registered SSRF observation failed provenance validation",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        analysis_sessions = {
            item.verification_session_id for item in observations
            if item.phase is SsrfObservationPhase.ANALYSIS
        }
        # A provider record is the only trusted proof that a verification
        # session actually ran. With zero records there is no safe distinction
        # between "not attempted" and "attempted with no request", so the
        # deterministic resolver keeps this case BLOCKED rather than negative.
        analysis_session = (
            next(iter(analysis_sessions)) if len(analysis_sessions) == 1 else None
        )
        assessment = resolve_ssrf_assessment(
            observations,
            provider_status=provider_status,
            run_id=task.run_id,
            surface_id=candidate.surface_id,
            parameter=parameter,
            execution_approval=registration.execution_approval,
            destination_policy=registration.destination_policy,
            request_budget_available=task.request_budget > 0,
            analysis_verification_session_id=analysis_session,
            validation_verification_session_id=task.validation_id,
        )
        assessment_id = self._collector.record_ssrf_assessment(
            run_id=task.run_id,
            surface_id=candidate.surface_id,
            parameter=parameter,
            task_id=task.task_id,
            validation_id=task.validation_id,
            assessment=assessment,
            observation_evidence_ids=mapping,
            strategy=review_strategy,
        )
        current_observation_ids = tuple(
            mapping[item.observation_id]
            for item in observations
            if item.phase is SsrfObservationPhase.VALIDATION
            and item.verification_session_id == task.validation_id
            and item.observation_id in assessment.observation_ids
        )
        validation_evidence_ids = tuple(dict.fromkeys(
            (*current_observation_ids, assessment_id)
        ))
        validation_evidence = self._evidence.get_many(
            task.run_id, validation_evidence_ids,
        )
        proof = None
        if assessment.verdict is ValidationVerdict.CONFIRMED:
            proof = ValidationProof(
                proof_type=ValidationProofType.SSRF_UNAUTHORIZED_FETCH,
                evidence_ids=validation_evidence_ids,
                summary=(
                    "independent operator-owned request observation and an exact-Surface "
                    "destination policy were reproduced in the validation session"
                ),
            )
        reason = f"structured SSRF assessment: {assessment.reason_code.value}"
        if assessment.verdict is ValidationVerdict.CONFIRMED:
            result = self._validation_result(
                task, verdict=assessment.verdict, evidence=validation_evidence,
                reason=reason, reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                proof=proof,
            )
        elif assessment.verdict is ValidationVerdict.BLOCKED:
            result = self._validation_result(
                task, verdict=assessment.verdict, evidence=validation_evidence,
                reason=reason,
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        elif (
            assessment.verdict is ValidationVerdict.SUSPECTED
            and assessment.reason_code is SsrfAssessmentReason.MANUAL_REVIEW_REQUIRED
        ):
            result = self._validation_result(
                task, verdict=assessment.verdict, evidence=validation_evidence,
                reason=reason,
                reason_code=ValidationReasonCode.SSRF_MANUAL_REVIEW_REQUIRED,
            )
        elif (
            assessment.verdict is ValidationVerdict.SUSPECTED
            and owned_receiver
        ):
            result = self._validation_result(
                task, verdict=assessment.verdict, evidence=validation_evidence,
                reason=reason,
                reason_code=ValidationReasonCode.SSRF_OWNED_RECEIVER_ONLY,
            )
        elif assessment.verdict is ValidationVerdict.SUSPECTED:
            result = self._validation_result(
                task, verdict=assessment.verdict, evidence=validation_evidence,
                reason=reason,
                reason_code=ValidationReasonCode.SSRF_MANUAL_REVIEW_REQUIRED,
            )
        else:
            result = self._validation_result(
                task, verdict=assessment.verdict, evidence=validation_evidence,
                reason=reason,
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        return replace(
            result,
            new_evidence_ids=tuple(dict.fromkeys((*mapping.values(), assessment_id))),
        )

    def _validate_public_login(
        self, task: TaskEnvelope, candidate: Candidate, evidence: Sequence[Evidence],
    ) -> AgentResult:
        analysis = [
            item for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "public_login_credentials_analyzer"
            and item.observation.get("type") in {
                PUBLIC_LOGIN_VERIFIED, PUBLIC_LOGIN_UNVERIFIABLE,
            }
        ]
        if not any(item.observation.get("type") == PUBLIC_LOGIN_VERIFIED for item in analysis):
            blocked = any(
                item.observation.get("reason") in {
                    "observed_login_shape_missing", "approval_or_policy_blocked",
                    "tool_not_allowed",
                } for item in analysis
            )
            if blocked:
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                    reason="approved observed login replay was unavailable",
                    reason_code=ValidationReasonCode.POST_REQUEST_TEMPLATE_MISSING,
                )
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis did not verify a working public login pair",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        if self._collector is None:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="independent login collector is unavailable",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        target = observed_login_target(task.run_id, surface.url, self._surfaces, self._evidence)
        if target is None:
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                reason="observed login request shape is unavailable",
                reason_code=ValidationReasonCode.POST_REQUEST_TEMPLATE_MISSING,
            )
        verified, ids, reason = replay_public_login(
            self._collector, task, surface.url, target, validation_id=task.validation_id,
        )
        reproduced = self._evidence.get_many(task.run_id, ids)
        if not verified:
            blocked = reason in {"approval_or_policy_blocked", "tool_not_allowed"}
            script_only = tuple(item for item in reproduced if item.surface_id == candidate.surface_id)
            if blocked:
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=script_only,
                    reason="independent approved login replay was blocked",
                    reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
                )
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=script_only,
                reason="independent login replay did not establish a session",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.WORKING_PUBLIC_CREDENTIAL,
            evidence_ids=ids,
            summary="independent public script fetch and approved login established a session",
            related_surface_ids=(target[0],),
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=reproduced,
            reason="public login literals independently established a session",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
        )

    def _validate_graphql_suggestion(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        plans = {
            (item.observation.get("field"), item.observation.get("typo"))
            for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "graphql_suggestion_analyzer"
            and item.observation.get("type") == SUGGESTION_OBSERVATION
            and isinstance(item.observation.get("field"), str)
            and isinstance(item.observation.get("typo"), str)
        }
        if len(plans) != 1:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis did not reproduce a GraphQL field suggestion",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        field, typo = next(iter(plans))
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        request = suggestion_request(surface.surface_id, typo, "independent anonymous GraphQL field typo")
        response = matching_evidence(reproduction, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("GraphQL suggestion validation needs one read-only fetch")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=(request,))
        if response.evidence_type == "http_error":
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(response,),
                reason="independent field typo request failed",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        if not suggested_field(response.observation, typo, field):
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(response,),
                reason="independent field typo did not reproduce a name suggestion",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.GRAPHQL_FIELD_SUGGESTION_EXPOSURE,
            evidence_ids=(response.evidence_id,),
            summary="independent anonymous field typo query reproduced a schema name suggestion",
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=(response,),
            reason="anonymous GraphQL field suggestion independently reproduced",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
        )

    def _validate_graphql_introspection(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        analysis_names = {
            item.observation.get("query_type_name") for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "graphql_introspection_analyzer"
            and item.observation.get("type") == INTROSPECTION_OBSERVATION
            and isinstance(item.observation.get("query_type_name"), str)
        }
        if not analysis_names:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis did not reproduce schema access",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        request = introspection_request(surface.surface_id, "independent anonymous GraphQL schema access")
        response = matching_evidence(reproduction, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("GraphQL introspection validation needs one read-only fetch")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=(request,))
        if response.evidence_type == "http_error":
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(response,),
                reason="independent schema fetch failed",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        if schema_name(response.observation) not in analysis_names:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(response,),
                reason="independent schema fetch did not reproduce schema data",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.GRAPHQL_INTROSPECTION_EXPOSURE,
            evidence_ids=(response.evidence_id,),
            summary="independent anonymous read-only query reproduced GraphQL schema data",
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=(response,),
            reason="anonymous GraphQL schema access independently reproduced",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
        )

    def _validate_cors(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        analysis_signal = any(
            item.surface_id == candidate.surface_id
            and item.created_by == "cors_analyzer"
            and item.observation.get("type") == CORS_OBSERVATION
            for item in evidence
        )
        if not analysis_signal:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis produced no reflected credentialed CORS signal",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        search_parameter, graphql_query = cors_probe_shape(surface)
        requests = build_cors_requests(
            surface.surface_id, CORS_VALIDATION_ORIGIN,
            f"CORS validation {task.validation_id}",
            search_parameter=search_parameter, graphql_query=graphql_query,
        )
        collected = tuple(matching_evidence(reproduction, surface.url, request)
                          for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "CORS validation lacks read-only request budget",
                    required_requests=len(missing),
                )
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=missing)
        if cors_reflection_signal(
            collected[0], collected[1], CORS_VALIDATION_ORIGIN,
            require_graphql_data=graphql_query,
        ):
            proof_evidence = tuple(item for item in collected if item is not None)
            proof = ValidationProof(
                proof_type=ValidationProofType.CORS_ORIGIN_REFLECTION,
                evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                summary="independent read-only request reproduced credentialed reflection of a second Origin",
            )
            return self._validation_result(
                task, verdict=ValidationVerdict.CONFIRMED, evidence=proof_evidence,
                reason="two distinct foreign origins were reflected with credentials allowed",
                reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
            )
        return self._validation_result(
            task, verdict=ValidationVerdict.REJECTED,
            evidence=tuple(item for item in collected if item is not None),
            reason="independent second Origin was not credentialed and reflected",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_open_redirect(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        parameters = tuple(dict.fromkeys(
            parameter for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "open_redirect_analyzer"
            and item.observation.get("type") == REDIRECT_OBSERVATION
            and isinstance((parameter := item.observation.get("parameter")), str)
            and parameter in surface.parameters
        ))
        if not parameters:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis produced no redirect parameter signal",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        marker = probe_marker(f"{task.validation_id}{candidate.candidate_id}", prefix="redirect")
        probe_url = redirect_probe_url(marker)
        requests = build_redirect_requests(
            surface, surface.parameters, parameters, probe_url=probe_url,
            purpose=f"open redirect validation {task.validation_id}",
        )
        collected = tuple(matching_evidence(reproduction, surface.url, request)
                          for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "open redirect validation lacks read-only request budget",
                    required_requests=len(missing),
                )
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=missing)
        control = collected[0]
        if control is None:
            raise AgentContractError("open redirect control response missing")
        if redirected_to_probe(control, probe_url):
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(control,),
                reason="redirect control already contained the probe destination",
                reason_code=ValidationReasonCode.CONTROL_SIGNAL_PRESENT,
            )
        for probe in collected[1:]:
            if probe is not None and redirected_to_probe(probe, probe_url):
                proof_evidence = (control, probe)
                proof = ValidationProof(
                    proof_type=ValidationProofType.OPEN_REDIRECT,
                    evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                    summary="independent GET control/probe reproduced an off-origin navigation destination",
                )
                return self._validation_result(
                    task, verdict=ValidationVerdict.CONFIRMED, evidence=proof_evidence,
                    reason="independent navigation destination matched local loopback probe origin",
                    reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
                )
        return self._validation_result(
            task, verdict=ValidationVerdict.REJECTED,
            evidence=tuple(item for item in collected if item is not None),
            reason="independent probe did not reproduce an off-origin navigation destination",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_sensitive_exposure(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """Independently re-fetch client content; never place values in proof."""

        analysis_fields = {
            path for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "sensitive_exposure_analyzer"
            and item.observation.get("type") == EXPOSURE_OBSERVATION
            for path in item.observation.get("field_paths", ())
            if isinstance(path, str)
        }
        if not analysis_fields:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis did not reproduce credential-shaped client fields",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        if not reproduction:
            return self._needs_evidence(
                task, candidate.surface_id, candidate.vulnerability_type
            )
        response = reproduction[-1]
        if response.evidence_type == "http_error":
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(response,),
                reason="independent client content fetch failed",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        repeated = analysis_fields.intersection(exposed_json_field_paths(response.observation))
        if not repeated:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(response,),
                reason="independent fetch did not reproduce credential-shaped fields",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.SENSITIVE_DATA_EXPOSURE,
            evidence_ids=(response.evidence_id,),
            summary="independent client content fetch reproduced credential-shaped fields",
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=(response,),
            reason="credential-shaped client fields independently reproduced",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
        )

    def _validate_error_detail_exposure(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        analysis_signals = {
            (item.observation.get("stack_kind"), item.observation.get("probe_mode"))
            for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "error_disclosure_analyzer"
            and item.observation.get("type") == ERROR_TRACE_OBSERVATION
            and isinstance(item.observation.get("stack_kind"), str)
            and item.observation.get("probe_mode") in {"graphql", "diagnostic_get"}
        }
        if not analysis_signals:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis found no exposed stack frames",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        graphql = any(mode == "graphql" for _, mode in analysis_signals)
        request = error_detail_request(candidate.surface_id, graphql=graphql, validation=True)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        response = matching_evidence(reproduction, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("error detail validation needs one read-only GET")
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=(request,),
            )
        if response.evidence_type == "http_error":
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(response,),
                reason="independent diagnostic GET failed",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        if (exposed_error_stack(response.observation), "graphql" if graphql else "diagnostic_get") not in analysis_signals:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(response,),
                reason="independent GET did not reproduce stack frames",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.ERROR_DETAIL_EXPOSURE,
            evidence_ids=(response.evidence_id,),
            summary="independent GET reproduced internal stack frames in an error response",
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=(response,),
            reason="internal error stack independently reproduced",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
        )

    def _validate_source_map_exposure(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        analysis_signatures = {
            (item.observation.get("content_digest"), item.observation.get("source_count"))
            for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "source_map_exposure_analyzer"
            and item.observation.get("type") == SOURCE_MAP_OBSERVATION
            and isinstance(item.observation.get("content_digest"), str)
            and type(item.observation.get("source_count")) is int
        }
        if not analysis_signatures:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis found no original source text in the public map",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        if not reproduction:
            return self._needs_evidence(task, candidate.surface_id, SOURCE_MAP_TYPE)
        response = reproduction[-1]
        if response.evidence_type == "http_error":
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=(response,),
                reason="independent source map fetch failed",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        signature = exposed_source_map_signature(response.observation)
        if signature not in analysis_signatures:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(response,),
                reason="independent fetch did not reproduce the original source text",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )
        proof = ValidationProof(
            proof_type=ValidationProofType.SOURCE_MAP_EXPOSURE,
            evidence_ids=(response.evidence_id,),
            summary="independent GET reproduced original source text in a public source map",
        )
        return self._validation_result(
            task, verdict=ValidationVerdict.CONFIRMED, evidence=(response,),
            reason="public source map original content independently reproduced",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
        )

    def _validate_postmessage_xss(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """Only an independent foreign-origin execution can confirm a message sink."""

        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        plans = tuple(dict.fromkeys(
            (item.observation.get("message_type"), item.observation.get("html_field"))
            for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == POSTMESSAGE_ANALYZER
            and item.observation.get("type") == "postmessage_reflection"
            and isinstance(item.observation.get("message_type"), str)
            and isinstance(item.observation.get("html_field"), str)
        ))[:4]
        if not plans:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="foreign-origin benign message did not reach an HTML sink",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        marker = probe_marker(
            f"{task.validation_id}{candidate.candidate_id}",
            prefix=XSS_EXECUTION_MARKER_PREFIX,
        )
        requests = (
            message_request(
                surface.surface_id, HttpRequestKind.POSTMESSAGE_CONTROL,
            ),
            *(
                message_request(
                    surface.surface_id, HttpRequestKind.POSTMESSAGE_EXECUTION,
                    event_type=event_type, field=field, marker=marker, index=index,
                )
                for index, (event_type, field) in enumerate(plans)
            ),
        )
        collected = tuple(
            matching_evidence(reproduction, surface.url, request)
            for request in requests
        )
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "postMessage XSS validation lacks independent browser budget",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )
        observed = tuple(item for item in collected if item is not None)
        if any(item.observation.get("type") == "browser_error" for item in observed):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=observed,
                reason="independent foreign-origin browser probe failed",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        control = observed[0]
        if control.observation.get("script_executed") is True:
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=observed,
                reason="browser control unexpectedly contained an execution signal",
                reason_code=ValidationReasonCode.CONTROL_SIGNAL_PRESENT,
            )
        for item in observed[1:]:
            if (
                item.observation.get("type") == "browser_execution"
                and item.observation.get("foreign_origin_message") is True
                and item.observation.get("script_executed") is True
                and item.observation.get("execution_marker") == marker
            ):
                proof = ValidationProof(
                    proof_type=ValidationProofType.XSS_EXECUTION,
                    evidence_ids=(control.evidence_id, item.evidence_id),
                    summary="independent foreign-origin message executed a fixed browser canary",
                )
                return self._validation_result(
                    task, verdict=ValidationVerdict.CONFIRMED,
                    evidence=(control, item), proof=proof,
                    reason="foreign-origin message independently executed in the target",
                    reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                )
        return self._validation_result(
            task, verdict=ValidationVerdict.REJECTED, evidence=observed,
            reason="independent foreign-origin message did not execute",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_xss(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        evidence: Sequence[Evidence],
        reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """Analysis의 반사 위치를 실제 브라우저에서 독립적으로 실행 검증한다."""

        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        signaled_parameters = tuple(
            dict.fromkeys(
                parameter
                for item in evidence
                if item.surface_id == candidate.surface_id
                and item.observation.get("type") == "reflection"
                and isinstance((parameter := item.observation.get("parameter")), str)
                and parameter in surface.parameters
            )
        )
        if not signaled_parameters:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no reflected parameter to execute",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )

        marker = probe_marker(
            f"{task.validation_id}{candidate.candidate_id}",
            prefix=XSS_EXECUTION_MARKER_PREFIX,
        )
        requests = build_probe_requests(
            surface,
            surface.parameters,
            control_value="hacklipse-control",
            probe_value=marker,
            purpose=f"XSS execution validation {task.validation_id}",
            probe_parameters=signaled_parameters,
            suggested_tool=BROWSER_XSS_TOOL,
        )
        secondary_attributes = tuple(dict.fromkeys(
            attribute
            for item in evidence
            if item.surface_id == candidate.surface_id
            and item.created_by == "heuristic_xss_analyzer"
            and item.observation.get("type") == "dom_secondary_attribute_sink"
            and isinstance((attribute := item.observation.get("attribute")), str)
        ))[:2]
        secondary_plans = []
        for attribute in secondary_attributes:
            try:
                secondary_marker = attribute_execution_marker(
                    f"{task.validation_id}{candidate.candidate_id}", attribute
                )
            except ValueError:
                continue
            secondary_requests = build_probe_requests(
                surface, surface.parameters,
                control_value="hacklipse-control",
                probe_value=secondary_marker,
                purpose=f"XSS secondary execution validation {task.validation_id}",
                probe_parameters=signaled_parameters,
                suggested_tool=BROWSER_XSS_TOOL,
            )[1:]
            secondary_plans.append((secondary_marker, secondary_requests))
        all_requests = (
            *requests,
            *(request for _, batch in secondary_plans for request in batch),
        )
        collected = tuple(
            matching_evidence(reproduction, surface.url, request)
            for request in all_requests
        )
        missing_direct = tuple(
            request for request, item in zip(requests, collected[:len(requests)])
            if item is None
        )
        missing_secondary = tuple(
            request for request, item in zip(
                all_requests[len(requests):], collected[len(requests):]
            ) if item is None
        )
        if missing_direct:
            missing = (*missing_direct, *missing_secondary)
            if task.request_budget < len(missing_direct):
                raise BudgetExceeded(
                    "XSS validation lacks budget for independent browser control/probe requests",
                    required_requests=len(missing_direct),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=(
                    missing if task.request_budget >= len(missing)
                    else missing_direct
                ),
            )

        direct = tuple(item for item in collected[:len(requests)] if item is not None)
        if any(item.observation.get("type") == "browser_error" for item in direct):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=direct,
                reason="independent browser reproduction could not execute",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )

        control = direct[0]
        if control.observation.get("script_executed") is True:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=direct,
                reason="browser control unexpectedly contained an execution signal",
                reason_code=ValidationReasonCode.CONTROL_SIGNAL_PRESENT,
            )

        for parameter, probe in zip(signaled_parameters, direct[1:]):
            if (
                probe.observation.get("type") != "browser_execution"
                or probe.observation.get("script_executed") is not True
                or probe.observation.get("execution_marker") != marker
            ):
                continue
            proof_evidence = (control, probe)
            proof = ValidationProof(
                proof_type=ValidationProofType.XSS_EXECUTION,
                evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                summary=(
                    "independent headless browser execution reproduced the XSS effect "
                    f"for parameter {parameter}"
                ),
            )
            return self._validation_result(
                task,
                verdict=ValidationVerdict.CONFIRMED,
                evidence=proof_evidence,
                reason="independent browser control/probe comparison executed the XSS marker",
                reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                proof=proof,
            )

        if missing_secondary:
            if task.request_budget < len(missing_secondary):
                raise BudgetExceeded(
                    "secondary XSS validation lacks its full browser probe batch",
                    required_requests=len(missing_secondary),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing_secondary,
            )

        reproduced = tuple(item for item in collected if item is not None)
        offset = len(requests)
        for secondary_marker, secondary_requests in secondary_plans:
            secondary = reproduced[offset:offset + len(secondary_requests)]
            offset += len(secondary_requests)
            if any(
                item.observation.get("type") == "browser_error"
                for item in secondary
            ):
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED,
                    evidence=reproduced,
                    reason="secondary browser reproduction could not execute",
                    reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
                )
            for parameter, probe in zip(signaled_parameters, secondary):
                if (
                    probe.observation.get("type") != "browser_execution"
                    or probe.observation.get("script_executed") is not True
                    or probe.observation.get("execution_marker") != secondary_marker
                ):
                    continue
                proof_evidence = (control, probe)
                proof = ValidationProof(
                    proof_type=ValidationProofType.XSS_EXECUTION,
                    evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                    summary=(
                        "independent headless browser execution reproduced a "
                        f"secondary DOM sink for parameter {parameter}"
                    ),
                )
                return self._validation_result(
                    task, verdict=ValidationVerdict.CONFIRMED,
                    evidence=proof_evidence,
                    reason="independent browser control and secondary probe executed the XSS marker",
                    reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                    proof=proof,
                )

        return self._validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent browser probe did not execute the XSS marker",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_sqli(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        evidence: Sequence[Evidence],
        reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """Analysis 신호를 요청 계획에만 쓰고 SQL 효과를 독립 재현한다."""

        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        graphql_plans = tuple(
            plan for item in evidence
            if item.surface_id == surface.surface_id
            for plan in graphql_query_plans(item)
        )
        if graphql_plans and "graphql_introspection" in surface.discovery_types:
            return self._validate_graphql_sqli(
                task, candidate, evidence, reproduction, surface, graphql_plans
            )
        boolean_parameters = tuple(
            dict.fromkeys(
                parameter
                for item in evidence
                if item.surface_id == candidate.surface_id
                and item.observation.get("type") == "sqli_differential"
                and isinstance((parameter := item.observation.get("parameter")), str)
                and parameter in surface.parameters
            )
        )
        signaled_parameters = tuple(
            dict.fromkeys(
                parameter
                for item in evidence
                if item.surface_id == candidate.surface_id
                and item.observation.get("type") == "sql_error"
                and isinstance((parameter := item.observation.get("parameter")), str)
                and parameter in surface.parameters
            )
        )
        if boolean_parameters:
            requests = build_sqli_boolean_requests(
                surface,
                surface.parameters,
                probe_parameters=boolean_parameters,
                purpose=f"SQLi validation {task.validation_id}",
            )
            collected = tuple(
                matching_evidence(reproduction, surface.url, request)
                for request in requests
            )
            missing = tuple(
                request for request, item in zip(requests, collected) if item is None
            )
            if missing:
                if task.request_budget < len(missing):
                    raise BudgetExceeded(
                        "SQLi validation lacks budget for boolean reproduction requests"
                    )
                return AgentResult(
                    task_id=task.task_id,
                    status=AgentResultStatus.NEEDS_EVIDENCE,
                    evidence_requests=missing,
                )

            reproduced = tuple(item for item in collected if item is not None)
            for index, parameter in enumerate(boolean_parameters):
                true_response = collected[index * 2]
                false_response = collected[index * 2 + 1]
                if true_response is None or false_response is None:
                    continue
                if sql_boolean_signal(true_response, false_response) is None:
                    continue
                proof_evidence = (true_response, false_response)
                proof = ValidationProof(
                    proof_type=ValidationProofType.SQLI_EFFECT,
                    evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                    summary=(
                        "independent bounded true/false predicates reproduced an HTTP "
                        f"response differential for parameter {parameter}"
                    ),
                )
                return self._validation_result(
                    task,
                    verdict=ValidationVerdict.CONFIRMED,
                    evidence=proof_evidence,
                    reason=(
                        "independent boolean predicate comparison reproduced the SQLi effect"
                    ),
                    reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                    proof=proof,
                )
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=reproduced,
                reason=(
                    "independent boolean predicates did not reproduce the response differential"
                ),
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )

        if not signaled_parameters:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no SQL error signal to reproduce",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )

        marker = probe_marker(
            f"{task.validation_id}{candidate.candidate_id}",
            prefix="hacklipsevalidation",
        )
        requests = build_probe_requests(
            surface,
            surface.parameters,
            control_value=marker,
            probe_value=marker + _SQLI_SYNTAX_BREAKER,
            purpose=f"SQLi validation {task.validation_id}",
            probe_parameters=signaled_parameters,
        )
        collected = tuple(
            matching_evidence(reproduction, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "SQLi validation lacks budget for independent control/probe requests",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )

        reproduced = tuple(item for item in collected if item is not None)
        # A redirect is still a complete HTTP response and can be the control
        # side of a useful differential (for example, a normal login attempt
        # redirects while a quote probe reaches a database error page).  The
        # runtime deliberately does not follow redirects, so treating every
        # 3xx as missing evidence discards exactly that signal.  Transport
        # errors remain incomparable.
        if any(
            item.observation.get("type") == "http_error"
            for item in reproduced
        ):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=reproduced,
                reason="independent SQLi reproduction could not obtain comparable responses",
                reason_code=ValidationReasonCode.COMPARABLE_RESPONSES_MISSING,
            )

        control = reproduced[0]
        for parameter, probe in zip(signaled_parameters, reproduced[1:]):
            signal = sql_error_signal(control, probe)
            if signal is None:
                continue
            proof_evidence = (control, probe)
            engine = signal.get("engine") or "unknown"
            proof = ValidationProof(
                proof_type=ValidationProofType.SQLI_EFFECT,
                evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                summary=(
                    f"independent quote probe reproduced a SQL error differential "
                    f"for parameter {parameter} (engine={engine})"
                ),
            )
            return self._validation_result(
                task,
                verdict=ValidationVerdict.CONFIRMED,
                evidence=proof_evidence,
                reason="independent control/probe comparison reproduced the SQLi effect",
                reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                proof=proof,
            )

        return self._validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent quote probe did not reproduce the SQL error differential",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_graphql_sqli(
        self, task: TaskEnvelope, candidate: Candidate,
        evidence: Sequence[Evidence], reproduction: Sequence[Evidence],
        surface, plans,
    ) -> AgentResult:
        """Re-run only signaled read queries with a fresh validation marker."""

        offered = {(plan.field, plan.argument): plan for plan in plans}
        selected = tuple(dict.fromkeys(
            (field, argument)
            for item in evidence
            if item.surface_id == surface.surface_id
            and item.observation.get("type") == "sql_error"
            and isinstance((field := item.observation.get("graphql_field")), str)
            and isinstance((argument := item.observation.get("graphql_argument")), str)
            and (field, argument) in offered
        ))
        if not selected:
            auth_blocked = any(
                item.surface_id == surface.surface_id
                and item.observation.get("request_kind") in {
                    "graphql_query_control", "graphql_query_probe"
                }
                and graphql_auth_blocked_response(item)
                for item in evidence
            )
            if auth_blocked:
                return self._validation_result(
                    task, verdict=ValidationVerdict.BLOCKED, evidence=(),
                    reason="GraphQL read queries require an authorized session",
                    reason_code=ValidationReasonCode.AUTHENTICATION_REQUIRED,
                )
            return self._validation_result(
                task, verdict=ValidationVerdict.REJECTED, evidence=(),
                reason="analysis produced no GraphQL SQL error signal to reproduce",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )
        marker = probe_marker(
            f"{task.validation_id}{candidate.candidate_id}",
            prefix="hacklipsevalidation",
        )
        requests = tuple(
            request for key in selected
            for request in graphql_query_requests(
                surface.surface_id, offered[key], marker,
                f"GraphQL SQLi validation {task.validation_id}",
            )
        )
        collected = tuple(
            matching_evidence(reproduction, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "GraphQL SQLi validation lacks budget for independent pairs",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )
        reproduced = tuple(item for item in collected if item is not None)
        if any(graphql_auth_blocked_response(item) for item in reproduced):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=reproduced,
                reason="independent GraphQL reproduction requires an authorized session",
                reason_code=ValidationReasonCode.AUTHENTICATION_REQUIRED,
            )
        if any(
            item.observation.get("type") in {"http_error", "http_redirect"}
            for item in reproduced
        ):
            return self._validation_result(
                task, verdict=ValidationVerdict.BLOCKED, evidence=reproduced,
                reason="independent GraphQL SQLi responses were not comparable",
                reason_code=ValidationReasonCode.COMPARABLE_RESPONSES_MISSING,
            )
        for index, (field, argument) in enumerate(selected):
            control, probe = collected[2 * index:2 * index + 2]
            if control is None or probe is None:
                raise AgentContractError("GraphQL validation pair is missing")
            signal = sql_error_signal(control, probe)
            if signal is None:
                continue
            proof = ValidationProof(
                proof_type=ValidationProofType.SQLI_EFFECT,
                evidence_ids=(control.evidence_id, probe.evidence_id),
                summary=(
                    "independent GraphQL query argument quote probe reproduced "
                    f"a SQL error differential for {field}.{argument}"
                ),
            )
            return self._validation_result(
                task, verdict=ValidationVerdict.CONFIRMED,
                evidence=(control, probe),
                reason="independent GraphQL control/probe reproduced SQLi effect",
                reason_code=ValidationReasonCode.CONFIRMED_PROOF, proof=proof,
            )
        return self._validation_result(
            task, verdict=ValidationVerdict.REJECTED, evidence=reproduced,
            reason="independent GraphQL quote probe did not reproduce SQL error",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_access_control(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        evidence: Sequence[Evidence],
    ) -> AgentResult:
        """Analysis 결론을 쓰지 않고 자기 세션에서 세 요청을 다시 수행해 판정한다.

        Analysis가 만든 object_id_auth Observation은 "어디를 어떤 객체 ID로 볼지"를 알려주는
        지시일 뿐 확정 근거가 아니다. 실제 판정은 이 validation_id로 새로 수집한 Evidence
        세 개로만 한다.
        """

        plan = _access_control_plan(evidence)
        if plan is None:
            # Analysis 신호가 없으면 무엇을 재현해야 하는지 알 수 없다. 조용히 통과시키지
            # 않고 미확정으로 남긴다.
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                validation=self._validation_result(
                    task,
                    verdict=ValidationVerdict.SUSPECTED,
                    evidence=(),
                    reason="no object_id_auth observation to reproduce independently",
                    reason_code=ValidationReasonCode.ACCESS_PLAN_MISSING,
                ).validation,
            )

        identifier, actor_id, owner_id = plan
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        requests = build_access_control_requests(
            surface,
            identifier,
            actor_object_id=actor_id,
            owner_object_id=owner_id,
            purpose=f"independent access control validation {task.validation_id}",
        )
        collected = [
            matching_evidence(evidence, surface.url, request) for request in requests
        ]
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "access control validation lacks independent request budget",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )

        actor_control, owner_control, probe = collected
        session_evidence = tuple(
            item for item in (actor_control, owner_control, probe) if item is not None
        )
        # 세 요청 모두 이번 validation 세션의 중앙 수집 Evidence여야 한다.
        if len(session_evidence) != 3 or any(
            not _is_reproduction_evidence(item, task.validation_id)
            for item in (actor_control, owner_control, probe)
            if item is not None
        ):
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                validation=self._validation_result(
                    task,
                    verdict=ValidationVerdict.SUSPECTED,
                    evidence=(),
                    reason="access control reproduction did not belong to this validation session",
                    reason_code=ValidationReasonCode.VALIDATION_SESSION_MISMATCH,
                ).validation,
            )

        assert actor_control is not None and owner_control is not None and probe is not None
        if not unauthorized_object_exposed(
            actor_control, owner_control, probe, actor_id, owner_id
        ):
            # owner 객체가 actor 세션에서 보이지 않는다. 권한 검사가 동작한 것이다.
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                validation=self._validation_result(
                    task,
                    verdict=ValidationVerdict.REJECTED,
                    evidence=session_evidence,
                    reason="actor session did not expose the owner object",
                    reason_code=ValidationReasonCode.ACCESS_NOT_EXPOSED,
                ).validation,
            )

        proof = ValidationProof(
            proof_type=ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS,
            evidence_ids=tuple(item.evidence_id for item in session_evidence),
            summary=(
                f"actor session read object {owner_id} owned by another principal "
                f"through identifier {identifier}"
            ),
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=self._validation_result(
                task,
                verdict=ValidationVerdict.CONFIRMED,
                evidence=session_evidence,
                reason="independent reproduction exposed another principal's object",
                reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                proof=proof,
            ).validation,
        )

    def _validate_path_traversal(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        evidence: Sequence[Evidence],
        reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """고정된 비민감 파일 읽기를 현재 Validation 세션에서 독립 재현한다."""

        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if candidate.routing_capability_id == HIDDEN_BODY_CAPABILITY:
            return self._validate_hidden_body_parameter(
                task, candidate, surface, evidence, reproduction
            )
        if surface.method.upper() == "POST":
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=(),
                reason="valid POST request template and safe proof target are unavailable",
                reason_code=ValidationReasonCode.POST_REQUEST_TEMPLATE_MISSING,
            )
        if is_restricted_file_surface(evidence, surface):
            return self._validate_path_traversal_bypass(
                task, candidate, surface, evidence, reproduction
            )
        signaled_parameters = tuple(
            dict.fromkeys(
                parameter
                for item in evidence
                if item.surface_id == candidate.surface_id
                and item.observation.get("type") == PATH_TRAVERSAL_OBSERVATION
                and isinstance((parameter := item.observation.get("parameter")), str)
                and parameter
                in path_parameter_candidates(evidence, surface, surface.parameters)
            )
        )
        if not signaled_parameters:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no safe-file read signal to reproduce",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )

        requests = build_path_traversal_requests(
            surface,
            surface.parameters,
            signaled_parameters,
            purpose=f"Path Traversal validation {task.validation_id}",
        )
        collected = tuple(
            matching_evidence(reproduction, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "Path Traversal validation lacks budget for independent requests",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )

        reproduced = tuple(item for item in collected if item is not None)
        if any(
            item.observation.get("type") in {"http_error", "http_redirect"}
            for item in reproduced
        ):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=reproduced,
                reason="independent safe-file reproduction could not obtain comparable responses",
                reason_code=ValidationReasonCode.COMPARABLE_RESPONSES_MISSING,
            )

        control = reproduced[0]
        for parameter, probe in zip(signaled_parameters, reproduced[1:]):
            if not path_traversal_signal(control, probe):
                continue
            proof_evidence = (control, probe)
            proof = ValidationProof(
                proof_type=ValidationProofType.PATH_TRAVERSAL_FILE_READ,
                evidence_ids=tuple(item.evidence_id for item in proof_evidence),
                summary=(
                    "independent fixed safe-file probe reproduced an out-of-directory "
                    f"file read for parameter {parameter}"
                ),
            )
            return self._validation_result(
                task,
                verdict=ValidationVerdict.CONFIRMED,
                evidence=proof_evidence,
                reason="independent control/probe comparison reproduced the safe-file read",
                reason_code=ValidationReasonCode.CONFIRMED_PROOF,
                proof=proof,
            )

        return self._validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent probe did not reproduce the safe-file read",
            reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
        )

    def _validate_hidden_body_parameter(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        surface,
        evidence: Sequence[Evidence],
        reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """Never replay a hidden POST without a verified normal request template."""

        return self._validation_result(
            task,
            verdict=ValidationVerdict.BLOCKED,
            evidence=(),
            reason="valid POST request template and session refresh are unavailable",
            reason_code=ValidationReasonCode.POST_REQUEST_TEMPLATE_MISSING,
        )

    def _validate_path_traversal_bypass(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        surface,
        evidence: Sequence[Evidence],
        reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """확장자 필터 우회 읽기를 독립 세션에서 다시 만든다.

        Analysis 의 판정은 읽지 않는다. 좌표(어느 표면인가)만 가져오고 control 과
        probe 를 이 Validation 세션에서 새로 수집한다.
        """

        signaled = any(
            item.surface_id == candidate.surface_id
            and item.observation.get("type") == PATH_TRAVERSAL_OBSERVATION
            and item.observation.get("bypass") == PATH_TRAVERSAL_BYPASS_OBSERVATION
            for item in evidence
        )
        if not signaled:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no filter bypass signal to reproduce",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )

        requests = build_path_traversal_bypass_requests(
            surface, purpose=f"Path Traversal validation {task.validation_id}"
        )
        collected = tuple(
            matching_evidence(reproduction, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "Path Traversal validation lacks budget for independent requests",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )

        control, probe = collected
        assert control is not None and probe is not None
        if any(
            item.observation.get("type") in {"http_error", "http_redirect"}
            for item in (control, probe)
        ):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=(control, probe),
                reason="independent bypass reproduction could not obtain comparable responses",
                reason_code=ValidationReasonCode.COMPARABLE_RESPONSES_MISSING,
            )
        if not path_traversal_bypass_signal(control, probe):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(control, probe),
                reason="independent probe did not reproduce the filter bypass read",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )

        proof_evidence = (control, probe)
        proof = ValidationProof(
            proof_type=ValidationProofType.PATH_TRAVERSAL_FILE_READ,
            evidence_ids=tuple(item.evidence_id for item in proof_evidence),
            summary=(
                "independent probe read a file the server refused to serve directly "
                f"at {surface.url.rsplit('/', 1)[-1]} using the fixed extension filter bypass"
            ),
        )
        return self._validation_result(
            task,
            verdict=ValidationVerdict.CONFIRMED,
            evidence=proof_evidence,
            reason="independent control/probe comparison reproduced the filter bypass read",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF,
            proof=proof,
        )

    def _validate_ssti(
        self,
        task: TaskEnvelope,
        candidate: Candidate,
        evidence: Sequence[Evidence],
        reproduction: Sequence[Evidence],
    ) -> AgentResult:
        """고정 산술식의 서버 측 평가를 현재 Validation 세션에서 다시 수행한다."""

        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        signaled_parameters = tuple(
            dict.fromkeys(
                parameter
                for item in evidence
                if item.surface_id == candidate.surface_id
                and item.observation.get("type") == SSTI_OBSERVATION
                and isinstance((parameter := item.observation.get("parameter")), str)
                and parameter in surface.parameters
            )
        )
        if "username" not in signaled_parameters:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no fixed-arithmetic SSTI signal to reproduce",
                reason_code=ValidationReasonCode.ANALYSIS_SIGNAL_MISSING,
            )

        requests = build_ssti_requests(
            surface,
            "username",
            purpose=f"SSTI validation {task.validation_id}",
        )
        collected = tuple(
            matching_ssti_evidence(reproduction, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "SSTI validation lacks budget for its independent safe request sequence",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )

        reproduced = tuple(item for item in collected if item is not None)
        if any(item.observation.get("type") == "http_error" for item in reproduced):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=reproduced,
                reason="independent SSTI sequence encountered an HTTP execution error",
                reason_code=ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR,
            )
        cleanup_status = reproduced[-1].observation.get("status")
        if cleanup_status not in {302, 303}:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=reproduced,
                reason="independent SSTI sequence could not restore the safe username",
                reason_code=ValidationReasonCode.CLEANUP_FAILED,
            )
        if not ssti_execution_signal(collected):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=reproduced,
                reason="independent fixed arithmetic probe was not evaluated by the template",
                reason_code=ValidationReasonCode.PROBE_SIGNAL_NOT_REPRODUCED,
            )

        proof = ValidationProof(
            proof_type=ValidationProofType.SSTI_EXECUTION,
            evidence_ids=tuple(item.evidence_id for item in reproduced),
            summary=(
                "independent approved profile control/probe sequence reproduced fixed "
                "server-side arithmetic evaluation and restored a safe username"
            ),
        )
        return self._validation_result(
            task,
            verdict=ValidationVerdict.CONFIRMED,
            evidence=reproduced,
            reason="independent control/probe comparison reproduced the SSTI effect",
            reason_code=ValidationReasonCode.CONFIRMED_PROOF,
            proof=proof,
        )

    @staticmethod
    def _validation_result(
        task: TaskEnvelope,
        *,
        verdict: ValidationVerdict,
        evidence: Sequence[Evidence],
        reason: str,
        reason_code: ValidationReasonCode,
        proof: ValidationProof | None = None,
    ) -> AgentResult:
        # reason_code는 기본값 없는 키워드 인자다. 새 분기를 추가하면서 빠뜨리면
        # 조용히 UNSPECIFIED로 흐르지 않고 호출 시점에 TypeError로 드러난다.
        evidence_ids = tuple(dict.fromkeys(item.evidence_id for item in evidence))
        validation = ValidationResult(
            validation_id=task.validation_id or "",
            run_id=task.run_id,
            candidate_id=task.candidate_id or "",
            verdict=verdict,
            evidence_ids=evidence_ids,
            reason=reason,
            reason_code=reason_code,
            reproduction_count=len(evidence_ids),
            proof=proof,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=validation,
        )

    def _decide(self, task: TaskEnvelope, reproduction: Sequence[Evidence]) -> AgentResult:
        """범용 HTTP 상태 대신 세션 실행 가능 여부만 보수적으로 판정한다."""

        latest = reproduction[-1]
        status = latest.observation.get("status")
        blocked = latest.observation.get("type") == "http_error"
        validation = ValidationResult(
            validation_id=task.validation_id,  # type: ignore[arg-type]
            run_id=task.run_id,
            candidate_id=task.candidate_id,  # type: ignore[arg-type]
            verdict=(
                ValidationVerdict.BLOCKED if blocked else ValidationVerdict.SUSPECTED
            ),
            evidence_ids=tuple(dict.fromkeys(item.evidence_id for item in reproduction)),
            reason=(
                "validation-session request could not execute"
                if blocked
                else (
                    "validation-session request returned "
                    f"type={latest.observation.get('type')} status={status}, but no "
                    "vulnerability-specific proof was produced"
                )
            ),
            reason_code=(
                ValidationReasonCode.REPRODUCTION_EXECUTION_ERROR
                if blocked
                else ValidationReasonCode.GENERIC_NO_PROOF
            ),
            reproduction_count=len(reproduction),
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            validation=validation,
        )

    def _needs_evidence(
        self, task: TaskEnvelope, surface_id: str, vulnerability_type: str
    ) -> AgentResult:
        """아직 독립 재현 시도가 없으면 재현 요청 하나를 만들어 반환한다."""

        request = EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface_id,
            reason=(
                f"independent reproduction fetch required to confirm "
                f"{vulnerability_type} on surface {surface_id}"
            ),
            suggested_tool=_REPRODUCTION_TOOL,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.NEEDS_EVIDENCE,
            evidence_requests=(request,),
        )


def _is_reproduction_evidence(evidence: Evidence, validation_id: str) -> bool:
    return bool(
        evidence.validation_id == validation_id
        and evidence.source_task_id is not None
        and evidence.created_by.startswith("execution_runtime:")
        and str(evidence.observation.get("type")) in _REPRODUCTION_EVIDENCE_TYPES
    )


def _access_control_plan(
    evidence: Sequence[Evidence],
) -> tuple[str, str, str] | None:
    """Analysis Observation에서 재현에 필요한 좌표만 읽는다(판정은 읽지 않는다)."""

    for item in reversed(list(evidence)):
        observation = item.observation
        if observation.get("type") != "object_id_auth":
            continue
        identifier = observation.get("identifier_parameter")
        location = observation.get("identifier_location", "query")
        actor_id = observation.get("actor_object_id")
        owner_id = observation.get("owner_object_id")
        if all(isinstance(value, str) and value for value in (identifier, actor_id, owner_id)):
            token = f"path:{identifier}" if location == "path" else str(identifier)
            return token, str(actor_id), str(owner_id)
    return None
