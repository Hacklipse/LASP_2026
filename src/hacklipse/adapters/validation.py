"""Analysis 결론 없이 Evidence만으로 Candidate를 독립 판정하는 결정적 Validation Agent."""

from __future__ import annotations

from collections.abc import Sequence

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    EvidenceRequest,
    TaskEnvelope,
    ValidationProof,
    ValidationProofType,
    ValidationResult,
    ValidationVerdict,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import build_probe_requests, matching_evidence, probe_marker
from .path_traversal_analysis import (
    PATH_TRAVERSAL_OBSERVATION,
    PATH_TRAVERSAL_TOOL,
    build_path_traversal_requests,
    path_traversal_signal,
)
from .access_control_analysis import (
    ACCESS_CONTROL_TOOL,
    build_access_control_requests,
    unauthorized_object_exposed,
)
from .routing import DEFAULT_RULES
from .sqli_analysis import sql_error_signal
from .ssti_analysis import (
    SSTI_OBSERVATION,
    SSTI_TOOL,
    build_ssti_requests,
    matching_ssti_evidence,
    ssti_execution_signal,
)
from .xss_execution import BROWSER_XSS_TOOL, XSS_EXECUTION_MARKER_PREFIX

# Router가 Candidate를 만들 때 쓴 것과 같은 taxonomy. Candidate가 알려진 취약점
# 유형을 벗어나면(Router가 만들 수 없는 값) 계약 위반으로 간주한다. Analysis
# Agent의 자유 서술 결론(hypothesis)은 여기서도 참고하지 않는다.
_EXPECTED_SIGNAL = {rule.vulnerability_type: rule.observation_type for rule in DEFAULT_RULES}

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
    ) -> None:
        self._candidates = candidate_store
        self._evidence = evidence_store
        self._surfaces = surface_store

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
        if specialized_path_validation:
            required_tool = PATH_TRAVERSAL_TOOL
        elif specialized_access_validation:
            required_tool = ACCESS_CONTROL_TOOL
        elif specialized_ssti_validation:
            required_tool = SSTI_TOOL
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
            return self._validate_xss(task, candidate, evidence, reproduction)

        if not reproduction:
            return self._needs_evidence(
                task, candidate.surface_id, candidate.vulnerability_type
            )
        return self._decide(task, reproduction)

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
        collected = tuple(
            matching_evidence(reproduction, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise AgentContractError(
                    "XSS validation lacks budget for independent browser control/probe requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
            )

        reproduced = tuple(item for item in collected if item is not None)
        if any(item.observation.get("type") == "browser_error" for item in reproduced):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=reproduced,
                reason="independent browser reproduction could not execute",
            )

        control = reproduced[0]
        if control.observation.get("script_executed") is True:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=reproduced,
                reason="browser control unexpectedly contained an execution signal",
            )

        for parameter, probe in zip(signaled_parameters, reproduced[1:]):
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
                proof=proof,
            )

        return self._validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent browser probe did not execute the XSS marker",
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
        if not signaled_parameters:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no SQL error signal to reproduce",
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
                raise AgentContractError(
                    "SQLi validation lacks budget for independent control/probe requests"
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
                reason="independent SQLi reproduction could not obtain comparable responses",
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
                proof=proof,
            )

        return self._validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent quote probe did not reproduce the SQL error differential",
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
                return AgentResult(
                    task_id=task.task_id,
                    status=AgentResultStatus.COMPLETED,
                    validation=self._validation_result(
                        task,
                        verdict=ValidationVerdict.SUSPECTED,
                        evidence=(),
                        reason="independent access control reproduction exceeded the request budget",
                    ).validation,
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
                ).validation,
            )

        assert owner_control is not None and probe is not None
        if not unauthorized_object_exposed(owner_control, probe, owner_id):
            # owner 객체가 actor 세션에서 보이지 않는다. 권한 검사가 동작한 것이다.
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                validation=self._validation_result(
                    task,
                    verdict=ValidationVerdict.REJECTED,
                    evidence=session_evidence,
                    reason="actor session did not expose the owner object",
                ).validation,
            )

        proof = ValidationProof(
            proof_type=ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS,
            evidence_ids=tuple(item.evidence_id for item in session_evidence),
            summary=(
                f"actor session read object {owner_id} owned by another principal "
                f"through parameter {identifier}"
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
        signaled_parameters = tuple(
            dict.fromkeys(
                parameter
                for item in evidence
                if item.surface_id == candidate.surface_id
                and item.observation.get("type") == PATH_TRAVERSAL_OBSERVATION
                and isinstance((parameter := item.observation.get("parameter")), str)
                and parameter in surface.parameters
            )
        )
        if not signaled_parameters:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=(),
                reason="analysis produced no safe-file read signal to reproduce",
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
                raise AgentContractError(
                    "Path Traversal validation lacks budget for independent requests"
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
                proof=proof,
            )

        return self._validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent probe did not reproduce the safe-file read",
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
                raise AgentContractError(
                    "SSTI validation lacks budget for its independent safe request sequence"
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
            )
        cleanup_status = reproduced[-1].observation.get("status")
        if cleanup_status not in {302, 303}:
            return self._validation_result(
                task,
                verdict=ValidationVerdict.BLOCKED,
                evidence=reproduced,
                reason="independent SSTI sequence could not restore the safe username",
            )
        if not ssti_execution_signal(collected):
            return self._validation_result(
                task,
                verdict=ValidationVerdict.REJECTED,
                evidence=reproduced,
                reason="independent fixed arithmetic probe was not evaluated by the template",
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
            proof=proof,
        )

    @staticmethod
    def _validation_result(
        task: TaskEnvelope,
        *,
        verdict: ValidationVerdict,
        evidence: Sequence[Evidence],
        reason: str,
        proof: ValidationProof | None = None,
    ) -> AgentResult:
        evidence_ids = tuple(dict.fromkeys(item.evidence_id for item in evidence))
        validation = ValidationResult(
            validation_id=task.validation_id or "",
            run_id=task.run_id,
            candidate_id=task.candidate_id or "",
            verdict=verdict,
            evidence_ids=evidence_ids,
            reason=reason,
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
        actor_id = observation.get("actor_object_id")
        owner_id = observation.get("owner_object_id")
        if all(isinstance(value, str) and value for value in (identifier, actor_id, owner_id)):
            return str(identifier), str(actor_id), str(owner_id)
    return None
