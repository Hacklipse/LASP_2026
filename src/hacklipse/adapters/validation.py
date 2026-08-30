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
from .routing import DEFAULT_RULES
from .sqli_analysis import sql_error_signal

# Router가 Candidate를 만들 때 쓴 것과 같은 taxonomy. Candidate가 알려진 취약점
# 유형을 벗어나면(Router가 만들 수 없는 값) 계약 위반으로 간주한다. Analysis
# Agent의 자유 서술 결론(hypothesis)은 여기서도 참고하지 않는다.
_EXPECTED_SIGNAL = {rule.vulnerability_type: rule.observation_type for rule in DEFAULT_RULES}

# HttpExecutionRuntime(및 그 대역)이 실제 재현 요청 결과에 붙이는 Observation 유형.
# 최초 Recon이 남긴 신호 관측(예: "url_or_file_parameter")과는 구분되는, Validator
# 자신이 직접 수행을 요청한 독립적인 재요청의 결과만 재현 근거로 인정한다.
_REPRODUCTION_EVIDENCE_TYPES = frozenset({"http_response", "http_error", "http_redirect"})

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
        if _REPRODUCTION_TOOL not in task.allowed_tools:
            raise AgentContractError("validation HTTP tool is not allowed by the task")

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

        evidence_ids = tuple(dict.fromkeys(task.evidence_ids))
        evidence = self._evidence.get_many(task.run_id, evidence_ids)
        reproduction = [
            item
            for item in evidence
            if _is_reproduction_evidence(item, task.validation_id)
        ]

        if candidate.vulnerability_type == "SQLi":
            return self._validate_sqli(task, candidate, evidence, reproduction)

        if not reproduction:
            return self._needs_evidence(
                task, candidate.surface_id, candidate.vulnerability_type
            )
        return self._decide(task, reproduction)

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
            return self._sql_validation_result(
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
            return self._sql_validation_result(
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
            return self._sql_validation_result(
                task,
                verdict=ValidationVerdict.CONFIRMED,
                evidence=proof_evidence,
                reason="independent control/probe comparison reproduced the SQLi effect",
                proof=proof,
            )

        return self._sql_validation_result(
            task,
            verdict=ValidationVerdict.REJECTED,
            evidence=reproduced,
            reason="independent quote probe did not reproduce the SQL error differential",
        )

    @staticmethod
    def _sql_validation_result(
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
