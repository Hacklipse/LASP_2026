"""Analysis 결론 없이 Evidence만으로 Candidate를 독립 판정하는 결정적 Validation Agent."""

from __future__ import annotations

from collections.abc import Sequence

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    TaskEnvelope,
    ValidationResult,
    ValidationVerdict,
)
from hacklipse.ports import CandidateStore, EvidenceStore

from .routing import DEFAULT_RULES

# Router가 Candidate를 만들 때 쓴 것과 같은 taxonomy. Candidate가 알려진 취약점
# 유형을 벗어나면(Router가 만들 수 없는 값) 계약 위반으로 간주한다. Analysis
# Agent의 자유 서술 결론(hypothesis)은 여기서도 참고하지 않는다.
_EXPECTED_SIGNAL = {rule.vulnerability_type: rule.observation_type for rule in DEFAULT_RULES}

# HttpExecutionRuntime(및 그 대역)이 실제 재현 요청 결과에 붙이는 Observation 유형.
# 최초 Recon이 남긴 신호 관측(예: "url_or_file_parameter")과는 구분되는, Validator
# 자신이 직접 수행을 요청한 독립적인 재요청의 결과만 재현 근거로 인정한다.
_REPRODUCTION_EVIDENCE_TYPES = frozenset({"http_response", "http_error", "http_redirect"})

_REPRODUCTION_TOOL = "http_get"
class ValidationAgent:
    """현재 Validation 세션의 Evidence만으로 보수적인 baseline 판정을 내린다.

    LLM을 쓰지 않는 이 구현은 범용 HTTP 응답만으로 취약점을 확정하지 않는다.
    현재 세션의 요청이 응답을 받았으면 SUSPECTED, 네트워크 실행이 막혔으면 BLOCKED를
    반환한다. 취약점별 proof를 만드는 후속 Validator만 CONFIRMED를 반환할 수 있다.
    """

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        evidence_store: EvidenceStore,
    ) -> None:
        self._candidates = candidate_store
        self._evidence = evidence_store

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

        if not reproduction:
            return self._needs_evidence(task, candidate.surface_id, candidate.vulnerability_type)
        return self._decide(task, reproduction)

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
