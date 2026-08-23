"""Analysis 결론 없이 Evidence만으로 Candidate를 독립 판정하는 결정적 Validation Agent."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from uuid import uuid4

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
_SUCCESS_STATUS_RANGE = range(200, 400)


class ValidationAgent:
    """Candidate/Evidence 참조만 받아 독립 재현 여부를 스스로 판정한다.

    LLM을 쓰지 않는다: 판정 기준은 "Validator 자신이 요청해 독립적으로 수집한
    재현 응답이 성공적으로 돌아왔는가" 하나뿐이다. 페이로드 특이적 반사·오류 문구
    비교는 하지 않는다 — 그 수준의 판단은 Phase 6 LLM Analysis의 몫이다. Finding을
    직접 만들 권한은 없고, ValidationResult만 반환한다.
    """

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """독립 재현 Evidence가 있으면 판정하고, 없으면 재현 요청을 반환한다."""

        if task.candidate_id is None:
            raise AgentContractError("validation task is missing a candidate")

        candidate = self._candidates.get(task.run_id, task.candidate_id)
        if candidate.vulnerability_type not in _EXPECTED_SIGNAL:
            raise AgentContractError(
                "validation agent has no reproduction rule for "
                f"vulnerability type: {candidate.vulnerability_type}"
            )

        evidence_ids = tuple(dict.fromkeys(task.evidence_ids))
        evidence = self._evidence.get_many(task.run_id, evidence_ids)
        reproduction = [item for item in evidence if _is_reproduction_evidence(item)]

        if not reproduction:
            return self._needs_evidence(task, candidate.surface_id, candidate.vulnerability_type)
        return self._decide(task, reproduction)

    def _decide(self, task: TaskEnvelope, reproduction: Sequence[Evidence]) -> AgentResult:
        """가장 최근 독립 재현 응답의 성공 여부로 CONFIRMED/REJECTED를 정한다."""

        latest = reproduction[-1]
        status = latest.observation.get("status")
        reproduced = latest.observation.get("type") == "http_response" and (
            isinstance(status, int) and status in _SUCCESS_STATUS_RANGE
        )
        validation = ValidationResult(
            validation_id=f"validation-{self._id_factory()}",
            run_id=task.run_id,
            candidate_id=task.candidate_id,  # type: ignore[arg-type]
            verdict=ValidationVerdict.CONFIRMED if reproduced else ValidationVerdict.REJECTED,
            evidence_ids=tuple(dict.fromkeys(item.evidence_id for item in reproduction)),
            reason=(
                f"independent reproduction request returned type={latest.observation.get('type')} "
                f"status={status}"
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


def _is_reproduction_evidence(evidence: Evidence) -> bool:
    return str(evidence.observation.get("type")) in _REPRODUCTION_EVIDENCE_TYPES
