"""Analysis LLM의 시간 제한과 결정적 복구 경계."""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

from hacklipse.application.errors import LlmOutputContractError
from hacklipse.domain import AgentResult, Evidence, TaskEnvelope
from hacklipse.ports import Agent, EvidenceStore, LlmClient
from hacklipse.ports.errors import (
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmRequest, LlmResponse

_FALLBACK_TYPE = "analysis_llm_fallback"
_RECOVERABLE = (
    LlmTimeout, LlmTransportError, LlmResponseFormatError, LlmRefused,
    LlmOutputContractError,
)


class BoundedAnalysisLlmClient:
    """모델 호출 뒤 Analysis Task가 복구할 시간을 남긴다."""

    def __init__(self, delegate: LlmClient) -> None:
        self._delegate = delegate

    def complete(self, request: LlmRequest) -> LlmResponse:
        return self._delegate.complete(
            replace(request, timeout_seconds=min(request.timeout_seconds / 2, 30.0))
        )


class FallbackAnalysisAgent:
    """공급자 실패 시 같은 Candidate를 안전한 결정적 Analyzer로 계속한다."""

    def __init__(
        self, primary: Agent, fallback: Agent, evidence_store: EvidenceStore
    ) -> None:
        self._primary = primary
        self._fallback = fallback
        self._evidence = evidence_store

    def handle(self, task: TaskEnvelope) -> AgentResult:
        previous = self._evidence.get_many(task.run_id, task.evidence_ids)
        if any(
            item.created_by == task.agent_type
            and item.observation.get("type") == _FALLBACK_TYPE
            and item.observation.get("candidate_id") == task.candidate_id
            for item in previous
        ):
            return self._fallback.handle(task)

        try:
            return self._primary.handle(task)
        except _RECOVERABLE as error:
            result = self._fallback.handle(task)
            marker = Evidence(
                evidence_id=f"evi-{uuid4()}",
                run_id=task.run_id,
                surface_id=task.surface_id,
                created_by=task.agent_type,
                evidence_type="observation",
                source_task_id=task.task_id,
                observation={
                    "type": _FALLBACK_TYPE,
                    "candidate_id": task.candidate_id,
                    "source": "deterministic_fallback",
                    "reason": type(error).__name__,
                },
            )
            self._evidence.append(marker)
            return replace(
                result, new_evidence_ids=result.new_evidence_ids + (marker.evidence_id,)
            )
