"""LLM 없이 고정 규칙으로 reflected-input 신호를 수집하는 XSS baseline Agent.

탐침 절차는 `probing` 모듈을 공유한다 — LLM 구현과 SQLi 구현이 같은 사전 조건·같은
요청 형태를 써야 결과를 같은 축에서 비교할 수 있다.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import (
    ANALYSIS_TOOL,
    CONTROL_VALUE,
    build_probe_requests,
    has_observation_record,
    marker_reflected,
    matching_evidence,
    resolve_analysis_task,
    response_body,
)

XSS_ANALYSIS_TOOL = ANALYSIS_TOOL
_REFLECTION_MARKER = "hacklipse7331"

HEURISTIC_XSS_ANALYZER = "heuristic_xss_analyzer"


class HeuristicXssAnalyzer:
    """control/probe 응답의 marker 반사를 결정적으로 비교하는 Analysis Agent.

    외부 요청은 직접 실행하지 않고 EvidenceRequest로 Orchestrator에 반환한다.
    입력 반사 신호만 만들며 최종 취약점 판정은 독립 Validation의 책임이다.
    """

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """필요한 요청은 중앙 수집으로 반환하고, 수집 뒤 반사를 판정한다."""

        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="XSS",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
        )
        requests = build_probe_requests(
            surface,
            parameters,
            control_value=CONTROL_VALUE,
            probe_value=_REFLECTION_MARKER,
            purpose=f"XSS candidate {candidate.candidate_id}",
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )

        if missing:
            if task.request_budget < len(missing):
                raise AgentContractError(
                    "xss baseline lacks budget for its remaining evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:  # missing 분기 이후에는 도달하지 않는 방어선.
            raise AgentContractError("xss baseline control evidence was not collected")
        control_body = response_body(control)
        new_evidence_ids: list[str] = []

        for parameter, probe in zip(parameters, collected[1:]):
            if probe is None:  # missing 분기 이후에는 도달하지 않는 방어선.
                raise AgentContractError("xss baseline probe evidence was not collected")
            if marker_reflected(
                control_body, response_body(probe), _REFLECTION_MARKER
            ) and not has_observation_record(
                evidence,
                HEURISTIC_XSS_ANALYZER,
                "reflection",
                parameter,
                control.evidence_id,
                probe.evidence_id,
            ):
                reflection_id = f"evi-{self._id_factory()}"
                self._evidence.append(
                    Evidence(
                        evidence_id=reflection_id,
                        run_id=task.run_id,
                        surface_id=surface.surface_id,
                        created_by=HEURISTIC_XSS_ANALYZER,
                        evidence_type="observation",
                        observation={
                            "type": "reflection",
                            "parameter": parameter,
                            "control_evidence_id": control.evidence_id,
                            "probe_evidence_id": probe.evidence_id,
                        },
                    )
                )
                new_evidence_ids.append(reflection_id)

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )
