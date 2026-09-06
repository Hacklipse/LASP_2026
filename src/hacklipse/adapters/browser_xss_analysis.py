"""SPA 클라이언트 라우트의 DOM 반사를 브라우저로 관측하는 XSS Analysis Agent.

서버가 본문에 값을 되돌려주는 반사는 `xss_analysis` 가 담당한다. Angular·React 처럼
클라이언트가 DOM 을 그리는 대상에서는 HTTP 본문에 값이 나타나지 않으므로 그 방식으로는
신호가 0 이 된다. 여기서는 같은 `browser_xss` 도구로 값이 DOM 까지 도달하는지만 본다.

Analysis 는 반사까지만 관측한다. 실행 증명은 독립 Validation 이 자기 marker 로 다시
만든다 — 여기서 실행을 관측해 버리면 분석 증적이 증명을 대신하게 된다.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import (
    has_observation_record,
    matching_evidence,
    probe_marker,
    resolve_analysis_task,
)
from .xss_execution import BROWSER_XSS_TOOL, XSS_REFLECTION_MARKER_PREFIX

BROWSER_XSS_ANALYZER = "browser_xss_analyzer"


class BrowserXssAnalyzer:
    """클라이언트 라우트 파라미터가 DOM 에 반사되는지 관측한다.

    외부 실행은 직접 하지 않고 EvidenceRequest 로 Orchestrator 에 반환한다.
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
        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="XSS",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=BROWSER_XSS_TOOL,
        )
        marker = probe_marker(
            f"{task.task_id}{candidate.candidate_id}",
            prefix=XSS_REFLECTION_MARKER_PREFIX,
        )
        requests = _build_reflection_requests(
            surface.surface_id,
            parameters,
            marker,
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
                raise BudgetExceeded(
                    "browser xss analysis lacks budget for its remaining probes"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        new_evidence_ids: list[str] = []
        for parameter, probe in zip(parameters, collected):
            if probe is None:  # missing 분기 이후에는 도달하지 않는 방어선.
                raise AgentContractError("browser xss probe evidence was not collected")
            if probe.observation.get("dom_reflected") is not True:
                continue
            if has_observation_record(
                evidence,
                BROWSER_XSS_ANALYZER,
                "reflection",
                parameter,
                probe.evidence_id,
                probe.evidence_id,
            ):
                continue
            reflection_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=reflection_id,
                    run_id=task.run_id,
                    surface_id=surface.surface_id,
                    created_by=BROWSER_XSS_ANALYZER,
                    evidence_type="observation",
                    observation={
                        "type": "reflection",
                        "parameter": parameter,
                        # 반사 탐침은 control 이 없다. 값이 DOM 에 있는지 없는지가
                        # 그 자체로 차이이므로 비교 대상 요청이 필요 없다.
                        "control_evidence_id": probe.evidence_id,
                        "probe_evidence_id": probe.evidence_id,
                        "observed_in": "dom",
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


def _build_reflection_requests(
    surface_id: str,
    parameters: tuple[str, ...],
    marker: str,
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """파라미터마다 무해한 반사 marker 하나만 싣는 브라우저 탐침을 만든다."""

    if not parameters:
        raise AgentContractError("browser xss analysis requires at least one parameter")
    return tuple(
        EvidenceRequest(
            evidence_type="browser_execution",
            surface_id=surface_id,
            reason=f"dom reflection probe for parameter {parameter} on {purpose}",
            suggested_tool=BROWSER_XSS_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=((parameter, marker),),
                request_kind=HttpRequestKind.PROBE,
            ),
        )
        for parameter in parameters
    )
