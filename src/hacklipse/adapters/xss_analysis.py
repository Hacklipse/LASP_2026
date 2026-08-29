"""LLM 없이 고정 규칙으로 reflected-input 신호를 수집하는 XSS baseline Agent."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from hacklipse.application import RuntimeEvidenceCollector
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

XSS_ANALYSIS_TOOL = "http_get"
_CONTROL_VALUE = "hacklipse-control"
_REFLECTION_MARKER = "hacklipse7331"


class HeuristicXssAnalyzer:
    """control/probe 응답의 marker 반사를 결정적으로 비교하는 Analysis Agent.

    이 Agent는 입력 반사 신호만 만든다. 실제 XSS 실행 가능성이나 최종 취약점
    판정은 독립 Validation 단계의 책임이다.
    """

    def __init__(
        self,
        *,
        collector: RuntimeEvidenceCollector,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._collector = collector
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """파라미터별 무해한 probe를 보내고 반사 Observation을 저장한다."""

        candidate, surface, parameters = self._resolve_task(task)
        required_requests = 1 + len(parameters)
        if task.request_budget < required_requests:
            raise AgentContractError(
                "xss baseline requires one control request and one probe per parameter"
            )

        control_values = tuple((name, _CONTROL_VALUE) for name in parameters)
        control_id = self._collect(
            task,
            surface.url,
            control_values,
            HttpRequestKind.CONTROL,
            reason=f"XSS baseline control request for candidate {candidate.candidate_id}",
        )
        control_body = self._body(task.run_id, control_id)
        evidence_ids = [control_id]

        for parameter in parameters:
            probe_values = tuple(
                (name, _REFLECTION_MARKER if name == parameter else _CONTROL_VALUE)
                for name in parameters
            )
            probe_id = self._collect(
                task,
                surface.url,
                probe_values,
                HttpRequestKind.PROBE,
                reason=(
                    f"XSS baseline reflection probe for parameter {parameter} "
                    f"on candidate {candidate.candidate_id}"
                ),
            )
            evidence_ids.append(probe_id)
            probe_body = self._body(task.run_id, probe_id)
            if _is_reflected(control_body, probe_body):
                reflection_id = f"evi-{self._id_factory()}"
                self._evidence.append(
                    Evidence(
                        evidence_id=reflection_id,
                        run_id=task.run_id,
                        surface_id=surface.surface_id,
                        created_by="heuristic_xss_analyzer",
                        evidence_type="observation",
                        observation={
                            "type": "reflection",
                            "parameter": parameter,
                            "control_evidence_id": control_id,
                            "probe_evidence_id": probe_id,
                        },
                    )
                )
                evidence_ids.append(reflection_id)

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )

    def _resolve_task(self, task: TaskEnvelope):
        if task.candidate_id is None or task.surface_id is None or task.target_url is None:
            raise AgentContractError("xss analysis task is missing candidate or surface context")
        if XSS_ANALYSIS_TOOL not in task.allowed_tools:
            raise AgentContractError("xss analysis HTTP tool is not allowed by the task")

        candidate = self._candidates.get(task.run_id, task.candidate_id)
        if candidate.vulnerability_type != "XSS":
            raise AgentContractError("heuristic XSS analyzer received a non-XSS candidate")
        if candidate.surface_id != task.surface_id:
            raise AgentContractError("xss candidate and task reference different surfaces")

        surface = self._surfaces.get(task.run_id, task.surface_id)
        if surface.url != task.target_url:
            raise AgentContractError("xss analysis task target does not match its surface")
        if surface.method.upper() != "GET" or not surface.parameters:
            raise AgentContractError("xss baseline supports parameterized GET surfaces only")

        # Task가 참조한 기존 Evidence도 같은 Run에 실제로 존재해야 한다.
        self._evidence.get_many(task.run_id, task.evidence_ids)
        parameters = tuple(dict.fromkeys(surface.parameters))
        return candidate, surface, parameters

    def _collect(
        self,
        task: TaskEnvelope,
        target_url: str,
        query_parameters: tuple[tuple[str, str], ...],
        request_kind: HttpRequestKind,
        *,
        reason: str,
    ) -> str:
        return self._collector.collect(
            task.run_id,
            target_url,
            EvidenceRequest(
                evidence_type="http_response",
                surface_id=task.surface_id or "",
                reason=reason,
                suggested_tool=XSS_ANALYSIS_TOOL,
                http_request=HttpRequestSpec(
                    method="GET",
                    query_parameters=query_parameters,
                    request_kind=request_kind,
                ),
            ),
            task_id=task.task_id,
        )

    def _body(self, run_id: str, evidence_id: str) -> str | None:
        body = self._evidence.get(run_id, evidence_id).observation.get("body")
        return body if isinstance(body, str) else None


def _is_reflected(control_body: str | None, probe_body: str | None) -> bool:
    """고정 marker가 control에는 없고 probe에는 있을 때만 반사로 인정한다."""

    return bool(
        probe_body is not None
        and _REFLECTION_MARKER in probe_body
        and (control_body is None or _REFLECTION_MARKER not in control_body)
    )
