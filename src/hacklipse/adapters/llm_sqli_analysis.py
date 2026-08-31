"""LLM으로 SQLi probe 대상을 고르고 Python으로 오류 차이를 판정하는 Agent.

역할은 구조적으로 분리한다.

    LLM     Surface에 실제 존재하는 파라미터 중 DB 질의에 닿을 가능성이 큰 것 선택
    Python  무해한 marker와 고정 작은따옴표 probe 생성, control/probe 오류 차이 판정

LLM은 요청 값이나 SQL 문자열을 반환하지 않는다. 따라서 UNION, 인증 우회, 데이터 조회
같은 payload가 LLM 출력에서 Runtime으로 전달될 필드가 없다. 확정 판정도 이 Agent의
역할이 아니며, Validation이 별도 control/probe로 SQLI_EFFECT를 재현해야 한다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, Surface, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, LlmClient, SurfaceStore
from hacklipse.ports.llm import LlmMessage, LlmRequest

from .probing import (
    build_probe_requests,
    has_observation_record,
    matching_evidence,
    probe_marker,
    resolve_analysis_task,
    validate_probe_selection,
)
from .sqli_analysis import sql_error_signal

LLM_SQLI_ANALYZER = "llm_sqli_analyzer"
_PLAN_OBSERVATION = "sqli_probe_plan"
_SYNTAX_BREAKER = "'"

_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "parameters": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
    "required": ["parameters", "reason"],
    "additionalProperties": False,
}

_PLAN_SYSTEM = (
    "You select which query parameters of a single authorized test surface are worth "
    "checking for possible SQL parser reachability. You never choose values or SQL "
    "payloads: the caller uses a fixed benign marker and appends one syntax-breaking "
    "quote. Return only parameter names that appear in the provided list. Prefer lookup, "
    "identifier, filter, search, sort, pagination, or record-selection inputs that may be "
    "used in a database query. Exclude submit-button and presentation-only parameters. "
    "Return an empty list if none are worth spending requests on."
)


class LlmSqliAnalyzer:
    """LLM 선택과 결정적 SQL 오류 관찰을 결합하되 요청은 중앙 수집에 맡긴다."""

    def __init__(
        self,
        *,
        llm_client: LlmClient,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._llm = llm_client
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="SQLi",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))

        stored = _stored_plan(evidence, surface.surface_id)
        new_evidence_ids: list[str] = []
        if stored is None:
            plan, plan_id = self._plan(task, surface, parameters)
            new_evidence_ids.append(plan_id)
        else:
            plan, plan_id = stored

        selected = tuple(plan["parameters"])
        marker = str(plan["marker"])
        if not selected:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_evidence_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        requests = build_probe_requests(
            surface,
            parameters,
            control_value=marker,
            probe_value=marker + _SYNTAX_BREAKER,
            purpose=f"SQLi candidate {candidate.candidate_id}",
            probe_parameters=selected,
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise AgentContractError(
                    "llm sqli analyzer lacks budget for its remaining evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                new_evidence_ids=tuple(new_evidence_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:
            raise AgentContractError("llm sqli analyzer control evidence was not collected")

        reason = str(plan["reason"])
        for parameter, probe in zip(selected, collected[1:]):
            if probe is None:
                raise AgentContractError("llm sqli analyzer probe evidence was not collected")
            signal = sql_error_signal(control, probe)
            if signal is None:
                continue
            if has_observation_record(
                evidence,
                LLM_SQLI_ANALYZER,
                "sql_error",
                parameter,
                control.evidence_id,
                probe.evidence_id,
            ):
                continue
            observation_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=observation_id,
                    run_id=task.run_id,
                    surface_id=surface.surface_id,
                    created_by=LLM_SQLI_ANALYZER,
                    evidence_type="observation",
                    observation={
                        "type": "sql_error",
                        "parameter": parameter,
                        "control_evidence_id": control.evidence_id,
                        "probe_evidence_id": probe.evidence_id,
                        "plan_evidence_id": plan_id,
                        "selection_source": "llm",
                        "selection_reason": reason,
                        **signal,
                    },
                )
            )
            new_evidence_ids.append(observation_id)

        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_evidence_ids),
            candidate_ids=(candidate.candidate_id,),
        )

    def _plan(
        self,
        task: TaskEnvelope,
        surface: Surface,
        parameters: tuple[str, ...],
    ) -> tuple[dict[str, object], str]:
        response = self._llm.complete(
            LlmRequest(
                messages=(
                    LlmMessage(
                        role="user",
                        content=(
                            f"Surface path: {urlsplit(surface.url).path or '/'}\n"
                            f"Method: {surface.method.upper()}\n"
                            f"Parameters: {', '.join(parameters)}\n"
                            f"Request budget for this analysis: {task.request_budget}\n"
                            "Select parameters worth checking for SQL parser reachability."
                        ),
                    ),
                ),
                system=_PLAN_SYSTEM,
                response_schema=_PLAN_SCHEMA,
                timeout_seconds=task.timeout_seconds,
            )
        )
        selected, dropped = validate_probe_selection(
            response.payload.get("parameters"),
            parameters,
            task.request_budget,
            analyzer_name="llm sqli analyzer",
        )
        reason = response.payload.get("reason")
        if not isinstance(reason, str):
            raise AgentContractError("llm sqli plan reason must be a string")
        plan: dict[str, object] = {
            "type": _PLAN_OBSERVATION,
            "parameters": list(selected),
            "marker": probe_marker(self._id_factory()),
            "reason": reason,
            "offered_parameters": list(parameters),
            "dropped_for_budget": list(dropped),
        }
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=LLM_SQLI_ANALYZER,
                evidence_type="observation",
                observation=plan,
            )
        )
        return plan, evidence_id


def _stored_plan(
    evidence: Sequence[Evidence], surface_id: str
) -> tuple[dict[str, object], str] | None:
    for item in reversed(evidence):
        if (
            item.created_by == LLM_SQLI_ANALYZER
            and item.surface_id == surface_id
            and item.observation.get("type") == _PLAN_OBSERVATION
        ):
            parameters = item.observation.get("parameters")
            marker = item.observation.get("marker")
            reason = item.observation.get("reason")
            if (
                isinstance(parameters, list)
                and isinstance(marker, str)
                and marker
                and isinstance(reason, str)
            ):
                return (
                    {
                        "parameters": [str(name) for name in parameters],
                        "marker": marker,
                        "reason": reason,
                    },
                    item.evidence_id,
                )
    return None
