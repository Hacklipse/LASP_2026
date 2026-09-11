"""LLM 이 브라우저 DOM 반사 탐침 대상을 고르는 XSS Analysis Agent.

`BrowserXssAnalyzer` 와 같은 사전 조건·요청 형태·반사 판정을 공유한다
(`browser_xss_analysis` 의 공용 함수). 같은 SPA 표면에서 두 구현의 선택을 비교할 수
있게 하는 것이 이 Agent 의 존재 이유다.

역할 분담 — LLM 이 만들 수 있는 것과 없는 것을 구조로 갈라놓는다.

    LLM     클라이언트 라우트의 어떤 파라미터를 탐침할지
    Python  marker 문자열, 요청 URL, 도구, 예산, DOM 반사 여부 자체

LLM 은 쿼리 "값"을 만들지 않는다. marker 는 Python 이 만들고 도메인이 반사 marker 와
실행 marker 를 배타적으로 강제하므로, 분석이 실행 증명을 만들 자리가 애초에 없다.

**반사 맥락 해석 단계는 두지 않는다.** HTTP 판(`llm_xss_analysis`)은 응답 본문을 갖고
있어 marker 주변을 잘라 맥락을 물을 수 있지만, 브라우저 탐침이 남기는 것은
`dom_reflected` 불리언 하나뿐이다(`xss_execution.dom_reflection_script`). 근거 없이
맥락을 묻는 것은 해석이 아니라 환각이므로, 맥락 분류를 하려면 먼저 Runtime 이 DOM
발췌를 남기도록 확장해야 한다. innerHTML 에는 사용자 데이터가 섞일 수 있어 그 확장은
마스킹 정책과 함께 별도로 결정할 일이다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    Surface,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, LlmClient, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.ports.llm import LlmMessage, LlmRequest

from .browser_xss_analysis import (
    build_reflection_requests,
    record_dom_reflection_observations,
)
from .knowledge_prompt import (
    knowledge_system_prompt,
    render_knowledge_hints,
    safe_selection_reason,
)
from .llm_parameter_names import alias_parameter_names
from .probing import (
    matching_evidence,
    probe_marker,
    resolve_analysis_task,
    validate_probe_selection,
)
from .xss_execution import BROWSER_XSS_TOOL, XSS_REFLECTION_MARKER_PREFIX

LLM_BROWSER_XSS_ANALYZER = "llm_browser_xss_analyzer"
_PLAN_OBSERVATION = "browser_xss_probe_plan"

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
    "You select which client-side route parameters of a single authorized test surface "
    "are worth probing for DOM reflection in a single-page application. You never choose "
    "values: the caller substitutes a fixed benign marker that contains no executable "
    "characters. Return only parameter names that appear in the provided list. Prefer "
    "parameters whose name or route position suggests the value is rendered back into the "
    "page by client-side code, such as search terms, identifiers echoed in a result "
    "heading, or redirect targets. Exclude parameters that only control paging, sorting, "
    "or presentation. Return an empty list if none are worth spending requests on."
)


class LlmBrowserXssAnalyzer:
    """LLM 이 탐침 대상을 정하고, Python 이 실행 경계와 반사 사실을 지킨다."""

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
            vulnerability_type="XSS",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=BROWSER_XSS_TOOL,
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))

        # 계획을 Evidence 로 남겨 두 번째 호출에서 그대로 복원한다. Agent 안에 상태를
        # 들고 있지 않아야 재개가 되고, 계획 자체도 감사 대상이 된다.
        stored = _stored_plan(evidence, surface.surface_id)
        new_evidence_ids: list[str] = []
        if stored is None:
            selected, plan_id = self._plan(task, surface, parameters)
            new_evidence_ids.append(plan_id)
        else:
            selected, plan_id = stored

        if not selected:
            # LLM 이 탐침할 값이 없다고 판단한 경우. 요청을 아예 쓰지 않는다.
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_evidence_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        # marker 는 휴리스틱 판과 같은 규칙으로 만든다. task 와 candidate 로부터
        # 결정적이므로 NEEDS_EVIDENCE 라운드를 넘어가도 같은 값이 복원된다.
        marker = probe_marker(
            f"{task.task_id}{candidate.candidate_id}",
            prefix=XSS_REFLECTION_MARKER_PREFIX,
        )
        requests = build_reflection_requests(
            surface.surface_id,
            selected,
            marker,
            purpose=f"XSS candidate {candidate.candidate_id}",
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "llm browser xss analysis lacks budget for its remaining probes"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                new_evidence_ids=tuple(new_evidence_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        new_evidence_ids.extend(
            record_dom_reflection_observations(
                task=task,
                surface=surface,
                selected=selected,
                probes=collected,
                evidence=evidence,
                evidence_store=self._evidence,
                created_by=LLM_BROWSER_XSS_ANALYZER,
                id_factory=self._id_factory,
                extra={
                    "plan_evidence_id": plan_id,
                    "selection_source": "llm",
                },
            )
        )
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
    ) -> tuple[tuple[str, ...], str]:
        """LLM 에 탐침 대상을 묻고 계획을 Evidence 로 고정한다."""

        aliases = alias_parameter_names(parameters)
        response = self._llm.complete(
            LlmRequest(
                messages=(
                    LlmMessage(
                        role="user",
                        content=(
                            f"Surface route: {_route_of(surface.url)}\n"
                            f"Method: {surface.method.upper()}\n"
                            f"Parameters: {', '.join(aliases.prompt_names)}\n"
                            f"Request budget for this analysis: {task.request_budget}\n"
                            "Select the parameters worth probing for DOM reflection."
                            + render_knowledge_hints(task.knowledge_hints)
                        ),
                    ),
                ),
                system=knowledge_system_prompt(_PLAN_SYSTEM, task.knowledge_hints),
                response_schema=_PLAN_SCHEMA,
                timeout_seconds=task.timeout_seconds,
            )
        )
        selected, dropped = validate_probe_selection(
            aliases.decode_selection(response.payload.get("parameters")),
            parameters,
            task.request_budget,
            analyzer_name="llm browser xss analyzer",
            # 반사 탐침은 control 요청이 없다. 예산 전부를 probe 에 쓸 수 있다.
            control_requests=0,
        )
        reason = response.payload.get("reason")
        if not isinstance(reason, str):
            raise AgentContractError("llm browser xss plan reason must be a string")
        reason = safe_selection_reason(reason, task.knowledge_hints)
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=LLM_BROWSER_XSS_ANALYZER,
                evidence_type="observation",
                observation={
                    "type": _PLAN_OBSERVATION,
                    "parameters": list(selected),
                    "reason": reason,
                    "offered_parameters": list(parameters),
                    "dropped_for_budget": list(dropped),
                },
            )
        )
        return selected, evidence_id


def _stored_plan(
    evidence: Sequence[Evidence], surface_id: str
) -> tuple[tuple[str, ...], str] | None:
    """이전 호출이 남긴 탐침 계획을 복원한다."""

    for item in reversed(evidence):
        if (
            item.created_by == LLM_BROWSER_XSS_ANALYZER
            and item.surface_id == surface_id
            and item.observation.get("type") == _PLAN_OBSERVATION
        ):
            parameters = item.observation.get("parameters")
            if isinstance(parameters, list):
                return tuple(str(name) for name in parameters), item.evidence_id
    return None


def _route_of(url: str) -> str:
    """SPA 라우트는 fragment 안쪽에 있다. query 값은 프롬프트에 싣지 않는다."""

    parts = urlsplit(url)
    fragment = parts.fragment.split("?", 1)[0]
    return f"{parts.path or '/'}#{fragment}" if fragment else (parts.path or "/")
