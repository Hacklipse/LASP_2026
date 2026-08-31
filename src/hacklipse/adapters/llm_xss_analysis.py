"""LLM에 탐침 대상 선택과 반사 맥락 해석을 맡기는 XSS Analysis Agent.

`HeuristicXssAnalyzer`와 같은 사전 조건·요청 형태·반사 판정을 공유한다(xss_analysis의
공용 함수). 같은 Surface에서 두 구현의 결과를 비교하는 것이 이 Agent의 존재 이유다.

역할 분담 — LLM이 만들 수 있는 것과 없는 것을 구조로 갈라놓는다.

    LLM     어떤 파라미터를 탐침할지, 반사가 어떤 맥락인지
    Python  marker 문자열, 요청 URL, 도구, 예산, 반사 여부 자체

LLM은 쿼리 "값"을 만들지 않는다. marker는 Python이 생성하고 LLM은 파라미터 이름만
고르므로, 페이로드가 요청에 실릴 자리가 애초에 없다. 프롬프트 지시가 아니라 구조적
보장이다.

반사 여부도 Python이 원문에서 직접 확인한다. LLM이 반사됐다고 주장해도 marker가
실제로 없으면 기각한다. LLM은 사실을 만들 수 없고 해석만 덧붙인다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
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
from hacklipse.ports.llm import LlmMessage, LlmRequest

from .probing import (
    CONTROL_VALUE,
    build_probe_requests,
    has_observation_record,
    marker_reflected,
    matching_evidence,
    probe_marker,
    resolve_analysis_task,
    response_body,
)

LLM_XSS_ANALYZER = "llm_xss_analyzer"
_PLAN_OBSERVATION = "xss_probe_plan"

# 반사 맥락 분류. 악용 가능성이 여기서 갈린다 — 같은 "반사됨"이라도 HTML 인코딩된
# 텍스트와 따옴표 없는 속성 값은 완전히 다른 이야기다. 휴리스틱 baseline은 이 축을
# 아예 못 만든다.
REFLECTION_CONTEXTS = (
    "html_text",
    "html_attribute",
    "script_block",
    "html_comment",
    "url_context",
    "unclassified",
)

# 응답 본문에서 marker 주변만 잘라 프롬프트에 싣는다. 전체 본문을 보내면 비용도 크고
# 페이지에 있을 수 있는 개인정보까지 외부로 나간다. 헤더는 아예 싣지 않는다.
_EXCERPT_RADIUS = 240

_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "parameters": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
    "required": ["parameters", "reason"],
    "additionalProperties": False,
}

_INTERPRETATION_SCHEMA = {
    "type": "object",
    "properties": {
        "reflections": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "parameter": {"type": "string"},
                    "context": {"type": "string", "enum": list(REFLECTION_CONTEXTS)},
                    "encoded": {"type": "boolean"},
                    "note": {"type": "string"},
                },
                "required": ["parameter", "context", "encoded", "note"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["reflections"],
    "additionalProperties": False,
}

_PLAN_SYSTEM = (
    "You select which query parameters of a single authorized test surface are worth "
    "probing for input reflection. You never choose values: a fixed benign marker is "
    "substituted by the caller. Return only parameter names that appear in the provided "
    "list. Prefer parameters whose name or position suggests their value is rendered back "
    "into the response. Return an empty list if none are worth spending requests on."
)

_INTERPRETATION_SYSTEM = (
    "You classify where a benign marker appears in an HTTP response excerpt. You are given "
    "excerpts that already contain the marker; your job is only to describe the syntactic "
    "context and whether the marker was output-encoded. Do not assert exploitability and do "
    "not propose payloads. Report one entry per parameter you were given."
)


class LlmXssAnalyzer:
    """LLM이 탐침 계획과 반사 맥락을 정하고, Python이 실행 경계와 사실을 지킨다."""

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
        """계획이 없으면 세우고, 증적이 모이면 해석한다. 요청은 직접 실행하지 않는다."""

        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="XSS",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))

        # 계획을 Evidence로 남겨 두 번째 호출에서 그대로 복원한다. Agent 안에 상태를
        # 들고 있지 않아야 재개가 되고, 계획 자체도 감사 대상이 된다.
        plan = _stored_plan(evidence, surface.surface_id)
        new_evidence_ids: list[str] = []
        if plan is None:
            plan, plan_id = self._plan(task, surface, parameters, candidate.candidate_id)
            new_evidence_ids.append(plan_id)

        selected = tuple(plan["parameters"])
        marker = str(plan["marker"])
        if not selected:
            # LLM이 탐침할 값이 없다고 판단한 경우. 요청을 아예 쓰지 않는다.
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_evidence_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        requests = build_probe_requests(
            surface,
            selected,
            control_value=CONTROL_VALUE,
            probe_value=marker,
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
                raise AgentContractError(
                    "llm xss analyzer lacks budget for its remaining evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                new_evidence_ids=tuple(new_evidence_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:  # missing 분기 이후에는 도달하지 않는 방어선.
            raise AgentContractError("llm xss analyzer control evidence was not collected")

        new_evidence_ids.extend(
            self._interpret(task, surface, selected, marker, control, collected[1:], evidence)
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
        candidate_id: str,
    ) -> tuple[dict[str, object], str]:
        """LLM에 탐침 대상을 묻고 계획을 Evidence로 고정한다."""

        response = self._llm.complete(
            LlmRequest(
                messages=(
                    LlmMessage(
                        role="user",
                        content=(
                            f"Surface path: {_path_of(surface.url)}\n"
                            f"Method: {surface.method.upper()}\n"
                            f"Parameters: {', '.join(parameters)}\n"
                            f"Request budget for this analysis: {task.request_budget}\n"
                            "Select the parameters worth probing for reflection."
                        ),
                    ),
                ),
                system=_PLAN_SYSTEM,
                response_schema=_PLAN_SCHEMA,
                timeout_seconds=task.timeout_seconds,
            )
        )
        selected, dropped = _validate_selection(
            response.payload.get("parameters"), parameters, task.request_budget
        )
        plan: dict[str, object] = {
            "type": _PLAN_OBSERVATION,
            "parameters": list(selected),
            "marker": probe_marker(self._id_factory()),
            "reason": str(response.payload.get("reason", "")),
            "offered_parameters": list(parameters),
            # 예산 때문에 잘라낸 대상을 남긴다. 조용한 축소는 "전부 봤다"로 읽힌다.
            "dropped_for_budget": list(dropped),
        }
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=LLM_XSS_ANALYZER,
                evidence_type="observation",
                observation=plan,
            )
        )
        return plan, evidence_id

    def _interpret(
        self,
        task: TaskEnvelope,
        surface: Surface,
        selected: tuple[str, ...],
        marker: str,
        control: Evidence,
        probes: Sequence[Evidence | None],
        evidence: Sequence[Evidence],
    ) -> list[str]:
        """Python이 확인한 반사에만 LLM 맥락 분류를 덧붙여 Observation을 만든다."""

        control_body = response_body(control)
        confirmed: list[tuple[str, Evidence, str]] = []
        for parameter, probe in zip(selected, probes):
            if probe is None:  # missing 분기 이후에는 도달하지 않는 방어선.
                raise AgentContractError("llm xss analyzer probe evidence was not collected")
            probe_body = response_body(probe)
            # 반사 "여부"는 LLM에게 묻지 않는다. 원문 대조가 사실의 원천이다.
            if not marker_reflected(control_body, probe_body, marker):
                continue
            if has_observation_record(
                evidence,
                LLM_XSS_ANALYZER,
                "reflection",
                parameter,
                control.evidence_id,
                probe.evidence_id,
            ):
                continue
            confirmed.append((parameter, probe, _excerpt(probe_body or "", marker)))

        if not confirmed:
            return []

        classifications = self._classify(marker, confirmed, task.timeout_seconds)
        new_ids: list[str] = []
        for parameter, probe, _ in confirmed:
            classification = classifications.get(
                parameter, {"context": "unclassified", "encoded": False, "note": ""}
            )
            reflection_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=reflection_id,
                    run_id=task.run_id,
                    surface_id=surface.surface_id,
                    created_by=LLM_XSS_ANALYZER,
                    evidence_type="observation",
                    observation={
                        # Router 규칙과 heuristic baseline이 쓰는 것과 같은 유형이어야
                        # 두 구현의 결과를 같은 축에서 셀 수 있다.
                        "type": "reflection",
                        "parameter": parameter,
                        "control_evidence_id": control.evidence_id,
                        "probe_evidence_id": probe.evidence_id,
                        "context": classification["context"],
                        "encoded": classification["encoded"],
                        "note": classification["note"],
                        # 사실은 Python이, 맥락은 LLM이 만들었다는 것을 관측에 남긴다.
                        "context_source": "llm",
                    },
                )
            )
            new_ids.append(reflection_id)
        return new_ids

    def _classify(
        self,
        marker: str,
        confirmed: Sequence[tuple[str, Evidence, str]],
        timeout_seconds: float,
    ) -> dict[str, dict[str, object]]:
        """반사가 확인된 파라미터의 맥락만 LLM에 묻는다."""

        excerpts = "\n\n".join(
            f"### parameter: {parameter}\n{excerpt}" for parameter, _, excerpt in confirmed
        )
        response = self._llm.complete(
            LlmRequest(
                messages=(
                    LlmMessage(
                        role="user",
                        content=(
                            f"Marker: {marker}\n\n"
                            f"{excerpts}\n\n"
                            "Classify the syntactic context of the marker in each excerpt."
                        ),
                    ),
                ),
                system=_INTERPRETATION_SYSTEM,
                response_schema=_INTERPRETATION_SCHEMA,
                timeout_seconds=timeout_seconds,
            )
        )
        expected = {parameter for parameter, _, _ in confirmed}
        return _validate_classifications(response.payload.get("reflections"), expected)


def _stored_plan(
    evidence: Sequence[Evidence], surface_id: str
) -> dict[str, object] | None:
    """이전 호출이 남긴 탐침 계획을 복원한다."""

    for item in reversed(evidence):
        if (
            item.created_by == LLM_XSS_ANALYZER
            and item.surface_id == surface_id
            and item.observation.get("type") == _PLAN_OBSERVATION
        ):
            parameters = item.observation.get("parameters")
            marker = item.observation.get("marker")
            if isinstance(parameters, list) and isinstance(marker, str) and marker:
                return {"parameters": [str(name) for name in parameters], "marker": marker}
    return None


def _validate_selection(
    raw: object, offered: tuple[str, ...], request_budget: int
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """LLM이 고른 파라미터가 실재하는지 확인하고 예산에 맞게 자른다."""

    if not isinstance(raw, list):
        raise AgentContractError("llm xss plan did not return a parameter list")
    selected: list[str] = []
    for name in raw:
        if not isinstance(name, str):
            raise AgentContractError("llm xss plan returned a non-string parameter")
        if name not in offered:
            # 존재하지 않는 파라미터를 만들어낸 것은 계약 위반이다. 조용히 버리지 않는다.
            raise AgentContractError(
                f"llm xss plan named a parameter that is not on the surface: {name}"
            )
        if name not in selected:
            selected.append(name)

    # control 1개 + probe N개가 필요하므로 예산에서 1을 뺀 만큼만 탐침할 수 있다.
    affordable = max(request_budget - 1, 0)
    if len(selected) <= affordable:
        return tuple(selected), ()
    return tuple(selected[:affordable]), tuple(selected[affordable:])


def _validate_classifications(
    raw: object, expected: set[str]
) -> dict[str, dict[str, object]]:
    """맥락 분류를 검증한다. 확인되지 않은 파라미터에 대한 주장은 버린다."""

    if not isinstance(raw, list):
        raise AgentContractError("llm xss interpretation did not return a reflection list")
    classifications: dict[str, dict[str, object]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise AgentContractError("llm xss interpretation returned a non-object entry")
        parameter = item.get("parameter")
        context = item.get("context")
        encoded = item.get("encoded")
        # Python이 반사를 확인하지 않은 파라미터에 대한 주장은 근거가 없으므로 버린다.
        if parameter not in expected:
            continue
        if context not in REFLECTION_CONTEXTS:
            raise AgentContractError(
                f"llm xss interpretation used an unknown reflection context: {context}"
            )
        if not isinstance(encoded, bool):
            raise AgentContractError(
                "llm xss interpretation encoded field must be boolean"
            )
        note = item.get("note")
        if not isinstance(note, str):
            raise AgentContractError("llm xss interpretation note must be a string")
        classifications[str(parameter)] = {
            "context": str(context),
            "encoded": encoded,
            "note": note,
        }
    return classifications


def _excerpt(body: str, marker: str) -> str:
    """marker 주변만 잘라낸다. 본문 전체를 프롬프트에 싣지 않기 위한 경계다."""

    index = body.find(marker)
    if index < 0:
        return ""
    start = max(index - _EXCERPT_RADIUS, 0)
    end = min(index + len(marker) + _EXCERPT_RADIUS, len(body))
    return body[start:end]


def _path_of(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path or "/"
