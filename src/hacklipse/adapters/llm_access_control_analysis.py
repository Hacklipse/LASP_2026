"""LLM에 객체 식별자 파라미터 선택만 맡기는 Access Control Analysis Agent.

`HeuristicAccessControlAnalyzer`와 같은 요청 형태·같은 `object_id_auth` Observation을
만든다. 같은 Surface에서 두 구성의 결과를 비교하는 것이 이 Agent의 존재 이유다.

역할 분담 — LLM이 만들 수 있는 것과 없는 것을 구조로 갈라놓는다.

    LLM     어떤 파라미터가 객체를 가리키는가 (이름 하나 고르기)
    Python  객체 ID 값, 인증 주체, 요청 URL, 도구, 판정

LLM에 넘기는 것은 Surface 경로·메서드·파라미터 이름·남은 예산뿐이다. 응답 본문, 사용자
이름, Cookie, credential_ref, 실제 객체 ID는 프롬프트에 실리지 않는다. 남의 프로필을
읽어보는 검사이므로 개인정보가 프롬프트로 나가지 않는 것이 특히 중요하다.

LLM이 고른 이름이 Surface에 없거나 식별자 형태가 아니면 거부한다. 객체 ID·토큰·Cookie·
URL은 애초에 고를 자리가 없다.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, Evidence, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, LlmClient, SurfaceStore
from hacklipse.ports.llm import LlmMessage, LlmRequest

from .access_control_analysis import (
    ACCESS_CONTROL_TOOL,
    HeuristicAccessControlAnalyzer,
    access_identifier_options,
)
from .probing import resolve_analysis_task
from .request_safety import is_object_identifier_parameter

LLM_ACCESS_CONTROL_ANALYZER = "llm_access_control_analyzer"

_SELECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "parameters": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
    "required": ["parameters", "reason"],
    "additionalProperties": False,
}

_SELECTION_SYSTEM = (
    "You pick which identifier candidate of a single authorized test surface identifies the "
    "object being requested, so that an object-level authorization check can be tested. "
    "A candidate prefixed with path: represents a numeric URL path segment; other candidates "
    "are query parameters. Return only exact candidates that appear in the provided list. "
    "Prefer candidates that "
    "name a record or account identifier. Never pick parameters that carry actions, CSRF "
    "tokens, submit buttons, or session identifiers. You do not choose identifier values, "
    "credentials, URLs, or payloads; the caller supplies those. Return an empty list if no "
    "parameter identifies an object."
)


class LlmAccessControlAnalyzer:
    """LLM이 식별자 파라미터를 고르고, Python이 실행 경계와 판정을 지킨다."""

    def __init__(
        self,
        *,
        llm_client: LlmClient,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        actor_object_id: str | None = None,
        owner_object_id: str | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._llm = llm_client
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._task: TaskEnvelope | None = None
        self._surface = None
        self._selected: dict[str, str | None] = {}
        self._id_factory = id_factory or (lambda: str(uuid4()))
        # 판정과 요청 조립은 결정적 구현을 그대로 쓴다. 두 구성이 갈라지는 지점은
        # "어떤 파라미터를 볼 것인가" 하나여야 결과 차이를 그 선택 탓으로 돌릴 수 있다.
        self._baseline = HeuristicAccessControlAnalyzer(
            candidate_store=candidate_store,
            surface_store=surface_store,
            evidence_store=evidence_store,
            actor_object_id=actor_object_id,
            owner_object_id=owner_object_id,
            identifier_selector=self._identifier_for,
            id_factory=self._id_factory,
        )

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """LLM이 고른 식별자로 결정적 분석 절차를 수행한다."""

        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="Access Control",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=ACCESS_CONTROL_TOOL,
            allow_parameterless_get=True,
        )
        offered = access_identifier_options(surface, parameters)
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        if candidate.candidate_id in self._selected:
            found, stored = True, self._selected[candidate.candidate_id]
        else:
            found, stored = _stored_selection(evidence, surface.surface_id, offered)
        plan_id: str | None = None
        if not found:
            selected, reason = self._select_identifier(task, surface, offered)
            plan_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=plan_id,
                    run_id=task.run_id,
                    surface_id=surface.surface_id,
                    created_by=LLM_ACCESS_CONTROL_ANALYZER,
                    evidence_type="analysis_plan",
                    observation={
                        "type": "llm_access_control_plan",
                        "selected_identifier": selected,
                        "selection_reason": reason,
                    },
                )
            )
        else:
            selected = stored

        self._selected[candidate.candidate_id] = selected
        # 선택자가 호출될 때 필요한 문맥을 넘긴다. 선택 결과는 Evidence에 보존하므로
        # 프로세스 재시작 뒤에도 같은 파라미터로 독립 검증까지 이어진다.
        self._task, self._surface = task, surface
        result = self._baseline.handle(task)
        if plan_id is None:
            return result
        return replace(
            result,
            new_evidence_ids=tuple(dict.fromkeys((plan_id, *result.new_evidence_ids))),
        )

    def _identifier_for(self, parameters) -> str | None:
        task, surface = self._task, self._surface
        if task is None or surface is None:  # handle() 밖에서 호출될 수 없다.
            raise AgentContractError("identifier selection ran outside a task")
        key = task.candidate_id or ""
        if key in self._selected:
            return self._selected[key]
        identifier, _ = self._select_identifier(task, surface, tuple(parameters))
        if identifier is not None:
            self._selected[task.candidate_id or ""] = identifier
        return identifier

    def _select_identifier(
        self, task: TaskEnvelope, surface, parameters: tuple[str, ...]
    ) -> tuple[str | None, str]:
        """LLM에 식별자 좌표만 보여주고 하나를 고르게 한다."""

        response = self._llm.complete(
            LlmRequest(
                messages=(
                    LlmMessage(
                        role="user",
                        content=(
                            f"Surface path: {_path_of(surface)}\n"
                            f"Method: {surface.method.upper()}\n"
                            f"Identifier candidates: {', '.join(parameters)}\n"
                            f"Request budget for this analysis: {task.request_budget}\n"
                            "Select the candidate that identifies the requested object."
                        ),
                    ),
                ),
                system=_SELECTION_SYSTEM,
                response_schema=_SELECTION_SCHEMA,
                timeout_seconds=task.timeout_seconds,
            )
        )
        selected = _validate_selection(response.payload.get("parameters"), parameters)
        reason = response.payload.get("reason")
        return selected, reason if isinstance(reason, str) else ""


def _validate_selection(raw: object, offered: tuple[str, ...]) -> str | None:
    """LLM이 고른 이름이 실재하고 식별자 형태인지 확인한다."""

    if not isinstance(raw, list):
        raise AgentContractError("llm access control selection was not a list")
    for name in raw:
        if not isinstance(name, str):
            raise AgentContractError("llm access control selection was not a string")
        if name not in offered:
            # 존재하지 않는 파라미터를 만들어낸 것은 계약 위반이다. 조용히 버리지 않는다.
            raise AgentContractError(
                f"llm named a parameter that is not on the surface: {name}"
            )
        if not (
            name.startswith("path:")
            and is_object_identifier_parameter(name.removeprefix("path:"))
        ) and not is_object_identifier_parameter(name):
            # action·token·submit을 객체 식별자로 취급하면 엉뚱한 값을 바꿔가며 찌른다.
            raise AgentContractError(
                f"llm selected a parameter that does not identify an object: {name}"
            )
        return name
    return None


def _stored_selection(
    evidence: tuple[Evidence, ...], surface_id: str, offered: tuple[str, ...]
) -> tuple[bool, str | None]:
    """저장된 LLM 계획을 재사용한다. 빈 선택도 재호출 없이 복원한다."""

    for item in reversed(evidence):
        if item.surface_id != surface_id:
            continue
        if item.observation.get("type") != "llm_access_control_plan":
            continue
        selected = item.observation.get("selected_identifier")
        if selected is None:
            return True, None
        if isinstance(selected, str) and selected in offered:
            return True, selected
        raise AgentContractError("stored access control selection is invalid")
    return False, None


def _path_of(surface) -> str:
    from urllib.parse import urlsplit

    path = urlsplit(surface.url).path or "/"
    index = surface.path_identifier_index
    if index is None or surface.path_identifier is None:
        return path
    segments = path.split("/")
    if not (1 <= index < len(segments)):
        raise AgentContractError("surface path identifier index is invalid")
    segments[index] = "{" + surface.path_identifier + "}"
    return "/".join(segments)
