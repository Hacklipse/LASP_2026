"""LLM은 SSTI 후보 필드만 선택하고 실행·사실 판정은 Python이 수행한다."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, Surface, TaskEnvelope
from hacklipse.ports.errors import BudgetExceeded
from hacklipse.ports import CandidateStore, EvidenceStore, LlmClient, SurfaceStore
from hacklipse.ports.llm import LlmMessage, LlmRequest

from .probing import validate_probe_selection
from .ssti_analysis import (
    SSTI_TOOL,
    build_ssti_requests,
    matching_ssti_evidence,
    record_ssti_observation,
    resolve_ssti_task,
)

LLM_SSTI_ANALYZER = "llm_ssti_analyzer"
_PLAN_OBSERVATION = "ssti_probe_plan"

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
    "You select which fields of one authorized POST form may be rendered by a server-side "
    "template. Return only names from the provided list. Prefer username, display name, "
    "message, content, or template-like text fields. Never return a value, expression, "
    "payload, URL, header, cookie, or credential: the caller owns one fixed harmless "
    "arithmetic probe. Exclude email, role, upload, URL, and submit-button fields. Return "
    "an empty list if no field plausibly reaches server-side rendering."
)


class LlmSstiAnalyzer:
    """구조화 LLM 선택을 고정 Juice Shop username 산술 검증으로 제한한다."""

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
        candidate, surface, parameters = resolve_ssti_task(
            task,
            candidate_store=self._candidates,
            surface_store=self._surfaces,
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        stored = _stored_plan(evidence, surface.surface_id)
        new_ids: list[str] = []
        if stored is None:
            plan, plan_id = self._plan(task, surface, parameters)
            new_ids.append(plan_id)
        else:
            plan, plan_id = stored

        selected = tuple(plan["parameters"])
        # Python 안전 계약은 현재 Juice Shop의 username 하나만 허용한다. LLM이 다른
        # 텍스트 필드를 선택해도 상태 변경 요청으로 확장하지 않는다.
        if "username" not in selected:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        requests = build_ssti_requests(
            surface,
            "username",
            purpose=f"SSTI candidate {candidate.candidate_id}",
        )
        collected = tuple(
            matching_ssti_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded("LLM SSTI analyzer lacks budget for its safe request sequence")
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                new_evidence_ids=tuple(new_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        new_ids.extend(
            record_ssti_observation(
                task=task,
                surface=surface,
                parameter="username",
                collected=collected,
                evidence=evidence,
                evidence_store=self._evidence,
                created_by=LLM_SSTI_ANALYZER,
                id_factory=self._id_factory,
                extra={
                    "plan_evidence_id": plan_id,
                    "selection_source": "llm",
                    "selection_reason": str(plan["reason"]),
                },
            )
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_ids),
            candidate_ids=(candidate.candidate_id,),
        )

    def _plan(
        self, task: TaskEnvelope, surface: Surface, parameters: tuple[str, ...]
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
                            "Select fields that may reach server-side template rendering."
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
            analyzer_name="llm SSTI analyzer",
        )
        reason = response.payload.get("reason")
        if not isinstance(reason, str):
            raise AgentContractError("llm SSTI plan reason must be a string")
        plan: dict[str, object] = {
            "type": _PLAN_OBSERVATION,
            "parameters": list(selected),
            "reason": reason,
            "offered_parameters": list(parameters),
            "dropped_for_budget": list(dropped),
            "probe_contract": "fixed_arithmetic_only",
        }
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=LLM_SSTI_ANALYZER,
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
            item.created_by == LLM_SSTI_ANALYZER
            and item.surface_id == surface_id
            and item.observation.get("type") == _PLAN_OBSERVATION
        ):
            parameters = item.observation.get("parameters")
            reason = item.observation.get("reason")
            if isinstance(parameters, list) and isinstance(reason, str):
                return (
                    {"parameters": [str(name) for name in parameters], "reason": reason},
                    item.evidence_id,
                )
    return None
