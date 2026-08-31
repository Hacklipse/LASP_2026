"""LLM으로 Path Traversal 파라미터를 고르고 Python으로 고정 safe-file 읽기를 확인한다."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, Surface, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, LlmClient, SurfaceStore
from hacklipse.ports.llm import LlmMessage, LlmRequest

from .path_traversal_analysis import (
    PATH_TRAVERSAL_PROBE_PATH,
    PATH_TRAVERSAL_TOOL,
    build_path_traversal_requests,
    record_path_traversal_observations,
)
from .probing import matching_evidence, resolve_analysis_task, validate_probe_selection

LLM_PATH_TRAVERSAL_ANALYZER = "llm_path_traversal_analyzer"
_PLAN_OBSERVATION = "path_traversal_probe_plan"

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
    "You select which query parameters of one authorized test surface may control a "
    "server-side file path or include target. Return only names from the provided list. "
    "Prefer file, page, path, template, include, document, directory, or download inputs. "
    "Never return a path, filename, URL, payload, or value: the caller substitutes one "
    "fixed read-only, low-sensitivity proof path. Exclude submit buttons and "
    "presentation-only inputs. "
    "Return an empty list if no parameter plausibly controls a file path."
)


class LlmPathTraversalAnalyzer:
    """LLM은 이름만 선택하고 고정 safe-file 요청과 사실 판정은 Python에 맡긴다."""

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
            vulnerability_type="Path Traversal",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=PATH_TRAVERSAL_TOOL,
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
        if not selected:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        requests = build_path_traversal_requests(
            surface,
            parameters,
            selected,
            purpose=f"Path Traversal candidate {candidate.candidate_id}",
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
                    "llm path traversal analyzer lacks budget for its evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                new_evidence_ids=tuple(new_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:
            raise AgentContractError("path traversal control evidence was not collected")
        new_ids.extend(
            record_path_traversal_observations(
                task=task,
                surface=surface,
                selected=selected,
                control=control,
                probes=collected[1:],
                evidence=evidence,
                evidence_store=self._evidence,
                created_by=LLM_PATH_TRAVERSAL_ANALYZER,
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
                            "Select parameters that may control a server-side file path."
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
            analyzer_name="llm path traversal analyzer",
        )
        reason = response.payload.get("reason")
        if not isinstance(reason, str):
            raise AgentContractError("llm path traversal plan reason must be a string")
        plan: dict[str, object] = {
            "type": _PLAN_OBSERVATION,
            "parameters": list(selected),
            "reason": reason,
            "offered_parameters": list(parameters),
            "dropped_for_budget": list(dropped),
            # 감사용 메타데이터일 뿐, LLM 응답에서 가져오지 않는다.
            "proof_path": PATH_TRAVERSAL_PROBE_PATH,
        }
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=LLM_PATH_TRAVERSAL_ANALYZER,
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
            item.created_by == LLM_PATH_TRAVERSAL_ANALYZER
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
