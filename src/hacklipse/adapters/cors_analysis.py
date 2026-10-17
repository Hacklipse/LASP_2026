"""Read-only CORS check using two fixed, unowned Origin header values."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest,
    HttpRequestKind, HttpRequestSpec, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence, resolve_analysis_task

CORS_TYPE = "CORS"
CORS_OBSERVATION = "cors_origin_reflection"
CORS_ANALYSIS_ORIGIN = "https://probe-a.invalid"
CORS_VALIDATION_ORIGIN = "https://probe-b.invalid"


def build_cors_requests(surface_id: str, origin: str, purpose: str) -> tuple[EvidenceRequest, ...]:
    if origin not in {CORS_ANALYSIS_ORIGIN, CORS_VALIDATION_ORIGIN}:
        raise ValueError("CORS probe Origin must be a fixed reserved value")
    return (
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface_id,
            reason=f"CORS control for {purpose}", suggested_tool="http_get",
            http_request=HttpRequestSpec(method="GET", request_kind=HttpRequestKind.CONTROL),
        ),
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface_id,
            reason=f"CORS probe for {purpose}", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", headers=(("Origin", origin),),
                request_kind=HttpRequestKind.CORS_PROBE,
            ),
        ),
    )


def _header(evidence: Evidence | None, name: str) -> str | None:
    if evidence is None:
        return None
    raw = evidence.observation.get("headers")
    if not isinstance(raw, (list, tuple)):
        return None
    values = [value for item in raw
              if isinstance(item, (list, tuple)) and len(item) == 2
              for key, value in (item,)
              if isinstance(key, str) and key.casefold() == name
              and isinstance(value, str)]
    return values[0] if len(values) == 1 else None


def cors_reflection_signal(control: Evidence | None, probe: Evidence | None,
                           origin: str) -> bool:
    """Require a usable response, exact reflected origin, and credential permission."""

    if control is None or probe is None:
        return False
    if control.evidence_type != "http_response" or probe.evidence_type != "http_response":
        return False
    if any(type(item.observation.get("status")) is not int
           or not 200 <= item.observation["status"] < 300
           for item in (control, probe)):
        return False
    return (
        _header(control, "access-control-allow-origin") != origin
        and _header(probe, "access-control-allow-origin") == origin
        and (_header(probe, "access-control-allow-credentials") or "").casefold() == "true"
    )


class CorsAnalyzer:
    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, _ = resolve_analysis_task(
            task, vulnerability_type=CORS_TYPE,
            candidate_store=self._candidates, surface_store=self._surfaces,
        )
        requests = build_cors_requests(surface.surface_id, CORS_ANALYSIS_ORIGIN,
                                       f"CORS analysis {candidate.candidate_id}")
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        collected = tuple(matching_evidence(evidence, surface.url, request) for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded("CORS analysis lacks read-only request budget")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=missing, candidate_ids=(candidate.candidate_id,))
        if not cors_reflection_signal(collected[0], collected[1], CORS_ANALYSIS_ORIGIN):
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                               candidate_ids=(candidate.candidate_id,))
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(Evidence(
            evidence_id=evidence_id, run_id=task.run_id, surface_id=surface.surface_id,
            created_by="cors_analyzer", evidence_type="observation",
            source_task_id=task.task_id,
            observation={"type": CORS_OBSERVATION,
                         "control_evidence_id": collected[0].evidence_id,
                         "probe_evidence_id": collected[1].evidence_id},
        ))
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           new_evidence_ids=(evidence_id,),
                           candidate_ids=(candidate.candidate_id,))
