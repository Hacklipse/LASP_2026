"""Read-only CORS check using two fixed, unowned Origin header values."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest,
    HttpRequestKind, HttpRequestSpec, Surface, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence, resolve_analysis_task

CORS_TYPE = "CORS"
CORS_OBSERVATION = "cors_origin_reflection"
CORS_ANALYSIS_ORIGIN = "https://probe-a.invalid"
CORS_VALIDATION_ORIGIN = "https://probe-b.invalid"
CORS_SEARCH_INPUT_NAMES = frozenset({"q", "query", "search", "term", "keyword"})
CORS_SEARCH_VALUE = "hacklipse-control"
CORS_GRAPHQL_QUERY = "query { __typename }"


def cors_search_parameter(parameters: Sequence[str]) -> str | None:
    """Use one discovered search field; never replay observed query values."""

    return next((name for name in parameters
                 if name.casefold() in CORS_SEARCH_INPUT_NAMES), None)


def cors_probe_shape(surface: Surface) -> tuple[str | None, bool]:
    graphql_query = "graphql_introspection" in surface.discovery_types
    return (
        None if graphql_query else cors_search_parameter(surface.parameters),
        graphql_query,
    )


def build_cors_requests(
    surface_id: str, origin: str, purpose: str,
    *, search_parameter: str | None = None, graphql_query: bool = False,
) -> tuple[EvidenceRequest, ...]:
    if origin not in {CORS_ANALYSIS_ORIGIN, CORS_VALIDATION_ORIGIN}:
        raise ValueError("CORS probe Origin must be a fixed reserved value")
    if search_parameter is not None and search_parameter.casefold() not in CORS_SEARCH_INPUT_NAMES:
        raise ValueError("CORS search probe needs a bounded search field")
    if graphql_query and search_parameter is not None:
        raise ValueError("CORS probe must use one request shape")
    query = (
        (("query", CORS_GRAPHQL_QUERY),) if graphql_query else
        ((search_parameter, CORS_SEARCH_VALUE),) if search_parameter else ()
    )
    return (
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface_id,
            reason=f"CORS control for {purpose}", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=query,
                request_kind=HttpRequestKind.CONTROL,
            ),
        ),
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface_id,
            reason=f"CORS probe for {purpose}", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=query,
                headers=(("Origin", origin),),
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
                           origin: str, *, require_graphql_data: bool = False) -> bool:
    """Require a usable response, exact reflected origin, and credential permission."""

    if control is None or probe is None:
        return False
    if control.evidence_type != "http_response" or probe.evidence_type != "http_response":
        return False
    if any(type(item.observation.get("status")) is not int
           or not 200 <= item.observation["status"] < 300
           for item in (control, probe)):
        return False
    if require_graphql_data:
        for item in (control, probe):
            body = item.observation.get("body")
            if not isinstance(body, str) or len(body) > 65536:
                return False
            try:
                document = json.loads(body)
            except (TypeError, ValueError):
                return False
            if (not isinstance(document, dict)
                    or not isinstance(document.get("data"), dict)
                    or document.get("errors")):
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
            allow_parameterless_get=True,
            allowed_methods=("GET",),
        )
        search_parameter, graphql_query = cors_probe_shape(surface)
        requests = build_cors_requests(
            surface.surface_id, CORS_ANALYSIS_ORIGIN,
            f"CORS analysis {candidate.candidate_id}",
            search_parameter=search_parameter, graphql_query=graphql_query,
        )
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        collected = tuple(matching_evidence(evidence, surface.url, request) for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded("CORS analysis lacks read-only request budget")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=missing, candidate_ids=(candidate.candidate_id,))
        if not cors_reflection_signal(
            collected[0], collected[1], CORS_ANALYSIS_ORIGIN,
            require_graphql_data=graphql_query,
        ):
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
