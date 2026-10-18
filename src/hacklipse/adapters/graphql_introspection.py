"""Check whether a GraphQL endpoint exposes its schema anonymously."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence


INTROSPECTION_TYPE = "GraphQL Introspection Exposure"
INTROSPECTION_RECON_OBSERVATION = "graphql_introspection_available"
INTROSPECTION_OBSERVATION = "graphql_introspection_exposure"
INTROSPECTION_DOCUMENT = "query { __schema { queryType { name } } }"


def schema_name(observation: dict) -> str | None:
    """Accept actual schema data, not a 200 response with GraphQL errors."""

    if (observation.get("status") != 200 or observation.get("truncated")
            or not isinstance(observation.get("body"), str)
            or len(observation["body"]) > 65536):
        return None
    try:
        document = json.loads(observation["body"])
    except (TypeError, ValueError):
        return None
    if not isinstance(document, dict) or document.get("errors"):
        return None
    data = document.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    query = schema.get("queryType") if isinstance(schema, dict) else None
    name = query.get("name") if isinstance(query, dict) else None
    return name if isinstance(name, str) and name.isidentifier() and len(name) <= 80 else None


def introspection_request(surface_id: str, reason: str) -> EvidenceRequest:
    return EvidenceRequest(
        evidence_type="http_response", surface_id=surface_id, reason=reason,
        suggested_tool="http_get", anonymous=True,
        http_request=HttpRequestSpec(
            method="GET", query_parameters=(("query", INTROSPECTION_DOCUMENT),),
        ),
    )


class GraphqlIntrospectionAnalyzer:
    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None:
            raise AgentContractError("GraphQL introspection analysis requires a candidate")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if (candidate.vulnerability_type != INTROSPECTION_TYPE
                or task.surface_id != surface.surface_id or surface.method != "GET"
                or "graphql_introspection" not in surface.discovery_types):
            raise AgentContractError("invalid GraphQL introspection analysis surface")
        request = introspection_request(surface.surface_id, "recheck anonymous GraphQL schema access")
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        response = matching_evidence(evidence, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("GraphQL introspection analysis needs one read-only fetch")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=(request,), candidate_ids=(candidate.candidate_id,))
        name = schema_name(response.observation)
        if name is None:
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                               candidate_ids=(candidate.candidate_id,))
        observation = Evidence(
            evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
            surface_id=surface.surface_id, created_by="graphql_introspection_analyzer",
            evidence_type="observation", source_task_id=task.task_id,
            observation={"type": INTROSPECTION_OBSERVATION,
                         "query_type_name": name, "response_evidence_id": response.evidence_id},
        )
        self._evidence.append(observation)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           candidate_ids=(candidate.candidate_id,),
                           new_evidence_ids=(observation.evidence_id,))
