"""Detect anonymous GraphQL field-name suggestions from observed schema names."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence


SUGGESTION_TYPE = "GraphQL Field Suggestion Exposure"
SUGGESTION_PLAN = "graphql_suggestion_probe_plan"
SUGGESTION_OBSERVATION = "graphql_field_suggestion_exposure"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")


def suggestion_plan(operations: tuple[tuple[str, str], ...]) -> tuple[str, str] | None:
    """Use a schema-observed query name; never guess a target-specific field."""

    names = {name for kind, name in operations if kind == "query" and _NAME.fullmatch(name)}
    for name in sorted(names, key=lambda item: (-len(item), item)):
        typo = name[:-1]
        if len(name) >= 6 and not name.startswith("__") and typo not in names:
            return name, typo
    return None


def suggestion_request(surface_id: str, typo: str, reason: str) -> EvidenceRequest:
    if not _NAME.fullmatch(typo) or len(typo) < 5:
        raise AgentContractError("GraphQL suggestion probe needs a bounded observed field")
    return EvidenceRequest(
        evidence_type="http_response", surface_id=surface_id,
        reason=reason, suggested_tool="http_get", anonymous=True,
        http_request=HttpRequestSpec(
            method="GET", query_parameters=(("query", f"query {{ {typo} }}"),),
        ),
    )


def suggested_field(observation: dict, typo: str, field: str) -> bool:
    """Require a GraphQL validation error that explicitly suggests the known field."""

    if (not _NAME.fullmatch(field) or not _NAME.fullmatch(typo)
            or observation.get("status") != 200 or observation.get("truncated")
            or not isinstance(observation.get("body"), str)
            or len(observation["body"]) > 65536):
        return False
    try:
        document = json.loads(observation["body"])
    except (TypeError, ValueError):
        return False
    if not isinstance(document, dict) or document.get("data") is not None:
        return False
    errors = document.get("errors")
    if not isinstance(errors, list) or not 0 < len(errors) <= 20:
        return False
    return any(
        isinstance(item, dict) and isinstance(item.get("message"), str)
        and f'Cannot query field "{typo}"' in item["message"]
        and f'Did you mean "{field}"?' in item["message"]
        for item in errors
    )


class GraphqlSuggestionAnalyzer:
    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None:
            raise AgentContractError("GraphQL suggestion analysis requires a candidate")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if (candidate.vulnerability_type != SUGGESTION_TYPE
                or task.surface_id != surface.surface_id or surface.method != "GET"
                or "graphql_introspection" not in surface.discovery_types):
            raise AgentContractError("invalid GraphQL suggestion analysis surface")
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        plans = [item.observation for item in evidence
                 if item.surface_id == surface.surface_id
                 and item.created_by == "recon" and item.observation.get("type") == SUGGESTION_PLAN]
        if len(plans) != 1:
            raise AgentContractError("GraphQL suggestion plan missing or ambiguous")
        field, typo = plans[0].get("field"), plans[0].get("typo")
        if (not isinstance(field, str) or not isinstance(typo, str)
                or not _NAME.fullmatch(field) or typo != field[:-1]):
            raise AgentContractError("invalid GraphQL suggestion probe plan")
        request = suggestion_request(surface.surface_id, typo, "check anonymous GraphQL field suggestion")
        response = matching_evidence(evidence, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("GraphQL suggestion analysis needs one read-only fetch")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=(request,), candidate_ids=(candidate.candidate_id,))
        if not suggested_field(response.observation, typo, field):
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                               candidate_ids=(candidate.candidate_id,))
        observation = Evidence(
            evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
            surface_id=surface.surface_id, created_by="graphql_suggestion_analyzer",
            evidence_type="observation", source_task_id=task.task_id,
            observation={"type": SUGGESTION_OBSERVATION, "field": field,
                         "typo": typo, "response_evidence_id": response.evidence_id},
        )
        self._evidence.append(observation)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           candidate_ids=(candidate.candidate_id,),
                           new_evidence_ids=(observation.evidence_id,))
