"""Analyze observed client message HTML sinks with a benign foreign-origin canary."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest,
    HttpRequestKind, HttpRequestSpec, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .postmessage_plan import POSTMESSAGE_ANALYZER, POSTMESSAGE_PLAN
from .probing import matching_evidence, probe_marker, resolve_analysis_task
from .xss_execution import BROWSER_XSS_TOOL, XSS_REFLECTION_MARKER_PREFIX


def message_request(
    surface_id: str, kind: HttpRequestKind, *, event_type: str = "",
    field: str = "", marker: str = "", index: int = 0,
) -> EvidenceRequest:
    body = None if kind is HttpRequestKind.POSTMESSAGE_CONTROL else json.dumps(
        {"type": event_type, "field": field, "marker": marker},
        separators=(",", ":"), sort_keys=True,
    )
    return EvidenceRequest(
        evidence_type="browser_execution", surface_id=surface_id,
        reason=f"foreign-origin message {kind.value} plan {index}",
        suggested_tool=BROWSER_XSS_TOOL,
        http_request=HttpRequestSpec(
            method="GET", body=body, request_kind=kind,
        ),
    )


class PostMessageXssAnalyzer:
    """Select a bounded observed plan; DOM reflection remains only a candidate signal."""

    def __init__(
        self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
        evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, _ = resolve_analysis_task(
            task, vulnerability_type="XSS", candidate_store=self._candidates,
            surface_store=self._surfaces, required_tool=BROWSER_XSS_TOOL,
            allow_parameterless_get=True,
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        plans = tuple(dict.fromkeys(
            (item.observation.get("message_type"), item.observation.get("html_field"))
            for item in evidence
            if item.surface_id == surface.surface_id
            and item.created_by == "recon"
            and item.observation.get("type") == POSTMESSAGE_PLAN
            and isinstance(item.observation.get("message_type"), str)
            and isinstance(item.observation.get("html_field"), str)
        ))[:4]
        marker = probe_marker(
            f"{task.run_id}{candidate.candidate_id}",
            prefix=XSS_REFLECTION_MARKER_PREFIX,
        )
        requests = tuple(
            message_request(
                surface.surface_id, HttpRequestKind.POSTMESSAGE_REFLECTION,
                event_type=event_type, field=field, marker=marker, index=index,
            )
            for index, (event_type, field) in enumerate(plans)
        )
        collected = tuple(matching_evidence(evidence, surface.url, item) for item in requests)
        missing = tuple(item for item, proof in zip(requests, collected) if proof is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "postMessage reflection analysis lacks request budget",
                    required_requests=len(missing),
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing, candidate_ids=(candidate.candidate_id,),
            )
        new_ids = []
        for (event_type, field), proof in zip(plans, collected):
            if proof is None or proof.observation.get("type") != "browser_execution":
                continue
            if (
                proof.observation.get("foreign_origin_message") is not True
                or proof.observation.get("dom_reflected") is not True
                or proof.observation.get("reflection_marker") != marker
            ):
                continue
            if any(
                item.created_by == POSTMESSAGE_ANALYZER
                and item.observation.get("probe_evidence_id") == proof.evidence_id
                for item in evidence
            ):
                continue
            observation_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=observation_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by=POSTMESSAGE_ANALYZER,
                evidence_type="observation", observation={
                    "type": "postmessage_reflection",
                    "message_type": event_type,
                    "html_field": field,
                    "probe_evidence_id": proof.evidence_id,
                },
            ))
            new_ids.append(observation_id)
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_ids), candidate_ids=(candidate.candidate_id,),
        )
