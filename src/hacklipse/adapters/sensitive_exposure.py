"""Detect reproducible exposure of credential material in public HTML JSON.

Only field paths are retained as observations. Values stay in the normal,
access-controlled HTTP evidence and never enter a routing claim or report.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from uuid import uuid4

from bs4 import BeautifulSoup

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded
from .probing import matching_evidence


EXPOSURE_TYPE = "Sensitive Data Exposure"
EXPOSURE_OBSERVATION = "sensitive_json_exposure"
_SENSITIVE_FIELD = re.compile(
    r"(?:^|[_-])(?:client[_-]?secret|signing[_-]?secret|"
    r"private[_-]?key|admin[_-]?token|smtp[_-]?password)(?:$|[_-])",
    re.I,
)
_MAX_HTML = 2 * 1024 * 1024
_MAX_JSON = 128 * 1024


def _credential_field(path: tuple[str, ...]) -> bool:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", path[-1]).lower()
    parent = path[-2].lower() if len(path) > 1 else ""
    return bool(_SENSITIVE_FIELD.search(name) or
                (name in {"pass", "password", "passwd"} and parent in {"smtp", "mail", "database", "db"}))


def exposed_json_field_paths(observation: dict) -> tuple[str, ...]:
    """Return names of strongly credential-shaped fields in embedded JSON."""

    status = observation.get("status")
    media = observation.get("content_type", "")
    body = observation.get("body")
    if (
        type(status) is not int or not 200 <= status < 300
        or not isinstance(media, str) or "text/html" not in media.lower()
        or not isinstance(body, str) or len(body) > _MAX_HTML
        or observation.get("truncated")
    ):
        return ()
    soup = BeautifulSoup(body, "html.parser")
    found: set[str] = set()
    for script in soup.select('script[type="application/json"]')[:32]:
        raw = script.string
        if not isinstance(raw, str) or len(raw) > _MAX_JSON:
            continue
        try:
            document = json.loads(raw)
        except (TypeError, ValueError):
            continue
        pending: list[tuple[object, tuple[str, ...], int]] = [(document, (), 0)]
        visited = 0
        while pending and visited < 300:
            value, path, depth = pending.pop()
            visited += 1
            if depth >= 6 or not isinstance(value, dict):
                continue
            for key, child in list(value.items())[:100]:
                if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", key):
                    continue
                child_path = (*path, key)
                if isinstance(child, dict):
                    pending.append((child, child_path, depth + 1))
                elif (
                    _credential_field(child_path)
                    and isinstance(child, str) and len(child) >= 8
                    and child.strip() == child
                    and child.lower() not in {"redacted", "placeholder", "undefined", "null"}
                ):
                    found.add(".".join(child_path))
    return tuple(sorted(found))[:32]


class SensitiveExposureAnalyzer:
    """Re-fetch candidate HTML and record field names only; Validation decides."""

    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None:
            raise AgentContractError("sensitive exposure task has no candidate")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if candidate.vulnerability_type != EXPOSURE_TYPE or task.surface_id != surface.surface_id or surface.method != "GET":
            raise AgentContractError("invalid sensitive exposure analysis surface")
        request = EvidenceRequest(
            evidence_type="sensitive_exposure_analysis", surface_id=surface.surface_id,
            reason="recheck public embedded JSON field names", suggested_tool="http_get",
            http_request=HttpRequestSpec(method="GET"),
        )
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        response = matching_evidence(evidence, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("sensitive exposure analysis needs one read-only fetch")
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                candidate_ids=(candidate.candidate_id,),
                evidence_requests=(request,),
            )
        names = exposed_json_field_paths(response.observation)
        new_ids: tuple[str, ...] = ()
        if names:
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=evidence_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by="sensitive_exposure_analyzer",
                evidence_type="observation", source_task_id=task.task_id,
                observation={"type": EXPOSURE_OBSERVATION, "field_paths": list(names),
                             "response_evidence_id": response.evidence_id},
            ))
            new_ids = (evidence_id,)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           new_evidence_ids=new_ids, candidate_ids=(candidate.candidate_id,))
