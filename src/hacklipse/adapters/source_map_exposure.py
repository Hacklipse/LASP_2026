"""Discover and verify public source maps referenced by served JavaScript.

The map body is parsed only inside the execution boundary. Routing and proof
records contain a digest and counts, never source text or local source paths.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence


SOURCE_MAP_TYPE = "Source Map Exposure"
SOURCE_MAP_REFERENCE = "source_map_reference"
SOURCE_MAP_OBSERVATION = "source_map_content_exposure"
_REFERENCE = re.compile(r"(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)")
_SOURCE_FILE = re.compile(r"\.(?:js|jsx|ts|tsx|mjs|cjs)\Z", re.I)
_MAX_MAP_BYTES = 4 * 1024 * 1024


def source_map_urls(script_url: str, body: str) -> tuple[str, ...]:
    """Resolve only explicit, same-origin map references on a fetched script."""

    if not isinstance(body, str) or len(body) > _MAX_MAP_BYTES:
        return ()
    script = urlsplit(script_url)
    if script.scheme not in {"http", "https"} or not script.netloc:
        return ()
    found: list[str] = []
    for match in _REFERENCE.finditer(body):
        ref = match.group(1)
        if len(ref) > 240 or ref.startswith(("data:", "//")):
            continue
        url = urljoin(script_url, ref)
        parsed = urlsplit(url)
        if (
            parsed.scheme != script.scheme or parsed.netloc != script.netloc
            or parsed.query or parsed.fragment or not parsed.path.endswith(".map")
        ):
            continue
        if url not in found:
            found.append(url)
        if len(found) == 2:
            break
    return tuple(found)


def exposed_source_map_signature(observation: dict) -> tuple[str, int] | None:
    """Require real original source text and return a reproducible digest."""

    status = observation.get("status")
    body = observation.get("body")
    if (
        type(status) is not int or not 200 <= status < 300
        or observation.get("truncated")
        or not isinstance(body, str) or len(body) > _MAX_MAP_BYTES
    ):
        return None
    try:
        document = json.loads(body)
    except (TypeError, ValueError):
        return None
    if not isinstance(document, dict) or document.get("version") != 3:
        return None
    sources = document.get("sources")
    contents = document.get("sourcesContent")
    if (
        not isinstance(sources, list) or not isinstance(contents, list)
        or not 0 < len(sources) <= 500 or len(sources) != len(contents)
    ):
        return None
    exposed: list[tuple[str, str]] = []
    for name, content in zip(sources, contents):
        if (
            isinstance(name, str) and len(name) <= 300
            and _SOURCE_FILE.search(name.split("?", 1)[0])
            and "node_modules/" not in name
            and isinstance(content, str) and 64 <= len(content) <= 500_000
        ):
            exposed.append((name, content))
    if not exposed:
        return None
    digest = hashlib.sha256(
        json.dumps(exposed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return digest, len(exposed)


class SourceMapExposureAnalyzer:
    """Fetch the linked map; Validation independently fetches it again."""

    def __init__(
        self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
        evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None or task.surface_id is None or task.target_url is None:
            raise AgentContractError("source map analysis needs candidate and surface")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if (
            candidate.vulnerability_type != SOURCE_MAP_TYPE
            or candidate.surface_id != task.surface_id
            or surface.url != task.target_url or surface.method.upper() != "GET"
            or "http_get" not in task.allowed_tools
        ):
            raise AgentContractError("invalid source map analysis surface")
        request = EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason="read explicitly linked public source map", suggested_tool="http_get",
            http_request=HttpRequestSpec(method="GET"),
        )
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        response = matching_evidence(evidence, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("source map analysis needs one GET request")
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=(request,), candidate_ids=(candidate.candidate_id,),
            )
        signature = exposed_source_map_signature(response.observation)
        new_ids: tuple[str, ...] = ()
        if signature is not None:
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=evidence_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by="source_map_exposure_analyzer",
                evidence_type="observation", source_task_id=task.task_id,
                observation={
                    "type": SOURCE_MAP_OBSERVATION, "content_digest": signature[0],
                    "source_count": signature[1], "response_evidence_id": response.evidence_id,
                },
            ))
            new_ids = (evidence_id,)
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=new_ids, candidate_ids=(candidate.candidate_id,),
        )
