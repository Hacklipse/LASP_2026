"""Bounded GET redirect probes; the runtime never follows Location headers."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from html.parser import HTMLParser
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest,
    HttpRequestKind, HttpRequestSpec, Surface, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence, probe_marker, resolve_analysis_task

REDIRECT_TYPE = "Open Redirect"
REDIRECT_OBSERVATION = "open_redirect"
REDIRECT_PARAMETER_HINTS = (
    "next", "return", "return_url", "redirect", "redirect_uri",
    "destination", "dest", "url",
)
_PROBE_ORIGIN = "http://127.0.0.1:9"


def redirect_parameters(parameters: Sequence[str]) -> tuple[str, ...]:
    offered = {name.casefold() for name in REDIRECT_PARAMETER_HINTS}
    return tuple(name for name in parameters if name.casefold() in offered)


def redirect_probe_url(marker: str) -> str:
    """The marker is a URL value only. The HTTP runtime must not follow it."""

    return f"{_PROBE_ORIGIN}/{marker}"


def redirected_to_probe(evidence: Evidence | None, expected_url: str) -> bool:
    if evidence is None:
        return False
    observation = evidence.observation
    destination_hashes = observation.get("open_redirect_destination_hashes")
    if (
        isinstance(destination_hashes, (list, tuple))
        and hashlib.sha256(expected_url.encode("utf-8")).hexdigest()
        in destination_hashes
    ):
        return True
    if (
        evidence.evidence_type == "http_redirect"
        and observation.get("status") in {301, 302, 303, 307, 308}
        and observation.get("location") == expected_url
    ):
        return True
    # A user-controlled link can navigate away without a 3xx response. A
    # reflected string is insufficient: require a real anchor destination.
    body = observation.get("body")
    media = observation.get("content_type")
    if (
        evidence.evidence_type != "http_response" or observation.get("status") != 200
        or not isinstance(media, str) or media.split(";", 1)[0].strip().casefold() != "text/html"
        or not isinstance(body, str) or len(body) > 128 * 1024
        or observation.get("truncated")
    ):
        return False
    parser = _AnchorDestination(expected_url)
    parser.feed(body)
    return parser.matched


class _AnchorDestination(HTMLParser):
    def __init__(self, expected_url: str):
        super().__init__()
        self.expected_url = expected_url
        self.matched = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "a" and any(
            name.casefold() == "href" and value == self.expected_url
            for name, value in attrs
        ):
            self.matched = True


def build_redirect_requests(
    surface: Surface, parameters: Sequence[str], selected: Sequence[str],
    *, probe_url: str, purpose: str,
) -> tuple[EvidenceRequest, ...]:
    all_parameters = tuple(dict.fromkeys(parameters))
    if not all_parameters or not selected or any(name not in all_parameters for name in selected):
        raise ValueError("redirect probe needs observed input fields")
    requests = [EvidenceRequest(
        evidence_type="http_response", surface_id=surface.surface_id,
        reason=f"redirect control for {purpose}", suggested_tool="http_get",
        http_request=HttpRequestSpec(
            method="GET", query_parameters=tuple((name, "/") for name in all_parameters),
            request_kind=HttpRequestKind.CONTROL,
        ),
    )]
    for name in selected:
        requests.append(EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason=f"redirect probe for {name} on {purpose}", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=tuple((field, probe_url if field == name else "/")
                                       for field in all_parameters),
                request_kind=HttpRequestKind.OPEN_REDIRECT_PROBE,
            ),
        ))
    return tuple(requests)


class OpenRedirectAnalyzer:
    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, parameters = resolve_analysis_task(
            task, vulnerability_type=REDIRECT_TYPE,
            candidate_store=self._candidates, surface_store=self._surfaces,
        )
        selected = redirect_parameters(parameters)
        if not selected:
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                               candidate_ids=(candidate.candidate_id,))
        probe_url = redirect_probe_url(probe_marker(candidate.candidate_id, prefix="redirect"))
        requests = build_redirect_requests(
            surface, parameters, selected, probe_url=probe_url,
            purpose=f"open redirect analysis {candidate.candidate_id}",
        )
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        collected = tuple(matching_evidence(evidence, surface.url, request) for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded("open redirect analysis lacks read-only request budget")
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                               evidence_requests=missing, candidate_ids=(candidate.candidate_id,))
        control = collected[0]
        signal_ids: list[str] = []
        for parameter, probe in zip(selected, collected[1:]):
            if not redirected_to_probe(probe, probe_url) or redirected_to_probe(control, probe_url):
                continue
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=evidence_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by="open_redirect_analyzer",
                evidence_type="observation", source_task_id=task.task_id,
                observation={"type": REDIRECT_OBSERVATION, "parameter": parameter,
                             "control_evidence_id": control.evidence_id,
                             "probe_evidence_id": probe.evidence_id},
            ))
            signal_ids.append(evidence_id)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           new_evidence_ids=tuple(signal_ids), candidate_ids=(candidate.candidate_id,))
