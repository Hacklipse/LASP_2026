"""Check whether a read-only error route exposes internal stack frames."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import matching_evidence, resolve_analysis_task


ERROR_DISCLOSURE_TYPE = "Error Detail Exposure"
ERROR_ROUTE_OBSERVATION = "error_route_candidate"
ERROR_GRAPHQL_OBSERVATION = "graphql_error_probe_candidate"
ERROR_TRACE_OBSERVATION = "error_stack_trace_exposure"
_GRAPHQL_ANALYSIS_QUERY = "query {"
_GRAPHQL_VALIDATION_QUERY = "query { )"
_ERROR_PATH_TOKENS = frozenset({
    "debug", "error", "errors", "exception", "exceptions", "trace", "traces",
})
_PYTHON_FRAME = re.compile(r"(?m)^\s*File [\"'][^\r\n]{1,240}[\"'], line \d+\b")
_JS_FRAME = re.compile(r"(?m)^\s*at [^\r\n]{1,160}:[1-9]\d*:[1-9]\d*\)?\s*$")
_JAVA_FRAME = re.compile(r"(?m)^\s*at [\w.$]+\([^\r\n()]{1,120}\.java:\d+\)")
_RUBY_FRAME = re.compile(r"(?m)^\s*[^\r\n]{1,160}\.rb:\d+:in [`']")


def error_route_candidate(url: str) -> bool:
    """Select a bounded family of conventional diagnostic GET paths."""

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if parsed.query or parsed.fragment or parsed.path.endswith((".js", ".mjs", ".map")):
        return False
    return bool(_ERROR_PATH_TOKENS.intersection(
        token.casefold() for token in re.split(r"[/._-]+", parsed.path) if token
    ))


def exposed_error_stack(observation: dict) -> str | None:
    """Return only a stack family; never retain frame paths or response text."""

    status, body = observation.get("status"), observation.get("body")
    if (
        type(status) is not int or not 200 <= status <= 599
        or observation.get("truncated") or not isinstance(body, str)
        or not 80 <= len(body) <= 65536
    ):
        return None
    media = observation.get("content_type", "")
    if isinstance(media, str) and media.split(";", 1)[0].strip().casefold() in {
        "application/json", "application/graphql-response+json",
    }:
        try:
            document = json.loads(body)
        except ValueError:
            document = None
        errors = document.get("errors") if isinstance(document, dict) else None
        if isinstance(errors, list) and 0 < len(errors) <= 10:
            for error in errors:
                extension = error.get("extensions") if isinstance(error, dict) else None
                stack = extension.get("stack") if isinstance(extension, dict) else None
                if not isinstance(stack, str) or not 80 <= len(stack) <= 8192:
                    continue
                if len(_JS_FRAME.findall(stack)) >= 2:
                    return "graphql_javascript"
                if "Traceback (most recent call last):" in stack and _PYTHON_FRAME.search(stack):
                    return "graphql_python"
    if status < 500:
        return None
    if "Traceback (most recent call last):" in body and _PYTHON_FRAME.search(body):
        return "python"
    if len(_JS_FRAME.findall(body)) >= 2:
        return "javascript"
    if len(_JAVA_FRAME.findall(body)) >= 2:
        return "java"
    if len(_RUBY_FRAME.findall(body)) >= 2:
        return "ruby"
    return None


def error_detail_request(
    surface_id: str, *, graphql: bool, validation: bool = False,
) -> EvidenceRequest:
    """Use a fixed, read-only parser error for GraphQL; no operation runs."""

    return EvidenceRequest(
        evidence_type="http_response", surface_id=surface_id,
        reason="independently reproduce public error stack" if validation
               else "check discovered error route for internal stack frames",
        suggested_tool="http_get",
        anonymous=graphql,
        http_request=HttpRequestSpec(
            method="GET",
            query_parameters=(
                (("query", _GRAPHQL_VALIDATION_QUERY if validation else _GRAPHQL_ANALYSIS_QUERY),)
                if graphql else ()
            ),
        ),
    )


class ErrorDisclosureAnalyzer:
    """Read a discovered diagnostic route; Validation fetches it independently."""

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
            task, vulnerability_type=ERROR_DISCLOSURE_TYPE,
            candidate_store=self._candidates, surface_store=self._surfaces,
            allow_parameterless_get=True,
        )
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        graphql = any(
            item.surface_id == surface.surface_id
            and item.created_by == "recon"
            and item.observation.get("type") == ERROR_GRAPHQL_OBSERVATION
            for item in evidence
        )
        if surface.parameters or not (graphql or error_route_candidate(surface.url)):
            raise AgentContractError("error detail analysis requires an observed read-only error surface")
        request = error_detail_request(surface.surface_id, graphql=graphql)
        response = matching_evidence(evidence, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("error detail analysis needs one GET request")
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=(request,), candidate_ids=(candidate.candidate_id,),
            )
        stack_kind = exposed_error_stack(response.observation)
        new_ids: tuple[str, ...] = ()
        if stack_kind:
            signal = Evidence(
                evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                surface_id=surface.surface_id, created_by="error_disclosure_analyzer",
                evidence_type="observation", source_task_id=task.task_id,
                observation={
                    "type": ERROR_TRACE_OBSERVATION,
                    "stack_kind": stack_kind,
                    "probe_mode": "graphql" if graphql else "diagnostic_get",
                    "response_evidence_id": response.evidence_id,
                },
            )
            self._evidence.append(signal)
            new_ids = (signal.evidence_id,)
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=new_ids, candidate_ids=(candidate.candidate_id,),
        )
