"""관측/명세 출처를 구분하는 GET SSRF control/probe와 결정적 Analyzer."""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlsplit

from hacklipse.application.execution import RuntimeEvidenceCollector
from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestKind,
    HttpRequestSpec, Surface, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded, RecordNotFound

from .probing import matching_evidence, resolve_analysis_task

SSRF_TYPE = "SSRF"
SSRF_ANALYZER = "ssrf_analyzer"
SSRF_CALLBACK_CAPABILITY = "ssrf.callback_observed_url_query"
SSRF_CALLBACK_DECLARED_CAPABILITY = "ssrf.callback_declared_url_query"
SSRF_CANARY_CAPABILITY = "ssrf.internal_canary_observed_url_query"
SSRF_CANARY_DECLARED_CAPABILITY = "ssrf.internal_canary_declared_url_query"
SSRF_OWNED_RECEIVER_CAPABILITY = "ssrf.internal_request_log_observed_url_query"
SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY = (
    "ssrf.internal_request_log_declared_url_query"
)
# Backwards-compatible public names. Existing callers mean the callback
# strategy when they ask for the original SSRF capability.
SSRF_CAPABILITY = SSRF_CALLBACK_CAPABILITY
SSRF_DECLARED_CAPABILITY = SSRF_CALLBACK_DECLARED_CAPABILITY
SSRF_CALLBACK_STRATEGIES = frozenset({
    "observed_url_callback_probe", "declared_url_callback_probe",
})
SSRF_CANARY_STRATEGIES = frozenset({
    "observed_url_internal_canary_probe",
    "declared_url_internal_canary_probe",
})
SSRF_OWNED_RECEIVER_STRATEGIES = frozenset({
    "observed_url_internal_request_log_probe",
    "declared_url_internal_request_log_probe",
})
SSRF_PARAMETER_HINTS = frozenset({
    "url", "uri", "link", "image", "image_url", "feed", "feed_url",
    "webhook", "callback", "target", "destination", "source", "resource",
})
_CONTROL_VALUE = "hacklipse-control"
SSRF_CONTEXT_TOOL = "get_surface_context"
SSRF_PROBE_TOOL = "probe_observed_url_input"
SSRF_RESULT_TOOL = "read_probe_result"
SSRF_ANALYSIS_TOOLS = (SSRF_CONTEXT_TOOL, SSRF_PROBE_TOOL, SSRF_RESULT_TOOL)
SSRF_RESULT_TYPE = "ssrf_probe_result"
SSRF_DESTINATION_HINT_TYPE = "ssrf_destination_hint"
SSRF_URL_FETCH_REVIEW_TYPE = "ssrf_url_fetch_review"


def is_ssrf_canary_candidate(candidate) -> bool:
    """Return whether a Candidate is explicitly bound to internal canary work."""

    return (
        candidate.routing_capability_id in {
            SSRF_CANARY_CAPABILITY, SSRF_CANARY_DECLARED_CAPABILITY,
        }
        or candidate.analysis_strategy_id in SSRF_CANARY_STRATEGIES
    )


def is_ssrf_callback_candidate(candidate) -> bool:
    """Return whether a Candidate is explicitly bound to callback work."""

    return (
        candidate.routing_capability_id in {
            SSRF_CALLBACK_CAPABILITY, SSRF_CALLBACK_DECLARED_CAPABILITY,
        }
        or candidate.analysis_strategy_id in SSRF_CALLBACK_STRATEGIES
    )


def is_ssrf_owned_receiver_candidate(candidate) -> bool:
    """Return whether a Candidate uses an operator-owned inbound request log."""

    return (
        candidate.routing_capability_id in {
            SSRF_OWNED_RECEIVER_CAPABILITY,
            SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY,
        }
        or candidate.analysis_strategy_id in SSRF_OWNED_RECEIVER_STRATEGIES
    )


def ssrf_local_validation_reserve(task: TaskEnvelope) -> int:
    """Reserve only proof requests not already held by the Orchestrator."""

    return max(0, 2 - task.validation_request_reserve)


def ssrf_parameter_sources(
    surface: Surface, evidence: tuple[Evidence, ...] = (),
) -> tuple[tuple[str, str], ...]:
    """Separate replayable inputs from OpenAPI-declared GET query names."""

    if surface.method.upper() != "GET" or urlsplit(surface.url).fragment:
        return ()
    observed_names = {name for name, _ in surface.observed_query}
    observed_names.update(name for name, _ in parse_qsl(
        urlsplit(surface.url).query, keep_blank_values=True,
    ))
    declared_names = {
        name
        for item in evidence
        if item.run_id == surface.run_id and item.surface_id == surface.surface_id
        and item.evidence_type == "observation"
        and item.observation.get("type") == "openapi_request_structure"
        and item.observation.get("method") == "GET"
        and isinstance(item.observation.get("query_parameter_names"), (list, tuple))
        for name in item.observation["query_parameter_names"]
        if isinstance(name, str)
    }
    coordinates = tuple(
        (name, "observed_query" if name in observed_names else "openapi_declaration")
        for name in dict.fromkeys(surface.parameters)
        if name.casefold() in SSRF_PARAMETER_HINTS
        and (name in observed_names or name in declared_names)
    )
    return tuple(sorted(coordinates, key=lambda item: item[1] != "observed_query"))


def ssrf_parameters(
    surface: Surface, evidence: tuple[Evidence, ...] = (),
) -> tuple[str, ...]:
    return tuple(name for name, _ in ssrf_parameter_sources(surface, evidence))


def build_ssrf_requests(
    surface: Surface, parameter: str, callback_url: str,
    evidence: tuple[Evidence, ...] = (),
) -> tuple[EvidenceRequest, EvidenceRequest]:
    """같은 GET Surface에서 한 필드만 callback URL로 바꾸는 두 요청을 만든다."""

    if parameter not in ssrf_parameters(surface, evidence):
        raise ValueError("SSRF probe requires an observed or declared URL-like GET parameter")
    parsed = urlsplit(callback_url)
    if (
        (parsed.scheme != "https" and not (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "host.docker.internal"}
        )) or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment
    ):
        raise ValueError("SSRF callback must be an HTTPS or loopback-test URL without credentials")
    observed = dict(surface.observed_query)
    observed.update(parse_qsl(urlsplit(surface.url).query, keep_blank_values=True))
    # shortcut: preserve only bounded non-URL companion values; richer request
    # templates need a provenance-aware runtime contract before expansion.
    names = tuple(dict.fromkeys((*observed, *surface.parameters)))
    control = tuple((name, _CONTROL_VALUE if name == parameter or
                     name.casefold() in SSRF_PARAMETER_HINTS else observed[name])
                    for name in names if name == parameter or name in observed)
    probe = tuple((name, callback_url if name == parameter else
                   _CONTROL_VALUE if name.casefold() in SSRF_PARAMETER_HINTS else observed[name])
                  for name in names if name == parameter or name in observed)
    return (
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason=f"SSRF control for {parameter}", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=control,
                request_kind=HttpRequestKind.SSRF_CONTROL,
            ),
        ),
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason=f"SSRF callback probe for {parameter}", suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=probe,
                request_kind=HttpRequestKind.SSRF_PROBE,
            ),
        ),
    )


def build_ssrf_canary_request(
    surface: Surface, parameter: str, canary_url: str,
    evidence: tuple[Evidence, ...] = (),
) -> EvidenceRequest:
    """Replay only an observed GET coordinate with the operator's exact canary URL."""

    if parameter not in ssrf_parameters(surface, evidence):
        raise ValueError("SSRF canary requires an observed or declared URL-like GET parameter")
    observed = dict(surface.observed_query)
    observed.update(parse_qsl(urlsplit(surface.url).query, keep_blank_values=True))
    names = tuple(dict.fromkeys((*observed, *surface.parameters)))
    query = tuple(
        (name, canary_url if name == parameter else
         _CONTROL_VALUE if name.casefold() in SSRF_PARAMETER_HINTS else observed[name])
        for name in names if name == parameter or name in observed
    )
    return EvidenceRequest(
        evidence_type="http_response", surface_id=surface.surface_id,
        reason=f"SSRF operator canary probe for {parameter}", suggested_tool="http_get",
        http_request=HttpRequestSpec(
            method="GET", query_parameters=query,
            request_kind=HttpRequestKind.SSRF_CANARY_PROBE,
        ),
    )


def build_ssrf_canary_requests(
    surface: Surface, parameter: str, canary_url: str,
    evidence: tuple[Evidence, ...] = (),
) -> tuple[EvidenceRequest, EvidenceRequest]:
    """Build a bounded control and the exact operator-approved URL request."""

    probe = build_ssrf_canary_request(surface, parameter, canary_url, evidence)
    assert probe.http_request is not None
    control = EvidenceRequest(
        evidence_type="http_response", surface_id=surface.surface_id,
        reason=f"SSRF controlled endpoint control for {parameter}",
        suggested_tool="http_get",
        http_request=HttpRequestSpec(
            method="GET",
            query_parameters=tuple(
                (name, _CONTROL_VALUE if name == parameter else value)
                for name, value in probe.http_request.query_parameters
            ),
            request_kind=HttpRequestKind.SSRF_CONTROL,
        ),
    )
    return control, probe


def build_ssrf_owned_receiver_requests(
    surface: Surface, parameter: str, receiver_url: str,
    evidence: tuple[Evidence, ...] = (),
) -> tuple[EvidenceRequest, EvidenceRequest]:
    """Build control/probe for one centrally issued owned-receiver ticket."""

    if parameter not in ssrf_parameters(surface, evidence):
        raise ValueError(
            "SSRF owned receiver requires an observed or declared URL-like GET parameter"
        )
    observed = dict(surface.observed_query)
    observed.update(parse_qsl(urlsplit(surface.url).query, keep_blank_values=True))
    names = tuple(dict.fromkeys((*observed, *surface.parameters)))
    probe_query = tuple(
        (name, receiver_url if name == parameter else
         _CONTROL_VALUE if name.casefold() in SSRF_PARAMETER_HINTS else observed[name])
        for name in names if name == parameter or name in observed
    )
    control_query = tuple(
        (name, _CONTROL_VALUE if name == parameter else value)
        for name, value in probe_query
    )
    return (
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason=f"SSRF owned receiver control for {parameter}",
            suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=control_query,
                request_kind=HttpRequestKind.SSRF_CONTROL,
            ),
        ),
        EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason=f"SSRF owned receiver probe for {parameter}",
            suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET", query_parameters=probe_query,
                request_kind=HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
            ),
        ),
    )


def canary_marker_signal(control: Evidence, probe: Evidence) -> bool:
    """Only a central, untruncated response differential is a marker signal."""

    return (
        control.created_by == "execution_runtime:http_get"
        and probe.created_by == "execution_runtime:http_get"
        and control.evidence_type == "http_response"
        and probe.evidence_type == "http_response"
        and control.observation.get("request_kind") == HttpRequestKind.SSRF_CONTROL.value
        and probe.observation.get("request_kind") == HttpRequestKind.SSRF_CANARY_PROBE.value
        and control.observation.get("ssrf_canary_marker_present") is False
        and probe.observation.get("ssrf_canary_marker_present") is True
    )


def poll_ssrf_callbacks(
    collector: RuntimeEvidenceCollector, evidence_store: EvidenceStore,
    task: TaskEnvelope, surface: Surface, probe_request: EvidenceRequest,
    probe_evidence_id: str,
) -> tuple[str, ...]:
    """Make at most two bounded provider polls, never target retries."""

    ids: list[str] = []
    for _ in range(2):
        ids.extend(collector.collect_ssrf_callbacks(
            task.run_id, task.candidate_id or "", surface.url, probe_request,
            probe_evidence_id, task_id=task.task_id,
            validation_id=task.validation_id,
            poll_timeout_seconds=collector.ssrf_callback_poll_wait_seconds,
        ))
        if any(
            evidence_store.get(task.run_id, evidence_id).observation.get("type")
            == "ssrf_callback_http"
            for evidence_id in ids
        ):
            break
    return tuple(dict.fromkeys(ids))


def has_http_callback(evidence: tuple[Evidence, ...], probe_evidence_id: str) -> bool:
    return any(
        item.created_by == "execution_runtime:ssrf_callback"
        and item.observation.get("type") == "ssrf_callback_http"
        and item.observation.get("probe_evidence_id") == probe_evidence_id
        for item in evidence
    )


def has_owned_receiver_observation(
    evidence: tuple[Evidence, ...], probe_evidence_id: str,
) -> bool:
    return any(
        item.created_by == "execution_runtime:ssrf_observation_provider"
        and item.observation.get("type") == "ssrf_server_request_observation"
        and item.observation.get("observation_mode") == "owned_receiver"
        and item.observation.get("probe_evidence_id") == probe_evidence_id
        and item.observation.get("source_verified") is True
        for item in evidence
    )


def record_ssrf_result(
    evidence_store: EvidenceStore, task: TaskEnvelope, parameter: str,
    probe_evidence_id: str, callback_ids: tuple[str, ...], status: str,
    coordinate_source: str = "observed_query", strategy_id: str = "",
) -> Evidence:
    """Persist a retry-stable, non-secret result for one observed coordinate."""

    digest = hashlib.sha256(
        f"{task.run_id}\0{task.candidate_id}\0{strategy_id}\0{parameter}\0"
        f"{probe_evidence_id}".encode()
    ).hexdigest()[:32]
    evidence_id = f"evi-ssrf-result-{digest}"
    try:
        return evidence_store.get(task.run_id, evidence_id)
    except RecordNotFound:
        item = Evidence(
            evidence_id=evidence_id, run_id=task.run_id,
            surface_id=task.surface_id, created_by=SSRF_ANALYZER,
            evidence_type="observation", source_task_id=task.task_id,
            observation={
                "type": SSRF_RESULT_TYPE,
                "candidate_id": task.candidate_id,
                "strategy_id": strategy_id,
                "parameter": parameter,
                "coordinate_source": coordinate_source,
                "status": status,
                "probe_evidence_id": probe_evidence_id,
                "callback_evidence_ids": list(callback_ids),
                "supporting_evidence_ids": list(callback_ids),
            },
        )
        evidence_store.append(item)
        return item


def ssrf_result_status(
    evidence_store: EvidenceStore, run_id: str,
    callback_ids: tuple[str, ...], probe_evidence_id: str,
) -> str:
    hits = evidence_store.get_many(run_id, callback_ids)
    if has_http_callback(hits, probe_evidence_id):
        return "http"
    if any(item.observation.get("type") == "ssrf_callback_dns" for item in hits):
        return "dns"
    return "no_hit"


class SsrfAnalyzer:
    """An observed URL input gets one bounded control/probe and callback A."""

    def __init__(
        self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
        evidence_store: EvidenceStore, collector: RuntimeEvidenceCollector,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._collector = collector

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, _ = resolve_analysis_task(
            task, vulnerability_type=SSRF_TYPE,
            candidate_store=self._candidates, surface_store=self._surfaces,
        )
        registration = self._collector.ssrf_review_for_surface(
            task.run_id, surface.surface_id,
        )
        canary = self._collector.ssrf_canary_proof_for_run(task.run_id)
        if is_ssrf_owned_receiver_candidate(candidate):
            if registration is None or not self._collector.ssrf_owned_receiver_enabled:
                return AgentResult(
                    task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                    candidate_ids=(candidate.candidate_id,),
                )
            return self._handle_owned_receiver(
                task, candidate, surface, registration,
            )
        if is_ssrf_canary_candidate(candidate):
            if registration is None or canary is None:
                return AgentResult(
                    task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                    candidate_ids=(candidate.candidate_id,),
                )
            return self._handle_registered_canary(task, candidate, surface, registration)
        if not is_ssrf_callback_candidate(candidate):
            reviewed = self._handle_registered_review(task, candidate, surface)
            if reviewed is not None:
                return reviewed
        surface_evidence = tuple(item for item in self._evidence.list_by_run(task.run_id)
                                 if item.surface_id == surface.surface_id)
        sources = dict(ssrf_parameter_sources(surface, surface_evidence))
        parameters = tuple(sources)
        registration = self._collector.ssrf_review_for_surface(
            task.run_id, surface.surface_id,
        )
        if registration is not None:
            parameters = tuple(
                item for item in parameters if item == registration.parameter
            )
        if not parameters:
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                candidate_ids=(candidate.candidate_id,),
            )
        # shortcut: one eligible URL field per Surface; expand only with a
        # ticket key that includes the field and budget reserved per probe.
        try:
            ticket = self._collector.issue_ssrf_ticket(
                task.run_id, candidate.candidate_id, parameters[0]
            )
        except (OSError, TimeoutError):
            outcome = record_ssrf_result(
                self._evidence, task, parameters[0], "", (), "provider_error",
                sources[parameters[0]], candidate.analysis_strategy_id,
            )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                new_evidence_ids=(outcome.evidence_id,),
                candidate_ids=(candidate.candidate_id,),
            )
        requests = build_ssrf_requests(surface, parameters[0], ticket.url, surface_evidence)
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        collected = tuple(matching_evidence(evidence, surface.url, request) for request in requests)
        missing = tuple(request for request, item in zip(requests, collected) if item is None)
        if missing:
            required = len(missing) + ssrf_local_validation_reserve(task)
            if task.request_budget < required:
                raise BudgetExceeded(
                    "SSRF analysis must reserve independent validation requests",
                    required_requests=required,
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing, candidate_ids=(candidate.candidate_id,),
            )
        probe = collected[1]
        assert probe is not None
        try:
            callback_ids = poll_ssrf_callbacks(
                self._collector, self._evidence, task, surface, requests[1], probe.evidence_id,
            )
            status = ssrf_result_status(self._evidence, task.run_id, callback_ids, probe.evidence_id)
        except (OSError, TimeoutError):
            callback_ids, status = (), "provider_error"
        outcome = record_ssrf_result(
            self._evidence, task, parameters[0], probe.evidence_id, callback_ids, status,
            sources[parameters[0]], candidate.analysis_strategy_id,
        )
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=callback_ids + (outcome.evidence_id,),
            candidate_ids=(candidate.candidate_id,),
        )

    def _handle_owned_receiver(
        self, task: TaskEnvelope, candidate, surface: Surface, registration,
    ) -> AgentResult:
        """Run Analysis ticket A without consulting the public OAST provider."""

        if candidate.exploration_parameters != (registration.parameter,):
            raise AgentContractError(
                "SSRF owned-receiver Candidate does not match the approved coordinate"
            )
        surface_evidence = tuple(
            item for item in self._evidence.list_by_run(task.run_id)
            if item.surface_id == surface.surface_id
        )
        source = dict(ssrf_parameter_sources(surface, surface_evidence)).get(
            registration.parameter,
        )
        if source is None:
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                candidate_ids=(candidate.candidate_id,),
            )
        try:
            ticket = self._collector.issue_ssrf_owned_receiver_ticket(
                task.run_id, candidate.candidate_id, surface.surface_id,
                registration.parameter,
            )
        except (OSError, TimeoutError):
            outcome = record_ssrf_result(
                self._evidence, task, registration.parameter, "", (),
                "provider_error", source, candidate.analysis_strategy_id,
            )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                new_evidence_ids=(outcome.evidence_id,),
                candidate_ids=(candidate.candidate_id,),
            )
        requests = build_ssrf_owned_receiver_requests(
            surface, registration.parameter, ticket.url, surface_evidence,
        )
        evidence = tuple(
            item for item in self._evidence.get_many(task.run_id, task.evidence_ids)
            if item.validation_id is None
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            required = len(missing) + ssrf_local_validation_reserve(task)
            if task.request_budget < required:
                raise BudgetExceeded(
                    "SSRF owned-receiver analysis must reserve two validation requests",
                    required_requests=required,
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing, candidate_ids=(candidate.candidate_id,),
            )
        probe = collected[1]
        assert probe is not None
        try:
            observation_ids = self._collector.collect_ssrf_owned_receiver_observations(
                task.run_id, candidate.candidate_id, surface.url, requests[1],
                probe.evidence_id, task_id=task.task_id,
            )
            status = (
                "owned_request_observed"
                if has_owned_receiver_observation(
                    self._evidence.get_many(task.run_id, observation_ids),
                    probe.evidence_id,
                )
                else "no_hit"
            )
        except (OSError, TimeoutError):
            observation_ids, status = (), "provider_error"
        outcome = record_ssrf_result(
            self._evidence, task, registration.parameter, probe.evidence_id,
            observation_ids, status, source, candidate.analysis_strategy_id,
        )
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=observation_ids + (outcome.evidence_id,),
            candidate_ids=(candidate.candidate_id,),
        )

    def _handle_registered_canary(
        self, task: TaskEnvelope, candidate, surface: Surface, registration,
    ) -> AgentResult:
        """Analyze only the approved coordinate, independently of callback access."""

        canary = self._collector.ssrf_canary_proof_for_run(task.run_id)
        if (
            canary is None or canary.surface_id != surface.surface_id
            or candidate.exploration_parameters != (registration.parameter,)
            or registration.execution_approval.verification_endpoint_ref
            != self._collector.ssrf_verification_endpoint_ref(task.run_id, canary.url)
        ):
            raise AgentContractError("SSRF canary review and Candidate do not match")
        surface_evidence = tuple(
            item for item in self._evidence.list_by_run(task.run_id)
            if item.surface_id == surface.surface_id
        )
        requests = build_ssrf_canary_requests(
            surface, registration.parameter, canary.url, surface_evidence,
        )
        evidence = tuple(
            item for item in self._evidence.get_many(task.run_id, task.evidence_ids)
            if item.validation_id is None
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request)
            for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            required = len(missing) + ssrf_local_validation_reserve(task)
            if task.request_budget < required:
                raise BudgetExceeded(
                    "SSRF analysis must reserve two validation requests",
                    required_requests=required,
                )
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing, candidate_ids=(candidate.candidate_id,),
            )
        control, probe = collected
        assert control is not None and probe is not None
        status = "controlled_marker" if canary_marker_signal(control, probe) else "no_marker"
        outcome = record_ssrf_result(
            self._evidence, task, registration.parameter, probe.evidence_id,
            (), status,
            dict(ssrf_parameter_sources(surface, surface_evidence))[registration.parameter],
            candidate.analysis_strategy_id,
        )
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=(outcome.evidence_id,),
            candidate_ids=(candidate.candidate_id,),
        )

    def _handle_registered_review(
        self, task: TaskEnvelope, candidate, surface: Surface,
    ) -> AgentResult | None:
        registration = self._collector.ssrf_review_for_surface(
            task.run_id, surface.surface_id,
        )
        if registration is None or not self._collector.ssrf_observation_enabled:
            return None
        if candidate.exploration_parameters != (registration.parameter,):
            raise AgentContractError(
                "SSRF Candidate does not match the registered coordinate"
            )
        try:
            _, _, mapping = self._collector.collect_server_request_observations(
                run_id=task.run_id,
                surface_id=surface.surface_id,
                parameter=registration.parameter,
                task_id=task.task_id,
            )
        except (AgentContractError, OSError, TimeoutError):
            mapping = {}
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(mapping.values()),
            candidate_ids=(candidate.candidate_id,),
        )
