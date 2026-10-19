"""Bounded, result-oriented local file-read probes for observed GET inputs."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import hashlib
from posixpath import normpath
import re
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from hacklipse.domain import (
    AgentResult, AgentResultStatus, Candidate, Evidence, EvidenceRequest,
    ExecutionRequest, ExecutionResult, HttpRequestKind, HttpRequestSpec,
    Surface, TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import has_observation_record, matching_evidence, resolve_analysis_task
from .request_safety import has_state_changing_parameters

FILE_READ_TOOL = "file_read_probe"
FILE_READ_ANALYZER = "arbitrary_file_read_analyzer"
FILE_READ_OBSERVATION = "arbitrary_file_read_signal"
PATH_INPUT = "{path}"
CONTROL_VALUE = "hacklipse-file-read-control"
_CONTROL_PATTERN = re.compile(r"hacklipse-file-read-control-[0-9a-f]{12}")


@dataclass(frozen=True, slots=True)
class SafeFileTarget:
    """Explicit, non-sensitive proof path and content markers for one environment."""

    key: str
    request_value: str
    markers: tuple[str, ...]
    # Multiple bounded encodings can point at the same proof file. Keeping the
    # canonical public path separate makes the static-file control meaningful.
    public_path: str | None = None
    strategy: str = "configured"

    def __post_init__(self) -> None:
        if not self.key or not self.request_value or not self.markers:
            raise ValueError("file-read target requires a key, path, and markers")
        if (len(self.request_value) > 256 or any(char in self.request_value for char in "\r\n\x00?&#")
                or "://" in self.request_value):
            raise ValueError("file-read target must be a bounded local path")
        if any(not marker or len(marker) > 128 for marker in self.markers):
            raise ValueError("file-read markers must be bounded and non-empty")
        if any(marker in self.request_value for marker in self.markers):
            raise ValueError("file-read marker cannot occur in its request path")
        if self.request_value == CONTROL_VALUE or _CONTROL_PATTERN.fullmatch(
            self.request_value
        ):
            raise ValueError("file-read target cannot equal its control marker")
        if self.public_path is not None and (
            not self.public_path.startswith("/")
            or normpath(self.public_path) != self.public_path
            or len(self.public_path) > 256
            or any(char in self.public_path for char in "\r\n\x00?&#")
        ):
            raise ValueError("file-read public path must be a bounded absolute path")
        if not self.strategy or len(self.strategy) > 64:
            raise ValueError("file-read strategy must be a short non-empty label")

    @property
    def configuration_fingerprint(self) -> str:
        encoded = "\x00".join((
            self.key, self.request_value, _public_path(self), self.strategy,
            *self.markers,
        )).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def validate_safe_file_targets(targets: Sequence[SafeFileTarget]) -> None:
    if not targets or len({target.key for target in targets}) != len(targets):
        raise ValueError("file-read targets need unique non-empty keys")
    if len({target.request_value for target in targets}) != len(targets):
        raise ValueError("file-read targets need unique request paths")


DEFAULT_SAFE_FILE_TARGETS = (
    SafeFileTarget(
        "os-release-absolute", "/etc/os-release", ("PRETTY_NAME=", "ID="),
        public_path="/etc/os-release", strategy="absolute",
    ),
    SafeFileTarget(
        "os-release-relative-2", "../../etc/os-release", ("PRETTY_NAME=", "ID="),
        public_path="/etc/os-release", strategy="relative-depth-2",
    ),
    SafeFileTarget(
        "os-release-relative-3", "../../../etc/os-release", ("PRETTY_NAME=", "ID="),
        public_path="/etc/os-release", strategy="relative-depth-3",
    ),
    SafeFileTarget(
        "os-release-relative-5", "../../../../../etc/os-release",
        ("PRETTY_NAME=", "ID="), public_path="/etc/os-release",
        strategy="relative-depth-5",
    ),
    SafeFileTarget(
        "os-release-double-encoded-3", "..%2f..%2f..%2fetc%2fos-release",
        ("PRETTY_NAME=", "ID="), public_path="/etc/os-release",
        strategy="double-encoded-relative-depth-3",
    ),
)


def validate_file_read_request(
    request: ExecutionRequest, targets: Sequence[SafeFileTarget],
    surface: Surface | None = None,
) -> None:
    """The dedicated tool can change exactly one query value to an approved path."""

    if request.tool != FILE_READ_TOOL:
        raise ValueError("file-read request requires its dedicated tool")
    if request.method.upper() != "GET" or request.body is not None or request.headers:
        raise ValueError("file-read probe only supports headerless GET requests")
    if request.path_suffix is not None or request.identifier_parameter is not None:
        raise ValueError("file-read probe cannot mutate the URL path")
    if request.request_kind is HttpRequestKind.FILE_READ_PUBLIC_CHECK:
        parsed = urlsplit(request.target_url)
        allowed_paths = {_public_path(target) for target in targets}
        if (request.query_parameters or request.file_read_path_index is not None
                or parsed.path not in allowed_paths or parsed.query):
            raise ValueError("file-read public check must request an approved direct path")
        return
    if surface is None:
        raise ValueError("file-read probe requires its stored surface template")
    if (
        request.surface_id != surface.surface_id
        or request.target_url != surface.url
        or surface.method.upper() != "GET"
    ):
        raise ValueError("file-read probe does not match its stored surface")
    path_input = request.file_read_path_index is not None
    if path_input:
        path = urlsplit(request.target_url).path
        segments = path.split("/")
        if (request.query_parameters != surface.observed_query
                or surface.parameters
                or request.file_read_parameter is not None
                or request.file_read_path_index != len(segments) - 1
                or not segments[-1]):
            raise ValueError("file-read path probe must replace the final observed segment")
        values = [request.file_read_path_value]
    else:
        parameter = request.file_read_parameter
        if parameter is None or parameter not in surface.parameters:
            raise ValueError("file-read probe requires an observed input")
        values = [dict(request.query_parameters)[parameter]]
        if request.query_parameters != _query_for(surface, parameter, values[0]):
            raise ValueError("file-read probe may mutate only its declared input")
    if request.request_kind is HttpRequestKind.CONTROL:
        if any(not _is_control_value(value) for value in values):
            raise ValueError("file-read control must use its fixed marker")
        return
    if request.request_kind is not HttpRequestKind.ARBITRARY_FILE_READ_PROBE:
        raise ValueError("file-read request kind must be control or probe")
    allowed = {target.request_value for target in targets}
    if sum(value in allowed for value in values) != 1:
        raise ValueError("file-read probe must use one approved proof path")
    if any(value not in allowed for value in values):
        raise ValueError("file-read probe contains an unapproved value")


def project_file_read_result(
    request: ExecutionRequest, result: ExecutionResult,
    targets: Sequence[SafeFileTarget],
) -> ExecutionResult:
    """Persist only a marker match, never the fetched file body or raw headers."""

    if request.tool != FILE_READ_TOOL:
        return result
    observation = dict(result.observation)
    body = observation.pop("body", None)
    observation.pop("headers", None)
    observation.pop("location", None)
    match = False
    if isinstance(body, str):
        values = {value for _, value in request.query_parameters}
        if request.file_read_path_value is not None:
            values.add(request.file_read_path_value)
        public_path = urlsplit(request.target_url).path
        match = any(
            (request.request_kind is HttpRequestKind.CONTROL
             or target.request_value in values
             or (request.request_kind is HttpRequestKind.FILE_READ_PUBLIC_CHECK
                 and _public_path(target) == public_path))
            and all(marker in body for marker in target.markers)
            for target in targets
        )
    observation["file_read_marker_match"] = match
    return ExecutionResult(
        execution_id=result.execution_id, evidence_type=result.evidence_type,
        observation=observation, content_hash=result.content_hash,
    )


def build_file_read_requests(
    surface: Surface, parameter: str, target: SafeFileTarget, *, purpose: str
) -> tuple[EvidenceRequest, EvidenceRequest]:
    path_input = parameter == PATH_INPUT
    control_value = _control_value(purpose)
    if surface.method.upper() != "GET" or (
        not path_input and parameter not in surface.parameters
    ):
        raise ValueError("file-read probe needs an observed GET input")
    if path_input and (surface.parameters or not urlsplit(surface.url).path.strip("/")):
        raise ValueError("file-read path probe needs a parameterless path surface")
    def make(kind: HttpRequestKind, value: str, label: str) -> EvidenceRequest:
        target_suffix = "" if kind is HttpRequestKind.CONTROL else f" [{target.key}]"
        return EvidenceRequest(
            evidence_type="http_response", surface_id=surface.surface_id,
            reason=f"{label} for {purpose}: {parameter}{target_suffix}",
            suggested_tool=FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=kind,
                query_parameters=(
                    surface.observed_query
                    if path_input
                    else _query_for(surface, parameter, value)
                ),
                file_read_parameter=None if path_input else parameter,
                file_read_path_index=(
                    len(urlsplit(surface.url).path.split("/")) - 1 if path_input else None
                ),
                file_read_path_value=value if path_input else None,
            ),
        )
    return (
        make(HttpRequestKind.CONTROL, control_value, "file-read control"),
        make(HttpRequestKind.ARBITRARY_FILE_READ_PROBE, target.request_value, "file-read probe"),
    )


def _query_for(
    surface: Surface, parameter: str, value: str
) -> tuple[tuple[str, str], ...]:
    """Preserve the observed request and replace exactly one query coordinate."""

    observed = dict(surface.observed_query)
    return tuple(
        (name, value if name == parameter else observed.get(name, ""))
        for name in dict.fromkeys(surface.parameters)
    )


def _control_value(purpose: str) -> str:
    suffix = hashlib.sha256(purpose.encode("utf-8")).hexdigest()[:12]
    return f"{CONTROL_VALUE}-{suffix}"


def _is_control_value(value: str | None) -> bool:
    return isinstance(value, str) and _CONTROL_PATTERN.fullmatch(value) is not None


def _public_path(target: SafeFileTarget) -> str:
    return normpath(
        target.public_path or "/" + target.request_value.lstrip("/")
    )


def build_public_file_check(
    surface: Surface, target: SafeFileTarget, *, purpose: str
) -> EvidenceRequest:
    parsed = urlsplit(surface.url)
    direct_url = urlunsplit((parsed.scheme, parsed.netloc, _public_path(target), "", ""))
    return EvidenceRequest(
        evidence_type="http_response", surface_id=surface.surface_id,
        reason=f"direct public-file check for {purpose}: {_public_path(target)}",
        suggested_tool=FILE_READ_TOOL, target_url_override=direct_url,
        http_request=HttpRequestSpec(
            method="GET", request_kind=HttpRequestKind.FILE_READ_PUBLIC_CHECK,
        ),
    )


def file_read_signal(control: Evidence, probe: Evidence) -> bool:
    status = probe.observation.get("status")
    return bool(
        isinstance(status, int) and 200 <= status < 300
        and probe.observation.get("file_read_marker_match") is True
        and control.observation.get("file_read_marker_match") is not True
        and probe.observation.get("truncated") is not True
        and control.content_hash != probe.content_hash
        and isinstance(probe.observation.get("body_bytes"), int)
        and probe.observation["body_bytes"] > 0
    )


class ArbitraryFileReadAnalyzer:
    """Analyze observed GET inputs using only configured safe proof files."""

    def __init__(
        self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        targets: tuple[SafeFileTarget, ...] = DEFAULT_SAFE_FILE_TARGETS,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._targets = targets
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, parameters = resolve_analysis_task(
            task, vulnerability_type="Arbitrary File Read",
            candidate_store=self._candidates, surface_store=self._surfaces,
            required_tool=FILE_READ_TOOL,
            allow_parameterless_get=True,
        )
        if urlsplit(surface.url).fragment or has_state_changing_parameters(parameters):
            raise ValueError("file-read analysis requires a safe server-side GET surface")
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        offered = parameters or (PATH_INPUT,)
        pairs = _bounded_probe_pairs(offered, self._targets, task.request_budget)
        expanded = tuple(
            request
            for parameter, target in pairs
            for request in build_file_read_requests(
                surface, parameter, target, purpose=f"candidate {candidate.candidate_id}"
            )
        )
        requests = tuple({
            request.request_fingerprint(surface.url): request
            for request in expanded
        }.values())
        missing = tuple(
            request for request in requests
            if matching_evidence(evidence, surface.url, request) is None
        )
        if missing:
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing, candidate_ids=(candidate.candidate_id,),
            )
        new_ids: list[str] = []
        for parameter, target in pairs:
            control_request, probe_request = build_file_read_requests(
                surface, parameter, target, purpose=f"candidate {candidate.candidate_id}"
            )
            control = matching_evidence(evidence, surface.url, control_request)
            probe = matching_evidence(evidence, surface.url, probe_request)
            if control is None or probe is None or not file_read_signal(control, probe):
                continue
            if has_observation_record(
                evidence, FILE_READ_ANALYZER, FILE_READ_OBSERVATION, parameter,
                control.evidence_id, probe.evidence_id,
            ):
                continue
            observation_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=observation_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by=FILE_READ_ANALYZER,
                evidence_type="observation",
                observation={
                    "type": FILE_READ_OBSERVATION, "parameter": parameter,
                    "target_key": target.key,
                    "target_fingerprint": target.configuration_fingerprint,
                    "strategy": target.strategy,
                    "control_evidence_id": control.evidence_id,
                    "probe_evidence_id": probe.evidence_id,
                },
            ))
            new_ids.append(observation_id)
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_ids), candidate_ids=(candidate.candidate_id,),
        )


def _bounded_probe_pairs(
    parameters: Sequence[str], targets: Sequence[SafeFileTarget], budget: int
) -> tuple[tuple[str, SafeFileTarget], ...]:
    """Spend one shared control per input, then probe inputs round-robin."""

    selected: list[tuple[str, SafeFileTarget]] = []
    controlled: set[str] = set()
    used = 0
    for target in targets:
        for parameter in parameters:
            cost = 1 + (parameter not in controlled)
            if used + cost > budget:
                continue
            selected.append((parameter, target))
            controlled.add(parameter)
            used += cost
    return tuple(selected)
