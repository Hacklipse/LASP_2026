"""고정된 비민감 파일만 읽는 결정적 Path Traversal baseline Agent.

자동 탐침은 임의 파일 경로를 받지 않는다. 일반적인 Linux 컨테이너에 기본 존재하는
비민감 OS 식별 파일 ``/etc/os-release``만 고정 상대 경로로 요청하고, 응답의 두 표식이
control에는 없고 probe에만 나타나는지 비교한다. Agent는 요청을 직접 실행하지 않는다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    PATH_TRAVERSAL_SAFE_PROBE_PATH,
    ExecutionRequest,
    Surface,
    TaskEnvelope,
    is_path_traversal_safe_probe_value,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore

from .probing import (
    CONTROL_VALUE,
    has_observation_record,
    matching_evidence,
    resolve_analysis_task,
    response_body,
)

PATH_TRAVERSAL_TOOL = "path_traversal_probe"
HEURISTIC_PATH_TRAVERSAL_ANALYZER = "heuristic_path_traversal_analyzer"
PATH_TRAVERSAL_OBSERVATION = "path_traversal_file_read"
PATH_TRAVERSAL_PROBE_PATH = PATH_TRAVERSAL_SAFE_PROBE_PATH
PATH_TRAVERSAL_PROOF_FILE = "/etc/os-release"
PATH_TRAVERSAL_PROOF_MARKERS = ("PRETTY_NAME=", "VERSION_ID=")


def validate_path_traversal_request(request: ExecutionRequest) -> None:
    """전용 도구가 고정된 비민감 파일 외의 경로를 실행하지 못하게 한다."""

    if request.tool != PATH_TRAVERSAL_TOOL:
        raise ValueError("path traversal request must use its dedicated tool")
    if request.method.upper() != "GET" or request.body is not None or request.headers:
        raise ValueError("path traversal safe-file probe supports plain GET requests only")
    if not request.query_parameters:
        raise ValueError("path traversal safe-file probe requires query parameters")

    values = tuple(value for _, value in request.query_parameters)
    if request.request_kind is HttpRequestKind.CONTROL:
        if any(value != CONTROL_VALUE for value in values):
            raise ValueError("path traversal control may only use the fixed control marker")
        return
    if request.request_kind is not HttpRequestKind.PATH_TRAVERSAL_PROBE:
        raise ValueError("path traversal tool requires control or safe-file probe kind")
    proof_paths = tuple(
        value for value in values if is_path_traversal_safe_probe_value(value)
    )
    if len(proof_paths) != 1:
        raise ValueError("path traversal probe must change exactly one parameter")
    if any(
        value != CONTROL_VALUE and not is_path_traversal_safe_probe_value(value)
        for value in values
    ):
        raise ValueError("path traversal probe contains a non-approved path")


class HeuristicPathTraversalAnalyzer:
    """Recon의 파일형 파라미터에 고정 safe-file control/probe를 수행한다."""

    def __init__(
        self,
        *,
        candidate_store: CandidateStore,
        surface_store: SurfaceStore,
        evidence_store: EvidenceStore,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        candidate, surface, parameters = resolve_analysis_task(
            task,
            vulnerability_type="Path Traversal",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=PATH_TRAVERSAL_TOOL,
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        selected = path_parameters_from_evidence(evidence, surface, parameters)
        if not selected:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                candidate_ids=(candidate.candidate_id,),
            )

        requests = build_path_traversal_requests(
            surface,
            parameters,
            selected,
            purpose=f"Path Traversal candidate {candidate.candidate_id}",
        )
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise AgentContractError(
                    "path traversal baseline lacks budget for its evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:
            raise AgentContractError("path traversal control evidence was not collected")
        new_ids = record_path_traversal_observations(
            task=task,
            surface=surface,
            selected=selected,
            control=control,
            probes=collected[1:],
            evidence=evidence,
            evidence_store=self._evidence,
            created_by=HEURISTIC_PATH_TRAVERSAL_ANALYZER,
            id_factory=self._id_factory,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_ids),
            candidate_ids=(candidate.candidate_id,),
        )


def path_parameters_from_evidence(
    evidence: Sequence[Evidence],
    surface: Surface,
    parameters: tuple[str, ...],
) -> tuple[str, ...]:
    """Recon이 파일/URL형으로 관찰한 현재 Surface 파라미터만 선택한다."""

    return tuple(
        dict.fromkeys(
            parameter
            for item in evidence
            if item.surface_id == surface.surface_id
            and item.observation.get("type") == "url_or_file_parameter"
            and isinstance((parameter := item.observation.get("parameter")), str)
            and parameter in parameters
        )
    )


def build_path_traversal_requests(
    surface: Surface,
    parameters: Sequence[str],
    selected: Sequence[str],
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """control 1개와 파라미터별 고정 safe-file probe를 만든다."""

    all_parameters = tuple(dict.fromkeys(parameters))
    selected_parameters = tuple(dict.fromkeys(selected))
    if not all_parameters or not selected_parameters:
        raise AgentContractError("path traversal plan must name at least one parameter")
    if any(parameter not in all_parameters for parameter in selected_parameters):
        raise AgentContractError("path traversal parameter must belong to the surface")

    requests = [
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"control request for {purpose}",
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=tuple(
                    (name, CONTROL_VALUE) for name in all_parameters
                ),
                request_kind=HttpRequestKind.CONTROL,
            ),
        )
    ]
    for parameter in selected_parameters:
        requests.append(
            EvidenceRequest(
                evidence_type="http_response",
                surface_id=surface.surface_id,
                reason=f"safe-file probe for parameter {parameter} on {purpose}",
                suggested_tool=PATH_TRAVERSAL_TOOL,
                http_request=HttpRequestSpec(
                    method="GET",
                    query_parameters=tuple(
                        (
                            name,
                            PATH_TRAVERSAL_PROBE_PATH
                            if name == parameter
                            else CONTROL_VALUE,
                        )
                        for name in all_parameters
                    ),
                    request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                ),
            )
        )
    return tuple(requests)


def path_traversal_signal(control: Evidence, probe: Evidence) -> bool:
    """probe에만 os-release 표식이 나타난 성공적인 파일 읽기인지 확인한다."""

    control_body = response_body(control) or ""
    probe_body = response_body(probe) or ""
    status = probe.observation.get("status")
    return bool(
        isinstance(status, int)
        and 200 <= status < 300
        and all(marker in probe_body for marker in PATH_TRAVERSAL_PROOF_MARKERS)
        and all(marker not in control_body for marker in PATH_TRAVERSAL_PROOF_MARKERS)
    )


def record_path_traversal_observations(
    *,
    task: TaskEnvelope,
    surface: Surface,
    selected: Sequence[str],
    control: Evidence,
    probes: Sequence[Evidence | None],
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
    extra: dict[str, object] | None = None,
) -> list[str]:
    """Python이 확인한 고정 safe-file 읽기만 공통 Observation으로 저장한다."""

    new_ids: list[str] = []
    for parameter, probe in zip(selected, probes):
        if probe is None:
            raise AgentContractError("path traversal probe evidence was not collected")
        if not path_traversal_signal(control, probe):
            continue
        if has_observation_record(
            evidence,
            created_by,
            PATH_TRAVERSAL_OBSERVATION,
            parameter,
            control.evidence_id,
            probe.evidence_id,
        ):
            continue
        observation_id = f"evi-{id_factory()}"
        observation: dict[str, object] = {
            "type": PATH_TRAVERSAL_OBSERVATION,
            "parameter": parameter,
            "proof_file": PATH_TRAVERSAL_PROOF_FILE,
            "control_evidence_id": control.evidence_id,
            "probe_evidence_id": probe.evidence_id,
        }
        if extra:
            observation.update(extra)
        evidence_store.append(
            Evidence(
                evidence_id=observation_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by=created_by,
                evidence_type="observation",
                observation=observation,
            )
        )
        new_ids.append(observation_id)
    return new_ids
