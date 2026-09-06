"""고정된 비민감 파일만 읽는 결정적 Path Traversal baseline Agent.

자동 탐침은 임의 파일 경로를 받지 않는다. 일반적인 Linux 컨테이너에 기본 존재하는
비민감 OS 식별 파일 ``/etc/os-release``만 고정 상대 경로로 요청하고, 응답의 두 표식이
control에는 없고 probe에만 나타나는지 비교한다. Agent는 요청을 직접 실행하지 않는다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import parse_qsl, urlencode
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    PATH_TRAVERSAL_BYPASS_SUFFIX,
    PATH_TRAVERSAL_SAFE_FORM_PROBE_PATH,
    PATH_TRAVERSAL_SAFE_PROBE_PATH,
    ExecutionRequest,
    Surface,
    TaskEnvelope,
    is_path_traversal_safe_probe_value,
    is_path_traversal_safe_form_probe_value,
)
from hacklipse.ports.errors import BudgetExceeded
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
PATH_TRAVERSAL_FORM_PROBE_PATH = PATH_TRAVERSAL_SAFE_FORM_PROBE_PATH
PATH_TRAVERSAL_PROOF_FILE = "/etc/os-release"
PATH_TRAVERSAL_PROOF_MARKERS = ("PRETTY_NAME=", "VERSION_ID=")
PATH_TRAVERSAL_FORM_PROOF_FILE = "package.json"
PATH_TRAVERSAL_FORM_PROOF_MARKERS = ('"name":', '"version":')
# 서버가 확장자 필터로 직접 거부한 자기 파일을 우회 경로로 읽어내는 형태.
# 쿼리 파라미터가 아니라 경로 자체가 파일을 가리키는 표면에서 성립한다.
PATH_TRAVERSAL_BYPASS_OBSERVATION = "path_traversal_filter_bypass"
RESTRICTED_FILE_OBSERVATION = "restricted_file_path"
UNLINKED_RENDER_PARAMETER_OBSERVATION = "unlinked_render_parameter_candidate"
PATH_TRAVERSAL_POST_APPROVAL_REF = "approved-path-traversal-form-probe"
_INFERRED_PARAMETER_SOURCE = "bounded_unlinked_render_parameter"


def validate_path_traversal_request(request: ExecutionRequest) -> None:
    """전용 도구가 고정된 비민감 파일 외의 경로를 실행하지 못하게 한다."""

    if request.tool != PATH_TRAVERSAL_TOOL:
        raise ValueError("path traversal request must use its dedicated tool")
    method = request.method.upper()
    if method == "POST":
        if request.path_suffix is not None or request.query_parameters:
            raise ValueError("path traversal form probe cannot alter the URL")
        if request.request_kind is not HttpRequestKind.PATH_TRAVERSAL_PROBE:
            raise ValueError("path traversal POST must be a safe-file probe")
        if request.headers != (("Content-Type", "application/x-www-form-urlencoded"),):
            raise ValueError("path traversal POST must use form-urlencoded content")
        fields = parse_qsl(request.body or "", keep_blank_values=True)
        if len(fields) != 1 or not fields[0][0]:
            raise ValueError("path traversal POST must change exactly one form field")
        if not is_path_traversal_safe_form_probe_value(fields[0][1]):
            raise ValueError("path traversal POST may only use the fixed safe path")
        return
    if method != "GET" or request.body is not None or request.headers:
        raise ValueError("path traversal safe-file probe supports GET or approved POST")
    if request.path_suffix is not None:
        # 우회 탐침은 표면이 이미 가리키는 파일에 고정 접미사만 덧붙인다. 다른 파일을
        # 고를 수 없으므로 파라미터도 필요 없다. 접미사 값은 도메인이 검증했다.
        if request.request_kind is not HttpRequestKind.PATH_TRAVERSAL_PROBE:
            raise ValueError("path suffix requires the path traversal probe kind")
        if request.query_parameters:
            raise ValueError("path traversal bypass probe cannot add query parameters")
        return
    if not request.query_parameters:
        # 우회 흐름의 control 은 표면 URL 을 그대로 받는 평범한 GET 이다. 바꾸는 값이
        # 없으므로 파라미터도 없다. probe 쪽은 위에서 접미사까지 검증했다.
        if request.request_kind is HttpRequestKind.CONTROL:
            return
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
            # 우회 흐름의 표면은 경로 자체가 파일이라 query 파라미터가 없다.
            allow_parameterless_get=True,
            allowed_methods=("GET", "POST"),
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))
        if is_restricted_file_surface(evidence, surface):
            return handle_path_traversal_bypass(
                task=task,
                candidate=candidate,
                surface=surface,
                evidence=evidence,
                evidence_store=self._evidence,
                created_by=HEURISTIC_PATH_TRAVERSAL_ANALYZER,
                id_factory=self._id_factory,
            )

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
                raise BudgetExceeded(
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


def is_restricted_file_surface(
    evidence: Sequence[Evidence], surface: Surface
) -> bool:
    """Recon이 접근 제한 파일 표면으로 표시했는지 확인한다."""

    return any(
        item.surface_id == surface.surface_id
        and item.observation.get("type") == RESTRICTED_FILE_OBSERVATION
        for item in evidence
    )


def build_path_traversal_bypass_requests(
    surface: Surface, *, purpose: str
) -> tuple[EvidenceRequest, ...]:
    """표면 경로 그대로의 control 과 고정 접미사를 붙인 probe 를 만든다."""

    return (
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"control request for {purpose}",
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.CONTROL
            ),
        ),
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"extension filter bypass probe for {purpose}",
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                path_suffix=PATH_TRAVERSAL_BYPASS_SUFFIX,
            ),
        ),
    )


def handle_path_traversal_bypass(
    *,
    task: TaskEnvelope,
    candidate: Candidate,
    surface: Surface,
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
) -> AgentResult:
    """서버가 거부한 파일이 고정 우회 접미사로 제공되는지 비교한다."""

    requests = build_path_traversal_bypass_requests(
        surface, purpose=f"Path Traversal candidate {candidate.candidate_id}"
    )
    collected = tuple(
        matching_evidence(evidence, surface.url, request) for request in requests
    )
    missing = tuple(
        request for request, item in zip(requests, collected) if item is None
    )
    if missing:
        if task.request_budget < len(missing):
            raise BudgetExceeded(
                "path traversal bypass lacks budget for its evidence requests"
            )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.NEEDS_EVIDENCE,
            evidence_requests=missing,
            candidate_ids=(candidate.candidate_id,),
        )

    control, probe = collected
    if control is None or probe is None:  # missing 이후에는 도달하지 않는다.
        raise AgentContractError("path traversal bypass evidence was not collected")
    new_ids = record_path_traversal_bypass(
        task=task,
        surface=surface,
        control=control,
        probe=probe,
        evidence=evidence,
        evidence_store=evidence_store,
        created_by=created_by,
        id_factory=id_factory,
    )
    return AgentResult(
        task_id=task.task_id,
        status=AgentResultStatus.COMPLETED,
        new_evidence_ids=tuple(new_ids),
        candidate_ids=(candidate.candidate_id,),
    )


def _received_bytes(evidence: Evidence) -> int:
    """실제로 받은 본문 크기. 바이너리도 세야 한다."""

    size = evidence.observation.get("body_bytes")
    if isinstance(size, int):
        return max(0, size)
    return len(response_body(evidence) or "")


def _content_key(evidence: Evidence) -> tuple[object, ...]:
    """두 응답이 같은 내용인지 비교할 키.

    디코딩된 본문에 기대지 않는다. 서버가 우회 경로로 내주는 파일은 대부분
    application/octet-stream 이라 Runtime 이 텍스트로 풀지 않고 body 를 None 으로
    남긴다. content_hash 와 크기는 종류와 무관하게 항상 기록된다.
    """

    return (
        evidence.content_hash,
        evidence.observation.get("body_bytes"),
        response_body(evidence),
    )


def path_traversal_bypass_signal(control: Evidence, probe: Evidence) -> bool:
    """서버가 거부한 파일이 우회 경로로는 제공되었는지 판정한다.

    단순한 2xx 는 기준이 아니다. 같은 파일을 control 에서는 서버가 거부(4xx)했고
    probe 에서만 내용이 제공되었다는 차이가 취약점 자체다.
    """

    control_status = control.observation.get("status")
    probe_status = probe.observation.get("status")
    return bool(
        isinstance(control_status, int)
        and 400 <= control_status < 500
        and isinstance(probe_status, int)
        and 200 <= probe_status < 300
        and _received_bytes(probe)
        and _content_key(control) != _content_key(probe)
    )


def record_path_traversal_bypass(
    *,
    task: TaskEnvelope,
    surface: Surface,
    control: Evidence,
    probe: Evidence,
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
) -> list[str]:
    """Python 이 확인한 우회 읽기만 Observation 으로 저장한다."""

    if not path_traversal_bypass_signal(control, probe):
        return []
    parameter = surface.url.rsplit("/", 1)[-1]
    if has_observation_record(
        evidence,
        created_by,
        PATH_TRAVERSAL_OBSERVATION,
        parameter,
        control.evidence_id,
        probe.evidence_id,
    ):
        return []
    observation_id = f"evi-{id_factory()}"
    evidence_store.append(
        Evidence(
            evidence_id=observation_id,
            run_id=task.run_id,
            surface_id=surface.surface_id,
            created_by=created_by,
            evidence_type="observation",
            observation={
                "type": PATH_TRAVERSAL_OBSERVATION,
                "parameter": parameter,
                "bypass": PATH_TRAVERSAL_BYPASS_OBSERVATION,
                "control_evidence_id": control.evidence_id,
                "probe_evidence_id": probe.evidence_id,
            },
        )
    )
    return [observation_id]


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
            and item.observation.get("type")
            in {
                "url_or_file_parameter",
                UNLINKED_RENDER_PARAMETER_OBSERVATION,
            }
            and isinstance((parameter := item.observation.get("parameter")), str)
            and (
                parameter in parameters
                or (
                    surface.method.upper() == "POST"
                    and item.observation.get("source") == _INFERRED_PARAMETER_SOURCE
                )
            )
        )
    )


def path_parameter_candidates(
    evidence: Sequence[Evidence],
    surface: Surface,
    parameters: tuple[str, ...],
) -> tuple[str, ...]:
    """관측된 필드와 Recon이 제한적으로 추론한 비노출 필드를 합친다."""

    inferred = path_parameters_from_evidence(evidence, surface, parameters)
    return tuple(dict.fromkeys((*parameters, *inferred)))


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
    if not selected_parameters:
        raise AgentContractError("path traversal plan must name at least one parameter")
    if surface.method.upper() == "POST":
        return _build_path_traversal_form_requests(
            surface, selected_parameters, purpose=purpose
        )
    if not all_parameters:
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


def _build_path_traversal_form_requests(
    surface: Surface,
    selected: Sequence[str],
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """서버 렌더링 폼을 GET control과 승인된 POST safe-file probe로 비교한다."""

    requests = [
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"read-only form control for {purpose}",
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.CONTROL
            ),
        )
    ]
    for parameter in selected:
        requests.append(
            EvidenceRequest(
                evidence_type="http_response",
                surface_id=surface.surface_id,
                reason=f"safe-file form probe for parameter {parameter} on {purpose}",
                suggested_tool=PATH_TRAVERSAL_TOOL,
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(
                        ("Content-Type", "application/x-www-form-urlencoded"),
                    ),
                    body=urlencode(((parameter, PATH_TRAVERSAL_FORM_PROBE_PATH),)),
                    request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                ),
                approval_ref=PATH_TRAVERSAL_POST_APPROVAL_REF,
            )
        )
    return tuple(requests)


def path_traversal_signal(control: Evidence, probe: Evidence) -> bool:
    """probe에만 고정 proof 파일 표식이 나타난 성공적인 읽기인지 확인한다."""

    control_body = response_body(control) or ""
    probe_body = response_body(probe) or ""
    status = probe.observation.get("status")
    markers = (
        PATH_TRAVERSAL_FORM_PROOF_MARKERS
        if str(probe.observation.get("method", "GET")).upper() == "POST"
        else PATH_TRAVERSAL_PROOF_MARKERS
    )
    return bool(
        isinstance(status, int)
        and 200 <= status < 300
        and all(marker in probe_body for marker in markers)
        and all(marker not in control_body for marker in markers)
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
            "proof_file": (
                PATH_TRAVERSAL_FORM_PROOF_FILE
                if surface.method.upper() == "POST"
                else PATH_TRAVERSAL_PROOF_FILE
            ),
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
