"""경로를 그대로 여는 표면에서 고정 절대 경로 파일 읽기를 증명한다.

Path Traversal 분석기는 상대 탈출 값 하나(``../../../../../etc/os-release``)만 보낸다.
그런데 ``..``를 거르는 필터는 절대 경로를 막지 못하는 경우가 흔해, 같은 파라미터에서
두 형태의 결과가 갈린다. CVE-Bench의 CVE-2024-3234에서 실제로 percent-encoded 탈출이
403으로 차단되는 것을 관측했다. 탈출 없이 경로를 그대로 여는 표면은 별개의 취약점이며,
``file_access`` 채점이 요구하는 능력도 이쪽이다.

읽을 파일은 도메인이 하나로 고정한다. Agent나 LLM이 ``/etc/passwd`` 같은 다른 파일을
고를 수 없고, 이 분석기는 "그 고정 파일을 읽을 수 있는가"만 판정한다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    ARBITRARY_FILE_READ_SAFE_PROBE_PATH,
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    ExecutionRequest,
    HttpRequestKind,
    HttpRequestSpec,
    Surface,
    TaskEnvelope,
    is_arbitrary_file_read_safe_probe_value,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded

from .probing import (
    has_observation_record,
    matching_evidence,
    resolve_analysis_task,
    response_body,
)
from .request_safety import has_state_changing_parameters
from .path_traversal_analysis import (
    has_file_like_path_assignment,
    prefers_path_assignment,
)

ARBITRARY_FILE_READ_TOOL = "arbitrary_file_read_probe"
HEURISTIC_ARBITRARY_FILE_READ_ANALYZER = "heuristic_arbitrary_file_read_analyzer"
ARBITRARY_FILE_READ_OBSERVATION = "arbitrary_file_read"
ARBITRARY_FILE_READ_PROBE_PATH = ARBITRARY_FILE_READ_SAFE_PROBE_PATH
ARBITRARY_FILE_READ_PROOF_FILE = "/etc/os-release"
# 고정 증명 파일에만 나타나는 표식. Path Traversal 과 같은 파일을 읽으므로 같은 표식을
# 쓴다. 둘 중 하나만 성립하는 경우를 구분하는 것은 표식이 아니라 보낸 값이다.
ARBITRARY_FILE_READ_PROOF_MARKERS = ("PRETTY_NAME=", "VERSION_ID=")
# 경로에 실린 입력 자리를 절대 경로로 탐침하는 capability. Path Traversal 쪽과 좌표는
# 같지만 싣는 값과 증명하는 사실이 다르므로 별도로 둔다.
ARBITRARY_FILE_READ_PATH_CAPABILITY = "arbitrary_file_read.http.path_assignment"
# 탐침이 바뀌지 않은 파라미터에 싣는 값. Path Traversal control 과 같은 역할이다.
CONTROL_VALUE = "hacklipse-control"
# Recon의 ``url_or_file_parameter`` 관측은 파일 이름과 URL 이름을 한 목록으로 묶는다
# (``file``·``path``와 ``url``·``redirect``가 같이 들어 있다). 그래서 이 관측으로
# 라우팅되는 분석기가 여럿이고, 표면 하나에서 후보가 여러 개 생긴다.
#
# 서버가 가진 파일을 여는 파라미터만 여기서 다룬다. URL을 받는 자리는 요청을 보내도
# 파일이 나올 수 없으므로, 그런 후보는 요청 0건으로 끝낸다. 외부 URL을 다루는 것은
# 다른 분석기의 몫이다.
_FILE_PARAMETER_HINTS = (
    "file",
    "path",
    "page",
    "template",
    "doc",
    "include",
    "folder",
    "dir",
    "load",
    "view",
    "download",
    "attachment",
    "name",
)
# 같은 이름 안에 URL 성격이 함께 드러나면 파일 자리로 보지 않는다. ``file_url`` 처럼
# 양쪽 힌트를 모두 가진 이름은 외부 자원을 가리킬 가능성이 높다.
_URL_PARAMETER_HINTS = ("url", "uri", "src", "link", "redirect", "dest", "target")


def looks_like_file_parameter(name: str) -> bool:
    """서버의 파일을 여는 파라미터로 보이는 이름인지 확인한다."""

    lowered = name.casefold()
    if any(hint in lowered for hint in _URL_PARAMETER_HINTS):
        return False
    return any(hint in lowered for hint in _FILE_PARAMETER_HINTS)


def validate_arbitrary_file_read_request(request: ExecutionRequest) -> None:
    """전용 도구가 고정된 비민감 파일 외의 경로를 실행하지 못하게 한다."""

    if request.tool != ARBITRARY_FILE_READ_TOOL:
        raise ValueError("arbitrary file read request must use its dedicated tool")
    if request.method.upper() != "GET":
        raise ValueError("arbitrary file read probe must be a GET request")
    if request.body is not None or request.headers:
        raise ValueError("arbitrary file read probe cannot carry a body or headers")
    if request.path_suffix is not None:
        raise ValueError("arbitrary file read probe cannot alter the path shape")
    if request.path_assignment_name is not None:
        # 경로에 실린 입력의 값만 바꾸는 탐침. 도메인이 이미 종류별 고정 값 하나만
        # 허용했고, 여기서는 이 도구로 들어온 요청에도 같은 계약이 적용됐는지
        # 독립적으로 다시 확인한다.
        if request.request_kind is not HttpRequestKind.ARBITRARY_FILE_READ_PROBE:
            raise ValueError("path assignment replacement requires the probe kind")
        if not is_arbitrary_file_read_safe_probe_value(
            request.path_assignment_value or ""
        ):
            raise ValueError("path assignment probe may only use the fixed safe path")
        if request.query_parameters:
            raise ValueError("path assignment probe cannot add query parameters")
        return

    values = tuple(value for _, value in request.query_parameters)
    if request.request_kind is HttpRequestKind.CONTROL:
        if any(value != CONTROL_VALUE for value in values):
            raise ValueError("arbitrary file read control may only use the fixed marker")
        return
    if not values:
        # 경로 좌표 흐름의 control 은 위에서 끝났다. 바꿀 값이 없는 probe 는 성립하지
        # 않으므로 여기서 막는다.
        raise ValueError("arbitrary file read probe requires a value to change")
    if request.request_kind is not HttpRequestKind.ARBITRARY_FILE_READ_PROBE:
        raise ValueError("arbitrary file read tool requires control or probe kind")
    proof_values = tuple(
        value for value in values if is_arbitrary_file_read_safe_probe_value(value)
    )
    if len(proof_values) != 1:
        raise ValueError("arbitrary file read probe must change exactly one parameter")
    if any(
        value != CONTROL_VALUE and not is_arbitrary_file_read_safe_probe_value(value)
        for value in values
    ):
        raise ValueError("arbitrary file read probe contains a non-approved path")


def build_arbitrary_file_read_requests(
    surface: Surface,
    parameters: Sequence[str],
    selected: Sequence[str],
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """control 1개와 파라미터별 고정 절대 경로 probe를 만든다."""

    all_parameters = tuple(dict.fromkeys(parameters))
    selected_parameters = tuple(dict.fromkeys(selected))
    if not selected_parameters or not all_parameters:
        raise AgentContractError("arbitrary file read plan must name at least one parameter")
    if surface.method.upper() != "GET":
        raise AgentContractError("arbitrary file read probe supports GET surfaces")
    if any(parameter not in all_parameters for parameter in selected_parameters):
        raise AgentContractError("arbitrary file read parameter must belong to the surface")

    query_names = all_parameters

    requests = [
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"control request for {purpose}",
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=tuple((name, CONTROL_VALUE) for name in query_names),
                request_kind=HttpRequestKind.CONTROL,
            ),
        )
    ]
    for parameter in selected_parameters:
        requests.append(
            EvidenceRequest(
                evidence_type="http_response",
                surface_id=surface.surface_id,
                reason=f"absolute path probe for parameter {parameter} on {purpose}",
                suggested_tool=ARBITRARY_FILE_READ_TOOL,
                http_request=HttpRequestSpec(
                    method="GET",
                    query_parameters=tuple(
                        (
                            name,
                            ARBITRARY_FILE_READ_PROBE_PATH
                            if name == parameter
                            else CONTROL_VALUE,
                        )
                        for name in query_names
                    ),
                    request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                ),
            )
        )
    return tuple(requests)


def build_arbitrary_file_read_path_requests(
    surface: Surface, *, purpose: str
) -> tuple[EvidenceRequest, ...]:
    """관측된 URL 그대로의 control 과 값만 절대 경로로 바꾼 probe 를 만든다.

    Path Traversal 쪽과 같은 좌표를 쓰지만 싣는 값이 다르다. ``..``를 거르는 필터가
    절대 경로는 막지 못하는 경우가 있어, 같은 자리에서 두 결과가 갈린다.
    """

    assignment = surface.path_assignment
    if assignment is None:
        raise AgentContractError(
            "arbitrary file read path probe requires an observed coordinate"
        )
    if surface.method.upper() != "GET":
        raise AgentContractError("arbitrary file read probe supports GET surfaces")
    if not assignment.matches(surface.url):
        raise AgentContractError("path assignment span does not match the surface URL")

    return (
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"observed path control request for {purpose}",
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.CONTROL
            ),
        ),
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=(
                f"absolute path probe for path assignment {assignment.name} on {purpose}"
            ),
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                path_assignment_name=assignment.name,
                path_assignment_value_start=assignment.value_start,
                path_assignment_value_end=assignment.value_end,
                path_assignment_value=ARBITRARY_FILE_READ_PROBE_PATH,
            ),
        ),
    )


def arbitrary_file_read_signal(control: Evidence, probe: Evidence) -> bool:
    """probe에만 고정 증명 파일 표식이 나타난 성공적인 읽기인지 확인한다."""

    control_body = response_body(control) or ""
    probe_body = response_body(probe) or ""
    status = probe.observation.get("status")
    return bool(
        isinstance(status, int)
        and 200 <= status < 300
        and all(marker in probe_body for marker in ARBITRARY_FILE_READ_PROOF_MARKERS)
        and all(
            marker not in control_body for marker in ARBITRARY_FILE_READ_PROOF_MARKERS
        )
    )


def record_arbitrary_file_read_observations(
    *,
    task: TaskEnvelope,
    selected: Sequence[str],
    control: Evidence,
    probes: Sequence[Evidence | None],
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
    extra: dict[str, object] | None = None,
) -> list[str]:
    """Python이 확인한 고정 파일 읽기만 Observation으로 저장한다."""

    new_ids: list[str] = []
    for parameter, probe in zip(selected, probes):
        if probe is None:
            raise AgentContractError("arbitrary file read probe evidence was not collected")
        if not arbitrary_file_read_signal(control, probe):
            continue
        if has_observation_record(
            evidence,
            created_by,
            ARBITRARY_FILE_READ_OBSERVATION,
            parameter,
            control.evidence_id,
            probe.evidence_id,
        ):
            continue
        observation_id = f"evi-{id_factory()}"
        observation: dict[str, object] = {
            "type": ARBITRARY_FILE_READ_OBSERVATION,
            "parameter": parameter,
            "proof_file": ARBITRARY_FILE_READ_PROOF_FILE,
            "control_evidence_id": control.evidence_id,
            "probe_evidence_id": probe.evidence_id,
        }
        if extra:
            observation.update(extra)
        evidence_store.append(
            Evidence(
                evidence_id=observation_id,
                run_id=task.run_id,
                surface_id=probe.surface_id,
                created_by=created_by,
                evidence_type="observation",
                source_task_id=task.task_id,
                observation=observation,
            )
        )
        new_ids.append(observation_id)
    return new_ids


class HeuristicArbitraryFileReadAnalyzer:
    """파일형 파라미터에 고정 절대 경로 control/probe를 수행한다."""

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
            vulnerability_type="Arbitrary File Read",
            candidate_store=self._candidates,
            surface_store=self._surfaces,
            required_tool=ARBITRARY_FILE_READ_TOOL,
            # 경로가 입력을 나르는 표면은 query 파라미터가 없다.
            allow_parameterless_get=True,
            allowed_methods=("GET",),
        )
        evidence = tuple(self._evidence.get_many(task.run_id, task.evidence_ids))

        hinted = tuple(
            name for name in candidate.exploration_parameters if name in parameters
        ) or parameters
        # 라우팅 관측이 파일 이름과 URL 이름을 구분하지 않으므로 여기서 좁힌다.
        # 후보는 이미 만들어졌지만 요청을 쓰지 않고 끝내므로 예산이 보존된다.
        selected = tuple(name for name in hinted if looks_like_file_parameter(name))
        if (
            has_state_changing_parameters(surface.parameters)
            or urlsplit(surface.url).fragment
        ):
            # 상태를 바꾸는 입력과 클라이언트 전용 좌표는 읽기 탐침 대상이 아니다.
            raise AgentContractError("invalid arbitrary file read target surface")
        if prefers_path_assignment(
            candidate, surface, evidence, selected,
            capability_id=ARBITRARY_FILE_READ_PATH_CAPABILITY,
        ):
            return self._handle_path_assignment(task, candidate, surface, evidence)
        if not selected:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                candidate_ids=(candidate.candidate_id,),
            )

        requests = build_arbitrary_file_read_requests(
            surface,
            parameters,
            selected,
            purpose=f"Arbitrary File Read candidate {candidate.candidate_id}",
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
                    "arbitrary file read baseline lacks budget for its evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        control = collected[0]
        if control is None:
            raise AgentContractError("arbitrary file read control evidence was not collected")
        new_ids = record_arbitrary_file_read_observations(
            task=task,
            selected=selected,
            control=control,
            probes=collected[1:],
            evidence=evidence,
            evidence_store=self._evidence,
            created_by=HEURISTIC_ARBITRARY_FILE_READ_ANALYZER,
            id_factory=self._id_factory,
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_ids),
            candidate_ids=(candidate.candidate_id,),
        )

    def _handle_path_assignment(
        self,
        task: TaskEnvelope,
        candidate,
        surface: Surface,
        evidence: Sequence[Evidence],
    ) -> AgentResult:
        """경로에 실린 입력 자리를 고정 절대 경로로 열 수 있는지 비교한다."""

        assignment = surface.path_assignment
        assert assignment is not None  # prefers_path_assignment 가 이미 확인했다.
        requests = build_arbitrary_file_read_path_requests(
            surface,
            purpose=f"Arbitrary File Read candidate {candidate.candidate_id}",
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
                    "arbitrary file read path probe lacks budget for its evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )

        control, probe = collected
        if control is None or probe is None:  # missing 이후에는 도달하지 않는다.
            raise AgentContractError("arbitrary file read path evidence was not collected")
        new_ids = record_arbitrary_file_read_observations(
            task=task,
            selected=(assignment.name,),
            control=control,
            probes=(probe,),
            evidence=evidence,
            evidence_store=self._evidence,
            created_by=HEURISTIC_ARBITRARY_FILE_READ_ANALYZER,
            id_factory=self._id_factory,
            extra={"location": "path_assignment"},
        )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(new_ids),
            candidate_ids=(candidate.candidate_id,),
        )
