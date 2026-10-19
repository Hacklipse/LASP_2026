"""고정된 비민감 파일만 읽는 결정적 Path Traversal baseline Agent.

자동 탐침은 임의 파일 경로를 받지 않는다. 일반적인 Linux 컨테이너에 기본 존재하는
비민감 OS 식별 파일 ``/etc/os-release``만 고정 상대 경로로 요청하고, 응답의 두 표식이
control에는 없고 probe에만 나타나는지 비교한다. Agent는 요청을 직접 실행하지 않는다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
import re

from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    PATH_TRAVERSAL_BYPASS_SUFFIX,
    PATH_TRAVERSAL_DECLARED_ROOT_ABSENT_FILE,
    PATH_TRAVERSAL_DECLARED_ROOT_PROOF_FILE,
    PATH_TRAVERSAL_SAFE_FORM_PROBE_PATH,
    PATH_TRAVERSAL_SAFE_PROBE_PATH,
    ExecutionRequest,
    Surface,
    TaskEnvelope,
    is_path_traversal_safe_probe_value,
    is_path_traversal_safe_form_probe_value,
    is_path_traversal_root_escape_value,
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
from .request_safety import has_state_changing_parameters
from .hidden_parameter_planner import HiddenParameterPlanner

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
# 경로에 `이름=값`으로 실린 입력을 관측했다는 사실. 입력의 "위치"만 말한다.
# 서버가 이를 실제 입력으로 처리하는지는 control/probe 비교 전에는 알 수 없다.
PATH_ASSIGNMENT_OBSERVATION = "path_embedded_assignment"
PATH_ASSIGNMENT_SOURCE = "observed_url_path"
# 그 이름이 서버의 파일을 여는 자리로 보인다는 "의미 가설". 위치와 별개의 필드다.
# 이 관측이 없으면 Path Traversal 가설을 세우지 않는다 — `url`·`redirect`처럼
# 원격 자원을 가리키는 이름에 파일 탐침을 보내도 파일이 나올 수 없기 때문이다.
FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION = "file_like_path_assignment"
# 경로에 `=`가 있었지만 좌표로 인정하지 않은 경우와 그 사유. 추측해서 실행하는 대신
# 무엇을 건너뛰었는지 감사할 수 있게 남긴다.
PATH_ASSIGNMENT_SKIPPED_OBSERVATION = "path_assignment_skipped"
PATH_ASSIGNMENT_CAPABILITY = "path_traversal.http.path_assignment"
# 선언된 하위 디렉터리 밖으로 나가는지 확인하는 좌표. 고정 OS 파일이 앱 루트 밖이라
# 영영 거부되는 대상에서도, 실제 취약점인 "디렉터리 탈출"은 증명할 수 있다.
ROOT_ESCAPE_CAPABILITY = "path_traversal.http.declared_root_escape"
PATH_TRAVERSAL_ROOT_ESCAPE_OBSERVATION = "declared_root_escape"
ROOT_ESCAPE_PROOF_FILE = PATH_TRAVERSAL_DECLARED_ROOT_PROOF_FILE
ROOT_ESCAPE_ABSENT_FILE = PATH_TRAVERSAL_DECLARED_ROOT_ABSENT_FILE


def declared_root_of(assignment) -> str | None:
    """관측된 값의 첫 디렉터리 이름. 이 표면이 의도한 하위 디렉터리로 본다.

    값에 디렉터리가 없으면(``/file=app.js``) 벗어날 하위 디렉터리 자체가 없으므로
    이 탐침은 성립하지 않는다.
    """

    head, separator, _ = assignment.observed_value.partition("/")
    if not separator or not head or head in {".", ".."}:
        return None
    return head if _ROOT_SEGMENT.fullmatch(head) else None


_ROOT_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
UNLINKED_RENDER_PARAMETER_OBSERVATION = "unlinked_render_parameter_candidate"
PATH_TRAVERSAL_POST_APPROVAL_REF = "approved-path-traversal-form-probe"
_INFERRED_PARAMETER_SOURCE = "bounded_unlinked_render_parameter"
HIDDEN_BODY_CAPABILITY = "path_traversal.hidden_body_parameter"
HIDDEN_PLAN_OBSERVATION = "hidden_body_parameter_plan"
_HIDDEN_BENIGN_PATH = "package.json"


def validate_path_traversal_request(request: ExecutionRequest) -> None:
    """전용 도구가 고정된 비민감 파일 외의 경로를 실행하지 못하게 한다."""

    if request.tool != PATH_TRAVERSAL_TOOL:
        raise ValueError("path traversal request must use its dedicated tool")
    method = request.method.upper()
    if method == "POST":
        if request.approval_ref != PATH_TRAVERSAL_POST_APPROVAL_REF:
            raise ValueError("path traversal POST requires its dedicated approval")
        if request.path_suffix is not None or request.query_parameters:
            raise ValueError("path traversal form probe cannot alter the URL")
        if request.request_kind not in {
            HttpRequestKind.CONTROL, HttpRequestKind.PATH_TRAVERSAL_PROBE
        }:
            raise ValueError("path traversal POST must be a control or safe-file probe")
        if request.headers != (("Content-Type", "application/x-www-form-urlencoded"),):
            raise ValueError("path traversal POST must use form-urlencoded content")
        fields = parse_qsl(request.body or "", keep_blank_values=True)
        if not fields or any(not name for name, _ in fields):
            raise ValueError("path traversal POST requires named form fields")
        changed = [value for _, value in fields if value]
        if request.request_kind is HttpRequestKind.CONTROL:
            if changed:
                raise ValueError("path traversal POST control must have blank field values")
        elif len(changed) != 1 or changed[0] not in {
            _HIDDEN_BENIGN_PATH, PATH_TRAVERSAL_FORM_PROBE_PATH
        }:
            raise ValueError("path traversal POST may change one fixed safe-file value")
        return
    if method != "GET" or request.body is not None or request.headers:
        raise ValueError("path traversal safe-file probe supports GET or approved POST")
    if (
        request.request_kind is HttpRequestKind.PATH_TRAVERSAL_ROOT_ESCAPE_PROBE
        and request.path_assignment_name is None
    ):
        # 이 종류는 관측된 경로 좌표에서만 성립한다. 좌표 없이 오면 바꿀 자리가 없다.
        raise ValueError("root escape probe requires an observed path assignment")
    if request.path_suffix is not None:
        # 우회 탐침은 표면이 이미 가리키는 파일에 고정 접미사만 덧붙인다. 다른 파일을
        # 고를 수 없으므로 파라미터도 필요 없다. 접미사 값은 도메인이 검증했다.
        if request.request_kind is not HttpRequestKind.PATH_TRAVERSAL_PROBE:
            raise ValueError("path suffix requires the path traversal probe kind")
        if request.query_parameters:
            raise ValueError("path traversal bypass probe cannot add query parameters")
        return
    if request.path_assignment_name is not None:
        # 경로에 실린 입력의 값만 바꾸는 탐침. 도메인이 이미 "고정 증명 경로 하나,
        # GET, 다른 변형 없음"을 강제했고, 여기서는 이 도구로 들어온 요청에도 같은
        # 계약이 적용됐는지 독립적으로 다시 확인한다.
        value = request.path_assignment_value or ""
        if request.request_kind is HttpRequestKind.PATH_TRAVERSAL_ROOT_ESCAPE_PROBE:
            if not is_path_traversal_root_escape_value(value):
                raise ValueError(
                    "root escape probe may only use the fixed escape shape"
                )
        elif request.request_kind is HttpRequestKind.PATH_TRAVERSAL_PROBE:
            if not is_path_traversal_safe_probe_value(value):
                raise ValueError("path assignment probe may only use the fixed safe path")
        else:
            raise ValueError("path assignment replacement requires a probe kind")
        if request.query_parameters:
            raise ValueError("path assignment probe cannot add query parameters")
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
        if candidate.routing_capability_id == HIDDEN_BODY_CAPABILITY:
            return handle_hidden_body_parameter(
                task=task,
                candidate=candidate,
                surface=surface,
                evidence=evidence,
                evidence_store=self._evidence,
                planner=HiddenParameterPlanner(None),
                created_by=HEURISTIC_PATH_TRAVERSAL_ANALYZER,
                id_factory=self._id_factory,
            )
        if surface.method.upper() == "POST":
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                candidate_ids=(candidate.candidate_id,),
                message="post_request_template_unavailable",
            )
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
        if prefers_path_assignment(
            candidate, surface, evidence, selected,
            capability_id=ROOT_ESCAPE_CAPABILITY,
        ) or prefers_path_assignment(candidate, surface, evidence, selected):
            return handle_path_assignment(
                task=task,
                candidate=candidate,
                surface=surface,
                evidence=evidence,
                evidence_store=self._evidence,
                created_by=HEURISTIC_PATH_TRAVERSAL_ANALYZER,
                id_factory=self._id_factory,
            )
        if candidate.exploration_parameters:
            # 탐색 힌트는 성공 증적이 아니다. 다른 Surface의 이름, 숨은 필드 추론,
            # 상태 변경 입력, 클라이언트 전용 URL은 이 경로에서 허용하지 않는다.
            if (
                any(name not in parameters for name in candidate.exploration_parameters)
                or has_state_changing_parameters(surface.parameters)
                or urlsplit(surface.url).fragment
            ):
                raise AgentContractError("invalid path traversal exploration parameters")
            if not selected:
                selected = candidate.exploration_parameters
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


def has_file_like_path_assignment(
    evidence: Sequence[Evidence], surface: Surface
) -> bool:
    """Recon이 이 표면의 경로 입력을 파일형으로 관측했는지 확인한다.

    위치 관측만으로는 부족하다. 경로에 ``redirect=``가 실려 있어도 그 자리에 파일
    경로를 보내 파일이 나올 수는 없고, 요청만 낭비된다.
    """

    return any(
        item.surface_id == surface.surface_id
        and item.observation.get("type") == FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION
        and item.observation.get("source") == PATH_ASSIGNMENT_SOURCE
        and surface.path_assignment is not None
        and item.observation.get("parameter") == surface.path_assignment.name
        for item in evidence
    )


def prefers_path_assignment(
    candidate: Candidate,
    surface: Surface,
    evidence: Sequence[Evidence],
    selected: Sequence[str],
    *,
    capability_id: str = PATH_ASSIGNMENT_CAPABILITY,
) -> bool:
    """이 Candidate가 query 좌표가 아니라 경로 좌표를 탐침해야 하는지 정한다.

    capability Router는 좌표마다 Candidate를 따로 만들므로 선언된 capability를 그대로
    따른다. 규칙 Router는 (Surface, 취약점 유형)당 Candidate를 하나만 만들기 때문에
    한쪽을 골라야 한다 — 기존 query 흐름을 그대로 두고, 고를 query 좌표가 없을 때만
    경로 좌표를 쓴다. 그래야 기존 결과가 바뀌지 않는다.

    ``capability_id``는 호출하는 분석기의 경로 좌표 capability다. Path Traversal과
    Arbitrary File Read가 같은 좌표를 서로 다른 값으로 탐침하므로, 어느 쪽 Candidate인지
    여기서 구분해야 한 분석기가 다른 쪽 Candidate를 가로채지 않는다.
    """

    if surface.path_assignment is None or not has_file_like_path_assignment(
        evidence, surface
    ):
        return False
    if candidate.routing_capability_id:
        return candidate.routing_capability_id == capability_id
    return not selected and not candidate.exploration_parameters


def build_path_assignment_plan_requests(
    surface: Surface,
    *,
    purpose: str,
    safe_file: bool,
    root_escape: bool,
) -> tuple[EvidenceRequest, ...]:
    """선택된 탐침들을 control 하나를 공유하는 한 벌의 요청으로 만든다.

    control 은 관측된 URL 그대로라 어느 탐침에나 같은 비교 기준이다. 따로 보내면
    같은 요청을 두 번 쓰게 되므로 공유한다.
    """

    if not safe_file and not root_escape:
        raise AgentContractError("path assignment plan must select at least one probe")
    requests = list(build_path_assignment_requests(surface, purpose=purpose))
    if not safe_file:
        requests = requests[:1]
    if root_escape:
        # 첫 요소는 같은 control 이므로 버리고 탐침만 덧붙인다.
        requests.extend(build_root_escape_requests(surface, purpose=purpose)[1:])
    return tuple(requests)


def build_path_assignment_requests(
    surface: Surface, *, purpose: str
) -> tuple[EvidenceRequest, ...]:
    """관측된 URL 그대로의 control 과 값만 교체한 probe 를 만든다.

    control 은 Recon 이 실제로 관측한 GET 요청이다. 값을 바꾸지 않으므로 좌표를 싣지
    않는다. probe 는 같은 scheme/host/method 와 같은 경로 구조에서 기록된 범위만
    고정 증명 경로로 바꾼다. 없던 query 를 덧붙이지 않는다.
    """

    assignment = surface.path_assignment
    if assignment is None:
        raise AgentContractError("path assignment probe requires an observed coordinate")
    if surface.method.upper() != "GET":
        raise AgentContractError("path assignment probe supports GET surfaces only")
    if not assignment.matches(surface.url):
        # 저장본과 URL 이 어긋나면 어디를 바꿔야 하는지 모르는 것이다. 다시 찾아보는
        # 것은 추측이므로 하지 않는다.
        raise AgentContractError("path assignment span does not match the surface URL")

    return (
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"observed path control request for {purpose}",
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.CONTROL
            ),
        ),
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=(
                f"safe-file probe for path assignment {assignment.name} on {purpose}"
            ),
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                path_assignment_name=assignment.name,
                path_assignment_value_start=assignment.value_start,
                path_assignment_value_end=assignment.value_end,
                path_assignment_value=PATH_TRAVERSAL_PROBE_PATH,
            ),
        ),
    )


def handle_path_assignment(
    *,
    task: TaskEnvelope,
    candidate: Candidate,
    surface: Surface,
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
) -> AgentResult:
    """경로에 실린 입력 자리에서 고정 증명 파일을 읽을 수 있는지 비교한다."""

    assignment = surface.path_assignment
    assert assignment is not None  # prefers_path_assignment 가 이미 확인했다.
    safe_file, root_escape = path_assignment_probe_plan(candidate, surface)
    purpose = f"Path Traversal candidate {candidate.candidate_id}"

    def gather(requests: tuple[EvidenceRequest, ...]):
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in requests
        )
        missing = tuple(
            request for request, item in zip(requests, collected) if item is None
        )
        return collected, missing

    def needs(missing: tuple[EvidenceRequest, ...]) -> AgentResult:
        if task.request_budget < len(missing):
            raise BudgetExceeded(
                "path assignment probe lacks budget for its evidence requests"
            )
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.NEEDS_EVIDENCE,
            evidence_requests=missing,
            candidate_ids=(candidate.candidate_id,),
        )

    # 디렉터리 밖 OS 파일을 직접 읽은 쪽이 더 강한 증명이므로 먼저 시도하고, 신호가
    # 없을 때만 탈출 탐침으로 넘어간다. 한꺼번에 보내면 OS 파일이 통하는 대상에서도
    # 표면마다 요청을 두 배로 쓴다.
    if safe_file:
        requests = build_path_assignment_requests(surface, purpose=purpose)
        collected, missing = gather(requests)
        if missing:
            return needs(missing)
        control, probe = collected
        if control is None or probe is None:
            raise AgentContractError("path assignment evidence was not collected")
        new_ids = record_path_traversal_observations(
            task=task,
            surface=surface,
            selected=(assignment.name,),
            control=control,
            probes=(probe,),
            evidence=evidence,
            evidence_store=evidence_store,
            created_by=created_by,
            id_factory=id_factory,
            extra={"location": "path_assignment"},
        )
        if new_ids or not root_escape:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_ids),
                candidate_ids=(candidate.candidate_id,),
            )

    requests = build_root_escape_requests(surface, purpose=purpose)
    collected, missing = gather(requests)
    if missing:
        return needs(missing)
    control, absent, escape = collected
    if control is None or absent is None or escape is None:
        raise AgentContractError("declared root escape evidence was not collected")
    new_ids = record_root_escape_observation(
        task=task,
        surface=surface,
        control=control,
        absent=absent,
        escape=escape,
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


def path_assignment_probe_plan(
    candidate: Candidate, surface: Surface
) -> tuple[bool, bool]:
    """이 Candidate가 경로 좌표에서 어떤 탐침을 보낼지 정한다.

    capability Router는 좌표·전략마다 Candidate를 따로 만들므로 선언된 것만 보낸다.
    규칙 Router는 (Surface, 취약점 유형)당 Candidate 하나뿐이라 한쪽만 고르면 다른
    증명 기회가 영영 사라진다. 그래서 규칙 모드에서는 둘 다 보내고 control을 공유한다.
    """

    escapable = declared_root_of(surface.path_assignment) is not None
    if candidate.routing_capability_id == PATH_ASSIGNMENT_CAPABILITY:
        return True, False
    if candidate.routing_capability_id == ROOT_ESCAPE_CAPABILITY:
        return False, escapable
    return True, escapable


def build_root_escape_requests(
    surface: Surface, *, purpose: str
) -> tuple[EvidenceRequest, ...]:
    """관측 URL control, 없는 파일 대조, 그리고 디렉터리 탈출 탐침을 만든다.

    세 번째가 증명이다. ``web_assets/../README.md``는 어휘 정규화 후 base 의
    ``README.md`` 하나만 가리키지만, 정규화 전에는 선언된 디렉터리 밖을 지난다.
    그 디렉터리로 읽기를 가두는 서버는 이 경로를 거부해야 한다. 내려주면 제한이
    강제되지 않는다는 뜻이다.

    두 번째는 "없는 파일"을 같은 자리에서 받아 본다. 200으로 오류 화면을 돌려주는
    앱에서 그 화면을 증명으로 오인하지 않기 위한 대조군이다.
    """

    assignment = surface.path_assignment
    if assignment is None:
        raise AgentContractError("root escape probe requires an observed coordinate")
    declared_root = declared_root_of(assignment)
    if declared_root is None:
        raise AgentContractError(
            "root escape probe requires an observed directory to escape"
        )
    if surface.method.upper() != "GET":
        raise AgentContractError("root escape probe supports GET surfaces only")
    if not assignment.matches(surface.url):
        raise AgentContractError("path assignment span does not match the surface URL")

    def escape(file_name: str, reason: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=reason,
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=HttpRequestKind.PATH_TRAVERSAL_ROOT_ESCAPE_PROBE,
                path_assignment_name=assignment.name,
                path_assignment_value_start=assignment.value_start,
                path_assignment_value_end=assignment.value_end,
                path_assignment_value=f"{declared_root}/../{file_name}",
            ),
        )

    return (
        EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=f"observed path control request for {purpose}",
            suggested_tool=PATH_TRAVERSAL_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.CONTROL
            ),
        ),
        escape(
            ROOT_ESCAPE_ABSENT_FILE,
            f"absent-file control outside the declared root for {purpose}",
        ),
        escape(
            ROOT_ESCAPE_PROOF_FILE,
            f"declared root escape probe for path assignment "
            f"{assignment.name} on {purpose}",
        ),
    )


def root_escape_signal(
    control: Evidence, absent: Evidence, escape: Evidence
) -> bool:
    """선언된 디렉터리 밖의 파일이 실제로 제공되었는지 판정한다.

    상태 코드 차이만으로는 확정하지 않는다. 탈출 경로가 2xx 로 비어 있지 않은 본문을
    돌려주고, 그 본문이 관측 파일과도 "없는 파일" 응답과도 달라야 한다. 세 번째 조건이
    200 으로 오류 화면을 주는 앱을 걸러 낸다.
    """

    status = escape.observation.get("status")
    body = response_body(escape)
    if not isinstance(status, int) or not 200 <= status < 300 or not body:
        return False
    return body != response_body(control) and body != response_body(absent)


def record_root_escape_observation(
    *,
    task: TaskEnvelope,
    surface: Surface,
    control: Evidence,
    absent: Evidence,
    escape: Evidence,
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    created_by: str,
    id_factory: Callable[[], str],
) -> list[str]:
    """Python 이 확인한 디렉터리 탈출 읽기만 Observation 으로 저장한다."""

    assignment = surface.path_assignment
    assert assignment is not None
    if not root_escape_signal(control, absent, escape):
        return []
    if has_observation_record(
        evidence,
        created_by,
        PATH_TRAVERSAL_OBSERVATION,
        assignment.name,
        control.evidence_id,
        escape.evidence_id,
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
                "parameter": assignment.name,
                "location": "path_assignment",
                "escape": PATH_TRAVERSAL_ROOT_ESCAPE_OBSERVATION,
                "declared_root": declared_root_of(assignment),
                "proof_file": ROOT_ESCAPE_PROOF_FILE,
                "control_evidence_id": control.evidence_id,
                "probe_evidence_id": escape.evidence_id,
            },
        )
    )
    return [observation_id]


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
                "file_serving_parameter",
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


def bounded_render_parameters_from_evidence(
    evidence: Sequence[Evidence], surface: Surface
) -> tuple[str, ...]:
    """Recon이 허용 목록에서 추가한 서버 렌더링 좌표만 반환한다."""

    return tuple(
        dict.fromkeys(
            parameter
            for item in evidence
            if item.surface_id == surface.surface_id
            and item.observation.get("type") == UNLINKED_RENDER_PARAMETER_OBSERVATION
            and item.observation.get("source") == _INFERRED_PARAMETER_SOURCE
            and isinstance((parameter := item.observation.get("parameter")), str)
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
        raise AgentContractError("valid POST request template is required for path traversal")
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


def build_hidden_body_requests(
    surface: Surface,
    parameters: Sequence[str],
    *,
    purpose: str,
) -> tuple[EvidenceRequest, ...]:
    """Block blank-form probes until verified POST replay is implemented."""

    raise AgentContractError("valid POST request template is required for hidden-body probes")


def hidden_body_signal(control: Evidence, benign: Evidence, traversal: Evidence) -> bool:
    """A 2xx marker in traversal only is required; error pages never confirm."""

    control_body = response_body(control) or ""
    benign_body = response_body(benign) or ""
    traversal_body = response_body(traversal) or ""
    status = traversal.observation.get("status")
    return bool(
        isinstance(status, int)
        and 200 <= status < 300
        and all(marker in traversal_body for marker in PATH_TRAVERSAL_FORM_PROOF_MARKERS)
        and all(marker not in control_body for marker in PATH_TRAVERSAL_FORM_PROOF_MARKERS)
        and all(marker not in benign_body for marker in PATH_TRAVERSAL_FORM_PROOF_MARKERS)
        and benign_body != traversal_body
    )


def handle_hidden_body_parameter(
    *,
    task: TaskEnvelope,
    candidate: Candidate,
    surface: Surface,
    evidence: Sequence[Evidence],
    evidence_store: EvidenceStore,
    planner: HiddenParameterPlanner,
    created_by: str,
    id_factory: Callable[[], str],
) -> AgentResult:
    """Report an untestable candidate without sending a synthetic blank POST."""

    # Field names are not a replayable request. This gate also protects candidates
    # restored from a database written before automatic routing was disabled.
    return AgentResult(
        task_id=task.task_id,
        status=AgentResultStatus.COMPLETED,
        candidate_ids=(candidate.candidate_id,),
        message="hidden_post_request_template_unavailable",
    )


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
