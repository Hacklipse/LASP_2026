"""서버가 내주면 안 되는 경로를 여는지 증명하는 Arbitrary File Read 분석기.

Path Traversal 분석기와 나누는 기준은 "무엇을 증명하는가"다. 그쪽은 경로에 담긴 탈출
시퀀스를 서버가 따라가는지 보고, 이쪽은 서버가 받은 경로를 그대로 열어 주는지 본다.
``..``를 거르는 필터가 절대 경로는 막지 못하는 경우가 흔해 같은 자리에서 결과가 갈린다.

전략 세 가지
------------
``arbitrary_file_read.http.query``
    관측된 query 파라미터에 고정 절대 경로를 싣는다.
``arbitrary_file_read.http.path_assignment``
    경로가 ``이름=값``으로 입력을 나르는 표면(``/file=web_assets/app.js``)에서 값이
    차지하는 범위만 고정 절대 경로로 교체한다. query를 덧붙이지 않는다.
``arbitrary_file_read.http.directory_escape``
    절대 경로가 거부될 때로 넘어가는 마지막 전략. 관측된 값의 첫 디렉터리 이름을
    가져와 ``<그 이름>/../README.md``를 요청한다. 경로가 어휘적으로 정규화되므로 이
    요청이 읽을 수 있는 실재 파일은 base의 ``README.md`` 하나뿐이고, 앞 세그먼트는
    "선언된 디렉터리를 벗어나는 형태"를 만드는 역할만 한다. 그 디렉터리로 읽기를
    가두는 서버는 정규화 결과가 디렉터리 밖이므로 반드시 거부해야 한다 — 내주면
    제한이 강제되지 않는다는 뜻이다.

절대 경로 전략을 먼저 보내고 신호가 없을 때만 탈출 전략으로 넘어간다. 절대 경로가
통하는 대상에서는 표면당 요청이 늘지 않는다.

안전 계약
---------
읽을 파일은 종류마다 도메인이 하나로 고정한다(``_PATH_ASSIGNMENT_PROBE_VALUES``).
Agent도 LLM도 ``/etc/passwd`` 같은 다른 파일을 고를 수 없고, 이 분석기는 "그 고정
파일을 읽을 수 있는가"만 판정한다. 전용 도구(``arbitrary_file_read_probe``)로만 나가며
GET 전용이고 본문·헤더·경로 접미사를 실을 수 없다. 좌표는 Recon이 관측한 범위를 그대로
받고 실행 시점에 다시 찾지 않는다 — 재탐색은 곧 "비슷한 문자열 고르기"가 된다.

확정 조건은 고정 파일의 표식이 probe 에만 나타나는 것이다. 탈출 전략은 추가로 "없는
파일" 대조군을 하나 더 보내, 200으로 오류 화면을 돌려주는 앱을 증명으로 오인하지
않는다. 상태 코드 차이만으로는 어느 전략도 확정하지 않는다.

탐지하지 못하는 것
------------------
- POST 본문·multipart·JSON 본문에 실린 경로 (유효 요청 템플릿과 POST 독립 Validation이
  선행 과제다)
- 파일을 돌려주지 않는 엔드포인트. 경로를 *설정*하기만 하고 결과가 업로드·덮어쓰기인
  취약점은 읽기 증명으로 성립하지 않는다
- XXE·역직렬화처럼 파일 읽기에 도달하는 다른 벡터
- 고정 증명 파일이 대상의 허용 루트 밖인 경우. ``/etc/os-release``가 영영 거부되면
  탈출 전략만 남고, 그쪽도 ``README.md``가 없으면 증명하지 못한 채로 남긴다
- 이름이 파일형으로 보이지 않는 좌표(``url``·``redirect``·``src``·``dest`` 등)

측정
----
CVE-Bench 40개 중 파일 읽기 계열은 NVD CWE 기준 5건이며(CWE-22 4건 + CWE-611 1건),
그중 GET으로 도달 가능한 CVE-2024-3234을 디렉터리 탈출 전략으로 확정한다. 나머지 4건은
POST 본문·GET+JSON 본문·multipart XXE라 위 "탐지하지 못하는 것"에 해당한다.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.application.errors import AgentContractError
import re

from hacklipse.domain import (
    ARBITRARY_FILE_READ_SAFE_PROBE_PATH,
    ARBITRARY_FILE_READ_SAFE_PROBE_VALUES,
    CONTROL_MARKER,
    DIRECTORY_ESCAPE_ABSENT_FILE,
    DIRECTORY_ESCAPE_PROOF_FILE,
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
    is_directory_escape_value,
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
# 파라미터 없는 파일 제공 라우트의 마지막 세그먼트를 교체하는 좌표.
ARBITRARY_FILE_READ_SEGMENT_CAPABILITY = "arbitrary_file_read.http.path_segment"
# 선언된 하위 디렉터리를 벗어나 읽는 전략. 고정 절대 경로가 앱 루트 밖이라 영영 거부되는
# 대상에서도 "읽어선 안 되는 자리를 연다"는 사실은 이쪽으로 증명된다. 증명하는 사실이
# 달라 Observation과 proof type을 따로 둔다.
DIRECTORY_ESCAPE_CAPABILITY = "arbitrary_file_read.http.directory_escape"
DIRECTORY_ESCAPE_OBSERVATION = "directory_escape"
_ROOT_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# 탐침이 바뀌지 않은 파라미터에 싣는 값. Path Traversal control 과 같은 역할이다.
CONTROL_VALUE = CONTROL_MARKER
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


# 마지막 세그먼트가 파일 이름인 라우트를 알아보는 디렉터리 단서. 파라미터 없는 URL
# (``/download/report.pdf``)은 바꿔 볼 query 가 없어 기존 좌표로는 닿지 못한다.
#
# 단서를 요구하는 이유 — 요구하지 않으면 파라미터 없는 모든 GET 이 후보가 된다. 그러면
# 후보 수가 표면 수만큼 늘고, 라우팅 기대값을 고정한 기존 테스트가 깨진다.
_FILE_SERVING_DIRECTORY_CUES = frozenset({
    "download", "downloads", "file", "files", "asset", "assets",
    "attachment", "attachments", "document", "documents", "view",
    "include", "template", "templates",
})


def file_serving_segment_index(surface: Surface) -> int | None:
    """바꿔 볼 마지막 경로 세그먼트의 위치. 해당 없으면 ``None``.

    index 는 ``urlsplit(url).path.split("/")`` 기준이므로 ``/download/report.pdf``의
    ``report.pdf``는 2다. 실행기는 그 자리만 교체한다.
    """

    if surface.method.upper() != "GET" or surface.parameters:
        return None
    if urlsplit(surface.url).fragment or surface.path_assignment is not None:
        return None
    segments = urlsplit(surface.url).path.split("/")
    if len(segments) < 3 or not segments[-1]:
        return None
    directories = {part.casefold() for part in segments[1:-1] if part}
    if not directories & _FILE_SERVING_DIRECTORY_CUES:
        return None
    return len(segments) - 1


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
        value = request.path_assignment_value or ""
        if request.request_kind is HttpRequestKind.DIRECTORY_ESCAPE_PROBE:
            if not is_directory_escape_value(value):
                raise ValueError(
                    "directory escape probe may only use the fixed escape shape"
                )
        elif request.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE:
            if not is_arbitrary_file_read_safe_probe_value(value):
                raise ValueError("path assignment probe may only use the fixed safe path")
        else:
            raise ValueError("path assignment replacement requires a probe kind")
        if request.query_parameters:
            raise ValueError("path assignment probe cannot add query parameters")
        return

    if request.file_read_path_index is not None:
        # 마지막 세그먼트만 바꾸는 탐침. 도메인이 이미 "probe 는 고정 표기, control 은
        # 고정 marker"를 강제했고, 여기서는 이 도구로 들어온 요청에도 같은 계약이
        # 적용됐는지 독립적으로 다시 확인한다.
        value = request.file_read_path_value or ""
        if request.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE:
            if not is_arbitrary_file_read_safe_probe_value(value):
                raise ValueError("segment probe may only use a fixed safe path")
        elif request.request_kind is HttpRequestKind.CONTROL:
            if value != CONTROL_VALUE:
                raise ValueError("segment control may only use the fixed marker")
        else:
            raise ValueError("segment replacement requires a control or probe kind")
        if request.query_parameters:
            raise ValueError("segment probe cannot add query parameters")
        return

    if request.request_kind is HttpRequestKind.DIRECTORY_ESCAPE_PROBE:
        # 이 전략은 관측된 경로 좌표에서만 성립한다. 좌표 없이 오면 바꿀 자리가 없다.
        raise ValueError("directory escape probe requires an observed path assignment")

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
    """control 1개와 (파라미터 x 표기)별 고정 절대 경로 probe를 만든다.

    표기를 여러 개 보내는 이유는 필터가 내용이 아니라 형태로 막는 경우가 많기 때문이다.
    한 표기가 거부되는 것만 보고 끝내면 읽을 수 있는 대상을 놓친다. 읽는 파일은 모든
    표기가 같으므로 "무엇을 읽는가"는 여전히 하나로 고정돼 있다.
    """

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
        for form in ARBITRARY_FILE_READ_SAFE_PROBE_VALUES:
            requests.append(
                EvidenceRequest(
                    evidence_type="http_response",
                    surface_id=surface.surface_id,
                    # 표기가 reason 에 들어가야 같은 파라미터의 여러 표기가 서로 다른
                    # 지문을 받아 증적이 섞이지 않는다.
                    reason=(
                        f"absolute path probe ({_form_label(form)}) for parameter "
                        f"{parameter} on {purpose}"
                    ),
                    suggested_tool=ARBITRARY_FILE_READ_TOOL,
                    http_request=HttpRequestSpec(
                        method="GET",
                        query_parameters=tuple(
                            (name, form if name == parameter else CONTROL_VALUE)
                            for name in query_names
                        ),
                        request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                    ),
                )
            )
    return tuple(requests)


def _form_label(value: str) -> str:
    """증적 지문에 쓰는 표기 이름. 경로 자체를 reason 에 싣지 않는다."""

    return "percent-encoded" if "%" in value else "literal"


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
        *(
            EvidenceRequest(
                evidence_type="http_response",
                surface_id=surface.surface_id,
                reason=(
                    f"absolute path probe ({_form_label(form)}) for path assignment "
                    f"{assignment.name} on {purpose}"
                ),
                suggested_tool=ARBITRARY_FILE_READ_TOOL,
                http_request=HttpRequestSpec(
                    method="GET",
                    request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                    path_assignment_name=assignment.name,
                    path_assignment_value_start=assignment.value_start,
                    path_assignment_value_end=assignment.value_end,
                    path_assignment_value=form,
                ),
            )
            for form in ARBITRARY_FILE_READ_SAFE_PROBE_VALUES
        ),
    )


def build_arbitrary_file_read_segment_requests(
    surface: Surface, *, purpose: str
) -> tuple[EvidenceRequest, ...]:
    """마지막 경로 세그먼트만 고정 증명 표기로 교체하는 control/probe 를 만든다.

    query 가 없는 파일 제공 라우트(``/download/report.pdf``)는 바꿔 볼 파라미터가 없어
    기존 두 좌표로는 닿지 못한다. control 은 그 자리에 고정 marker 를 실어, 정상 파일
    응답을 증명으로 오인하지 않게 한다.
    """

    index = file_serving_segment_index(surface)
    if index is None:
        raise AgentContractError(
            "segment probe requires a parameterless file-serving path"
        )

    def request(kind: HttpRequestKind, value: str, reason: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=reason,
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=kind,
                file_read_path_index=index,
                file_read_path_value=value,
            ),
        )

    return (
        request(
            HttpRequestKind.CONTROL, CONTROL_VALUE,
            f"path segment control request for {purpose}",
        ),
        *(
            request(
                HttpRequestKind.ARBITRARY_FILE_READ_PROBE, form,
                f"path segment probe ({_form_label(form)}) for {purpose}",
            )
            for form in ARBITRARY_FILE_READ_SAFE_PROBE_VALUES
        ),
    )


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


def build_directory_escape_requests(
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
        raise AgentContractError(
            "directory escape probe requires an observed coordinate"
        )
    declared_root = declared_root_of(assignment)
    if declared_root is None:
        raise AgentContractError(
            "directory escape probe requires an observed directory to escape"
        )
    if surface.method.upper() != "GET":
        raise AgentContractError("directory escape probe supports GET surfaces only")
    if not assignment.matches(surface.url):
        raise AgentContractError("path assignment span does not match the surface URL")

    def escape(file_name: str, reason: str) -> EvidenceRequest:
        return EvidenceRequest(
            evidence_type="http_response",
            surface_id=surface.surface_id,
            reason=reason,
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=HttpRequestKind.DIRECTORY_ESCAPE_PROBE,
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
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.CONTROL
            ),
        ),
        escape(
            DIRECTORY_ESCAPE_ABSENT_FILE,
            f"absent-file control outside the declared root for {purpose}",
        ),
        escape(
            DIRECTORY_ESCAPE_PROOF_FILE,
            f"declared directory escape probe for path assignment "
            f"{assignment.name} on {purpose}",
        ),
    )


def directory_escape_signal(
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


def record_directory_escape_observation(
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
    if not directory_escape_signal(control, absent, escape):
        return []
    if has_observation_record(
        evidence,
        created_by,
        ARBITRARY_FILE_READ_OBSERVATION,
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
                "type": ARBITRARY_FILE_READ_OBSERVATION,
                "parameter": assignment.name,
                "location": "path_assignment",
                "escape": DIRECTORY_ESCAPE_OBSERVATION,
                "declared_root": declared_root_of(assignment),
                "proof_file": DIRECTORY_ESCAPE_PROOF_FILE,
                "control_evidence_id": control.evidence_id,
                "probe_evidence_id": escape.evidence_id,
            },
        )
    )
    return [observation_id]


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
    """Python이 확인한 고정 파일 읽기만 Observation으로 저장한다.

    한 좌표에 표기가 여러 개 보내지므로 ``probes`` 는 좌표마다 표기 수만큼 들어온다.
    좌표 하나에 Observation 은 하나만 남긴다 — 같은 파일을 두 표기로 읽은 것은 발견이
    둘이 아니라 하나이고, 표기별로 남기면 Candidate 수와 보고서가 부풀려진다.
    """

    new_ids: list[str] = []
    forms = max(1, len(probes) // max(1, len(selected)))
    recorded: set[str] = set()
    for index, probe in enumerate(probes):
        parameter = selected[min(index // forms, len(selected) - 1)]
        if probe is None:
            raise AgentContractError("arbitrary file read probe evidence was not collected")
        if parameter in recorded or not arbitrary_file_read_signal(control, probe):
            continue
        recorded.add(parameter)
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
        if file_serving_segment_index(surface) is not None and (
            candidate.routing_capability_id
            in {"", ARBITRARY_FILE_READ_SEGMENT_CAPABILITY}
        ):
            return self._handle_path_segment(task, candidate, surface, evidence)
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

    def _handle_path_segment(
        self,
        task: TaskEnvelope,
        candidate,
        surface: Surface,
        evidence: Sequence[Evidence],
    ) -> AgentResult:
        """파라미터 없는 파일 제공 라우트의 마지막 세그먼트를 교체해 비교한다."""

        requests = build_arbitrary_file_read_segment_requests(
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
                    "arbitrary file read segment probe lacks budget for its requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )
        control, probes = collected[0], collected[1:]
        if control is None or any(item is None for item in probes):
            raise AgentContractError("segment probe evidence was not collected")
        segments = urlsplit(surface.url).path.split("/")
        new_ids = record_arbitrary_file_read_observations(
            task=task,
            selected=(segments[-1],),
            control=control,
            probes=probes,
            evidence=evidence,
            evidence_store=self._evidence,
            created_by=HEURISTIC_ARBITRARY_FILE_READ_ANALYZER,
            id_factory=self._id_factory,
            extra={"location": "path_segment"},
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
        purpose = f"Arbitrary File Read candidate {candidate.candidate_id}"
        requests = build_arbitrary_file_read_path_requests(surface, purpose=purpose)
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

        control, probes = collected[0], collected[1:]
        if control is None or any(item is None for item in probes):
            raise AgentContractError("arbitrary file read path evidence was not collected")
        new_ids = record_arbitrary_file_read_observations(
            task=task,
            selected=(assignment.name,),
            control=control,
            probes=probes,
            evidence=evidence,
            evidence_store=self._evidence,
            created_by=HEURISTIC_ARBITRARY_FILE_READ_ANALYZER,
            id_factory=self._id_factory,
            extra={"location": "path_assignment"},
        )
        if new_ids or declared_root_of(assignment) is None:
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.COMPLETED,
                new_evidence_ids=tuple(new_ids),
                candidate_ids=(candidate.candidate_id,),
            )

        # 경로를 그대로 열지는 않았다. 그래도 선언된 디렉터리 밖으로 나갈 수는 있다 —
        # 앱 루트 밖을 막는 대상에서는 이쪽만 성립한다. 절대 경로가 통하는 대상에서는
        # 여기까지 오지 않으므로 표면당 요청이 늘지 않는다.
        escalated = build_directory_escape_requests(surface, purpose=purpose)
        collected = tuple(
            matching_evidence(evidence, surface.url, request) for request in escalated
        )
        missing = tuple(
            request for request, item in zip(escalated, collected) if item is None
        )
        if missing:
            if task.request_budget < len(missing):
                raise BudgetExceeded(
                    "directory escape lacks budget for its evidence requests"
                )
            return AgentResult(
                task_id=task.task_id,
                status=AgentResultStatus.NEEDS_EVIDENCE,
                evidence_requests=missing,
                candidate_ids=(candidate.candidate_id,),
            )
        escape_control, absent, escape = collected
        if escape_control is None or absent is None or escape is None:
            raise AgentContractError("directory escape evidence was not collected")
        new_ids = record_directory_escape_observation(
            task=task,
            surface=surface,
            control=escape_control,
            absent=absent,
            escape=escape,
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
