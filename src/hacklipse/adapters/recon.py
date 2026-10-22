"""HTML과 JS 번들에서 공격 표면을 찾는 결정적 Recon Agent.

세 경로로 표면을 모은다.

    ① 서버 렌더링 HTML   폼·링크 파싱 (전통 웹앱)
    ② 다단계 크롤링      발견한 링크를 다시 요청 (인증 후 보호 페이지 도달)
    ③ JS 번들 정적 분석  SPA는 초기 HTML이 비어 있고 엔드포인트가 번들에 문자열로 남는다

③이 필요한 이유 — Angular/React 앱의 최초 HTML에는 링크도 폼도 없다. 그러나 런타임에
URL을 만들어야 하므로 경로가 소스에 리터럴로 박힌다. 브라우저 없이 정규식으로 뽑을 수
있고, 처음 보는 앱에서도 동작한다(학습 데이터 암기가 아니라 실제 관측이다).

브라우저를 띄우지 않으므로 동적으로 조립되는 URL과 코드 스플리팅된 청크는 놓친다.
그건 헤드리스 Runtime의 몫으로 남긴다.

크롤링과 폼 추출은 결정적이다. 선택한 모드에서만 LLM이 다음 방문 순서를 제안하며,
실행과 시간·요청 한도는 이 Agent가 통제한다.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    EvidenceRequest,
    PathAssignment,
    Surface,
    TaskEnvelope,
)
from hacklipse.domain.url_redaction import ssrf_destination_reference_parts
from hacklipse.ports import EvidenceStore, SurfaceStore
from hacklipse.ports import IterativeReconPlanner, ReconAction, ReconObservation
from hacklipse.ports.errors import ApprovalRequired, BudgetExceeded, PolicyViolation

from .llm_iterative_recon import (
    AGENTIC_RECON_PLANNER,
    build_recon_action_observation,
    find_stored_recon_action,
    recon_action_status_detail,
)
from .hidden_parameter_planner import safe_hidden_name
from .request_safety import has_state_changing_get
from .llm_parameter_names import alias_parameter_names
from .browser_recon import PlaywrightRecon
from .discovery_links import json_links_from_observation
from .graphql_discovery import (
    GRAPHQL_READ_QUERY_PLAN, GRAPHQL_SCHEMA_OPERATION, INTROSPECTION_QUERY,
    graphql_schema_operations, graphql_schema_query_inputs,
)
from .graphql_introspection import INTROSPECTION_RECON_OBSERVATION
from .graphql_suggestions import SUGGESTION_PLAN, suggestion_plan
from .llm_recon_planner import (
    RECON_PLANNER,
    ReconCandidate,
    ReconPlan,
    ReconPlanner,
    build_recon_plan_observation,
    find_stored_recon_plan,
    recon_plan_status_detail,
)
from .arbitrary_file_read import looks_like_file_parameter
from .path_traversal_analysis import (
    FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION,
    PATH_ASSIGNMENT_OBSERVATION,
    PATH_ASSIGNMENT_SKIPPED_OBSERVATION,
    PATH_ASSIGNMENT_SOURCE,
    RESTRICTED_FILE_OBSERVATION,
    UNLINKED_RENDER_PARAMETER_OBSERVATION,
)
from .sensitive_exposure import (
    EXPOSURE_OBSERVATION, CONFIG_ROUTE_OBSERVATION, TRUSTED_LOGIN_PAIR_COUNT,
    credential_config_route_candidate, exposed_json_field_paths,
)
from .public_login_credentials import PUBLIC_LOGIN_OBSERVATION
from .postmessage_plan import POSTMESSAGE_PLAN, postmessage_html_plans
from .source_map_exposure import SOURCE_MAP_REFERENCE, source_map_urls
from .error_disclosure import (
    ERROR_ROUTE_OBSERVATION, ERROR_GRAPHQL_OBSERVATION, error_route_candidate,
)
from .request_safety import has_state_changing_get
from .file_upload_analysis import UPLOAD_FORM, upload_form_plans
from .security import redacted_internal_url_path
from .ssrf_analysis import (
    SSRF_EDITOR_CATCHER_STRUCTURE,
    SSRF_DESTINATION_HINT_TYPE,
    SSRF_JSON_PARAMETER_HINTS,
    SSRF_URL_FETCH_REVIEW_TYPE,
    ssrf_parameter_sources,
)

# HttpExecutionRuntime이 GET 실행에 사용하는 도구 이름과 맞춘다(tests/test_http_runtime.py).
RECON_TOOL = "http_get"

DEFAULT_MAX_PAGES = 10
DEFAULT_MAX_SCRIPTS = 8
_RECON_DEADLINE_RESERVE_SECONDS = 5.0
_MAX_AGENTIC_LLM_CALLS = 3
_MAX_AGENTIC_LLM_CALL_SECONDS = 15.0

# 남은 예산의 이 비율까지만 정찰에 쓴다. 정찰이 예산을 다 먹으면 뒤의 Analysis가
# 아무것도 못 한다 — 찾기만 하고 확인은 못 하는 상태가 된다.
_RECON_BUDGET_SHARE = 0.5
_SPARSE_OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json")
_MAX_SSRF_DESTINATION_HINTS = 32
_MAX_SSRF_HINT_SOURCE_BYTES = 1_048_576
_ABSOLUTE_HTTP_URL = re.compile(
    r"(?i)https?://(?:[a-z0-9._~!$&()*+,;=:%-]{1,128}@)?"
    r"(?:\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]{0,252})"
    r"(?::[0-9]{1,5})?(?:/[a-z0-9._~!$&'()*+,;=:@%/?#-]{0,512})?"
)
@dataclass(frozen=True, slots=True)
class SsrfDestinationHint:
    destination_origin: str
    path_hint: str
    destination_fingerprint: str


@dataclass(frozen=True, slots=True)
class _SsrfDestinationCandidate:
    raw_url: str
    destination_origin: str
    path_hint: str
    host_kind: str
    fingerprint_material: bytes

# JS 리터럴에서 절대 경로를 뽑는다. 템플릿 리터럴의 `${host}/path` 형태도 받는다.
_JS_PATH = re.compile(
    r"""["'`](?:\$\{[^}]{0,60}\})?(/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100}?)(?=["'`?])"""
)
# `/path?param=`에서 파라미터 이름까지 얻는다. 앞에 `/`가 오면 `//host/path` 즉 외부
# URL의 일부이므로 제외한다 — 이 필터가 없으면 소셜 공유 링크가 전부 섞여 들어온다.
_JS_PATH_PARAM = re.compile(
    r"""(?<![/A-Za-z0-9._~-])(/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100})\?([A-Za-z0-9_]{1,40})="""
)
# `url: 'api/items.php?userId=3'` 처럼 **상대** 경로로 쓰인 라우트. 흔한 모양이지만
# 리터럴이 전부 라우트는 아니므로 `?name=` 를 요구한다 — 질의가 붙은 리터럴은 요청
# URL이라는 뜻이고, 그 질의 이름이 바로 찾고 있는 입력 좌표다. 상대 경로는 문서
# URL 기준으로만 해석하며, 기준이 없으면 쓰지 않는다.
_JS_RELATIVE_PATH_PARAM = re.compile(
    r"""["'`](?:\./)?([A-Za-z0-9][A-Za-z0-9._~/-]{0,100})\?([A-Za-z0-9_]{1,40})="""
)
# Bundlers often build a path from adjacent constant fragments, for example
# "/api/" + "items?term=". Only literal-to-literal addition is interpreted;
# variable values and template interpolation are never evaluated.
_JS_STRING_LITERAL = re.compile(r"""(["'`])([^"'`\\\r\n]{1,80})\1""")
_JS_LITERAL_JOIN = re.compile(r"\s*\+\s*\Z")
_JS_PATH_FRAGMENT = re.compile(r"[A-Za-z0-9._~/?=&-]{1,80}\Z")
_JS_PARAMETER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,39}\Z")
_JS_FETCH_MUTATION = re.compile(
    r"\b(?:fetch|fetchApi)\s*\(\s*(?P<quote>[\"'`])(?P<path>/[A-Za-z0-9][A-Za-z0-9._~/?=&-]{0,160})"
    r"(?P=quote)\s*,\s*\{[^{}]{0,240}?\bmethod\s*:\s*[\"'`]"
    r"(?P<method>POST|PUT|PATCH|DELETE)[\"'`]",
    re.I,
)
_JS_FETCH_JSON = re.compile(
    r"\bfetch\s*\(\s*([\"'`])(?P<path>/[A-Za-z0-9][A-Za-z0-9._~/?=&-]{0,160})\1"
    r"\s*,\s*\{(?P<options>[^;]{0,1024})",
    re.I,
)
_JS_JSON_GET = re.compile(
    r"\b(?:fetch|fetchApi)\s*\(\s*([\"'`])"
    r"(?P<path>/[A-Za-z0-9][A-Za-z0-9._~/?=&-]{0,160})\1"
    r"[^;\r\n]{0,180}?\)\s*\)\s*\.json\s*\(",
    re.I,
)
_JS_SINGLE_JSON_FIELD = re.compile(
    r"\bJSON\.stringify\s*\(\s*\{\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]{0,63})\s*:\s*[^,{}]{1,160}"
    r"\}\s*\)", re.I,
)
_JS_AXIOS_MUTATION = re.compile(
    r"\baxios\s*\.\s*(?P<method>post|put|patch|delete)\s*\(\s*"
    r"(?P<quote>[\"'`])(?P<path>/[A-Za-z0-9][A-Za-z0-9._~/?=&-]{0,160})(?P=quote)",
    re.I,
)
# SPA가 서버 렌더링 문서로 빠져나갈 때 쓰는 navigation sink. 단순 경로 리터럴과
# 달리 실제 HTML 문서일 가능성이 높으므로, 번들에서 발견한 뒤 예산 안에서 방문한다.
# 특정 제품의 경로 이름이 아니라 브라우저 API와 상대경로의 결합만 본다.
_JS_DOCUMENT_NAVIGATION = re.compile(
    r"""(?:window\.)?location\.(?:assign|replace)\([^)]{0,160}?["'`](/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100})["'`]"""
)

# Browser JavaScript often contains the only complete description of an AJAX
# request.  Keep these patterns deliberately structural: they recognize common
# request APIs and object literals without depending on product or route names.
_JS_GLOBAL_OBJECT = re.compile(
    r"(?:\bvar\s+|\blet\s+|\bconst\s+|\bwindow\.)"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]{0,80})\s*=\s*"
    r"(?P<object>\{.{0,8192}?\})\s*;",
    re.DOTALL,
)
_JS_AJAX_BLOCK = re.compile(
    r"(?:jQuery|\$)\.ajax\s*\(\s*\{(?P<body>.{0,4096}?)\}\s*\)",
    re.DOTALL,
)
_JS_OBJECT_ENTRY = re.compile(
    r"[\"']?(?P<name>[A-Za-z_$][A-Za-z0-9_$\[\]-]{0,80})[\"']?\s*:"
    r"\s*(?P<value>[\"'][^\"']{0,1024}[\"']|\[[^\]]{0,1024}\]|"
    r"[A-Za-z_$][A-Za-z0-9_$.()]{0,160}|-?\d+(?:\.\d+)?)",
    re.DOTALL,
)
_JS_URL_VALUE = re.compile(
    r"\burl\s*:\s*(?P<value>[\"'][^\"']{1,2048}[\"']|"
    r"[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*)"
)
_JS_METHOD_VALUE = re.compile(r"\b(?:method|type)\s*:\s*[\"'](?P<method>GET|POST)[\"']", re.I)
_JS_DATA_VALUE = re.compile(
    r"\bdata\s*:\s*(?:eval\s*\(\s*)?(?P<value>\{.{0,2048}?\}|"
    r"[A-Za-z_$][A-Za-z0-9_$]*)(?:\s*\))?\s*(?:,|$)",
    re.DOTALL,
)

# 결정적 Recon 단계에서 실제 요청 없이도 판단할 수 있는 유일한 신호: 파라미터 "이름"이
# 파일·경로·URL을 가리키는 것처럼 보이는가. Router.DEFAULT_RULES의 "url_or_file_parameter"
# 규칙과 맞아야 ROUTE 단계가 Candidate를 만들 수 있다.
# 값이 파일로 보이는지 판정할 때 쓰는 종류 목록. 파라미터 이름과 달리 이것은 파일
# 형식에 대한 것이어서 대상이 바뀌어도 유효하다.
_FILE_VALUE_EXTENSIONS = frozenset(
    {
        "php", "phtml", "html", "htm", "asp", "aspx", "jsp", "cgi", "pl",
        "js", "css", "txt", "md", "json", "xml", "yml", "yaml", "csv",
        "log", "ini", "conf", "cfg", "env", "bak", "tpl", "twig",
        "pdf", "png", "jpg", "jpeg", "gif", "svg", "zip", "tar", "gz",
    }
)
_FILE_OR_URL_PARAM_HINTS = (
    "file",
    "page",
    "path",
    "template",
    "doc",
    "include",
    "folder",
    "dir",
    "load",
    "view",
    "download",
    "src",
    "url",
    "redirect",
    "dest",
    "target",
)

# 템플릿 보간에서 끊기는 경로는 디렉터리까지만 남긴다. `${host}/ftp/order_${id}.pdf`
# 같은 리터럴은 파일명을 알 수 없지만 그 디렉터리는 실재하는 표면이다.
_JS_DIRECTORY = re.compile(
    r"""["'`](?:\$\{[^}]{0,60}\})?(/[A-Za-z0-9][A-Za-z0-9._~/-]{0,100}/)[A-Za-z0-9._~-]{0,40}\$\{"""
)
_JS_BARE_NUMERIC_PATH = re.compile(r"/\d+")
# SPA 클라이언트 라우트와 그 query 파라미터. 라우트 이동과 파라미터 선언이 서로
# 앞뒤 어느 쪽에도 올 수 있어 좁은 창 안에서 함께 나타나는 짝만 취한다.
# 따옴표 종류는 큰따옴표로 고정하지 않는다 — Angular 컴파일러 버전에 따라 배열 리터럴을
# 백틱으로 내보내기도 한다(`navigate([`/search`],i)`). 다른 JS 정규식들과 같은
# ["'`] 문자 클래스를 쓴다.
_JS_ROUTE_NAVIGATE = re.compile(r"""navigate\(\[["'`]/([A-Za-z0-9._~-]{1,40})["'`]\]""")
_JS_ROUTE_QUERY_PARAM = re.compile(r"""queryParams:\{([A-Za-z_][A-Za-z0-9_]{0,30}):""")
_ROUTE_BINDING_WINDOW = 200

# 웹 서버가 그대로 내주면 안 되는 확장자. 이런 파일이 표면으로 노출되어 있으면
# 서버가 직접 거부하는지, 우회 경로로는 제공되는지 확인할 가치가 있다.
_RESTRICTED_FILE_EXTENSIONS = (
    ".bak",
    ".conf",
    ".config",
    ".db",
    ".env",
    ".gg",
    ".ini",
    ".kdbx",
    ".key",
    ".log",
    ".pem",
    ".pyc",
    ".sql",
    ".yaml",
    ".yml",
)

# HTML 폼에 노출되지 않아도 서버 템플릿 엔진이 공통적으로 해석하는 렌더 옵션.
# Recon은 이를 관측값으로 가장하지 않고 ``source``가 붙은 추론 Evidence로 남긴다.
# 능동 POST는 Analysis의 승인·고정 safe-file 경계 뒤에서만 일어난다.
_UNLINKED_RENDER_PARAMETERS = ("layout",)

# 링크도 폼도 선언하지 않는 GET 쿼리 좌표의 후보 이름. 추측을 Surface로 바꾸지 않고,
# 마커를 실어 보낸 응답이 무파라미터 기준선과 달라졌을 때만 기록한다. 그래야 "이름을
# 찍어봤다"가 아니라 "그 좌표가 응답을 바꾼다"는 관측이 된다.
# 길이를 짧게 유지하는 이유는 비용이다. 한 이름이 요청 하나이고, 문서 페이지마다
# 반복되므로 전체 예산을 정찰이 다 먹으면 분석 단계가 굶는다.
_INFERRED_QUERY_PARAMETERS = (
    "name",
    "username",
    "q",
    "search",
    "message",
    "template",
    "page",
    "view",
)
_INFERENCE_MARKER = "hacklipse-probe-7193"
# 추론에 쓸 문서 페이지 수와 페이지당 이름 수의 상한.
_MAX_INFERENCE_PAGES = 2
_MAX_INFERENCE_NAMES = 8

_MAX_SCRIPT_BYTES = 4 * 1024 * 1024
_MAX_INLINE_SCRIPT_BYTES = 256 * 1024
_MAX_INLINE_SCRIPT_PATHS = 100
_MAX_API_SCHEMA_BYTES = 2 * 1024 * 1024
_MAX_SCHEMA_GET_SAMPLES = 4
_API_PATH = re.compile(r"/[A-Za-z0-9._~/-]{0,180}\Z")
_API_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,79}\Z")
_API_ITEM_PATH = re.compile(
    r"(?P<collection>/[A-Za-z0-9._~/-]{1,160})/\{(?P<identifier>[A-Za-z_][A-Za-z0-9_]{0,39})\}\Z"
)
# 한 round에서 모델이 비교할 좌표를 제한한다. 선택된 좌표는 다음 round의 창으로
# 이동하므로 이 값 밖의 Surface가 영구히 사라지는 것은 아니다. 응답 전체를 매번 다시
# 보내지 않고 현재 선택지와 직전 실행 문맥만 전달해 반복 prompt 비용을 제한한다.
_MAX_AGENTIC_SELECTABLE = 32
_MAX_AGENTIC_CONTEXT = 2
_MAX_AGENTIC_OBSERVATIONS = _MAX_AGENTIC_SELECTABLE + _MAX_AGENTIC_CONTEXT
_PATH_OBJECT_ID = re.compile(r"^[0-9]{1,10}$")
# 경로에 실린 입력 이름으로 인정할 형태. 도메인의 PathAssignment 불변식과 같은 모양을
# 쓴다 — 여기서 먼저 거르는 것은 거부당할 좌표로 Evidence를 만들지 않기 위해서다.
_PATH_ASSIGNMENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
_PATH_RESOURCE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
# 숫자 세그먼트를 뒤에 달지만 객체 컬렉션이 아닌 좌표. 형제가 여럿이어도 식별자로
# 보지 않는다 — 페이지네이션과 API 버전이 바로 이 모양이다.
_NON_OBJECT_PATH_RESOURCES = frozenset(
    {
        "api", "page", "pages", "p", "offset", "limit", "size", "per_page",
        "step", "part", "index", "v", "version", "ver", "rev",
        "year", "month", "day", "week", "hour", "minute",
    }
)
_SINGULAR_OBJECT_RESOURCES = frozenset(
    {
        "account",
        "address",
        "basket",
        "cart",
        "invoice",
        "order",
        "profile",
        "record",
        "user",
    }
)


def _looks_like_file_or_url_parameter(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _FILE_OR_URL_PARAM_HINTS)


def _looks_like_file_serving_parameter(url: str, name: str) -> bool:
    """Use a file-serving route to disambiguate generic filename fields."""

    if name.casefold() not in {"name", "filename"}:
        return False
    path_tokens = set(re.split(r"[/_-]+", urlsplit(url).path.casefold()))
    return bool(path_tokens.intersection({
        "attachment", "attachments", "download", "export", "file", "files", "media",
    }))


def _constant_js_paths(body: str) -> dict[str, tuple[str, ...]]:
    """Find bounded HTTP paths made solely from adjacent JS string literals."""

    literals = tuple(_JS_STRING_LITERAL.finditer(body))
    found: dict[str, set[str]] = {}
    for index, first in enumerate(literals):
        value = first.group(2)
        if not value.startswith("/") or value.startswith("//"):
            continue
        fragments = [value]
        previous = first
        for next_literal in literals[index + 1:index + 4]:
            gap = body[previous.end():next_literal.start()]
            fragment = next_literal.group(2)
            if _JS_LITERAL_JOIN.fullmatch(gap) is None or _JS_PATH_FRAGMENT.fullmatch(fragment) is None:
                break
            fragments.append(fragment)
            previous = next_literal
        if len(fragments) < 2:
            continue
        assembled = "".join(fragments)
        path, _, query = assembled.partition("?")
        if (
            len(path) > 120 or not path.startswith("/") or path.startswith("//")
            or ".." in path.split("/") or not _JS_PATH_FRAGMENT.fullmatch(path)
            or path.endswith("/")
        ):
            continue
        names = found.setdefault(path, set())
        for pair in query.split("&"):
            name, separator, _ = pair.partition("=")
            if separator and _JS_PARAMETER_NAME.fullmatch(name):
                names.add(name)
    return {path: tuple(sorted(names)) for path, names in found.items()}


def _literal_js_query_paths(body: str) -> dict[str, tuple[str, ...]]:
    """Collect all query field names from bounded same-origin path literals."""

    found: dict[str, set[str]] = {}
    for literal in _JS_STRING_LITERAL.finditer(body):
        value = literal.group(2)
        path, separator, query = value.partition("?")
        if (
            not separator or not path.startswith("/") or path.startswith("//")
            or len(path) > 100 or _API_PATH.fullmatch(path) is None
            or ".." in path.split("/")
        ):
            continue
        for item in query.split("&"):
            name, equals, _ = item.partition("=")
            if equals and _JS_PARAMETER_NAME.fullmatch(name):
                found.setdefault(path, set()).add(name)
    return {path: tuple(sorted(names)) for path, names in found.items()}


def _javascript_response(evidence: Evidence) -> bool:
    """Accept browser-fetched scripts, never HTML or JSON with JS-looking data."""

    observation = evidence.observation
    source = observation.get("requested_url")
    media = observation.get("content_type")
    if not isinstance(source, str) or not isinstance(media, str):
        return False
    media_type = media.split(";", 1)[0].strip().casefold()
    return media_type in {"application/javascript", "text/javascript", "application/x-javascript"} or (
        not media_type and urlsplit(source).path.casefold().endswith((".js", ".mjs"))
    )


def _json_links_from_response(evidence: Evidence, base_url: str) -> tuple[str, ...]:
    """Keep the Evidence wrapper for Recon callers and older adapter tests."""

    return json_links_from_observation(evidence.observation, base_url)


def _script_paths_from_body(
    body: str, origin, base_url: str | None = None
) -> list[tuple[str, tuple[str, ...], bool, bool]]:
    """Derive same-origin route candidates from a bounded script body."""

    parameters: dict[str, set[str]] = {}
    for match in _JS_PATH_PARAM.finditer(body):
        parameters.setdefault(match.group(1), set()).add(match.group(2))
    if base_url:
        for match in _JS_RELATIVE_PATH_PARAM.finditer(body):
            try:
                resolved = urlsplit(urljoin(base_url, match.group(1)))
            except ValueError:
                continue
            if (
                resolved.netloc.casefold() == origin.netloc.casefold()
                and resolved.path.startswith("/")
                and ".." not in resolved.path.split("/")
            ):
                parameters.setdefault(resolved.path, set()).add(match.group(2))
    for path, names in _literal_js_query_paths(body).items():
        parameters.setdefault(path, set()).update(names)
    for path, names in _constant_js_paths(body).items():
        parameters.setdefault(path, set()).update(names)
    document_paths = {match.group(1) for match in _JS_DOCUMENT_NAVIGATION.finditer(body)}
    json_get_paths = {match.group("path") for match in _JS_JSON_GET.finditer(body)}
    paths = {match.group(1) for match in _JS_PATH.finditer(body)}
    paths.update(parameters)
    paths.update(match.group(1) for match in _JS_DIRECTORY.finditer(body))
    paths = {
        path for path in paths
        if not (
            _JS_BARE_NUMERIC_PATH.fullmatch(path)
            and path not in parameters and path not in document_paths
        )
    }
    base = f"{origin.scheme}://{origin.netloc}"
    # Under a fixed frontier cap, routes with controllable inputs are more
    # useful than static asset paths. Keep explicit document navigation first.
    ordered_paths = (
        *sorted(document_paths),
        *sorted(path for path in paths - document_paths if path in json_get_paths),
        *sorted(path for path in paths - document_paths - json_get_paths
                if parameters.get(path)),
        *sorted(path for path in paths - document_paths - json_get_paths
                if not parameters.get(path)),
    )
    found = [
        (f"{base}{path}", tuple(sorted(parameters.get(path, ()))),
         path in document_paths or path in json_get_paths or path.endswith("/")
         or path.endswith(("/api-docs", "/openapi.json", "/swagger.json")),
         path in document_paths)
        for path in ordered_paths
    ]
    found.extend(
        (f"{base}/#/{route}", names, False, False)
        for route, names in sorted(_client_routes(body).items())
    )
    return found


def _script_mutation_shapes(body: str, origin) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Record literal client mutation routes without reconstructing or sending bodies."""

    base = f"{origin.scheme}://{origin.netloc}"
    shapes: set[tuple[str, str, tuple[str, ...]]] = set()
    for pattern in (_JS_FETCH_MUTATION, _JS_AXIOS_MUTATION):
        for match in pattern.finditer(body[:_MAX_SCRIPT_BYTES]):
            raw = match.group("path")
            path, _, query = raw.partition("?")
            if ".." in path.split("/") or path.startswith("//"):
                continue
            names = tuple(sorted({
                name for pair in query.split("&")
                if (name := pair.partition("=")[0]) and _JS_PARAMETER_NAME.fullmatch(name)
            }))
            shapes.add((base + path, match.group("method").upper(), names))
            if len(shapes) >= 128:
                return tuple(sorted(shapes))
    return tuple(sorted(shapes))


def _script_ssrf_json_shapes(body: str, origin) -> tuple[tuple[str, str], ...]:
    """Read literal POST JSON URL-field shapes; never infer a request body value."""

    base = f"{origin.scheme}://{origin.netloc}"
    shapes: set[tuple[str, str]] = set()
    for match in _JS_FETCH_JSON.finditer(body[:_MAX_SCRIPT_BYTES]):
        options = match.group("options")
        if (
            re.search(r"\bmethod\s*:\s*['\"]POST['\"]", options, re.I) is None
            or re.search(r"['\"]Content-Type['\"]\s*:\s*['\"]application/json['\"]", options, re.I) is None
        ):
            continue
        field = _JS_SINGLE_JSON_FIELD.search(options)
        if field is None or field.group("name").casefold() not in SSRF_JSON_PARAMETER_HINTS:
            continue
        path = match.group("path").split("?", 1)[0]
        if path.startswith("//") or ".." in path.split("/"):
            continue
        shapes.add((base + path, field.group("name")))
        if len(shapes) >= 32:
            break
    return tuple(sorted(shapes))


def _openapi_document(evidence: Evidence) -> dict | None:
    """Parse a bounded, successful OpenAPI response without trusting its paths."""

    observation = evidence.observation
    status = observation.get("status")
    media = observation.get("content_type", "")
    body = observation.get("body")
    if (
        evidence.evidence_type != "http_response"
        or type(status) is not int or not 200 <= status < 300
        or observation.get("truncated")
        or not isinstance(media, str)
        or media.split(";", 1)[0].strip().casefold() not in {
            "application/json", "application/vnd.oai.openapi+json"
        }
        or not isinstance(body, str) or len(body) > _MAX_API_SCHEMA_BYTES
    ):
        return None
    try:
        document = json.loads(body)
    except ValueError:
        return None
    if not isinstance(document, dict) or not isinstance(
        document.get("openapi") or document.get("swagger"), str
    ):
        return None
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return None
    return document


def _ueditor_catcher_shape(evidence: Evidence) -> tuple[str, str] | None:
    """Accept only a successful UEditor config declaring a remote-image catcher."""

    observation = evidence.observation
    media = observation.get("content_type")
    body = observation.get("body")
    if (
        evidence.evidence_type != "http_response"
        or observation.get("status") != 200
        or observation.get("truncated")
        or not isinstance(media, str)
        or media.split(";", 1)[0].strip().casefold() != "application/json"
        or not isinstance(body, str) or len(body) > 64_000
    ):
        return None
    try:
        config = json.loads(body)
    except ValueError:
        return None
    if not isinstance(config, dict):
        return None
    action = config.get("catcherActionName")
    field = config.get("catcherFieldName")
    if (
        not isinstance(action, str) or not isinstance(field, str)
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", action) is None
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", field) is None
    ):
        return None
    return action, field + "[]"


def _internal_destination_kind(hostname: str) -> str | None:
    """Classify only explicit internal-looking hosts; never invent a host."""

    host = hostname.casefold().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return "localhost"
    if host.endswith((".internal", ".local", ".svc", ".cluster.local")):
        return "internal_dns"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # An explicit URL containing a single DNS label is a concrete service
        # address (for example a container-network name), not a guessed name.
        if "." not in host and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", host):
            return "single_label_dns"
        return None
    if address.is_loopback:
        return "loopback_ip"
    if address.is_link_local:
        return "link_local_ip"
    if address.is_private:
        return "private_ip"
    return None


def _ssrf_destination_candidates(
    body: str,
) -> tuple[_SsrfDestinationCandidate, ...]:
    """Extract bounded, explicit internal HTTP(S) destinations from public content.

    Raw path material stays in this private, in-memory result solely so the
    caller can compute a run-keyed fingerprint. It must never enter Evidence.
    """

    if not isinstance(body, str) or not body:
        return ()
    found: dict[bytes, _SsrfDestinationCandidate] = {}
    for match in _ABSOLUTE_HTTP_URL.finditer(body[:_MAX_SSRF_HINT_SOURCE_BYTES]):
        if match.end() < len(body) and body[match.end()] in ":@":
            # Do not accept the hostname-looking prefix of a URL containing
            # userinfo, such as https://user:password@host/.
            continue
        raw = match.group(0).rstrip(".,;:)]}")
        try:
            parsed = urlsplit(raw)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            continue
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or hostname is None
        ):
            continue
        kind = _internal_destination_kind(hostname)
        if kind is None:
            continue
        normalized_host = hostname.casefold().rstrip(".")
        try:
            address = ipaddress.ip_address(normalized_host)
        except ValueError:
            pass
        else:
            normalized_host = address.compressed
        rendered_host = (
            f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        )
        if (parsed.scheme.casefold(), port) in {("http", 80), ("https", 443)}:
            port = None
        authority = rendered_host + (f":{port}" if port is not None else "")
        origin = f"{parsed.scheme.casefold()}://{authority}"
        canonical_destination = origin + (parsed.path or "/")
        if len(canonical_destination) > 640:
            continue
        fingerprint_material = (
            "ssrf-destination-v1\0" + canonical_destination
        ).encode("utf-8")
        found.setdefault(
            fingerprint_material,
            _SsrfDestinationCandidate(
                raw_url=raw,
                destination_origin=origin,
                path_hint=redacted_internal_url_path(parsed.path or "/"),
                host_kind=kind,
                fingerprint_material=fingerprint_material,
            ),
        )
        if len(found) >= _MAX_SSRF_DESTINATION_HINTS:
            break
    return tuple(sorted(found.values(), key=lambda item: (
        item.destination_origin, item.path_hint, item.fingerprint_material,
    )))


def _ssrf_destination_fingerprint(run_key: bytes, material: bytes) -> str:
    """Create a deterministic fingerprint that is unlinkable across Run keys."""

    if not isinstance(run_key, bytes) or len(run_key) < 32:
        raise ValueError("SSRF destination fingerprint key must be at least 32 bytes")
    return hmac.new(run_key, material, hashlib.sha256).hexdigest()


def sanitize_url_reference(
    raw_url: str,
    *,
    run_key: bytes | None = None,
    fingerprint_factory: Callable[[bytes], str] | None = None,
) -> SsrfDestinationHint | None:
    """Return the only URL fields that may be persisted as Recon Evidence.

    Query, fragment and userinfo are deliberately excluded. Secret-shaped path
    segments are replaced by ``{redacted}``, while the unredacted path is used
    only as input to a Run-keyed HMAC and never returned.
    """

    if (run_key is None) == (fingerprint_factory is None):
        raise ValueError(
            "provide exactly one SSRF destination fingerprint mechanism"
        )
    parts = ssrf_destination_reference_parts(raw_url)
    if parts is None:
        return None
    origin, path_hint, fingerprint_material = parts
    if fingerprint_factory is not None:
        fingerprint = fingerprint_factory(fingerprint_material)
    else:
        assert run_key is not None
        fingerprint = _ssrf_destination_fingerprint(run_key, fingerprint_material)
    return SsrfDestinationHint(
        destination_origin=origin,
        path_hint=path_hint,
        destination_fingerprint=fingerprint,
    )


def ssrf_destination_hints(
    body: str, *, run_key: bytes,
) -> tuple[SsrfDestinationHint, ...]:
    """Return persistence-safe metadata for explicit internal URLs."""

    unique: dict[str, SsrfDestinationHint] = {}
    for candidate in _ssrf_destination_candidates(body):
        hint = sanitize_url_reference(candidate.raw_url, run_key=run_key)
        if hint is not None:
            unique.setdefault(hint.destination_fingerprint, hint)
    return tuple(sorted(unique.values(), key=lambda item: (
        item.destination_origin, item.path_hint, item.destination_fingerprint,
    )))


def _ssrf_destination_hint_source(evidence: Evidence) -> str:
    if _openapi_document(evidence) is not None:
        return "openapi_document"
    status = evidence.observation.get("status")
    if type(status) is int and status >= 400:
        return "error_response"
    media = str(evidence.observation.get("content_type", "")).casefold()
    if "javascript" in media or "ecmascript" in media:
        return "delivered_javascript"
    return "http_response"


def _openapi_literal_surfaces(
    evidence: Evidence, origin
) -> list[tuple[str, str, tuple[str, ...], tuple[str, ...], str]]:
    """Read literal API request shapes, without resolving refs or sending mutations."""

    document = _openapi_document(evidence)
    if document is None:
        return []
    paths = document["paths"]
    base = f"{origin.scheme}://{origin.netloc}"
    found: list[tuple[str, str, tuple[str, ...], tuple[str, ...], str]] = []
    for path, operations in sorted(paths.items())[:200]:
        if (
            not isinstance(path, str) or not _API_PATH.fullmatch(path)
            or path.startswith("//") or ".." in path.split("/")
            or "{" in path or "}" in path
            or not isinstance(operations, dict)
        ):
            continue
        for method in ("get", "post", "put", "patch", "delete"):
            operation = operations.get(method)
            if not isinstance(operation, dict):
                continue
            query_names: list[str] = []
            for source in (operations.get("parameters"), operation.get("parameters")):
                if not isinstance(source, list):
                    continue
                for parameter in source[:64]:
                    if not isinstance(parameter, dict) or parameter.get("in") != "query":
                        continue
                    name = parameter.get("name")
                    if isinstance(name, str) and _API_FIELD.fullmatch(name):
                        query_names.append(name)
            body_names: list[str] = []
            content_type = ""
            request_body = operation.get("requestBody")
            content = request_body.get("content") if isinstance(request_body, dict) else None
            if isinstance(content, dict):
                for media in ("application/json", "application/x-www-form-urlencoded"):
                    entry = content.get(media)
                    if not isinstance(entry, dict):
                        continue
                    schema = entry.get("schema")
                    properties = schema.get("properties") if isinstance(schema, dict) else None
                    if isinstance(properties, dict):
                        body_names = [
                            name for name in list(properties)[:64]
                            if isinstance(name, str) and _API_FIELD.fullmatch(name)
                        ]
                    content_type = media
                    break
            found.append((
                base + path, method.upper(), tuple(dict.fromkeys(query_names)),
                tuple(dict.fromkeys(body_names)), content_type,
            ))
    return found


def _openapi_html_document_urls(evidence: Evidence, origin) -> tuple[str, ...]:
    """Sample only literal, input-free GET documents declared to return HTML."""

    document = _openapi_document(evidence)
    if document is None:
        return ()
    base = f"{origin.scheme}://{origin.netloc}"
    urls: list[str] = []
    for path, operations in sorted(document["paths"].items()):
        if (
            len(urls) >= _MAX_SCHEMA_GET_SAMPLES
            or not isinstance(path, str) or not _API_PATH.fullmatch(path)
            or path.startswith("//") or ".." in path.split("/")
            or not isinstance(operations, dict)
        ):
            continue
        get = operations.get("get")
        responses = get.get("responses") if isinstance(get, dict) else None
        response = responses.get("200") if isinstance(responses, dict) else None
        content = response.get("content", {}) if isinstance(response, dict) else None
        if (
            isinstance(content, dict)
            and any(isinstance(media, str) and media.casefold().startswith("text/html")
                    for media in content)
            and not operations.get("parameters")
            and not get.get("parameters")
        ):
            urls.append(base + path)
    return tuple(urls)


def _openapi_collection_templates(
    evidence: Evidence, origin
) -> tuple[tuple[str, str, str], ...]:
    """Find read-only collection/detail pairs declared by an API schema.

    A template alone is not a concrete URL. Recon may visit a declared GET
    collection and use an ID from its actual response to instantiate one
    detail URL; it never invents an ID or sends a mutation.
    """

    document = _openapi_document(evidence)
    if document is None:
        return ()
    paths = document["paths"]
    base = f"{origin.scheme}://{origin.netloc}"
    found: list[tuple[str, str, str]] = []
    for path, operations in sorted(paths.items())[:200]:
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        match = _API_ITEM_PATH.fullmatch(path)
        if match is None or not isinstance(operations.get("get"), dict):
            continue
        collection = match.group("collection")
        parent = paths.get(collection)
        if (
            not _API_PATH.fullmatch(collection)
            or collection.startswith("//") or ".." in collection.split("/")
            or not isinstance(parent, dict)
            or not isinstance(parent.get("get"), dict)
        ):
            continue
        found.append((base + collection, path, match.group("identifier")))
        if len(found) >= 2:
            break
    return tuple(found)


def _openapi_item_links(
    evidence: Evidence, origin, templates: Sequence[tuple[str, str]]
) -> tuple[str, ...]:
    """Use bounded numeric IDs observed in a collection response as URLs."""

    observation = evidence.observation
    body = observation.get("body")
    media = observation.get("content_type", "")
    if (
        evidence.evidence_type != "http_response"
        or type(observation.get("status")) is not int
        or not 200 <= observation["status"] < 300
        or observation.get("truncated")
        or not isinstance(body, str) or len(body) > 256 * 1024
        or not isinstance(media, str)
        or media.split(";", 1)[0].strip().casefold() not in {"application/json", "application/problem+json"}
    ):
        return ()
    try:
        document = json.loads(body)
    except ValueError:
        return ()
    lists = [document] if isinstance(document, list) else (
        [value for value in list(document.values())[:12] if isinstance(value, list)]
        if isinstance(document, dict) else []
    )
    found: list[str] = []
    base = f"{origin.scheme}://{origin.netloc}"
    for template, identifier in templates:
        for records in lists[:4]:
            for record in records[:32]:
                if not isinstance(record, dict):
                    continue
                value = record.get(identifier, record.get("id"))
                if type(value) is int and 0 < value <= 9_999_999_999:
                    path = template.replace("{" + identifier + "}", str(value))
                elif isinstance(value, str) and _PATH_OBJECT_ID.fullmatch(value):
                    path = template.replace("{" + identifier + "}", value)
                else:
                    continue
                if _API_PATH.fullmatch(path) and path not in found:
                    found.append(base + path)
                break
            if found and found[-1].startswith(base + template.split("{", 1)[0]):
                break
    return tuple(found[:2])
def _looks_like_file_value(value: str) -> bool:
    """관측된 **값**이 파일명이나 경로처럼 보이는지 판정한다.

    이름만 보면 좌표를 놓친다. XBEN-061은 ``post.php?id=`` 하나로 파일을 고르는데
    (``"posts/" . $id``), ``id``는 어느 대상에서도 파일 힌트가 아니고 넣어서도 안 된다.
    반면 그 좌표의 관측값은 ``EternalBlue.php``처럼 분명한 파일명이다.

    확장자는 열어 두지 않고 문서·스크립트 종류로 제한한다. 알파벳 확장자를 모두 받으면
    ``example.com``이 파일로 읽히고, 숫자를 받으면 ``3.14``가 걸린다. 종류 목록은 파일
    형식에 대한 것이므로 대상이 달라도 그대로 쓰인다.
    """

    candidate = value.strip()
    if not candidate or len(candidate) > 128:
        return False
    if "@" in candidate or "://" in candidate:
        return False
    if "/" in candidate or "\\" in candidate:
        return True
    _stem, _, extension = candidate.rpartition(".")
    return bool(_stem) and extension.lower() in _FILE_VALUE_EXTENSIONS


def _client_routes(body: str) -> dict[str, tuple[str, ...]]:
    """SPA 라우트 이름과 그 라우트가 받는 query 파라미터를 짝지어 뽑는다.

    번들은 minify 되어 있어 `navigate(["/search"], i)` 처럼 파라미터 선언이 변수로
    분리되기도 한다. 선언과 이동이 같은 함수 안에 있다는 성질만 이용해 좁은 창
    안에서 함께 나타나는 짝을 취한다. 창을 넓히면 무관한 라우트가 섞인다.
    """

    routes: dict[str, set[str]] = {}
    for match in _JS_ROUTE_QUERY_PARAM.finditer(body):
        start = max(0, match.start() - _ROUTE_BINDING_WINDOW)
        window = body[start : match.end() + _ROUTE_BINDING_WINDOW]
        nearby = _JS_ROUTE_NAVIGATE.search(window)
        if nearby is None:
            continue
        routes.setdefault(nearby.group(1), set()).add(match.group(1))
    return {route: tuple(sorted(names)) for route, names in routes.items()}


def _looks_like_restricted_file(url: str) -> bool:
    """웹으로 내주면 안 되는 확장자를 가진 파일 경로인지 본다."""

    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return any(name.endswith(suffix) for suffix in _RESTRICTED_FILE_EXTENSIONS)


def _deterministic_url_key(url: str) -> tuple[str, str, str, str, str, str]:
    """비교·회귀 모드에서 crawl frontier를 고정하는 URL 정렬 키."""

    parsed = urlsplit(url)
    return (
        parsed.scheme.casefold(),
        parsed.netloc.casefold(),
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
        url,
    )


def _script_priority(url: str) -> int:
    """공통 런타임이 작은 수집 창을 독점하지 않도록 앱 청크를 먼저 읽는다."""

    path = urlsplit(url).path.casefold()
    name = path.rsplit("/", 1)[-1]
    if re.search(r"(?:^|[/_.-])(app|page|layout|route|feature)(?:[/_.-]|$)", path):
        if not name.startswith("main-app"):
            return 0
    if re.match(r"(?:webpack|runtime|polyfills?|vendor|framework|main-app|\d+[.-])", name):
        return 2
    return 1


def _deterministic_pending(
    urls: Sequence[str],
    protected: Sequence[str] | set[str] = (),
    inbound: Mapping[str, set[str]] | None = None,
) -> list[str]:
    """보호 URL을 먼저, 그 안에서는 여러 문서가 가리킨 URL부터 고정한다.

    고정된 frontier 상한 아래에서 순수 경로 알파벳순은 콘텐츠 페이지가 기능 페이지를
    밀어낸다. 메뉴·사이드바에 실린 폼 페이지는 여러 문서에서 가리켜지고 기사 하나는
    보통 한 번만 가리켜지므로, 서로 다른 몇 개의 문서가 이 URL을 가리켰는지를 알파벳
    순서보다 먼저 본다. 같은 수면 URL 키로 끊어 재현성은 그대로다.
    """

    unique = tuple(dict.fromkeys(urls))
    protected_set = set(protected)
    counts = inbound or {}

    def rank(url: str) -> tuple:
        return (-len(counts.get(url, ())), _deterministic_url_key(url))

    return [
        *sorted((url for url in unique if url in protected_set), key=rank),
        *sorted((url for url in unique if url not in protected_set), key=rank),
    ]


class ReconAgent:
    """대상을 크롤링하고 응답에서 공격 표면을 구조화해 저장한다."""

    def __init__(
        self,
        *,
        collector: RuntimeEvidenceCollector,
        evidence_store: EvidenceStore,
        surface_store: SurfaceStore,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_scripts: int = DEFAULT_MAX_SCRIPTS,
        surface_collection_mode: str = "adaptive",
        seed_urls: Sequence[str] = (),
        infer_unlinked_render_parameters: bool = True,
        infer_unlinked_query_parameters: bool = False,
        ssrf_navigation: bool = False,
        id_factory: Callable[[], str] | None = None,
        planner: ReconPlanner | None = None,
        iterative_planner: IterativeReconPlanner | None = None,
        clock: Callable[[], float] | None = None,
        browser_recon: PlaywrightRecon | None = None,
    ) -> None:
        if max_pages < 1:
            raise ValueError("recon must fetch at least one page")
        if surface_collection_mode not in {"adaptive", "deterministic"}:
            raise ValueError("unsupported surface collection mode")
        if planner is not None and iterative_planner is not None:
            raise ValueError("only one recon planner may be configured")
        self._collector = collector
        self._evidence = evidence_store
        self._surfaces = surface_store
        self._max_pages = max_pages
        self._max_scripts = max_scripts
        self._surface_collection_mode = surface_collection_mode
        self._seed_urls = tuple(dict.fromkeys(seed_urls))
        self._infer_unlinked_render_parameters = infer_unlinked_render_parameters
        # 기본값을 끈 이유는 비용이다. 이름 하나가 요청 하나이므로 켜면 정찰이
        # 쓰는 요청 수가 늘고, 그만큼 분석 단계 몫이 줄어든다. 켤 쪽이 그 교환을
        # 알고 켜야 한다.
        self._infer_unlinked_query_parameters = infer_unlinked_query_parameters
        self._ssrf_navigation = ssrf_navigation
        self._id_factory = id_factory or (lambda: str(uuid4()))
        # None이면(휴리스틱 프로필) 아래 두 번째 crawl() 직전 분기 자체가 실행되지
        # 않아 기존 결정적 동작과 한 줄도 다르지 않다.
        self._planner = planner
        self._iterative_planner = iterative_planner
        self._clock = clock or time.monotonic
        self._browser_recon = browser_recon
        # Lightweight collector fakes used by pure Recon tests predate the
        # protected Run-HMAC API. Production always uses RuntimeEvidenceCollector;
        # only this fallback key stays private to the Recon process.
        self._fallback_ssrf_fingerprint_keys: dict[str, bytes] = {}

    def handle(self, task: TaskEnvelope) -> AgentResult:
        """예산 안에서 크롤링하며 Surface·Evidence를 채운다."""

        if task.target_url is None:
            raise AgentContractError("recon task is missing a target url")
        if RECON_TOOL not in task.allowed_tools:
            raise AgentContractError("recon tool is not allowed by the task")

        origin = urlsplit(task.target_url)
        targeted = task.surface_id is not None
        if targeted:
            target = self._surfaces.get(task.run_id, task.surface_id)
            if (
                target.url != task.target_url
                or target.method.upper() != "GET"
                or target.parameters
                or origin.fragment
            ):
                raise AgentContractError("targeted recon requires an existing simple GET surface")
        page_budget = 1 if targeted else self._page_budget(task)
        reserve = min(_RECON_DEADLINE_RESERVE_SECONDS, task.timeout_seconds / 10)
        work_deadline = self._clock() + task.timeout_seconds - reserve

        def remaining_work() -> float:
            return max(0.0, work_deadline - self._clock())

        def run_fingerprint(purpose: str, material: bytes) -> str:
            fingerprint = getattr(self._collector, "ssrf_run_fingerprint", None)
            if callable(fingerprint):
                return fingerprint(task.run_id, purpose, material)
            key = self._fallback_ssrf_fingerprint_keys.setdefault(
                task.run_id, secrets.token_bytes(32),
            )
            return _ssrf_destination_fingerprint(
                key, purpose.encode("utf-8") + b"\0" + material,
            )

        def private_url_fingerprint(url: str) -> str:
            material = ("recon-unvisited-v1\0" + url).encode("utf-8")
            return run_fingerprint("recon-unvisited", material)

        for seed_url in self._seed_urls:
            if not _same_origin(seed_url, origin):
                raise AgentContractError("recon seed URL belongs to another origin")
        # SPA 홈페이지와 별도 서버 렌더링 페이지처럼 서로 링크되지 않은 진입점을
        # 한 Recon 세션에서 함께 탐색할 수 있다. Juice Shop의 인증된 /profile이
        # 대표적이다.
        pending = (
            [task.target_url]
            if targeted
            else list(dict.fromkeys((task.target_url, *self._seed_urls)))
        )
        pending_discovery_types: dict[str, set[str]] = {
            url: {"seed"} for url in pending
        }
        fetched: set[str] = set()
        # URL -> 그 URL을 가리킨 서로 다른 문서들. 한 페이지에 같은 링크가 여러 번
        # 있어도 한 번으로 센다.
        inbound_documents: dict[str, set[str]] = {}
        responded: set[str] = set()
        successful: set[str] = set()
        parsed: set[str] = set()
        sensitive_exposure_seen: set[tuple[str, ...]] = set()
        script_request_shapes_seen: set[tuple[str, str, tuple[str, ...]]] = set()
        source_map_refs_seen: set[str] = set()
        script_references_seen: set[tuple[str, str]] = set()
        postmessage_seen: set[tuple[str, str, str]] = {
            (item.surface_id, item.observation.get("message_type"), item.observation.get("html_field"))
            for item in self._evidence.list_by_run(task.run_id)
            if item.surface_id is not None
            and item.created_by == "recon"
            and item.observation.get("type") == POSTMESSAGE_PLAN
        }
        error_routes_seen: set[str] = {
            item.surface_id for item in self._evidence.list_by_run(task.run_id)
            if item.created_by == "recon"
            and item.observation.get("type") == ERROR_ROUTE_OBSERVATION
            and item.surface_id is not None
        }
        credential_routes_seen: set[str] = {
            item.surface_id for item in self._evidence.list_by_run(task.run_id)
            if item.created_by == "recon"
            and item.observation.get("type") == CONFIG_ROUTE_OBSERVATION
            and item.surface_id is not None
        }
        # 파일형 경로 입력 가설은 이름 단위로 한 번만 세운다. `/file=a.js`와 `/file=b.js`는
        # 서로 다른 Surface지만 같은 서버 처리기를 가리키므로, 둘 다 라우팅하면 같은
        # 자리를 두 번 탐침하며 예산만 쓴다.
        path_assignment_names_seen: set[str] = {
            name for item in self._evidence.list_by_run(task.run_id)
            if item.created_by == "recon"
            and item.observation.get("type") == FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION
            and isinstance((name := item.observation.get("parameter")), str)
        }
        path_assignment_skips_seen: set[str] = set()
        api_schema_found = False
        schema_get_samples_queued = 0
        schema_collections: dict[str, list[tuple[str, str]]] = {}
        scripts: list[str] = []
        deferred_inline_urls: list[str] = []
        inline_seen_shapes: set[tuple[str, tuple[str, ...]]] = set()
        inline_path_count = 0
        # 리소스명 -> 관측된 숫자 세그먼트 값. 목록 페이지가 항목 링크를 형제로 함께
        # 내보내므로, 저장 전에 같은 배치 안에서 형제 수를 셀 수 있다.
        numeric_siblings: dict[str, set[str]] = {}
        ssrf_inline_docs_queued = 0
        document_pages: set[str] = set()
        browser_document_seeds: dict[str, int] = {}
        unparameterized_search_pages: dict[str, str] = {}
        # 쿼리 좌표 추론을 적용한 문서 페이지 수. 페이지마다 이름 목록을 다시 찍으면
        # 정찰이 예산을 다 쓰고 분석 단계가 굶는다.
        inference_pages = 0
        if targeted:
            # A second pass only visits this selected document. Preserve the
            # document-page form signal normally set during first-pass script discovery.
            document_pages.add(task.target_url)
        navigation_pages: set[str] = set()
        javascript_globals: dict[tuple[str, str], str] = {}
        evidence_ids: list[str] = []
        destination_hint_seen: set[tuple[str, str]] = {
            (
                str(item.observation.get("destination_origin")),
                str(item.observation.get("path_hint")),
            )
            for item in self._evidence.list_by_run(task.run_id)
            if item.created_by == "recon"
            and item.observation.get("type") == SSRF_DESTINATION_HINT_TYPE
            and isinstance(item.observation.get("destination_origin"), str)
            and isinstance(item.observation.get("path_hint"), str)
        }
        planner_status: str | None = None
        # 발견과 수집은 다르다 — 크롤링 예산이 모자라도 발견한 URL은 Surface로 남긴다.
        # (url, method, parameters) 조합으로 중복을 막는다. 같은 run_id로 다시 호출되면
        # (프로세스 재시작 후 재개 등) 이미 저장된 Surface를 먼저 채워 넣어 같은 URL에
        # 매번 새 surface_id가 발급되지 않게 한다. 안 그러면 §3.7 저장 계획 재사용의
        # offered_surface_ids 비교가 재개 때마다 어긋난다 — id_factory가 uuid4처럼
        # 호출마다 다른 값을 내는 게 기본값이기 때문이다.
        surfaces: dict[tuple[str, str, tuple[str, ...]], str] = {
            (
                _canonical_surface_url(existing.url, _path_identifier(existing.url)),
                existing.method,
                existing.parameters,
            ): existing.surface_id
            for existing in self._surfaces.list_by_run(task.run_id)
        }
        # pending에 오른 URL의 surface_id. Planner 후보를 만들 때 URL로 Store를 다시
        # 뒤지지 않고 이 dict로 바로 대응시킨다.
        pending_surface_ids: dict[str, str] = {}
        surface_discovery_types: dict[str, set[str]] = {}
        recently_fetched_surface_ids: list[str] = []
        deadline_exhausted = False
        stop_reason: str | None = None

        def record_response(url: str, evidence: Evidence) -> None:
            status = evidence.observation.get("status")
            if (
                evidence.evidence_type == "http_response"
                and type(status) is int and 100 <= status <= 599
            ):
                responded.add(url)
                if 200 <= status < 300:
                    successful.add(url)

        def record_ssrf_destination_hints(
            surface_id: str, body: str, source_evidence_id: str, evidence: Evidence,
        ) -> None:
            candidates = _ssrf_destination_candidates(body)
            for candidate in candidates:
                hint = sanitize_url_reference(
                    candidate.raw_url,
                    fingerprint_factory=lambda material: run_fingerprint(
                        "destination-hint", material,
                    ),
                )
                if hint is None:
                    continue
                fingerprint = hint.destination_fingerprint
                persisted_hint = (hint.destination_origin, hint.path_hint)
                if (
                    persisted_hint in destination_hint_seen
                    or len(destination_hint_seen) >= _MAX_SSRF_DESTINATION_HINTS
                ):
                    continue
                destination_hint_seen.add(persisted_hint)
                signal = Evidence(
                    evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": SSRF_DESTINATION_HINT_TYPE,
                        "source": _ssrf_destination_hint_source(evidence),
                        "source_evidence_id": source_evidence_id,
                        "destination_origin": hint.destination_origin,
                        "path_hint": hint.path_hint,
                        "destination_fingerprint": fingerprint,
                        "host_kind": candidate.host_kind,
                        "observed": True,
                        "probe_authorized": False,
                    },
                )
                self._evidence.append(signal)
                evidence_ids.append(signal.evidence_id)

        def remember(
            url: str,
            method: str,
            names: tuple[str, ...],
            observed: tuple[tuple[str, str], ...] = (),
            discovery_types: Sequence[str] = (),
        ) -> str:
            clean_url = url.split("?", 1)[0]
            path_identifier = _path_identifier(clean_url, numeric_siblings)
            assignment, skip_reason = _path_assignment(
                clean_url, source=PATH_ASSIGNMENT_SOURCE
            )
            if assignment is not None and assignment.name in names:
                # 같은 이름이 query에도 있으면 어느 자리를 관측한 것인지 단정할 수 없다.
                # 좌표를 섞지 않는다는 계약이 깨지므로 경로 쪽을 인정하지 않는다.
                assignment, skip_reason = None, "name_collides_with_query_parameter"
            key_url = _canonical_surface_url(clean_url, path_identifier)
            key = (key_url, method, names)
            def record_error_route(surface_id: str) -> None:
                if (
                    method != "GET" or names or len(error_routes_seen) >= 4
                    or surface_id in error_routes_seen
                    or not error_route_candidate(clean_url)
                    or has_state_changing_get(clean_url)
                ):
                    return
                error_routes_seen.add(surface_id)
                signal = Evidence(
                    evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": ERROR_ROUTE_OBSERVATION,
                        "source": "observed_diagnostic_path",
                    },
                )
                self._evidence.append(signal)
                evidence_ids.append(signal.evidence_id)
            def record_credential_route(surface_id: str) -> None:
                if (
                    method != "GET" or names or len(credential_routes_seen) >= 4
                    or surface_id in credential_routes_seen
                    or not credential_config_route_candidate(clean_url)
                    or has_state_changing_get(clean_url)
                ):
                    return
                credential_routes_seen.add(surface_id)
                signal = Evidence(
                    evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": CONFIG_ROUTE_OBSERVATION,
                        "source": "observed_config_path",
                    },
                )
                self._evidence.append(signal)
                evidence_ids.append(signal.evidence_id)
            existing = surfaces.get(key)
            if existing is not None:
                surface_discovery_types.setdefault(existing, set()).update(
                    discovery_types
                )
                record_error_route(existing)
                record_credential_route(existing)
                return existing
            surface_id = f"surface-{self._id_factory()}"
            surfaces[key] = surface_id
            surface_discovery_types.setdefault(surface_id, set()).update(
                discovery_types
            )
            self._store_surface(
                task.run_id,
                surface_id,
                clean_url,
                method,
                names,
                observed=observed,
                path_identifier=path_identifier,
                path_assignment=assignment,
                discovery_types=tuple(dict.fromkeys(discovery_types)),
            )
            record_error_route(surface_id)
            record_credential_route(surface_id)
            evidence_ids.extend(
                self._flag_suspect_parameters(
                    task.run_id, surface_id, names, clean_url, method, observed
                )
            )
            evidence_ids.extend(
                self._flag_path_assignment(
                    task.run_id,
                    surface_id,
                    assignment,
                    skip_reason,
                    method,
                    names_seen=path_assignment_names_seen,
                    skips_seen=path_assignment_skips_seen,
                )
            )
            if _looks_like_restricted_file(clean_url):
                evidence_ids.append(
                    self._flag_restricted_file(task.run_id, surface_id, clean_url)
                )
            return surface_id

        def record_postmessage_plans(document_surface_id: str, script_body: str) -> None:
            for event_type, field in postmessage_html_plans(script_body):
                key = (document_surface_id, event_type, field)
                if key in postmessage_seen or len(postmessage_seen) >= 24:
                    continue
                postmessage_seen.add(key)
                signal = Evidence(
                    evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                    surface_id=document_surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": POSTMESSAGE_PLAN,
                        "message_type": event_type,
                        "html_field": field,
                    },
                )
                self._evidence.append(signal)
                evidence_ids.append(signal.evidence_id)

        def remember_schema(
            shapes: Sequence[tuple[str, str, tuple[str, ...], tuple[str, ...], str]],
            source_evidence_id: str,
            collection_templates: Sequence[tuple[str, str, str]] = (),
        ) -> None:
            nonlocal schema_get_samples_queued
            for url, method, query_names, body_names, content_type in shapes:
                surface_id = remember(
                    url, method, tuple(dict.fromkeys((*query_names, *body_names))),
                    discovery_types=("openapi_schema",),
                )
                # A declaration supplies field names and media type, never a
                # replayable normal request or permission to send a mutation.
                shape_id = f"evi-{self._id_factory()}"
                self._evidence.append(Evidence(
                    evidence_id=shape_id, run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": "openapi_request_structure",
                        "schema_evidence_id": source_evidence_id,
                        "method": method,
                        "query_parameter_names": list(query_names),
                        "body_parameter_names": list(body_names),
                        "content_type": content_type,
                        "request_template_available": False,
                    },
                ))
                evidence_ids.append(shape_id)
            for collection_url, template, identifier in collection_templates:
                related = schema_collections.setdefault(collection_url, [])
                if (template, identifier) not in related:
                    related.append((template, identifier))
                if targeted or len(fetched) >= page_budget:
                    continue
                pending_surface_ids[collection_url] = remember(
                    collection_url, "GET", (),
                    discovery_types=("openapi_collection",),
                )
                pending_discovery_types.setdefault(collection_url, set()).add(
                    "openapi_collection"
                )
                if collection_url not in fetched and collection_url not in pending:
                    pending.append(collection_url)

            if not targeted:
                source_evidence = self._evidence.get(task.run_id, source_evidence_id)
                for html_url in _openapi_html_document_urls(source_evidence, origin):
                    if (
                        schema_get_samples_queued >= _MAX_SCHEMA_GET_SAMPLES
                        or len(fetched) + len(pending) >= page_budget - 2
                    ):
                        break
                    if html_url in fetched or html_url in pending or has_state_changing_get(html_url):
                        continue
                    pending_surface_ids[html_url] = remember(
                        html_url, "GET", (), discovery_types=("openapi_html_document",),
                    )
                    pending_discovery_types.setdefault(html_url, set()).add(
                        "openapi_html_document"
                    )
                    pending.append(html_url)
                    schema_get_samples_queued += 1

            # A schema declaration alone has no response evidence. Sample a
            # few literal, input-free GET routes so ordinary JSON links and
            # credential fields can enter Recon. Leave two crawl slots for
            # scripts or links already found, and never infer request values.
            if not targeted:
                for url, method, query_names, body_names, _ in sorted(
                    shapes, key=lambda item: (
                        urlsplit(item[0]).path.count("/"), item[0], item[1]
                    ),
                ):
                    if (
                        schema_get_samples_queued >= _MAX_SCHEMA_GET_SAMPLES
                        or len(fetched) + len(pending) >= page_budget - 2
                    ):
                        break
                    if (
                        method != "GET" or query_names or body_names
                        or has_state_changing_get(url)
                        # These routes already get independent Analysis and
                        # Validation requests; spend Recon samples elsewhere.
                        or error_route_candidate(url)
                        or credential_config_route_candidate(url)
                        or url in fetched or url in pending
                    ):
                        continue
                    surface_id = remember(
                        url, "GET", (), discovery_types=("openapi_schema_get",),
                    )
                    pending_surface_ids[url] = surface_id
                    pending_discovery_types.setdefault(url, set()).add(
                        "openapi_schema_get"
                    )
                    pending.append(url)
                    schema_get_samples_queued += 1

        def remember_source_maps(script_url: str, body: str, source_evidence_id: str) -> None:
            for map_url in source_map_urls(script_url, body):
                surface_id = remember(
                    map_url, "GET", (), discovery_types=("source_map_reference",),
                )
                if map_url in source_map_refs_seen:
                    continue
                # Each independently verified map needs two additional GETs.
                # Keep other linked maps as Surfaces without letting a large
                # bundle consume the analysis budget before validation.
                if len(source_map_refs_seen) >= 2:
                    continue
                source_map_refs_seen.add(map_url)
                signal_id = f"evi-{self._id_factory()}"
                self._evidence.append(Evidence(
                    evidence_id=signal_id, run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={"type": SOURCE_MAP_REFERENCE,
                                 "script_response_evidence_id": source_evidence_id},
                ))
                evidence_ids.append(signal_id)

        def record_sensitive_exposure(surface_id: str, fields: tuple[str, ...]) -> None:
            # Repeated client pages often embed the same application config.
            # One field set is one Run-level claim until a distinct field set
            # provides independently reportable evidence.
            if not fields or fields in sensitive_exposure_seen:
                return
            sensitive_exposure_seen.add(fields)
            signal_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=signal_id, run_id=task.run_id,
                surface_id=surface_id, created_by="recon",
                evidence_type="observation", source_task_id=task.task_id,
                observation={"type": EXPOSURE_OBSERVATION,
                             "field_paths": list(fields)},
            ))
            evidence_ids.append(signal_id)

        def record_public_login_pairs(surface_id: str, response: Evidence) -> None:
            count = response.observation.get(TRUSTED_LOGIN_PAIR_COUNT)
            if type(count) is not int or not 0 < count <= 8:
                return
            if any(
                item.surface_id == surface_id and item.created_by == "recon"
                and item.observation.get("type") == PUBLIC_LOGIN_OBSERVATION
                for item in self._evidence.list_by_run(task.run_id)
            ):
                return
            signal_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=signal_id, run_id=task.run_id,
                surface_id=surface_id, created_by="recon",
                evidence_type="observation", source_task_id=task.task_id,
                observation={"type": PUBLIC_LOGIN_OBSERVATION,
                             "source": "delivered_javascript", "pair_count": count},
            ))
            evidence_ids.append(signal_id)

        def record_script_request_shape(
            url: str, method: str, query_names: tuple[str, ...], source: str
        ) -> None:
            shape = (url, method, query_names)
            if shape in script_request_shapes_seen:
                return
            script_request_shapes_seen.add(shape)
            # Static code reveals a method and field names, not a valid body,
            # session, CSRF token, or approval to transmit a mutation.
            surface_id = remember(
                url, method, (), discovery_types=(source,)
            )
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=evidence_id, run_id=task.run_id,
                surface_id=surface_id, created_by="recon",
                evidence_type="observation", source_task_id=task.task_id,
                observation={
                    "type": "script_request_structure",
                    "method": method,
                    "query_parameter_names": list(query_names),
                    "request_template_available": False,
                },
            ))
            evidence_ids.append(evidence_id)

        def record_ssrf_json_shapes(script_body: str, source: str) -> None:
            for url, field in _script_ssrf_json_shapes(script_body, origin):
                surface_id = remember(
                    url, "POST", (field,), discovery_types=(source,),
                )
                if any(
                    item.surface_id == surface_id
                    and item.observation.get("type") == "javascript_json_request_structure"
                    for item in self._evidence.list_by_run(task.run_id)
                ):
                    continue
                evidence_id = f"evi-{self._id_factory()}"
                self._evidence.append(Evidence(
                    evidence_id=evidence_id, run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": "javascript_json_request_structure",
                        "method": "POST", "content_type": "application/json",
                        "body_parameter_names": [field],
                        "request_template_available": False,
                    },
                ))
                evidence_ids.append(evidence_id)

        def crawl(
            *,
            protected: Sequence[str] | set[str] = (),
            max_visits: int | None = None,
        ) -> int:
            nonlocal deadline_exhausted, api_schema_found, inline_path_count
            nonlocal inference_pages
            nonlocal ssrf_inline_docs_queued
            visited = 0
            while pending and len(fetched) < page_budget:
                if remaining_work() < 1.0:
                    deadline_exhausted = True
                    break
                if max_visits is not None and visited >= max_visits:
                    break
                if self._surface_collection_mode == "deterministic":
                    pending[:] = _deterministic_pending(pending, protected, inbound_documents)
                else:
                    # 메뉴·사이드바에 실린 기능 페이지는 여러 문서가 가리키고, 기사 하나는
                    # 보통 한 번만 가리켜진다. 문서에 나온 순서는 유지하되(안정 정렬) 가리킨
                    # 문서가 많은 쪽을 먼저 본다. 고정된 페이지 상한에서 콘텐츠 목록이 폼
                    # 페이지를 끝까지 밀어내는 것을 막는다.
                    pending.sort(key=lambda candidate: (
                        candidate not in protected,
                        -len(inbound_documents.get(candidate, ())),
                    ))
                url = pending.pop(0)
                if url in fetched:
                    continue
                fetched.add(url)
                visited += 1

                surface_id = remember(
                    url,
                    "GET",
                    _query_names(url),
                    _query_pairs(url),
                    tuple(sorted(pending_discovery_types.get(url, {"discovered"}))),
                )
                pending_surface_ids[url] = surface_id
                if has_state_changing_get(url):
                    # 상태를 바꾸는 GET은 가져오지 않는다. Surface로는 보존해 "검사하지
                    # 않았다"가 결과에 남는다.
                    #
                    # 정책 게이트가 승인 없는 이런 요청을 거부하므로, 시도하면
                    # ApprovalRequired가 recon 단계에서 Run 전체를 끝낸다. 인증을 세운
                    # 뒤에 특히 문제가 된다 — 로그아웃 링크는 로그인한 페이지에만
                    # 나타나므로, 크롤이 방금 만든 세션을 스스로 끊으려 하고 그 거부로
                    # 측정이 통째로 날아간다.
                    continue
                evidence_id, evidence = self._fetch(
                    task, url, surface_id, timeout_seconds=remaining_work()
                )
                record_response(url, evidence)
                evidence_ids.append(evidence_id)
                recently_fetched_surface_ids.append(surface_id)
                del recently_fetched_surface_ids[:-_MAX_AGENTIC_CONTEXT]

                # Runtime은 Scope 우회를 막기 위해 리다이렉트를 자동으로 따라가지 않는다.
                # Recon이 저장된 Location을 다시 정책 경계로 보내 같은 origin일 때만
                # 별도 GET으로 방문한다. 외부 origin과 리다이렉트 순환은 여기서 제외된다.
                if evidence.evidence_type == "http_redirect":
                    location = evidence.observation.get("location")
                    if isinstance(location, str) and location.strip():
                        redirected = urljoin(url, location)
                        if _same_origin(redirected, origin):
                            pending_surface_ids[redirected] = remember(
                                redirected,
                                "GET",
                                _query_names(redirected),
                                _query_pairs(redirected),
                                discovery_types=("http_redirect",),
                            )
                            pending_discovery_types.setdefault(
                                redirected, set()
                            ).add("http_redirect")
                            if redirected not in fetched and redirected not in pending:
                                pending.append(redirected)
                    continue

                body = evidence.observation.get("body")
                if isinstance(body, str) and body:
                    record_ssrf_destination_hints(
                        surface_id, body, evidence_id, evidence,
                    )
                if url not in successful or not isinstance(body, str) or not body:
                    continue
                if not _is_html_response(evidence):
                    # JSON/API 응답 안의 escaped HTML 조각을 실제 링크나 폼으로 오인하면
                    # `/api/\"https:/...` 같은 실행 불가능한 Surface가 생긴다. API 본문은
                    # status/content-type 관찰로 남기되 HTML parser에는 넣지 않는다.
                    if (
                        (_javascript_response(evidence) or (
                            urlsplit(url).path.casefold().endswith((".js", ".mjs"))
                            and "javascript" in str(
                                evidence.observation.get("content_type", "")
                            ).casefold()
                        ))
                        and len(body) <= _MAX_SCRIPT_BYTES
                    ):
                        parsed.add(url)
                        for mutation_url, method, names in _script_mutation_shapes(body, origin):
                            record_script_request_shape(
                                mutation_url, method, names, "javascript_link_request_shape"
                            )
                        record_ssrf_json_shapes(body, "javascript_link_json_request")
                        for literal_url, names, _, _ in _script_paths_from_body(body, origin):
                            if _same_origin(literal_url, origin):
                                remember(literal_url, "GET", names,
                                         discovery_types=("javascript_link_literal",))
                        continue
                    schema_surfaces = _openapi_literal_surfaces(evidence, origin)
                    record_sensitive_exposure(
                        surface_id, exposed_json_field_paths(evidence.observation)
                    )
                    if _openapi_document(evidence) is not None:
                        api_schema_found = True
                        parsed.add(url)
                        remember_schema(
                            schema_surfaces, evidence_id,
                            _openapi_collection_templates(evidence, origin),
                        )
                    for link in _openapi_item_links(
                        evidence, origin, schema_collections.get(url, ())
                    ):
                        pending_surface_ids[link] = remember(
                            link, "GET", (),
                            discovery_types=("openapi_collection_item",),
                        )
                        pending_discovery_types.setdefault(link, set()).add(
                            "openapi_collection_item"
                        )
                        if link not in fetched and link not in pending:
                            pending.append(link)
                    json_links = _json_links_from_response(evidence, url)
                    if json_links:
                        parsed.add(url)
                    for link in json_links:
                        pending_surface_ids[link] = remember(
                            link, "GET", _query_names(link), _query_pairs(link),
                            discovery_types=("json_link",),
                        )
                        pending_discovery_types.setdefault(link, set()).add("json_link")
                        if link not in fetched and link not in pending:
                            pending.append(link)
                    continue

                links, forms, sources, inline_scripts = _parse_page(body, url)
                parsed.add(url)
                location = urlsplit(url)
                if (
                    not targeted and not location.query and not location.fragment
                    and location.path.rstrip("/").rsplit("/", 1)[-1].casefold()
                    in {"search", "find", "lookup"}
                    and len(body) <= 64_000
                    and not any(
                        method == "GET" and names
                        for _, method, names, _ in forms
                    )
                ):
                    unparameterized_search_pages[url] = body
                # HTTP discovery can reach an unlinked HTML document through an
                # API schema or a script. Render a few confirmed documents so
                # their client-side navigation and fragment sinks are observed.
                if (
                    url != task.target_url
                    and not location.query and not location.fragment
                    and _same_origin(url, origin)
                ):
                    browser_document_seeds[url] = (
                        2 * bool(forms) + bool(inline_scripts or sources)
                    )
                record_sensitive_exposure(
                    surface_id, exposed_json_field_paths(evidence.observation)
                )
                for inline_body in inline_scripts:
                    javascript_globals.update(_javascript_globals(inline_body))
                    record_ssrf_json_shapes(inline_body, "inline_javascript_json_request")
                for inline_body in inline_scripts:
                    for request_url, method, fields in _javascript_requests(
                        inline_body, url, javascript_globals
                    ):
                        if not _same_origin(request_url, origin):
                            continue
                        remember(
                            request_url,
                            method,
                            tuple(name for name, _ in fields),
                            observed=fields,
                            discovery_types=("javascript_request",),
                        )
                for upload_plan in upload_form_plans(body, url):
                    upload_surface_id = remember(
                        upload_plan.url, "POST",
                        tuple(dict.fromkeys((upload_plan.parameter, *(name for name, _ in upload_plan.fields)))),
                        discovery_types=("html_form",),
                    )
                    upload_evidence_id = f"evi-{self._id_factory()}"
                    self._evidence.append(Evidence(
                        evidence_id=upload_evidence_id, run_id=task.run_id,
                        surface_id=upload_surface_id, created_by="recon",
                        evidence_type="observation",
                        observation={"type": UPLOAD_FORM, "source": "html_form",
                                     "parameter": upload_plan.parameter, "accept": upload_plan.accept,
                                     "source_surface_id": surface_id,
                                     "refresh_form": bool(upload_plan.fields)},
                    ))
                    evidence_ids.append(upload_evidence_id)
                for form_url, method, names, content_type in forms:
                    form_surface_id = remember(
                        form_url, method, names, discovery_types=("html_form",)
                    )
                    if (
                        method == "POST"
                        and names
                        and content_type == "application/x-www-form-urlencoded"
                    ):
                        evidence_ids.append(
                            self._flag_post_form_structure(
                                task.run_id, form_surface_id, names
                            )
                        )
                    if (
                        self._infer_unlinked_render_parameters
                        and method == "POST"
                        and url in document_pages
                    ):
                        evidence_ids.extend(
                            self._flag_unlinked_render_parameters(
                                task.run_id, form_surface_id
                            )
                        )
                if (
                    self._infer_unlinked_query_parameters
                    and not _query_names(url)
                    and inference_pages < _MAX_INFERENCE_PAGES
                    and page_budget > len(fetched)
                ):
                    inference_pages += 1
                    inferred, inferred_ids, spent = self._infer_query_parameters(
                        task, url, evidence, page_budget - len(fetched)
                    )
                    visited += spent
                    evidence_ids.extend(inferred_ids)
                    for name, observed in inferred:
                        remember(
                            url,
                            "GET",
                            (name,),
                            observed,
                            discovery_types=("inferred_query_parameter",),
                        )

                # 링크를 Surface로 만들기 전에 숫자 형제를 먼저 센다. remember가
                # 저장 시점에 식별자를 확정하고, 저장된 Surface는 덮어쓸 수 없다.
                for link in links:
                    if not _same_origin(link, origin):
                        continue
                    _record_numeric_sibling(link, numeric_siblings)

                for link in links:
                    if not _same_origin(link, origin):
                        continue
                    # 예산과 무관하게 표면으로 기록하고, 여유가 있으면 크롤링까지 한다.
                    pending_surface_ids[link] = remember(
                        link,
                        "GET",
                        _query_names(link),
                        _query_pairs(link),
                        discovery_types=("html_link",),
                    )
                    pending_discovery_types.setdefault(link, set()).add("html_link")
                    inbound_documents.setdefault(link, set()).add(url)
                    if link not in fetched and link not in pending:
                        pending.append(link)
                if self._ssrf_navigation:
                    for link in reversed(_data_navigation_links(body, url)):
                        if not _same_origin(link, origin):
                            continue
                        pending_surface_ids[link] = remember(
                            link, "GET", _query_names(link), _query_pairs(link),
                            discovery_types=("html_data_navigation",),
                        )
                        pending_discovery_types.setdefault(link, set()).add(
                            "html_data_navigation"
                        )
                        if link not in fetched and link not in pending:
                            pending.insert(0, link)
                for source in sources:
                    if source not in scripts and _same_origin(source, origin):
                        scripts.append(source)
                    if _same_origin(source, origin) and len(script_references_seen) < 200:
                        reference_key = (surface_id, source)
                        if reference_key not in script_references_seen:
                            script_references_seen.add(reference_key)
                            script_surface_id = remember(
                                source, "GET", (), discovery_types=("html_script_reference",),
                            )
                            reference = Evidence(
                                evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                                surface_id=script_surface_id, created_by="recon",
                                evidence_type="observation", source_task_id=task.task_id,
                                observation={
                                    "type": "client_script_reference",
                                    "document_surface_id": surface_id,
                                },
                            )
                            self._evidence.append(reference)
                            evidence_ids.append(reference.evidence_id)
                # Executable inline scripts can declare routes that do not
                # appear in anchors or external bundles. Record their shapes
                # now, but defer document visits until linked scripts have had
                # their reserved Recon slots.
                for inline_body in inline_scripts:
                    record_postmessage_plans(surface_id, inline_body)
                    if inline_path_count >= _MAX_INLINE_SCRIPT_PATHS:
                        break
                    for script_url, names, should_crawl, is_navigation in _script_paths_from_body(
                        inline_body, origin, url
                    ):
                        if inline_path_count >= _MAX_INLINE_SCRIPT_PATHS:
                            break
                        shape = (script_url, names)
                        if shape in inline_seen_shapes:
                            continue
                        inline_seen_shapes.add(shape)
                        inline_path_count += 1
                        pending_surface_ids[script_url] = remember(
                            script_url, "GET", names,
                            discovery_types=("inline_script_literal",),
                        )
                        pending_discovery_types.setdefault(script_url, set()).add(
                            "inline_script_literal"
                        )
                        ssrf_document = (
                            self._ssrf_navigation
                            and ssrf_inline_docs_queued < 8
                            and urlsplit(script_url).path.casefold().endswith(".html")
                        )
                        if should_crawl or ssrf_document:
                            document_pages.add(script_url)
                            if script_url not in fetched and script_url not in deferred_inline_urls:
                                deferred_inline_urls.append(script_url)
                                ssrf_inline_docs_queued += int(ssrf_document)
                        if is_navigation:
                            navigation_pages.add(script_url)
            return visited

        # 비교 모드에서도 사용자가 지정한 시작 URL은 항상 먼저 본다.
        initial_urls = tuple(pending)
        crawl(
            protected=initial_urls,
            max_visits=(len(initial_urls) if self._iterative_planner is not None else None),
        )
        # Observed inline document routes take precedence over speculative
        # OpenAPI/GraphQL locations. They remain pending while external scripts
        # use their reserved fetch slots below.
        for url in deferred_inline_urls:
            if url not in fetched and url not in pending:
                pending.append(url)

        # 번들 분석은 크롤링 뒤에 한다. 남은 예산 안에서만 스크립트를 받는다.
        affordable = max(min(self._max_scripts, page_budget - len(fetched)), 0)
        script_sources = sorted(
            scripts,
            key=lambda source: (
                _script_priority(source),
                _deterministic_url_key(source)
                if self._surface_collection_mode == "deterministic" else scripts.index(source),
            ),
        )
        for source in script_sources[:affordable]:
            if remaining_work() < 1.0:
                deadline_exhausted = True
                break
            fetched.add(source)
            script_paths, script_requests, script_evidence, script_parsed = self._discover_from_script(
                task,
                source,
                origin,
                javascript_globals,
                timeout_seconds=remaining_work(),
            )
            record_response(source, script_evidence)
            if script_parsed:
                parsed.add(source)
                script_body = script_evidence.observation.get("body")
                if isinstance(script_body, str):
                    script_surface_id = remember(
                        source, "GET", (), discovery_types=("javascript_response",),
                    )
                    record_ssrf_destination_hints(
                        script_surface_id, script_body,
                        script_evidence.evidence_id, script_evidence,
                    )
                    for document_id, script_url in script_references_seen:
                        if script_url == source:
                            record_postmessage_plans(document_id, script_body)
                    remember_source_maps(source, script_body, script_evidence.evidence_id)
                    exposed_fields = exposed_json_field_paths(script_evidence.observation)
                    if exposed_fields:
                        script_surface_id = remember(
                            source, "GET", (), discovery_types=("javascript_response",),
                        )
                        record_sensitive_exposure(script_surface_id, exposed_fields)
                    if script_evidence.observation.get(TRUSTED_LOGIN_PAIR_COUNT):
                        script_surface_id = remember(
                            source, "GET", (), discovery_types=("javascript_response",),
                        )
                        record_public_login_pairs(script_surface_id, script_evidence)
                    for url, method, names in _script_mutation_shapes(script_body, origin):
                        record_script_request_shape(
                            url, method, names, "script_request_shape"
                        )
                    record_ssrf_json_shapes(script_body, "javascript_json_request")
            for url, names, should_crawl, is_navigation in script_paths:
                discovery_type = (
                    "browser_navigation" if is_navigation else "script_literal"
                )
                pending_surface_ids[url] = remember(
                    url, "GET", names, discovery_types=(discovery_type,)
                )
                pending_discovery_types.setdefault(url, set()).add(discovery_type)
                # 번들이 가리킨 디렉터리와 서버 문서 navigation은 실제 응답을 봐야
                # 내부 파일이나 HTML 폼을 발견할 수 있다.
                if should_crawl:
                    document_pages.add(url)
                # 그중 실제 문서 이동만 Planner가 뒤로 밀 수 없는 보호 대상이다.
                # 디렉터리 추측과 달리 여기에 서버 렌더링 폼이 실제로 들어 있다.
                if is_navigation:
                    navigation_pages.add(url)
                # 기존 heuristic/hybrid는 문서·디렉터리만 방문한다. Agentic 경로는
                # 정답 seed 없이도 실제 JS/API 관찰에서 다음 GET을 고를 수 있어야
                # 하므로, 동일 origin에서 발견한 모든 GET Surface를 frontier에 둔다.
                if (
                    should_crawl or self._iterative_planner is not None
                ) and url not in fetched and url not in pending:
                    pending.append(url)
            for request_url, method, fields in script_requests:
                if not _same_origin(request_url, origin):
                    continue
                remember(
                    request_url,
                    method,
                    tuple(name for name, _ in fields),
                    observed=fields,
                    discovery_types=("javascript_request",),
                )

        # A public OpenAPI document provides request shapes without sending
        # mutations. Probe one conventional location only for a root-scoped
        # crawl with spare Recon budget. Declared body fields are not a valid
        # request template and do not authorize POST analysis.
        def probe_public_openapi() -> None:
            nonlocal api_schema_found
            # A root page with no useful links can still expose a machine-readable
            # API description. Try one conventional path for ordinary sites and
            # two more only when Recon has found almost no attack surface. This
            # is a bounded read-only discovery step, never a POST template.
            sparse_root = len(surfaces) <= 1 and len(fetched) <= 3
            paths = _SPARSE_OPENAPI_PATHS if sparse_root else _SPARSE_OPENAPI_PATHS[:1]
            for path in paths:
                if len(fetched) >= page_budget or remaining_work() < 1.0:
                    break
                schema_url = f"{origin.scheme}://{origin.netloc}{path}"
                if schema_url in fetched:
                    continue
                fetched.add(schema_url)
                schema_evidence_id, schema_evidence = self._fetch(
                    task, schema_url, None, timeout_seconds=remaining_work()
                )
                evidence_ids.append(schema_evidence_id)
                record_response(schema_url, schema_evidence)
                schema_surfaces = _openapi_literal_surfaces(schema_evidence, origin)
                if _openapi_document(schema_evidence) is None:
                    continue
                api_schema_found = True
                parsed.add(schema_url)
                schema_surface_id = remember(
                    schema_url, "GET", (), discovery_types=("openapi_document",),
                )
                schema_body = schema_evidence.observation.get("body")
                if isinstance(schema_body, str) and schema_body:
                    record_ssrf_destination_hints(
                        schema_surface_id, schema_body, schema_evidence_id,
                        schema_evidence,
                    )
                remember_schema(
                    schema_surfaces, schema_evidence_id,
                    _openapi_collection_templates(schema_evidence, origin),
                )
                if pending:
                    crawl(max_visits=2)
                break

        if (
            not targeted and not pending and not api_schema_found
            and origin.path in {"", "/"}
            and not origin.query and not origin.fragment
        ):
            probe_public_openapi()

        # GraphQL introspection is a read-only schema request. Query and
        # mutation names are discovery evidence only; they are not valid
        # replayable requests or authorization to execute a mutation.
        if (
            not targeted and not pending and not api_schema_found
            and origin.path in {"", "/"} and not origin.query and not origin.fragment
            and len(surfaces) <= 1 and len(fetched) < page_budget
            and remaining_work() >= 1.0
        ):
            graphql_endpoint = f"{origin.scheme}://{origin.netloc}/graphql"
            graphql_url = graphql_endpoint + "?" + urlencode({"query": INTROSPECTION_QUERY})
            fetched.add(graphql_url)
            graphql_evidence_id, graphql_evidence = self._fetch(
                task, graphql_url, None, timeout_seconds=remaining_work()
            )
            evidence_ids.append(graphql_evidence_id)
            record_response(graphql_url, graphql_evidence)
            operations = graphql_schema_operations(graphql_evidence.observation)
            if operations:
                parsed.add(graphql_url)
                graphql_surface_id = remember(
                    graphql_endpoint, "GET", (),
                    discovery_types=("graphql_introspection",),
                )
                schema_observation = Evidence(
                    evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                    surface_id=graphql_surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": INTROSPECTION_RECON_OBSERVATION,
                        "schema_evidence_id": graphql_evidence_id,
                    },
                )
                self._evidence.append(schema_observation)
                evidence_ids.append(schema_observation.evidence_id)
                error_probe = Evidence(
                    evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                    surface_id=graphql_surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": ERROR_GRAPHQL_OBSERVATION,
                        "schema_evidence_id": graphql_evidence_id,
                    },
                )
                self._evidence.append(error_probe)
                evidence_ids.append(error_probe.evidence_id)
                selected_suggestion = suggestion_plan(operations)
                if selected_suggestion is not None:
                    suggestion_observation = Evidence(
                        evidence_id=f"evi-{self._id_factory()}", run_id=task.run_id,
                        surface_id=graphql_surface_id, created_by="recon",
                        evidence_type="observation", source_task_id=task.task_id,
                        observation={
                            "type": SUGGESTION_PLAN,
                            "field": selected_suggestion[0],
                            "typo": selected_suggestion[1],
                            "schema_evidence_id": graphql_evidence_id,
                        },
                    )
                    self._evidence.append(suggestion_observation)
                    evidence_ids.append(suggestion_observation.evidence_id)
                for kind, name in operations:
                    operation_id = f"evi-{self._id_factory()}"
                    self._evidence.append(Evidence(
                        evidence_id=operation_id, run_id=task.run_id,
                        surface_id=graphql_surface_id, created_by="recon",
                        evidence_type="observation", source_task_id=task.task_id,
                        observation={
                            "type": GRAPHQL_SCHEMA_OPERATION,
                            "graphql_kind": kind, "operation": name,
                            "schema_evidence_id": graphql_evidence_id,
                        },
                    ))
                    evidence_ids.append(operation_id)
                query_inputs = graphql_schema_query_inputs(graphql_evidence.observation)
                if query_inputs:
                    plan_id = f"evi-{self._id_factory()}"
                    self._evidence.append(Evidence(
                        evidence_id=plan_id, run_id=task.run_id,
                        surface_id=graphql_surface_id, created_by="recon",
                        evidence_type="observation", source_task_id=task.task_id,
                        observation={
                            "type": GRAPHQL_READ_QUERY_PLAN,
                            "schema_evidence_id": graphql_evidence_id,
                            "plans": [
                                {
                                    "field": plan.field,
                                    "argument": plan.argument,
                                    "select_typename": plan.select_typename,
                                }
                                for plan in query_inputs
                            ],
                        },
                    ))
                    evidence_ids.append(plan_id)

        round_index = 0
        provider_fallback_status: str | None = None
        browser_llm_reserve = int(
            self._browser_recon is not None
            and not targeted
            and self._surface_collection_mode != "deterministic"
        )
        if self._iterative_planner is not None and pending and not targeted:
            llm_calls = 0
            while pending and len(fetched) < page_budget:
                if remaining_work() < 1.0:
                    deadline_exhausted = True
                    break
                if (
                    llm_calls >= _MAX_AGENTIC_LLM_CALLS - browser_llm_reserve
                    and provider_fallback_status is None
                ):
                    provider_fallback_status = (
                        "fallback:browser_call_reserve"
                        if browser_llm_reserve else "fallback:llm_call_limit"
                    )
                if self._surface_collection_mode == "deterministic" or provider_fallback_status:
                    pending[:] = _deterministic_pending(pending, navigation_pages, inbound_documents)
                remaining_budget = max(page_budget - len(fetched), 0)
                candidates = self._recon_candidates(
                    task.run_id, pending, pending_surface_ids
                )
                selectable_surface_ids = tuple(
                    dict.fromkeys(candidate.surface_id for candidate in candidates)
                )[:_MAX_AGENTIC_SELECTABLE]
                if not selectable_surface_ids:
                    stop_reason = "no_available_surface"
                    break
                observations = self._recon_observations(
                    task.run_id,
                    surface_discovery_types,
                    fetched,
                    selectable_surface_ids,
                    context_surface_ids=tuple(recently_fetched_surface_ids),
                )
                llm_timeout = min(
                    _MAX_AGENTIC_LLM_CALL_SECONDS, remaining_work() / 2
                )
                planner_task = replace(task, timeout_seconds=2 * llm_timeout)
                action, action_evidence_id, executed_surface_id, llm_called = self._next_action(
                    planner_task,
                    observations,
                    selectable_surface_ids,
                    remaining_budget,
                    round_index,
                    provider_fallback_status=provider_fallback_status,
                )
                llm_calls += int(llm_called)
                if action.status in {
                    "fallback:timeout", "fallback:transport_error", "fallback:refused"
                }:
                    provider_fallback_status = action.status
                evidence_ids.append(action_evidence_id)
                planner_status = recon_action_status_detail(action)
                if action.action == "stop" or executed_surface_id is None:
                    stop_reason = "planner_stop"
                    break

                url_by_surface_id: dict[str, str] = {}
                for url in pending:
                    surface_id = pending_surface_ids.get(url)
                    if surface_id is not None:
                        url_by_surface_id.setdefault(surface_id, url)
                selected_url = url_by_surface_id.get(executed_surface_id)
                if selected_url is None:
                    stop_reason = "selected_surface_missing"
                    break
                pending.remove(selected_url)
                pending.insert(0, selected_url)
                if crawl(max_visits=1) != 1:
                    stop_reason = "time_budget" if deadline_exhausted else "visit_unavailable"
                    break
                round_index += 1

        elif self._planner is not None and pending and not targeted:
            remaining_budget = max(page_budget - len(fetched), 0)
            candidates = self._recon_candidates(task.run_id, pending, pending_surface_ids)
            if candidates:
                plan, plan_evidence_id = self._plan(task, candidates, remaining_budget)
                evidence_ids.append(plan_evidence_id)
                planner_status = recon_plan_status_detail(plan)
                if self._surface_collection_mode == "deterministic":
                    # Planner 호출·결과는 감사를 위해 남기되 방문 집합은
                    # LLM 순서·stop에 좌우되지 않게 고정한다.
                    pending[:] = _deterministic_pending(pending, navigation_pages, inbound_documents)
                else:
                    pending[:] = self._apply_plan(
                        plan, pending, pending_surface_ids, navigation_pages
                    )

        # 번들에서 찾은 디렉터리 목록(또는 Planner가 고른 순서)을 남은 예산 안에서 마저 본다.
        if self._iterative_planner is None:
            crawl(protected=navigation_pages)

        # Agentic Recon defers observed links to its planner. If the only link
        # failed, the earlier schema check was skipped while that link was
        # pending; revisit the same bounded read-only fallback now.
        if (
            self._iterative_planner is not None and not targeted
            and not pending and not api_schema_found
            and origin.path in {"", "/"}
            and not origin.query and not origin.fragment
            and len(successful) == 1 and len(surfaces) <= 2
        ):
            probe_public_openapi()

        if deadline_exhausted and self._iterative_planner is not None:
            planner_status = "agentic_recon:fallback:time_budget"

        if self._iterative_planner is not None and pending and not targeted:
            unfetched_ids = tuple(dict.fromkeys(
                pending_surface_ids[url] for url in pending
                if url not in fetched and url in pending_surface_ids
            ))
            unregistered_hashes = tuple(dict.fromkeys(
                private_url_fingerprint(url)
                for url in pending
                if url not in fetched and url not in pending_surface_ids
            ))
            if unfetched_ids or unregistered_hashes:
                summary = {
                    "type": "recon_collection_summary",
                    "attempted_url_count": len(fetched),
                    "response_url_count": len(responded),
                    "fetched_url_count": len(successful),
                    "parsed_url_count": len(parsed),
                    "llm_call_count": llm_calls,
                    "fetched_surface_ids": sorted({
                        pending_surface_ids[url] for url in successful
                        if url in pending_surface_ids
                    }),
                    "unfetched_surface_ids": list(unfetched_ids),
                    "unfetched_url_hashes": list(unregistered_hashes),
                    "unfetched_count": len(unfetched_ids) + len(unregistered_hashes),
                    "reason": (
                        "time_budget" if deadline_exhausted else
                        stop_reason or
                        ("request_budget" if len(fetched) >= page_budget else "not_selected")
                    ),
                    "fallback_status": provider_fallback_status,
                }
                existing_summary = next((
                    item for item in self._evidence.list_by_run(task.run_id)
                    if item.created_by == AGENTIC_RECON_PLANNER
                    and item.observation == summary
                ), None)
                if existing_summary is None:
                    summary_id = f"evi-{self._id_factory()}"
                    self._evidence.append(Evidence(
                        evidence_id=summary_id, run_id=task.run_id,
                        surface_id=None, created_by=AGENTIC_RECON_PLANNER,
                        evidence_type="observation", observation=summary,
                    ))
                else:
                    summary_id = existing_summary.evidence_id
                evidence_ids.append(summary_id)

        # Search documents sometimes have no form or advertised query shape.
        # Spend at most two otherwise unused GET slots on an inert echo check;
        # a parameter becomes a Surface only after the server reflects it.
        search_marker = "hacklipse-search-control"
        search_probed: set[str] = set()

        def probe_search_pages() -> None:
            for search_url, baseline_body in list(unparameterized_search_pages.items()):
                if len(search_probed) >= 2 or len(fetched) >= page_budget:
                    break
                if remaining_work() < 1.0:
                    break
                if (
                    search_url in search_probed or search_marker in baseline_body
                    or has_state_changing_get(search_url)
                ):
                    continue
                search_key = _canonical_surface_url(
                    search_url, _path_identifier(search_url)
                )
                if any(
                    known_url == search_key and method == "GET" and "q" in names
                    for known_url, method, names in surfaces
                ):
                    continue
                probe_url = search_url + "?" + urlencode({"q": search_marker})
                if probe_url in fetched:
                    continue
                search_probed.add(search_url)
                fetched.add(probe_url)
                probe_evidence_id, probe_evidence = self._fetch(
                    task, probe_url, None, timeout_seconds=remaining_work()
                )
                evidence_ids.append(probe_evidence_id)
                record_response(probe_url, probe_evidence)
                probe_body = probe_evidence.observation.get("body")
                if (
                    probe_url in successful and isinstance(probe_body, str)
                    and search_marker in probe_body
                ):
                    sid = remember(
                        probe_url, "GET", ("q",), (("q", search_marker),),
                        ("observed_search_parameter",),
                    )
                    pending_surface_ids[probe_url] = sid
                    recently_fetched_surface_ids.append(sid)
                    del recently_fetched_surface_ids[:-_MAX_AGENTIC_CONTEXT]

        probe_search_pages()

        # An observed upload endpoint may expose UEditor's read-only config.
        # Its declared catcher action and field are useful coordinates, but
        # the config request still passes through the central PolicyGate.
        if not targeted and remaining_work() >= 1.0:
            editor_paths = sorted({
                url for url, method, _ in surfaces
                if method == "GET"
                and "upload" in urlsplit(url).path.casefold().split("/")
                and _same_origin(url, origin)
            })
            for editor_path in editor_paths[:1]:
                config_url = editor_path + "?" + urlencode({
                    "from": "ueditor", "action": "config",
                })
                if config_url in fetched:
                    continue
                try:
                    config_id, config_evidence = self._fetch(
                        task, config_url, None,
                        timeout_seconds=remaining_work(),
                    )
                except (ApprovalRequired, PolicyViolation, BudgetExceeded):
                    break
                fetched.add(config_url)
                evidence_ids.append(config_id)
                record_response(config_url, config_evidence)
                shape = _ueditor_catcher_shape(config_evidence)
                if shape is None:
                    break
                action, field = shape
                surface_id = remember(
                    editor_path, "GET", ("from", "action", field),
                    (("from", "ueditor"), ("action", action)),
                    ("ueditor_catcher_declaration",),
                )
                shape_id = f"evi-{self._id_factory()}"
                self._evidence.append(Evidence(
                    evidence_id=shape_id, run_id=task.run_id,
                    surface_id=surface_id, created_by="recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation={
                        "type": SSRF_EDITOR_CATCHER_STRUCTURE,
                        "source_evidence_id": config_id,
                        "method": "GET",
                        "query_parameter_names": [field],
                        "request_template_available": False,
                    },
                ))
                evidence_ids.append(shape_id)
                break

        if self._browser_recon is not None and not targeted:
            browser_budget = max(0, int(task.request_budget * _RECON_BUDGET_SHARE) - len(fetched))
            if browser_budget and remaining_work() > 1.0:
                browser_decisions = 0
                browser_llm_calls = 0

                def select_browser_page(
                    options: tuple[tuple[str, str], ...],
                    remaining_budget: int,
                    browser_seconds: float,
                ) -> str | None:
                    nonlocal browser_decisions, browser_llm_calls, planner_status
                    if (
                        self._iterative_planner is None
                        or self._surface_collection_mode == "deterministic"
                        or browser_decisions >= 1
                        or provider_fallback_status in {
                            "fallback:timeout", "fallback:transport_error", "fallback:refused"
                        }
                    ):
                        return None
                    llm_timeout = min(
                        _MAX_AGENTIC_LLM_CALL_SECONDS,
                        remaining_work() / 2,
                        browser_seconds / 2,
                    )
                    if llm_timeout < 1.0:
                        return None
                    offered = options[:_MAX_AGENTIC_SELECTABLE]
                    surface_ids = tuple(dict.fromkeys(sid for _, sid in offered))
                    observations = self._recon_observations(
                        task.run_id, surface_discovery_types, fetched,
                        surface_ids,
                        context_surface_ids=tuple(recently_fetched_surface_ids),
                    )
                    action, evidence_id, selected_id, called = self._next_action(
                        replace(task, timeout_seconds=2 * llm_timeout),
                        observations, surface_ids, remaining_budget,
                        round_index + browser_decisions,
                    )
                    browser_decisions += 1
                    browser_llm_calls += int(called)
                    evidence_ids.append(evidence_id)
                    planner_status = recon_action_status_detail(action)
                    if action.source != "llm" or selected_id is None:
                        return None
                    return next((url for url, sid in offered if sid == selected_id), None)

                discovery = self._browser_recon.discover(
                    task, remember=remember, request_budget=browser_budget,
                    timeout_seconds=remaining_work(),
                    document_seed_urls=tuple(sorted(
                        browser_document_seeds,
                        key=lambda url: (
                            -browser_document_seeds[url], _deterministic_url_key(url)
                        ),
                    )[:4]),
                    select_next=(
                        select_browser_page if self._iterative_planner is not None else None
                    ),
                )
                evidence_ids.extend(discovery.evidence_ids)
                script_documents: dict[str, set[str]] = {}
                for document_id, source_url in script_references_seen:
                    script_documents.setdefault(source_url, set()).add(document_id)
                for script_id, reference in discovery.observations:
                    if (
                        reference.get("type") != "client_script_reference"
                        or script_id is None
                        or not isinstance(reference.get("document_surface_id"), str)
                    ):
                        continue
                    source_url = self._surfaces.get(
                        task.run_id, script_id,
                    ).url
                    script_documents.setdefault(source_url, set()).add(
                        reference["document_surface_id"]
                    )
                # Browser-loaded scripts and JSON have already passed through
                # the shared collector. Parse their bounded responses without
                # another request or sending any form submission.
                browser_scripts_parsed = 0
                browser_json_link_responses = 0
                browser_schema_responses = 0
                for browser_evidence_id in discovery.evidence_ids:
                    browser_evidence = self._evidence.get(task.run_id, browser_evidence_id)
                    script_url = browser_evidence.observation.get("requested_url")
                    body = browser_evidence.observation.get("body")
                    status = browser_evidence.observation.get("status")
                    if (
                        browser_evidence.evidence_type != "http_response"
                        or not isinstance(script_url, str)
                        or not _same_origin(script_url, origin)
                        or type(status) is not int or not 200 <= status < 300
                        or browser_evidence.observation.get("truncated")
                        or not isinstance(body, str) or not body
                        or len(body) > _MAX_SCRIPT_BYTES
                    ):
                        continue
                    hint_surface_id = browser_evidence.surface_id or remember(
                        script_url, "GET", (),
                        discovery_types=("browser_observed_response",),
                    )
                    record_ssrf_destination_hints(
                        hint_surface_id, body, browser_evidence_id, browser_evidence,
                    )
                    browser_location = urlsplit(script_url)
                    if (
                        _is_html_response(browser_evidence)
                        and not browser_location.query and not browser_location.fragment
                        and browser_location.path.rstrip("/").rsplit("/", 1)[-1].casefold()
                        in {"search", "find", "lookup"}
                        and len(body) <= 64_000
                    ):
                        unparameterized_search_pages.setdefault(script_url, body)
                    if _javascript_response(browser_evidence):
                        # Message plans need only bounded source inspection, and
                        # must not be lost when endpoint extraction has already
                        # reached its separate JavaScript parse cap.
                        for document_id in script_documents.get(script_url, ()):
                            record_postmessage_plans(document_id, body)
                        if browser_evidence.observation.get(TRUSTED_LOGIN_PAIR_COUNT):
                            script_surface_id = remember(
                                script_url, "GET", (),
                                discovery_types=("browser_javascript_response",),
                            )
                            record_public_login_pairs(script_surface_id, browser_evidence)
                        if script_url in parsed or browser_scripts_parsed >= self._max_scripts:
                            continue
                        parsed.add(script_url)
                        browser_scripts_parsed += 1
                        remember_source_maps(script_url, body, browser_evidence_id)
                        exposed_fields = exposed_json_field_paths(browser_evidence.observation)
                        if exposed_fields:
                            script_surface_id = remember(
                                script_url, "GET", (),
                                discovery_types=("browser_javascript_response",),
                            )
                            record_sensitive_exposure(script_surface_id, exposed_fields)
                        for url, method, names in _script_mutation_shapes(body, origin):
                            record_script_request_shape(
                                url, method, names, "browser_script_request_shape"
                            )
                        record_ssrf_json_shapes(body, "browser_javascript_json_request")
                        for url, names, _, _ in _script_paths_from_body(
                            body, origin, script_url,
                        ):
                            if _same_origin(url, origin):
                                remember(url, "GET", names,
                                         discovery_types=("browser_script_literal",))
                        continue
                    if browser_evidence.surface_id is not None:
                        browser_surface = self._surfaces.get(
                            task.run_id, browser_evidence.surface_id
                        )
                        if browser_surface.method == "GET":
                            record_sensitive_exposure(
                                browser_evidence.surface_id,
                                exposed_json_field_paths(browser_evidence.observation),
                            )
                    schema_surfaces = _openapi_literal_surfaces(browser_evidence, origin)
                    if _openapi_document(browser_evidence) is not None:
                        parsed.add(script_url)
                        browser_schema_responses += 1
                        remember_schema(
                            schema_surfaces, browser_evidence_id,
                            _openapi_collection_templates(browser_evidence, origin),
                        )
                        continue
                    json_links = _json_links_from_response(browser_evidence, script_url)
                    if json_links:
                        parsed.add(script_url)
                        browser_json_link_responses += 1
                        for url in json_links:
                            remember(url, "GET", _query_names(url), _query_pairs(url),
                                     discovery_types=("browser_json_link",))
                probe_search_pages()
                observations = tuple(
                    (surface_id, {
                        **observation,
                        "planner_llm_call_count": browser_llm_calls,
                        "parsed_script_count": browser_scripts_parsed,
                        "parsed_json_link_response_count": browser_json_link_responses,
                        "parsed_schema_response_count": browser_schema_responses,
                    } if observation.get("type") == "browser_recon_summary" else observation)
                    for surface_id, observation in discovery.observations
                )
            else:
                observations = ((None, {
                    "type": "browser_recon_summary", "status": "skipped",
                    "stop_reason": "request_budget" if not browser_budget else "time_budget",
                }),)
            for surface_id, observation in observations:
                evidence_id = f"evi-{self._id_factory()}"
                self._evidence.append(Evidence(
                    evidence_id=evidence_id, run_id=task.run_id,
                    surface_id=surface_id, created_by="browser_recon",
                    evidence_type="observation", source_task_id=task.task_id,
                    observation=observation,
                ))
                evidence_ids.append(evidence_id)

        # The agentic planner emits its own decision trace. This compact
        # collection trace also covers heuristic runs and distinguishes URLs
        # attempted, responded to, and actually parsed. Never store raw pending
        # URLs, which can contain session or query values.
        unvisited_ids = tuple(dict.fromkeys(
            pending_surface_ids[url] for url in pending
            if url not in fetched and url in pending_surface_ids
        ))
        unvisited_hashes = tuple(dict.fromkeys(
            private_url_fingerprint(url)
            for url in pending
            if url not in fetched and url not in pending_surface_ids
        ))

        evidence_ids.extend(self._record_ssrf_url_fetch_reviews(task))
        response_surface_ids = {
            item.surface_id for item in self._evidence.list_by_run(task.run_id)
            if item.surface_id is not None
            and item.evidence_type == "http_response"
            and type(item.observation.get("status")) is int
            and 100 <= item.observation["status"] <= 599
        }
        discovered_without_response_ids = tuple(
            surface.surface_id for surface in self._surfaces.list_by_run(task.run_id)
            if surface.surface_id not in response_surface_ids
        )
        collection_summary = {
            "type": "recon_frontier_summary",
            "attempted_url_count": len(fetched),
            "response_url_count": len(responded),
            "successful_url_count": len(successful),
            "parsed_url_count": len(parsed),
            "unvisited_surface_ids": list(unvisited_ids),
            "unvisited_url_hashes": list(unvisited_hashes),
            "unvisited_count": len(unvisited_ids) + len(unvisited_hashes),
            "discovered_without_response_surface_count": len(discovered_without_response_ids),
            "discovered_without_response_surface_ids": list(discovered_without_response_ids[:200]),
            "stop_reason": (
                "time_budget" if deadline_exhausted else
                "request_budget" if pending and len(fetched) >= page_budget else
                stop_reason or "not_selected" if pending else "frontier_exhausted"
            ),
        }
        summary_id = f"evi-{self._id_factory()}"
        self._evidence.append(Evidence(
            evidence_id=summary_id, run_id=task.run_id,
            surface_id=None, created_by="recon",
            evidence_type="observation", source_task_id=task.task_id,
            observation=collection_summary,
        ))
        evidence_ids.append(summary_id)

        surface_ids = list(surfaces.values())
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(dict.fromkeys(evidence_ids)),
            surface_ids=tuple(dict.fromkeys(surface_ids)),
            message=planner_status,
        )

    def _record_ssrf_url_fetch_reviews(self, task: TaskEnvelope) -> tuple[str, ...]:
        """Record URL/value-free passive review facts without routing a Candidate."""

        run_evidence = tuple(self._evidence.list_by_run(task.run_id))
        reviewed = {
            item.surface_id for item in run_evidence
            if item.created_by == "recon"
            and item.observation.get("type") == SSRF_URL_FETCH_REVIEW_TYPE
            and item.surface_id is not None
        }
        created: list[str] = []
        for surface in sorted(
            self._surfaces.list_by_run(task.run_id), key=lambda item: item.surface_id
        ):
            if surface.surface_id in reviewed:
                continue
            coordinates = ssrf_parameter_sources(surface, run_evidence)
            if not coordinates:
                continue
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=surface.surface_id,
                created_by="recon",
                evidence_type="observation",
                source_task_id=task.task_id,
                observation={
                    "type": SSRF_URL_FETCH_REVIEW_TYPE,
                    "status": "REVIEW_REQUIRED",
                    "reason_code": "ssrf_manual_review_required",
                    "method": surface.method.upper(),
                    "parameter_names": [name for name, _ in coordinates],
                    "parameter_sources": [
                        {"name": name, "source": source}
                        for name, source in coordinates
                    ],
                    "manual_analysis_completed": False,
                    "observation_recorded": False,
                    "verification_performed": False,
                },
            ))
            created.append(evidence_id)
            reviewed.add(surface.surface_id)
        return tuple(created)

    def _page_budget(self, task: TaskEnvelope) -> int:
        """정찰이 쓸 요청 수. 뒤 단계가 쓸 예산을 남긴다."""

        if task.request_budget <= 0:
            return 1
        share = max(int(task.request_budget * _RECON_BUDGET_SHARE), 1)
        return max(min(self._max_pages, share), 1)

    def _fetch(
        self, task: TaskEnvelope, url: str, surface_id: str | None,
        *, timeout_seconds: float | None = None,
    ) -> tuple[str, Evidence]:
        """중앙 수집 경계를 거쳐 한 문서를 가져온다."""

        evidence_id = self._collector.collect(
            task.run_id,
            url,
            EvidenceRequest(
                evidence_type="page_fetch",
                surface_id=surface_id,
                reason=f"recon fetch of {url}",
                suggested_tool=RECON_TOOL,
            ),
            task_id=task.task_id,
            timeout_seconds=min(task.timeout_seconds, timeout_seconds or task.timeout_seconds),
            # Recon은 특정 취약점 Agent가 아니므로 Run 기본 세션을 쓴다. TaskFactory가
            # 선택한 참조를 전달하지 않으면 다중 취약점 Run에서 무인증으로 바뀐다.
            credential_ref=task.credential_ref,
        )
        return evidence_id, self._evidence.get(task.run_id, evidence_id)

    def _discover_from_script(
        self,
        task: TaskEnvelope,
        source: str,
        origin,
        javascript_globals: dict[tuple[str, str], str] | None = None,
        *, timeout_seconds: float | None = None,
    ) -> tuple[
        list[tuple[str, tuple[str, ...], bool, bool]],
        list[tuple[str, str, tuple[tuple[str, str], ...]]],
        Evidence,
        bool,
    ]:
        """JS 번들을 받아 경로 리터럴에서 Surface 후보를 만든다."""

        _, evidence = self._fetch(task, source, None, timeout_seconds=timeout_seconds)
        status = evidence.observation.get("status")
        body = evidence.observation.get("body")
        if (
            evidence.evidence_type != "http_response"
            or type(status) is not int or not 200 <= status < 300
            or not isinstance(body, str) or not body or len(body) > _MAX_SCRIPT_BYTES
        ):
            return [], [], evidence, False

        return (
            _script_paths_from_body(body, origin, source),
            _javascript_requests(body, source, javascript_globals or {}),
            evidence,
            True,
        )

    def _store_surface(
        self,
        run_id: str,
        surface_id: str,
        url: str,
        method: str,
        params: tuple[str, ...],
        *,
        observed: tuple[tuple[str, str], ...] = (),
        path_identifier: tuple[str, int, str] | None = None,
        path_assignment: PathAssignment | None = None,
        discovery_types: tuple[str, ...] = (),
    ) -> None:
        path_name, path_index, path_value = path_identifier or (None, None, None)
        self._surfaces.add(
            Surface(
                surface_id=surface_id,
                run_id=run_id,
                url=url,
                method=method,
                parameters=params,
                observed_query=observed,
                path_identifier=path_name,
                path_identifier_index=path_index,
                observed_path_identifier=path_value,
                path_assignment=path_assignment,
                discovery_types=discovery_types,
            )
        )

    def _flag_restricted_file(self, run_id: str, surface_id: str, url: str) -> str:
        """서버가 내주면 안 되는 확장자의 파일 표면을 Router 가 볼 수 있게 남긴다."""

        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=surface_id,
                created_by="recon",
                evidence_type="observation",
                observation={
                    "type": RESTRICTED_FILE_OBSERVATION,
                    "parameter": urlsplit(url).path.rsplit("/", 1)[-1],
                },
            )
        )
        return evidence_id

    def _flag_suspect_parameters(
        self,
        run_id: str,
        surface_id: str,
        params: tuple[str, ...],
        url: str,
        method: str,
        observed: tuple[tuple[str, str], ...] = (),
    ) -> list[str]:
        """파일·URL로 보이는 파라미터만 Observation으로 남긴다.

        세 가지 근거를 쓴다. 이름이 파일 힌트인 경우, 파일을 내보내는 GET 경로에서
        filename류 이름이 나온 경우, 그리고 이름은 힌트가 아니지만 **관측된 값**이
        파일명이나 경로인 경우다. 마지막 근거가 없으면 ``post.php?id=EternalBlue.php``
        처럼 이름만으로는 알 수 없는 좌표를 놓친다.
        """

        values: dict[str, list[str]] = {}
        for name, value in observed:
            values.setdefault(name, []).append(value)
        evidence_ids: list[str] = []
        for name in params:
            if _looks_like_file_or_url_parameter(name):
                observation_type = "url_or_file_parameter"
                basis = "name"
            elif method.upper() == "GET" and _looks_like_file_serving_parameter(url, name):
                observation_type = "file_serving_parameter"
                basis = "file_serving_route"
            elif any(_looks_like_file_value(value) for value in values.get(name, ())):
                # 이름으로는 알 수 없고 관측된 값이 파일명인 좌표.
                observation_type = "url_or_file_parameter"
                basis = "observed_value"
            else:
                continue
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    surface_id=surface_id,
                    created_by="recon",
                    evidence_type="observation",
                    observation={
                        "type": observation_type,
                        "parameter": name,
                        "basis": basis,
                    },
                )
            )
            evidence_ids.append(evidence_id)
        return evidence_ids

    def _flag_path_assignment(
        self,
        run_id: str,
        surface_id: str,
        assignment: PathAssignment | None,
        skip_reason: str | None,
        method: str,
        *,
        names_seen: set[str],
        skips_seen: set[str],
    ) -> list[str]:
        """경로에 실린 입력의 위치와, 그 이름이 파일형이라는 가설을 따로 남긴다.

        두 관측을 나누는 이유는 둘이 다른 주장이기 때문이다. 위치 관측은 "URL 경로에
        ``이름=값``이 있었다"는 구문 사실이고, 파일형 가설은 "그 이름이 서버의 파일을
        여는 자리로 보인다"는 해석이다. 어느 쪽도 "서버가 이를 입력으로 처리한다"는
        뜻이 아니며, 그 판정은 control/probe를 비교한 뒤에만 나온다.

        ``=``가 있었지만 좌표로 인정하지 않은 경우에는 사유만 남긴다. 추측해서 요청을
        만들지 않되, 무엇을 건너뛰었는지는 감사할 수 있어야 한다.
        """

        evidence_ids: list[str] = []
        if assignment is None:
            if skip_reason is None or skip_reason in skips_seen or len(skips_seen) >= 8:
                return evidence_ids
            skips_seen.add(skip_reason)
            evidence_ids.append(
                self._append_observation(
                    run_id,
                    surface_id,
                    {
                        "type": PATH_ASSIGNMENT_SKIPPED_OBSERVATION,
                        "reason": skip_reason,
                        "source": PATH_ASSIGNMENT_SOURCE,
                    },
                )
            )
            return evidence_ids

        evidence_ids.append(
            self._append_observation(
                run_id,
                surface_id,
                {
                    "type": PATH_ASSIGNMENT_OBSERVATION,
                    "parameter": assignment.name,
                    "location": "path_assignment",
                    "source": assignment.source,
                    # 구문 관측일 뿐이라는 것을 Evidence 자체에 남긴다. 이후 단계가
                    # 이 관측을 "검증된 서버 입력"으로 오해하지 않게 한다.
                    "interpretation": "syntactic_only",
                    "server_input_confirmed": False,
                },
            )
        )
        if (
            method.upper() != "GET"
            or not looks_like_file_parameter(assignment.name)
            or assignment.name in names_seen
            or len(names_seen) >= 4
        ):
            return evidence_ids
        names_seen.add(assignment.name)
        evidence_ids.append(
            self._append_observation(
                run_id,
                surface_id,
                {
                    "type": FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION,
                    "parameter": assignment.name,
                    "location": "path_assignment",
                    "source": PATH_ASSIGNMENT_SOURCE,
                    "server_input_confirmed": False,
                },
            )
        )
        return evidence_ids

    def _append_observation(
        self, run_id: str, surface_id: str, observation: dict[str, object]
    ) -> str:
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=surface_id,
                created_by="recon",
                evidence_type="observation",
                observation=observation,
            )
        )
        return evidence_id

    def _flag_post_form_structure(
        self, run_id: str, surface_id: str, names: tuple[str, ...]
    ) -> str:
        """Record a form-declared POST shape, not a submitted request or hidden field."""

        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=run_id,
                surface_id=surface_id,
                created_by="recon",
                evidence_type="observation",
                observation={
                    "type": "post_form_body_structure",
                    "source": "html_form",
                    "content_type": "application/x-www-form-urlencoded",
                    "field_names": list(names),
                    "observed_request": False,
                },
            )
        )
        return evidence_id

    def _infer_query_parameters(
        self,
        task: TaskEnvelope,
        url: str,
        baseline: Evidence,
        remaining: int,
    ) -> tuple[list[tuple[str, tuple[tuple[str, str], ...]]], list[str], int]:
        """마커를 실어 보내 응답을 바꾸는 GET 쿼리 좌표만 찾아낸다.

        링크나 폼이 이름을 선언해 주지 않는 좌표가 있다. XBEN-053은 ``/``에서
        ``username``을 읽지만 어디에도 그 이름이 적혀 있지 않아 정찰이 파라미터 없는
        Surface 하나만 남기고, 그러면 입력을 요구하는 모든 capability가
        input_parameter에서 떨어진다.

        이름을 찍어 Surface를 만들지는 않는다. 기준선과 비교해 마커가 응답에
        나타나거나 상태 코드가 달라진 경우만 기록한다. 둘 다 아니면 애플리케이션이
        그 좌표를 쓰지 않는다는 뜻이므로 버린다.
        """

        found: list[tuple[str, tuple[tuple[str, str], ...]]] = []
        evidence_ids: list[str] = []
        base_status = baseline.observation.get("status")
        base_body = baseline.observation.get("body")
        base_body = base_body if isinstance(base_body, str) else ""
        if _INFERENCE_MARKER in base_body:
            # 기준선에 이미 마커가 있으면 차등 비교가 성립하지 않는다.
            return found, evidence_ids, 0
        spent = 0
        for name in _INFERRED_QUERY_PARAMETERS[:_MAX_INFERENCE_NAMES]:
            if spent >= remaining:
                break
            if not safe_hidden_name(name, ()):
                continue
            probe_url = f"{url}{'&' if '?' in url else '?'}{urlencode(((name, _INFERENCE_MARKER),))}"
            evidence_id, probe = self._fetch(task, probe_url, None)
            evidence_ids.append(evidence_id)
            spent += 1
            probe_body = probe.observation.get("body")
            probe_body = probe_body if isinstance(probe_body, str) else ""
            reflected = _INFERENCE_MARKER in probe_body
            status_changed = probe.observation.get("status") != base_status
            if reflected or status_changed:
                found.append((name, ((name, _INFERENCE_MARKER),)))
        return found, evidence_ids, spent

    def _flag_unlinked_render_parameters(
        self, run_id: str, surface_id: str
    ) -> list[str]:
        """서버 렌더링 POST 폼에 제한된 비노출 옵션 후보를 남긴다."""

        evidence_ids: list[str] = []
        for name in _UNLINKED_RENDER_PARAMETERS:
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    surface_id=surface_id,
                    created_by="recon",
                    evidence_type="observation",
                    observation={
                        "type": UNLINKED_RENDER_PARAMETER_OBSERVATION,
                        "parameter": name,
                        "source": "bounded_unlinked_render_parameter",
                    },
                )
            )
            evidence_ids.append(evidence_id)
        return evidence_ids

    def _recon_candidates(
        self,
        run_id: str,
        pending: list[str],
        pending_surface_ids: dict[str, str],
    ) -> tuple[ReconCandidate, ...]:
        """호출 시점의 pending URL과 정확히 대응하는 Surface만 Planner 후보로 만든다."""

        observation_types: dict[str, list[str]] = {}
        for item in self._evidence.list_by_run(run_id):
            if item.evidence_type != "observation" or item.surface_id is None:
                continue
            observation_type = item.observation.get("type")
            if isinstance(observation_type, str):
                observation_types.setdefault(item.surface_id, []).append(
                    observation_type
                )

        candidates: list[ReconCandidate] = []
        for url in pending:
            surface_id = pending_surface_ids.get(url)
            if surface_id is None:
                continue
            surface = self._surfaces.get(run_id, surface_id)
            candidates.append(
                ReconCandidate(
                    surface_id=surface_id,
                    path=urlsplit(url).path or "/",
                    method=surface.method,
                    parameter_names=surface.parameters,
                    observation_types=tuple(
                        dict.fromkeys(observation_types.get(surface_id, ()))
                    ),
                )
            )
        return tuple(candidates)

    def _recon_observations(
        self,
        run_id: str,
        discovery_types: dict[str, set[str]],
        fetched_urls: set[str],
        focus_surface_ids: tuple[str, ...],
        *,
        context_surface_ids: tuple[str, ...] = (),
    ) -> tuple[ReconObservation, ...]:
        """Build the bounded answer-blind view for one action decision.

        The model receives every currently selectable coordinate plus only the most recent
        fetched coordinates. Older non-selectable observations remain in Evidence storage
        and the replay trace, but repeating them in every prompt does not help choose the
        next member of ``selectable_surface_ids``.
        """

        response_metadata: dict[str, tuple[int | None, str | None]] = {}
        for item in self._evidence.list_by_run(run_id):
            if item.surface_id is None or item.evidence_type != "http_response":
                continue
            status = item.observation.get("status")
            if type(status) is not int or not 100 <= status <= 599:
                status = None
            content_type = item.observation.get("content_type")
            if isinstance(content_type, str):
                content_type = _safe_recon_text(
                    content_type.split(";", 1)[0].strip().lower(), 100
                ) or None
            else:
                content_type = None
            response_metadata[item.surface_id] = (status, content_type)

        fetched_surface_urls = {
            _canonical_surface_url(
                url.split("?", 1)[0], _path_identifier(url.split("?", 1)[0])
            )
            for url in fetched_urls
        }
        observations: list[ReconObservation] = []
        for surface in self._surfaces.list_by_run(run_id):
            # A resumed run may already contain surfaces discovered in later rounds of a
            # previous attempt. Do not let that future state leak into an earlier round.
            if surface.surface_id not in discovery_types:
                continue
            metadata = (
                response_metadata.get(surface.surface_id)
                if surface.url in fetched_surface_urls
                else None
            )
            parsed = urlsplit(surface.url)
            path = parsed.path or "/"
            if parsed.fragment:
                path = f"{path}#{parsed.fragment}"
            path = _safe_recon_text(path, 512)
            if not path.startswith("/"):
                path = "/"
            observations.append(
                ReconObservation(
                    observation_id=f"recon-observation:{surface.surface_id}",
                    surface_id=surface.surface_id,
                    path=path,
                    method=surface.method.upper(),
                    parameter_names=alias_parameter_names(
                        surface.parameters
                    ).prompt_names,
                    discovery_types=tuple(
                        sorted(discovery_types.get(surface.surface_id, {"discovered"}))
                    ),
                    state="fetched" if metadata is not None else "discovered",
                    status_code=metadata[0] if metadata is not None else None,
                    content_type=metadata[1] if metadata is not None else None,
                )
            )
        focus = set(focus_surface_ids)
        context = set(context_surface_ids)
        observations = [
            item
            for item in observations
            if item.surface_id in focus or item.surface_id in context
        ]
        observations.sort(
            key=lambda item: (
                item.surface_id not in focus,
                item.surface_id not in context,
                item.state != "fetched",
                not bool(item.parameter_names),
            )
        )
        return tuple(observations[:_MAX_AGENTIC_OBSERVATIONS])

    def _next_action(
        self,
        task: TaskEnvelope,
        observations: tuple[ReconObservation, ...],
        selectable_surface_ids: tuple[str, ...],
        remaining_budget: int,
        round_index: int,
        *,
        provider_fallback_status: str | None = None,
    ) -> tuple[ReconAction, str, str | None, bool]:
        """Restore or persist exactly one policy-checked iterative Recon action."""

        stored = find_stored_recon_action(
            self._evidence.list_by_run(task.run_id),
            observations,
            selectable_surface_ids,
            round_index=round_index,
        )
        if stored is not None:
            return (*stored, False)

        if self._surface_collection_mode == "deterministic" or provider_fallback_status:
            selected = selectable_surface_ids[0]
            basis = next(
                (
                    (item.observation_id,)
                    for item in observations
                    if item.surface_id == selected
                ),
                (),
            )
            action = ReconAction(
                action="visit_surface",
                surface_id=selected,
                basis_observation_ids=basis,
                reason_code=(
                    "expand_coverage"
                    if provider_fallback_status in {
                        None, "fallback:browser_call_reserve",
                        "fallback:deterministic_collection",
                    }
                    else "planner_failure"
                ),
                source="deterministic_fallback",
                status=provider_fallback_status or "fallback:deterministic_collection",
            )
        else:
            action = _policy_checked_recon_action(
                self._iterative_planner.decide(
                    task=task,
                    observations=observations,
                    selectable_surface_ids=selectable_surface_ids,
                    remaining_budget=remaining_budget,
                    round_index=round_index,
                ),
                observations,
                selectable_surface_ids,
            )

        executed_surface_id = (
            action.surface_id if action.action == "visit_surface" else None
        )
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=None,
                created_by=AGENTIC_RECON_PLANNER,
                evidence_type="observation",
                observation=build_recon_action_observation(
                    action,
                    observations,
                    selectable_surface_ids,
                    round_index=round_index,
                    remaining_budget=remaining_budget,
                    executed_surface_id=executed_surface_id,
                ),
            )
        )
        return action, evidence_id, executed_surface_id, (
            self._surface_collection_mode != "deterministic"
            and provider_fallback_status is None
        )

    def _plan(
        self,
        task: TaskEnvelope,
        candidates: tuple[ReconCandidate, ...],
        remaining_budget: int,
    ) -> tuple[ReconPlan, str]:
        """저장된 계획을 재사용하거나, Planner를 불러 새 계획 Evidence를 남긴다."""

        offered_surface_ids = tuple(candidate.surface_id for candidate in candidates)
        stored = find_stored_recon_plan(
            self._evidence.list_by_run(task.run_id), offered_surface_ids
        )
        if stored is not None:
            return stored

        plan = self._planner.plan(
            task=task, candidates=candidates, remaining_budget=remaining_budget
        )
        evidence_id = f"evi-{self._id_factory()}"
        self._evidence.append(
            Evidence(
                evidence_id=evidence_id,
                run_id=task.run_id,
                surface_id=None,
                created_by=RECON_PLANNER,
                evidence_type="observation",
                observation=build_recon_plan_observation(plan, offered_surface_ids),
            )
        )
        return plan, evidence_id

    def _apply_plan(
        self,
        plan: ReconPlan,
        pending: list[str],
        pending_surface_ids: dict[str, str],
        protected: set[str],
    ) -> list[str]:
        """plan의 action과 allowlisted ID 순서를 실제 pending URL로 되돌린다.

        LLM이 만든 것은 순서와 continue/stop뿐이다. pending에 없는 URL은 Planner가
        어떤 ID를 내놓든 방문하지 않는다 — 새 URL을 만들지 않고, 코드가 이미 들고
        있던 pending_surface_ids 매핑을 뒤집어서만 찾는다.

        ``protected``는 번들의 실제 문서 이동(``location.assign`` 등)으로 판정된 표면이다.
        디렉터리 추측과 달리 여기에 서버 렌더링 폼이 실제로 들어 있다. Planner는 나머지의
        순서만 정하고 이것은 건드리지 못한다 — 빠지면 그 URL의 HTML 폼이 영영 파싱되지
        않아 POST Surface와 렌더 파라미터 신호가 통째로 사라지고, "검사했지만 없었다"와
        "애초에 검사하지 않았다"가 구분되지 않는다.

        제외뿐 아니라 **순서 강등도 막는다.** 정찰 예산은 pending 전부를 방문할 만큼
        넉넉하지 않아서, 보호 표면을 뒤로 미는 것은 제외하는 것과 결과가 같다. 그래서
        보호 표면은 원래 순서를 유지한 채 항상 앞에 둔다(``_discover_from_script``의
        ``ordered_paths``가 세우는 것과 같은 우선순위다).
        """

        # 원래 방문 순서를 유지한 채 보호 대상만 추린다.
        protected_order = [url for url in pending if url in protected]
        if plan.action == "stop":
            return protected_order

        url_by_surface_id: dict[str, str] = {}
        for url in pending:
            surface_id = pending_surface_ids.get(url)
            if surface_id is not None:
                url_by_surface_id.setdefault(surface_id, url)

        ranked = [
            url_by_surface_id[surface_id]
            for surface_id in plan.ranked_surface_ids
            if surface_id in url_by_surface_id and url_by_surface_id[surface_id] not in protected
        ]
        return [*protected_order, *ranked]


def _is_html_response(evidence: Evidence) -> bool:
    """Return whether a textual response is eligible for HTML structure parsing.

    Missing content type stays compatible with simple runtimes and old fixtures. An
    explicit non-HTML media type is authoritative: its body can still be observed, but
    HTML-looking strings inside JSON or JavaScript are data rather than page structure.
    """

    content_type = evidence.observation.get("content_type")
    if not isinstance(content_type, str) or not content_type.strip():
        return True
    media_type = content_type.split(";", 1)[0].strip().casefold()
    return media_type in {"text/html", "application/xhtml+xml"}


def _javascript_globals(body: str) -> dict[tuple[str, str], str]:
    """Extract scalar properties from localized JavaScript configuration objects.

    Frameworks such as WordPress emit runtime URLs and CSRF nonces in an inline
    object, while the request itself lives in an external script.  Returning a
    `(object, property) -> value` map lets the two independently observed pieces
    be joined without executing JavaScript.
    """

    values: dict[tuple[str, str], str] = {}
    for match in _JS_GLOBAL_OBJECT.finditer(body):
        object_name = match.group("name")
        raw_object = match.group("object")
        try:
            decoded = json.loads(raw_object)
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded = None
        if isinstance(decoded, dict):
            for name, value in decoded.items():
                if isinstance(name, str) and isinstance(value, (str, int, float, bool)):
                    values[(object_name, name)] = str(value)
            continue
        for entry in _JS_OBJECT_ENTRY.finditer(raw_object):
            value = _javascript_scalar(entry.group("value"), values)
            if value is not None:
                values[(object_name, entry.group("name"))] = value
    return values


def _javascript_scalar(
    raw: str, globals_by_property: dict[tuple[str, str], str]
) -> str | None:
    value = raw.strip()
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        return value[1:-1]
    if re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return value
    if "." in value:
        object_name, property_name = value.split(".", 1)
        resolved = globals_by_property.get((object_name, property_name))
        if resolved is not None:
            return resolved
    return None


def _javascript_object_fields(
    raw_object: str, globals_by_property: dict[tuple[str, str], str]
) -> tuple[tuple[str, str], ...]:
    fields: list[tuple[str, str]] = []
    for entry in _JS_OBJECT_ENTRY.finditer(raw_object):
        name = entry.group("name")
        raw_value = entry.group("value").strip()
        # Array-valued form fields need the conventional [] suffix when encoded
        # as application/x-www-form-urlencoded so server frameworks reconstruct
        # the observed collection shape.
        if raw_value.startswith("[") or ".map(" in raw_value:
            if not name.endswith("[]"):
                name += "[]"
        value = _javascript_scalar(raw_value, globals_by_property)
        fields.append((name, value if value is not None else "1"))
    return tuple(dict.fromkeys(fields))


def _javascript_requests(
    body: str,
    base_url: str,
    globals_by_property: dict[tuple[str, str], str],
) -> list[tuple[str, str, tuple[tuple[str, str], ...]]]:
    """Recover same-origin jQuery AJAX request templates from observed script text."""

    object_fields = {
        match.group("name"): _javascript_object_fields(
            match.group("object"), globals_by_property
        )
        for match in _JS_GLOBAL_OBJECT.finditer(body)
    }
    requests: list[tuple[str, str, tuple[tuple[str, str], ...]]] = []
    for match in _JS_AJAX_BLOCK.finditer(body):
        block = match.group("body")
        url_match = _JS_URL_VALUE.search(block)
        if url_match is None:
            continue
        raw_url = url_match.group("value").strip()
        url_value = _javascript_scalar(raw_url, globals_by_property)
        if url_value is None:
            continue
        resolved = urljoin(base_url, url_value)
        if urlsplit(resolved).scheme not in {"http", "https"}:
            continue
        method_match = _JS_METHOD_VALUE.search(block)
        method = method_match.group("method").upper() if method_match else "GET"
        data_match = _JS_DATA_VALUE.search(block)
        fields: tuple[tuple[str, str], ...] = ()
        if data_match is not None:
            raw_data = data_match.group("value").strip()
            fields = (
                _javascript_object_fields(raw_data, globals_by_property)
                if raw_data.startswith("{")
                else object_fields.get(raw_data, ())
            )
        requests.append((resolved.split("#", 1)[0], method, fields))
    return list(dict.fromkeys(requests))


def _data_navigation_links(body: str, base_url: str) -> tuple[str, ...]:
    """Read bounded, same-origin GET navigation declared by HTML data attributes."""

    if len(body) > 256_000:
        return ()
    origin = urlsplit(base_url)
    found: list[str] = []
    soup = BeautifulSoup(body, "lxml")
    for element in soup.select("[data-url], [data-href]")[:100]:
        if str(element.get("data-method", "GET")).upper() != "GET":
            continue
        raw = element.get("data-url") or element.get("data-href")
        if not isinstance(raw, str) or not raw.startswith(("/", "./", "../")):
            continue
        if raw.startswith("//") or len(raw) > 2048:
            continue
        resolved = urljoin(base_url, raw).split("#", 1)[0]
        parsed = urlsplit(resolved)
        if (
            parsed.scheme in {"http", "https"}
            and parsed.netloc == origin.netloc
            and not has_state_changing_get(resolved)
            and resolved not in found
        ):
            found.append(resolved)
        if len(found) >= 24:
            break
    return tuple(found)


def _parse_page(
    body: str, base_url: str
) -> tuple[list[str], list[tuple[str, str, tuple[str, ...], str]], list[str], list[str]]:
    """HTML에서 링크·폼·스크립트 출처를 뽑는다.

    lxml 파서는 닫는 태그가 없는 폼처럼 깨진 HTML도 복구한다 — 취약한 대상일수록
    HTML이 깨져 있을 확률이 높아 관용적인 파서가 필요하다.
    """

    soup = BeautifulSoup(body, "lxml")

    links = []
    for anchor in soup.find_all("a", href=True):
        resolved = urljoin(base_url, anchor["href"])
        if urlsplit(resolved).scheme in ("http", "https"):
            links.append(resolved)

    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        names = tuple(
            dict.fromkeys(
                field["name"]
                # 이름 있는 <button>도 폼 필드다. 브라우저는 누른 버튼의 name=value를
                # 함께 보내고, 그 값이 있어야 비로소 실행되는 분기가 흔하다 —
                # XBEN-071의 send.php는 isset($_POST['submit'])로 전체를 감싸므로
                # 버튼을 빼면 주입 지점에 닿는 요청을 만들 수 없다.
                for field in form.find_all(
                    ["input", "select", "textarea", "button"], attrs={"name": True}
                )
                if field["name"]
            )
        )
        forms.append(
            (
                urljoin(base_url, action).split("?", 1)[0],
                (form.get("method") or "GET").upper(),
                names,
                (form.get("enctype") or "application/x-www-form-urlencoded")
                .split(";", 1)[0].strip().casefold(),
            )
        )

    sources = [
        urljoin(base_url, script["src"]) for script in soup.find_all("script", src=True)
    ]
    for preload in soup.find_all("link", href=True):
        rel = {value.casefold() for value in preload.get("rel", ()) if isinstance(value, str)}
        if not (
            "modulepreload" in rel
            or ("preload" in rel and str(preload.get("as", "")).casefold() == "script")
        ):
            continue
        source = urljoin(base_url, preload["href"])
        if urlsplit(source).path.casefold().endswith((".js", ".mjs")):
            sources.append(source)
    sources = list(dict.fromkeys(sources))
    inline_scripts = []
    inline_bytes = 0
    for script in soup.find_all("script"):
        if script.has_attr("src"):
            continue
        media = (script.get("type") or "text/javascript").split(";", 1)[0].casefold()
        if media not in {"text/javascript", "application/javascript", "module"}:
            continue
        content = script.string
        if not isinstance(content, str) or not content:
            continue
        if inline_bytes + len(content) > _MAX_INLINE_SCRIPT_BYTES:
            continue
        inline_bytes += len(content)
        inline_scripts.append(content)
        if len(inline_scripts) >= 16:
            break
    return links, forms, sources, inline_scripts


# 경로 안에서 `=`로 입력을 싣는 표면을 찾을 때 의존하는 두 구분자의 인코딩 형태.
# 경로에 이것들이 있으면 어디까지가 이름이고 값인지 단정할 수 없다.
_ENCODED_PATH_DELIMITERS = ("%3d", "%2f")


def _path_assignment(url: str, *, source: str) -> tuple[PathAssignment | None, str | None]:
    """경로에 ``이름=값``으로 실린 입력 좌표를 보수적으로 식별한다.

    query가 아니라 경로가 입력을 나르는 프레임워크가 있다(``/file=web_assets/app.js``).
    그 자리를 query parameter로 기록하면 Analyzer가 ``?file=``을 덧붙인, 대상이 제공한
    적 없는 URL을 만든다. 그래서 값이 경로에서 차지하는 범위를 그대로 보존한다.

    모호하면 좌표를 만들지 않고 사유를 돌려준다. 여기서 추측하면 관측하지 않은 자리에
    요청을 보내게 되고, 그것은 이 도구가 하지 않기로 한 일이다. 반환값의 두 번째 항목은
    "``=``가 있었지만 인정하지 않은" 경우의 사유이며, ``=``가 아예 없으면 ``None``이다.

    값은 첫 ``=`` 뒤부터 경로 끝까지다. 파일 경로는 ``/``를 포함하는 것이 정상이라
    다음 세그먼트에서 자르면 값이 잘린다.
    """

    path = urlsplit(url).path
    marker = path.find("=")
    if marker < 0:
        return None, None
    lowered = path.casefold()
    if any(token in lowered for token in _ENCODED_PATH_DELIMITERS):
        # 인코딩된 `=`나 `/`가 섞이면 이름과 값의 경계를 단정할 수 없다.
        return None, "encoded_delimiter"
    if path.count("=") > 1:
        # `/file=a=b`는 값이 `a=b`인지 좌표가 둘인지 구분할 근거가 없다.
        return None, "ambiguous_multiple_assignments"
    name = path[path.rfind("/", 0, marker) + 1 : marker]
    if not name:
        return None, "empty_name"
    if _PATH_ASSIGNMENT_NAME.fullmatch(name) is None:
        # base64 꼬리(`/aGVsbG8=`)처럼 `=`를 포함한 경로를 입력으로 오인하지 않는다.
        return None, "name_not_identifier"
    value = path[marker + 1 :]
    if not value:
        return None, "empty_value"
    if value.startswith("/"):
        # `=/`는 세그먼트 끝의 padding으로 보이며 값의 시작 위치가 분명하지 않다.
        return None, "value_starts_with_separator"
    return (
        PathAssignment(
            name=name,
            value_start=marker + 1,
            value_end=len(path),
            observed_value=value,
            source=source,
        ),
        None,
    )


def _query_names(url: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(name for name, _ in parse_qsl(urlsplit(url).query)))


def _query_pairs(url: str) -> tuple[tuple[str, str], ...]:
    """관측된 query 값을 이름별로 한 번씩 보존한다."""

    pairs: dict[str, str] = {}
    for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        pairs.setdefault(name, value)
    return tuple(pairs.items())


def _record_numeric_sibling(url: str, siblings: dict[str, set[str]]) -> None:
    """`/<리소스>/<숫자>` 형태에서 리소스별 숫자 값을 모은다."""

    segments = urlsplit(url).path.split("/")
    for index in range(len(segments) - 1, 1, -1):
        value = segments[index]
        resource = segments[index - 1]
        if _PATH_OBJECT_ID.fullmatch(value) is None:
            continue
        if _PATH_RESOURCE.fullmatch(resource) is None:
            continue
        siblings.setdefault(resource.casefold(), set()).add(value)


def _path_identifier(
    url: str, numeric_siblings: Mapping[str, set[str]] | None = None
) -> tuple[str, int, str] | None:
    """`/users/17` 형태에서 논리 식별자명·세그먼트 위치·관측값을 얻는다.

    모든 숫자 경로를 객체로 보면 버전(`/v1/`)이나 연도까지 후보가 된다. 그래서 숫자
    바로 앞이 복수형 리소스명이거나 알려진 단수 객체명인 경우를 결정적으로 인정한다.

    그 둘에 해당하지 않아도, **같은 리소스 아래 서로 다른 숫자 값이 둘 이상** 관측됐고
    리소스가 페이지네이션·버전 이름이 아니면 객체 컬렉션으로 본다. 목록 페이지는 항목
    링크를 형제로 함께 내보내므로(`/edit_draft/2`와 `/edit_draft/3`) 이 구조는 리소스
    이름을 몰라도 판별된다. 이름 목록을 늘리는 방식은 대상마다 다른 이름을 계속
    추가해야 하고, 그렇게 맞춘 목록은 그 대상에서만 동작한다.
    """

    segments = urlsplit(url).path.split("/")
    for index in range(len(segments) - 1, 1, -1):
        value = segments[index]
        resource = segments[index - 1]
        if _PATH_OBJECT_ID.fullmatch(value) is None:
            continue
        lowered = resource.casefold()
        if _PATH_RESOURCE.fullmatch(resource) is None:
            continue
        if lowered.endswith("s") and len(resource) > 1:
            singular = resource[:-1]
        elif lowered in _SINGULAR_OBJECT_RESOURCES:
            singular = resource
        elif (
            numeric_siblings is not None
            and lowered not in _NON_OBJECT_PATH_RESOURCES
            and len(numeric_siblings.get(lowered, ())) >= 2
        ):
            singular = resource
        else:
            continue
        return f"{singular.casefold()}_id", index, value
    return None


def _canonical_surface_url(
    url: str, path_identifier: tuple[str, int, str] | None
) -> str:
    """서로 다른 concrete ID 링크를 동일 REST Surface 하나로 중복 제거한다."""

    if path_identifier is None:
        return url
    name, index, _ = path_identifier
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    segments[index] = "{" + name + "}"
    path = "/".join(segments)
    return parsed._replace(path=path).geturl()


def _same_origin(url: str, origin) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme in ("http", "https") and parsed.netloc == origin.netloc


def _safe_recon_text(value: str, limit: int) -> str:
    """Keep target-controlled labels printable and bounded before LLM serialization."""

    return "".join(character if character.isprintable() else "\ufffd" for character in value)[
        :limit
    ]


def _policy_checked_recon_action(
    proposed: object,
    observations: tuple[ReconObservation, ...],
    selectable_surface_ids: tuple[str, ...],
) -> ReconAction:
    """Enforce the current-run coordinate allowlist independently of the planner."""

    observation_ids = {item.observation_id for item in observations}
    valid = isinstance(proposed, ReconAction) and all(
        item in observation_ids for item in proposed.basis_observation_ids
    )
    if valid and proposed.action == "stop":
        return proposed
    if valid and proposed.surface_id in selectable_surface_ids:
        return proposed

    selected = selectable_surface_ids[0]
    basis = next(
        (
            (item.observation_id,)
            for item in observations
            if item.surface_id == selected
        ),
        (),
    )
    rejected = ()
    if isinstance(proposed, ReconAction) and proposed.surface_id:
        rejected = (proposed.surface_id,)
    return ReconAction(
        action="visit_surface",
        surface_id=selected,
        basis_observation_ids=basis,
        reason_code="planner_failure",
        source="deterministic_fallback",
        status="fallback:invalid_response",
        rejected_surface_ids=rejected,
    )
