"""Observation 유형을 전문 Analysis Agent로 연결하는 규칙 기반 Router."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from hacklipse.domain import Candidate, Evidence, RouteDecision, Run, Surface
from hacklipse.ports import AnalyzerCapability

from .analyzer_capabilities import (
    DEFAULT_ANALYZER_CAPABILITIES,
    analyzer_capability_coverage,
    capability_matches,
    exploration_parameters,
)
from .request_safety import (
    has_state_changing_parameters,
    object_identifier_parameters,
)
from .open_redirect_analysis import REDIRECT_PARAMETER_HINTS
from .arbitrary_file_read import file_serving_segment_index
from .path_traversal_analysis import FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION
from .cors_analysis import CORS_OBSERVATION, CORS_SEARCH_INPUT_NAMES
from .graphql_introspection import INTROSPECTION_TYPE, INTROSPECTION_RECON_OBSERVATION
from .graphql_suggestions import SUGGESTION_TYPE, SUGGESTION_PLAN
from .source_map_exposure import SOURCE_MAP_REFERENCE, SOURCE_MAP_TYPE
from .error_disclosure import (
    ERROR_DISCLOSURE_TYPE, ERROR_ROUTE_OBSERVATION, ERROR_GRAPHQL_OBSERVATION,
)
from .sensitive_exposure import CONFIG_ROUTE_OBSERVATION
from .public_login_credentials import PUBLIC_LOGIN_OBSERVATION, PUBLIC_LOGIN_TYPE
from .file_upload_analysis import UPLOAD_TYPE, UPLOAD_ANALYZER, UPLOAD_FORM
from .ssrf_analysis import (
    SSRF_ANALYZER,
    SSRF_CALLBACK_CAPABILITY, SSRF_CALLBACK_DECLARED_CAPABILITY,
    SSRF_CALLBACK_JSON_CAPABILITY, SSRF_CALLBACK_EDITOR_CAPABILITY,
    SSRF_CANARY_CAPABILITY, SSRF_CANARY_DECLARED_CAPABILITY,
    SSRF_CANARY_EDITOR_CAPABILITY,
    SSRF_OWNED_RECEIVER_CAPABILITY, SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY,
    SSRF_OWNED_RECEIVER_JSON_CAPABILITY, SSRF_OWNED_RECEIVER_EDITOR_CAPABILITY,
    SSRF_EDITOR_CATCHER_STRUCTURE,
    SSRF_JSON_PARAMETER_HINTS, SSRF_PARAMETER_HINTS, SSRF_TYPE,
    observed_url_parameter_names,
)

from .ssti_analysis import SSTI_PARAMETER_HINTS


@dataclass(frozen=True, slots=True)
class RoutingRule:
    """Observation 유형 하나에 대응하는 취약점 유형·Agent·우선순위."""

    observation_type: str
    vulnerability_type: str
    agent_type: str
    priority: float = 0.5
    # Observation 자체만으로는 부족한 Agent 계약(예: Path Traversal은 GET만)을
    # 라우팅 단계에서 함께 표현한다. None이면 기존처럼 모든 메서드를 허용한다.
    methods: tuple[str, ...] | None = None
    observation_parameter_field: str | None = None
    parameter_hints: tuple[str, ...] = ()
    capability_id: str = ""
    analysis_strategy_id: str = ""


@dataclass(frozen=True, slots=True)
class SurfaceRoutingRule:
    """구조화된 Surface만으로 탐색용 Candidate를 만드는 낮은 우선순위 규칙."""

    vulnerability_type: str
    agent_type: str
    methods: tuple[str, ...] = ("GET",)
    requires_parameters: bool = True
    parameter_hints: tuple[str, ...] = ()
    priority: float = 0.25
    max_candidates_per_origin: int | None = None
    capability_id: str = ""
    analysis_strategy_id: str = ""

    # SPA 클라이언트 라우트(`/#/search`)는 HTTP 요청 대상이 아니다. fragment 는
    # 서버로 전송되지 않으므로 HTTP 기반 Analyzer 가 받으면 매번 같은 루트 문서만
    # 받아 신호 없이 예산만 쓴다. 브라우저 도구를 쓰는 규칙만 opt-in 한다.
    client_route: bool = False
    requires_observed_query: bool = False

    def matches(self, surface: Surface) -> bool:
        if surface.method.upper() not in self.methods:
            return False
        if bool(urlsplit(surface.url).fragment) is not self.client_route:
            return False
        if self.requires_parameters and not surface.parameters:
            return False
        if self.parameter_hints:
            offered = {name.casefold() for name in surface.parameters}
            if not offered.intersection(hint.casefold() for hint in self.parameter_hints):
                return False
        if self.requires_observed_query:
            observed = {name for name, _ in surface.observed_query}
            observed.update(name for name, _ in parse_qsl(
                urlsplit(surface.url).query, keep_blank_values=True,
            ))
            if not any(name in observed for name in surface.parameters
                       if not self.parameter_hints or
                       name.casefold() in {hint.casefold() for hint in self.parameter_hints}):
                return False
        return True

    def priority_for(self, surface: Surface) -> float:
        """Spend a tight probe budget on general search inputs before opaque fields."""

        if self.vulnerability_type in {"XSS", "SQLi"} and any(
            name.casefold() in CORS_SEARCH_INPUT_NAMES for name in surface.parameters
        ):
            return min(1.0, self.priority + 0.12)
        return self.priority


class DiscoveredSurfaceRoutingRule(SurfaceRoutingRule):
    """Sample only surfaces with a recorded discovery source."""

    def matches(self, surface: Surface) -> bool:
        return bool(surface.discovery_types) and super().matches(surface)


class SsrfSurfaceRoutingRule(SurfaceRoutingRule):
    """Also route an observed URL value under a nonstandard field name."""

    def matches(self, surface: Surface) -> bool:
        if super().matches(surface):
            return True
        return (
            surface.method.upper() == "GET"
            and not urlsplit(surface.url).fragment
            and bool(set(surface.parameters) & observed_url_parameter_names(surface))
        )


@dataclass(frozen=True, slots=True)
class IdentifierSurfaceRoutingRule:
    """객체 식별자 파라미터가 있는 Surface만 Access Control 탐색 대상으로 만든다.

    Access Control은 "다른 사람의 객체를 가리키는 입력"이 있어야 성립한다. 파라미터가
    있다는 것만으로 후보를 만들면 검색어·정렬 옵션까지 전부 권한 검사 대상이 되어
    예산만 소모하고 신호는 나오지 않는다.
    """

    vulnerability_type: str
    agent_type: str
    methods: tuple[str, ...] = ("GET",)
    priority: float = 0.35

    def matches(self, surface: Surface) -> bool:
        if surface.method.upper() not in self.methods:
            return False
        if urlsplit(surface.url).fragment:
            return False
        return bool(
            object_identifier_parameters(surface.parameters)
            or surface.path_identifier is not None
        )


@dataclass(frozen=True, slots=True)
class FileServingSegmentRoutingRule(SurfaceRoutingRule):
    """마지막 세그먼트가 파일 이름인 파라미터 없는 라우트.

    파라미터가 없으면 다른 탐색 규칙은 이 표면을 건너뛴다. 디렉터리 단서를 요구하는
    이유는 요구하지 않으면 파라미터 없는 모든 GET 이 후보가 되기 때문이다 — 후보가
    표면 수만큼 늘고, 라우팅 기대값을 고정한 기존 테스트가 깨진다.
    """

    requires_parameters: bool = False

    def matches(self, surface: Surface) -> bool:
        return file_serving_segment_index(surface) is not None


# 첫 버전은 설명 가능하고 재현하기 쉬운 명시적 규칙으로 라우팅한다.
DEFAULT_RULES = (
    RoutingRule(UPLOAD_FORM, UPLOAD_TYPE, UPLOAD_ANALYZER, 0.25, methods=("POST",)),
    RoutingRule(
        "postmessage_html_plan", "XSS", "postmessage_xss_analyzer",
        # A fresh browser navigation is needed for the benign probe and both
        # validation requests. Run cheaper observed-input candidates first.
        0.24, methods=("GET",),
    ),
    RoutingRule(
        CONFIG_ROUTE_OBSERVATION, "Sensitive Data Exposure",
        "sensitive_exposure_analyzer", 0.38, methods=("GET",),
    ),
    RoutingRule(
        ERROR_ROUTE_OBSERVATION, ERROR_DISCLOSURE_TYPE,
        "error_disclosure_analyzer", 0.41, methods=("GET",),
    ),
    RoutingRule(
        ERROR_GRAPHQL_OBSERVATION, ERROR_DISCLOSURE_TYPE,
        "error_disclosure_analyzer", 0.41, methods=("GET",),
    ),
    RoutingRule(SUGGESTION_PLAN, SUGGESTION_TYPE,
                "graphql_suggestion_analyzer", 0.42, methods=("GET",)),
    RoutingRule(INTROSPECTION_RECON_OBSERVATION, INTROSPECTION_TYPE,
                "graphql_introspection_analyzer", 0.44, methods=("GET",)),
    RoutingRule(CORS_OBSERVATION, "CORS", "cors_analyzer", 0.75),
    RoutingRule("graphql_schema_operation", "CORS", "cors_analyzer", 0.43, methods=("GET",)),
    RoutingRule("open_redirect", "Open Redirect", "open_redirect_analyzer", 0.75),
    RoutingRule("sensitive_json_exposure", "Sensitive Data Exposure", "sensitive_exposure_analyzer", 0.75),
    RoutingRule(PUBLIC_LOGIN_OBSERVATION, PUBLIC_LOGIN_TYPE,
                "public_login_credentials_analyzer", 0.55, methods=("GET",)),
    RoutingRule("reflection", "XSS", "xss_analyzer", 0.8),
    RoutingRule(
        "browser_hash_reflection", "XSS", "browser_xss_analyzer",
        0.52, methods=("GET",),
    ),
    RoutingRule("sql_error", "SQLi", "sqli_analyzer", 0.8),
    RoutingRule("graphql_read_query_plan", "SQLi", "sqli_analyzer", 0.30, methods=("GET",)),
    RoutingRule("object_id_auth", "Access Control", "access_control_analyzer", 0.8),
    RoutingRule(
        "url_or_file_parameter",
        "Path Traversal",
        "path_traversal_analyzer",
        0.6,
        methods=("GET",),
    ),
    RoutingRule(
        # 경로에 실린 파일형 입력. 이름만 보고 세우는 query 가설과 달리 값이 실제로
        # 관측된 좌표라 우선순위를 조금 높게 둔다.
        FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION,
        "Path Traversal",
        "path_traversal_analyzer",
        0.62,
        methods=("GET",),
    ),
    RoutingRule(
        # 같은 관측에서 절대 경로 읽기도 올라온다. query 표면에서 url_or_file_parameter가
        # 두 분석기로 가는 것과 같은 구조다.
        FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION,
        "Arbitrary File Read",
        "arbitrary_file_read_analyzer",
        0.57,
        methods=("GET",),
    ),
    RoutingRule(
        "file_serving_parameter",
        "Path Traversal",
        "path_traversal_analyzer",
        0.44,
        methods=("GET",),
    ),
    RoutingRule(
        "unlinked_render_parameter_candidate",
        "Path Traversal",
        "path_traversal_analyzer",
        0.55,
        methods=("POST",),
    ),
    RoutingRule("template_error", "SSTI", "ssti_analyzer", 0.7),
    RoutingRule("template_execution", "SSTI", "ssti_analyzer", 0.9),
    # 파일 파라미터를 가리키는 같은 관측에서 상대 탈출과 함께 올라온다. ``..``를
    # 거르는 필터가 절대 경로는 막지 못하는 경우가 있어 둘 다 시도할 값이 있다.
    RoutingRule(
        "url_or_file_parameter",
        "Arbitrary File Read",
        "arbitrary_file_read_analyzer",
        0.55,
        methods=("GET",),
    ),
)

# Public source maps can be deliberately published for debugging or open
# source applications. Keep the independently verified check available for
# an explicit scan, without asserting a vulnerability in automatic mode.
OPTIONAL_SOURCE_MAP_RULES = (
    RoutingRule(SOURCE_MAP_REFERENCE, SOURCE_MAP_TYPE,
                "source_map_exposure_analyzer", 0.22, methods=("GET",)),
)


# `/ftp/*.bak%2500.md` 같은 제한 확장자 필터 우회 구현은 이후 별도 취약점 유형으로
# 재분류할 수 있도록 보존한다. 기본 Router에는 넣지 않아 일반/all 실행에서 Candidate와
# 반복 Analysis·Validation 요청을 만들지 않는다. 필요한 실험에서만 rules에 명시적으로
# 합쳐 사용한다.
OPTIONAL_RESTRICTED_FILE_BYPASS_RULES = (
    RoutingRule(
        "restricted_file_path",
        "Path Traversal",
        "path_traversal_analyzer",
        0.7,
        methods=("GET",),
    ),
)

# Observation이 아직 없어도 입력 가능한 Surface를 담당 Analyzer까지 보낸다.
# 실제 취약점 판정이 아니라 탐색 대상을 만드는 규칙이므로 기존 Evidence 규칙보다
# 낮은 priority를 사용한다.
DEFAULT_SURFACE_RULES = (
    # Sample public, read-only search surfaces instead of probing every GET.
    DiscoveredSurfaceRoutingRule(
        "CORS", "cors_analyzer",
        parameter_hints=tuple(sorted(CORS_SEARCH_INPUT_NAMES)), priority=0.43,
        max_candidates_per_origin=1,
    ),
    SurfaceRoutingRule(
        "Open Redirect", "open_redirect_analyzer",
        parameter_hints=REDIRECT_PARAMETER_HINTS, priority=0.50,
    ),
    SurfaceRoutingRule("XSS", "xss_analyzer", priority=0.30),
    # SPA 라우트의 DOM sink 는 브라우저로만 관측된다.
    SurfaceRoutingRule(
        "XSS", "browser_xss_analyzer", client_route=True, priority=0.40
    ),
    SurfaceRoutingRule("SQLi", "sqli_analyzer", priority=0.30),
    SurfaceRoutingRule(
        "SQLi", "sqli_analyzer", methods=("POST",), priority=0.30
    ),
    # 템플릿에 렌더링되는 좌표의 이름은 대상마다 name·message·template 등으로 다르다.
    # 힌트 목록은 분석기가 실제로 고를 때 쓰는 집합과 같은 상수를 참조해 두 곳으로
    # 갈라지지 않게 한다. POST를 username 하나로 좁혀 두었던 것은 그 경로가 프로필에
    # **쓰는** 요청뿐이었기 때문인데, 이제 응답에만 렌더링되는 폼은 상태를 남기지 않는
    # 경로로 확인하므로 그 제약이 필요 없다. 저장되는 /profile 쓰기는 분석기와 안전
    # 검증기가 여전히 username으로만 허용한다.
    SurfaceRoutingRule(
        "SSTI",
        "ssti_analyzer",
        methods=("POST",),
        parameter_hints=tuple(sorted(SSTI_PARAMETER_HINTS)),
        priority=0.20,
    ),
    SurfaceRoutingRule(
        "SSTI",
        "ssti_analyzer",
        methods=("GET",),
        parameter_hints=tuple(sorted(SSTI_PARAMETER_HINTS)),
        priority=0.20,
    ),
    IdentifierSurfaceRoutingRule(
        "Access Control", "access_control_analyzer", priority=0.35
    ),
    FileServingSegmentRoutingRule(
        "Arbitrary File Read", "arbitrary_file_read_analyzer", priority=0.21,
    ),
)

OPTIONAL_SSRF_SURFACE_RULES = (
    SsrfSurfaceRoutingRule(
        SSRF_TYPE, SSRF_ANALYZER,
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        requires_observed_query=True, priority=0.30,
        capability_id=SSRF_CALLBACK_CAPABILITY,
        analysis_strategy_id="observed_url_callback_probe",
    ),
)

OPTIONAL_SSRF_OBSERVATION_RULES = (
    RoutingRule(
        SSRF_EDITOR_CATCHER_STRUCTURE, SSRF_TYPE, SSRF_ANALYZER,
        0.28, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=(),
        capability_id=SSRF_CALLBACK_EDITOR_CAPABILITY,
        analysis_strategy_id="declared_url_callback_probe",
    ),
    RoutingRule(
        "openapi_request_structure", SSRF_TYPE, SSRF_ANALYZER,
        0.28, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        capability_id=SSRF_CALLBACK_DECLARED_CAPABILITY,
        analysis_strategy_id="declared_url_callback_probe",
    ),
    RoutingRule(
        "javascript_json_request_structure", SSRF_TYPE, SSRF_ANALYZER,
        0.28, methods=("POST",),
        observation_parameter_field="body_parameter_names",
        parameter_hints=tuple(sorted(SSRF_JSON_PARAMETER_HINTS)),
        capability_id=SSRF_CALLBACK_JSON_CAPABILITY,
        analysis_strategy_id="declared_json_callback_probe",
    ),
)

OPTIONAL_SSRF_CANARY_SURFACE_RULES = (
    SsrfSurfaceRoutingRule(
        SSRF_TYPE, SSRF_ANALYZER,
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        requires_observed_query=True, priority=0.31,
        capability_id=SSRF_CANARY_CAPABILITY,
        analysis_strategy_id="observed_url_internal_canary_probe",
    ),
)

OPTIONAL_SSRF_CANARY_OBSERVATION_RULES = (
    RoutingRule(
        SSRF_EDITOR_CATCHER_STRUCTURE, SSRF_TYPE, SSRF_ANALYZER,
        0.29, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=(),
        capability_id=SSRF_CANARY_EDITOR_CAPABILITY,
        analysis_strategy_id="declared_url_internal_canary_probe",
    ),
    RoutingRule(
        "openapi_request_structure", SSRF_TYPE, SSRF_ANALYZER,
        0.29, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        capability_id=SSRF_CANARY_DECLARED_CAPABILITY,
        analysis_strategy_id="declared_url_internal_canary_probe",
    ),
)

OPTIONAL_SSRF_OWNED_RECEIVER_SURFACE_RULES = (
    SsrfSurfaceRoutingRule(
        SSRF_TYPE, SSRF_ANALYZER,
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        requires_observed_query=True, priority=0.32,
        capability_id=SSRF_OWNED_RECEIVER_CAPABILITY,
        analysis_strategy_id="observed_url_internal_request_log_probe",
    ),
)

OPTIONAL_SSRF_OWNED_RECEIVER_OBSERVATION_RULES = (
    RoutingRule(
        SSRF_EDITOR_CATCHER_STRUCTURE, SSRF_TYPE, SSRF_ANALYZER,
        0.30, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=(),
        capability_id=SSRF_OWNED_RECEIVER_EDITOR_CAPABILITY,
        analysis_strategy_id="declared_url_internal_request_log_probe",
    ),
    RoutingRule(
        "openapi_request_structure", SSRF_TYPE, SSRF_ANALYZER,
        0.30, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        capability_id=SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY,
        analysis_strategy_id="declared_url_internal_request_log_probe",
    ),
    RoutingRule(
        "javascript_json_request_structure", SSRF_TYPE, SSRF_ANALYZER,
        0.30, methods=("POST",),
        observation_parameter_field="body_parameter_names",
        parameter_hints=tuple(sorted(SSRF_JSON_PARAMETER_HINTS)),
        capability_id=SSRF_OWNED_RECEIVER_JSON_CAPABILITY,
        analysis_strategy_id="declared_json_internal_request_log_probe",
    ),
)

# A registered passive review still needs an exact coordinate Candidate, but it
# is deliberately not labelled as callback or canary execution.
OPTIONAL_SSRF_REVIEW_SURFACE_RULES = (
    SsrfSurfaceRoutingRule(
        SSRF_TYPE, SSRF_ANALYZER,
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
        requires_observed_query=True, priority=0.30,
    ),
)

OPTIONAL_SSRF_REVIEW_OBSERVATION_RULES = (
    RoutingRule(
        SSRF_EDITOR_CATCHER_STRUCTURE, SSRF_TYPE, SSRF_ANALYZER,
        0.28, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=(),
    ),
    RoutingRule(
        "openapi_request_structure", SSRF_TYPE, SSRF_ANALYZER,
        0.28, methods=("GET",),
        observation_parameter_field="query_parameter_names",
        parameter_hints=tuple(sorted(SSRF_PARAMETER_HINTS)),
    ),
)


def _decision_key(
    surface_id: str, vulnerability_type: str, capability_id: str = "",
) -> tuple[str, str]:
    """Deduplicate provenance variants within one SSRF execution strategy."""

    if capability_id in {
        SSRF_CALLBACK_CAPABILITY, SSRF_CALLBACK_DECLARED_CAPABILITY,
        SSRF_CALLBACK_JSON_CAPABILITY, SSRF_CALLBACK_EDITOR_CAPABILITY,
    }:
        return surface_id, "ssrf.callback"
    if capability_id in {
        SSRF_CANARY_CAPABILITY, SSRF_CANARY_DECLARED_CAPABILITY,
        SSRF_CANARY_EDITOR_CAPABILITY,
    }:
        return surface_id, "ssrf.internal_canary"
    if capability_id in {
        SSRF_OWNED_RECEIVER_CAPABILITY,
        SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY,
        SSRF_OWNED_RECEIVER_JSON_CAPABILITY,
        SSRF_OWNED_RECEIVER_EDITOR_CAPABILITY,
    }:
        return surface_id, "ssrf.internal_request_log"
    return surface_id, capability_id or vulnerability_type



# 규칙이 만든 어떤 Candidate보다도 낮다(현재 규칙 최저값은 SSTI 탐색의 0.20).
# priority는 예산이 모자랄 때 무엇을 포기하는지에 대한 결정이므로, 설명 가능한 규칙
# 판정이 LLM 제안 때문에 잘리는 일이 없어야 한다.
ADVISOR_PRIORITY = 0.15

_PATH_TRAVERSAL_POST_OBSERVATION = "unlinked_render_parameter_candidate"
_PATH_TRAVERSAL_POST_SOURCE = "bounded_unlinked_render_parameter"
_ROUTER_REVIEW_POLICIES = frozenset({"weak", "ambiguous"})
_ADVISOR_MODES = frozenset({"supplemental", "primary"})


def _requires_state_change_approval(surface: Surface) -> bool:
    """입력 이름상 상태 변경 의도가 뚜렷해 선행 승인이 필요한지 계산한다.

    POST 자체의 최종 승인 여부는 중앙 PolicyGate가 검사한다. Router는 기존처럼
    비파괴적으로 보이는 POST 후보를 보존하되, 비밀번호 변경·삭제 같은 명시적 입력은
    승인된 Run에서만 후보로 만든다.
    """

    return has_state_changing_parameters(surface.parameters)

# Agentic hypothesis가 표현할 수 있는 근거와 후속 Evidence의 닫힌 vocabulary.
# 자유 문자열을 실행 계획처럼 취급하지 않도록 Router와 LLM Adapter가 같은 목록을
# 사용하고, 실제 실행·proof는 여전히 Analyzer와 Validation의 기존 계약이 결정한다.
CANDIDATE_REASON_CODES = frozenset(
    {
        "input_reflection_risk",
        "query_interpreter_risk",
        "file_path_resolution_risk",
        "template_rendering_risk",
        "object_authorization_risk",
        "observed_behavior_anomaly",
        "analyzer_contract_satisfied",
    }
)
CANDIDATE_EVIDENCE_TYPES = frozenset(
    {
        "control_response",
        "mutated_input_response",
        "browser_execution",
        "server_error_delta",
        "file_read_marker",
        "template_execution_marker",
        "cross_principal_response",
        "ssrf_callback_http",
        "ssrf_server_request_observation",
    }
)


@dataclass(frozen=True, slots=True)
class RouteSuggestion:
    """Advisor가 돌려주는 제안 하나. Candidate가 아니라 Candidate 후보다.

    Advisor는 Candidate를 만들지 않는다. candidate_id 부여·priority 결정·저장은 모두
    Router와 Orchestrator에 남는다. 그래야 Advisor가 잘못된 값을 내놓아도 Router가
    마지막 관문에서 한 번 더 거를 수 있다.

    ``evidence_ids``가 없는 것은 의도적이다. Advisor의 판단은 관측(Observation)이 아니라
    주장(Claim)이므로, 자기가 보지 않은 Evidence를 근거로 달 수 없다.
    """

    surface_id: str
    vulnerability_type: str
    agent_type: str
    # 왜 이 제안을 했는지에 대한 Advisor의 서술. Evidence 기록용이며 TaskEnvelope로
    # 넘기지 않는다 - 다른 Agent의 장문 추론을 Task에 싣지 않는다는 계약 때문이다.
    reason: str = ""
    # Agentic mode에서는 LLM이 프롬프트에 제공된 현재 Surface의 Observation ID만
    # 근거로 고를 수 있다. Router가 다시 소속을 확인한 뒤 Candidate에 연결한다.
    basis_evidence_ids: tuple[str, ...] = ()
    reason_code: str = ""
    required_evidence_types: tuple[str, ...] = ()
    # Agent가 등록한 실행 계약의 안정적인 식별자. 같은 취약점 유형에 여러 Agent가
    # 붙어도 이 ID로 서로 다른 실행 계획을 보존한다.
    capability_id: str = ""
    confidence: str = "low"
    priority_label: str = "normal"
    analysis_strategy_id: str = ""


class RouterAdvisor(Protocol):
    """규칙이 분류하지 못한 Surface에 대해 제안만 돌려주는 보조 판단자.

    Router는 이 Protocol만 알고 LLM을 모른다. 구현이 없으면(``advisor=None``) Router는
    규칙만으로 지금과 완전히 동일하게 동작한다.

    ``routed``는 규칙이 이미 결정한 ``(surface_id, vulnerability_type)`` 조합이다.
    구현체는 이 조합을 다시 제안하지 않는 것이 좋지만, 제안하더라도 Router가 규칙 결정을
    유지하므로 덮어쓰이지 않는다.
    """

    def advise(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
        routed: frozenset[tuple[str, str]],
    ) -> Sequence[RouteSuggestion]: ...


def _path_traversal_post_parameters(
    surface: Surface, evidence: Sequence[Evidence]
) -> tuple[str, ...]:
    """Recon이 현재 Run의 제한된 서버 렌더링 좌표로 표시한 POST 필드만 반환한다."""

    return tuple(
        dict.fromkeys(
            parameter
            for item in evidence
            if item.run_id == surface.run_id
            and item.surface_id == surface.surface_id
            and item.evidence_type == "observation"
            and item.observation.get("type") == _PATH_TRAVERSAL_POST_OBSERVATION
            and item.observation.get("source") == _PATH_TRAVERSAL_POST_SOURCE
            and isinstance((parameter := item.observation.get("parameter")), str)
            and parameter
        )
    )


def _supports_suggestion(
    surface: Surface,
    suggestion: RouteSuggestion,
    evidence: Sequence[Evidence] = (),
    capabilities: Sequence[AnalyzerCapability] = DEFAULT_ANALYZER_CAPABILITIES,
) -> bool:
    """Advisor 제안을 등록된 capability와 대조한다.

    이전처럼 Agent 이름별 분기를 두지 않는다. 새 Agent는 capability 등록만으로 이
    검사를 통과할 수 있다.
    """

    return any(
        capability.agent_type == suggestion.agent_type
        and capability.vulnerability_type == suggestion.vulnerability_type
        and (
            not suggestion.capability_id
            or capability.capability_id == suggestion.capability_id
        )
        and capability_matches(capability, surface, evidence)
        for capability in capabilities
    )


class RuleBasedVulnerabilityRouter:
    """Surface 탐색 규칙과 강한 Observation 규칙을 함께 사용하는 결정적 Router.

    ``advisor``를 주면 규칙이 비워 둔 자리에 한해 제안을 받아 Candidate를 더 만든다.
    주지 않으면 규칙만 사용하며 결과는 결정적이다.
    """

    def __init__(
        self,
        rules: Sequence[RoutingRule] = DEFAULT_RULES,
        surface_rules: Sequence[SurfaceRoutingRule] = DEFAULT_SURFACE_RULES,
        id_factory: Callable[[], str] | None = None,
        advisor: RouterAdvisor | None = None,
        advisor_priority: float = ADVISOR_PRIORITY,
        review_policy: str = "weak",
        advisor_mode: str = "supplemental",
        capabilities: Sequence[AnalyzerCapability] = DEFAULT_ANALYZER_CAPABILITIES,
    ) -> None:
        if review_policy not in _ROUTER_REVIEW_POLICIES:
            raise ValueError("review policy must be weak or ambiguous")
        if advisor_mode not in _ADVISOR_MODES:
            raise ValueError("advisor mode must be supplemental or primary")
        grouped_rules: dict[str, list[RoutingRule]] = {}
        for rule in rules:
            grouped_rules.setdefault(rule.observation_type, []).append(rule)
        self._rules = {
            observation_type: tuple(items)
            for observation_type, items in grouped_rules.items()
        }
        self._surface_rules = tuple(surface_rules)
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._advisor = advisor
        self._advisor_priority = advisor_priority
        self._review_policy = review_policy
        self._advisor_mode = advisor_mode
        self._capabilities = tuple(capabilities)
        self._capabilities_by_id = {
            capability.capability_id: capability for capability in self._capabilities
        }
        # 제안의 유효 범위를 규칙 목록에서 그대로 끌어온다. 별도 허용 목록을 두면
        # `standard_router()`의 `--vuln` 필터와 `IMPLEMENTED_ANALYZERS` 필터를 두 번
        # 관리하게 되고, 어긋나는 순간 Dispatcher가 AgentUnavailable로 Run을 죽인다.
        self._allowed_pairs = frozenset(
            (rule.vulnerability_type, rule.agent_type)
            for rule in (*rules, *surface_rules)
        ) | frozenset(
            (capability.vulnerability_type, capability.agent_type)
            for capability in self._capabilities
        )
        # fragment 표면을 다룰 수 있는 Agent. 규칙과 같은 기준을 제안에도 적용한다.
        self._client_route_agents = frozenset(
            rule.agent_type
            for rule in surface_rules
            if getattr(rule, "client_route", False)
        )
        # 감사 Adapter가 규칙/Advisor 결과를 분리해 기록할 때 읽는 호출별 상태다.
        self.last_rule_decisions: tuple[RouteDecision, ...] = ()
        self.last_advisor_suggestions: tuple[RouteSuggestion, ...] = ()
        self.last_advisor_outcomes: tuple[tuple[int, str], ...] = ()
        self.last_capability_assessments: tuple[object, ...] = ()
        self.last_analyzer_coverage: tuple[object, ...] = ()
        self.last_advisor_status = "not_configured" if advisor is None else "not_called"

    def route(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
    ) -> tuple[RouteDecision, ...]:
        """Surface와 Evidence를 대조해 중복 없는 Candidate를 만든다."""

        self.last_rule_decisions = ()
        self.last_advisor_suggestions = ()
        self.last_advisor_outcomes = ()
        self.last_capability_assessments = ()
        self.last_analyzer_coverage = analyzer_capability_coverage(
            self._capabilities, run, surfaces, evidence
        )
        self.last_advisor_status = (
            "not_configured" if self._advisor is None else "not_called"
        )
        decisions: dict[tuple[str, str], RouteDecision] = {}
        for item, rule in (
            (item, rule)
            for item in evidence
            for rule in self._rules.get(
                str(item.observation.get("type", "")), (),
            )
        ):
            observation_type = str(item.observation.get("type", ""))
            if item.surface_id is None:
                continue
            surface = next(
                (
                    candidate_surface
                    for candidate_surface in surfaces
                    if candidate_surface.surface_id == item.surface_id
                    and candidate_surface.run_id == run.run_id
                ),
                None,
            )
            if surface is None:
                continue
            if _requires_state_change_approval(surface) and not (
                run.execution_profile.state_changing_approved
            ):
                continue
            if rule.methods is not None and surface.method.upper() not in rule.methods:
                continue
            if rule.observation_parameter_field is not None:
                value = item.observation.get(rule.observation_parameter_field)
                names = (value,) if isinstance(value, str) else value if isinstance(value, (list, tuple)) else ()
                offered = {name.casefold() for name in names
                           if isinstance(name, str) and name in surface.parameters}
                if rule.parameter_hints and not offered.intersection(
                    hint.casefold() for hint in rule.parameter_hints
                ):
                    continue
                if not rule.parameter_hints and (
                    rule.vulnerability_type != SSRF_TYPE or not offered
                ):
                    continue
            key = _decision_key(
                item.surface_id, rule.vulnerability_type, rule.capability_id,
            )
            # 동일 Surface와 취약점 유형 조합은 하나의 Candidate만 생성한다.
            if key in decisions:
                continue
            candidate = Candidate(
                candidate_id=f"candidate-{self._id_factory()}",
                run_id=run.run_id,
                surface_id=item.surface_id,
                vulnerability_type=rule.vulnerability_type,
                hypothesis=f"{rule.vulnerability_type} candidate from {observation_type}",
                assigned_agent=rule.agent_type,
                evidence_ids=(item.evidence_id,),
                routing_capability_id=rule.capability_id,
                analysis_strategy_id=rule.analysis_strategy_id,
            )
            decisions[key] = RouteDecision(candidate=candidate, priority=rule.priority)

        # Some checks describe a server-wide setting. Sample a bounded number
        # of actual read surfaces per origin so these candidates cannot exhaust
        # the budget ahead of parameter-specific probes. Rank by path depth and
        # stable URL text; never consult benchmark labels or response verdicts.
        limited_surface_ids: dict[int, set[str]] = {}
        for index, rule in enumerate(self._surface_rules):
            limit = getattr(rule, "max_candidates_per_origin", None)
            if limit is None:
                continue
            offered: dict[tuple[str, str], list[Surface]] = {}
            for surface in surfaces:
                if surface.run_id != run.run_id or not rule.matches(surface):
                    continue
                parsed = urlsplit(surface.url)
                offered.setdefault((parsed.scheme, parsed.netloc), []).append(surface)
            limited_surface_ids[index] = {
                surface.surface_id
                for group in offered.values()
                for surface in sorted(
                    group,
                    key=lambda item: (
                        len([part for part in urlsplit(item.url).path.split("/") if part]),
                        item.url,
                    ),
                    reverse=True,
                )[:limit]
            }

        for surface in surfaces:
            if surface.run_id != run.run_id:
                continue
            if _requires_state_change_approval(surface) and not (
                run.execution_profile.state_changing_approved
            ):
                continue
            for index, rule in enumerate(self._surface_rules):
                if index in limited_surface_ids and surface.surface_id not in limited_surface_ids[index]:
                    continue
                if not rule.matches(surface):
                    continue
                key = _decision_key(
                    surface.surface_id,
                    rule.vulnerability_type,
                    getattr(rule, "capability_id", ""),
                )
                # 같은 취약점에 강한 Evidence 규칙이 이미 매칭됐다면 그것을 유지한다.
                if key in decisions:
                    existing = decisions[key]
                    priority = (
                        rule.priority_for(surface)
                        if isinstance(rule, SurfaceRoutingRule) else rule.priority
                    )
                    # A directly observed coordinate is safer to replay than a
                    # schema-only declaration for the same execution strategy.
                    if not (
                        getattr(rule, "capability_id", "") in {
                            SSRF_CALLBACK_CAPABILITY,
                            SSRF_CANARY_CAPABILITY,
                            SSRF_OWNED_RECEIVER_CAPABILITY,
                        }
                        and priority > existing.priority
                    ):
                        continue
                else:
                    priority = (
                        rule.priority_for(surface)
                        if isinstance(rule, SurfaceRoutingRule) else rule.priority
                    )
                candidate = Candidate(
                    candidate_id=f"candidate-{self._id_factory()}",
                    run_id=run.run_id,
                    surface_id=surface.surface_id,
                    vulnerability_type=rule.vulnerability_type,
                    hypothesis=(
                        f"{rule.vulnerability_type} exploration candidate from "
                        f"parameterized {surface.method.upper()} surface"
                    ),
                    assigned_agent=rule.agent_type,
                    evidence_ids=(),
                    routing_capability_id=getattr(rule, "capability_id", ""),
                    analysis_strategy_id=getattr(rule, "analysis_strategy_id", ""),
                )
                decisions[key] = RouteDecision(candidate=candidate, priority=priority)

        self.last_rule_decisions = tuple(
            sorted(decisions.values(), key=lambda item: item.priority, reverse=True)
        )

        # 3단계. Hybrid는 규칙이 비워 둔 자리만 Advisor 제안으로 채운다. Agentic은
        # 규칙 결과를 정답 힌트로 주지 않고 Analyzer capability로 실행 가능한 조합을
        # 다시 구성한다.
        if self._advisor is not None:
            if self._advisor_mode == "primary":
                # Agentic mode는 규칙 Candidate를 정답처럼 LLM에 먼저 주지 않는다.
                # LLM은 실행 가능 조합의 우선순위와 분석 계획만 정한다. 실제 전달
                # 대상은 Analyzer 실행 계약을 만족한 모든 조합이다.
                suggested, status = self._advisor_decisions(
                    run, surfaces, evidence, {}
                )
                trace = getattr(self._advisor, "last_trace", None)
                self.last_capability_assessments = tuple(
                    getattr(trace, "capabilities", ())
                )
                if trace is not None:
                    self.last_analyzer_coverage = tuple(trace.analyzer_coverage)
                adapter_fallback = (
                    getattr(trace, "source", None) == "deterministic_fallback"
                )
                advisor_failed = status.startswith("advisor_failed:")
                router_rejected_all = bool(self.last_advisor_suggestions) and not suggested
                if adapter_fallback:
                    reasons = ",".join(dict.fromkeys(
                        reason for _, reason in trace.rejected_items
                    ))
                    self.last_advisor_status = (
                        f"agentic_fallback:{trace.status}"
                        + (f":{reasons}" if reasons else "")
                    )
                    # Agentic LLM 장애나 형식 위반은 실행 가능한 Analyzer 조합을
                    # 제거할 근거가 아니다. Advisor가 capability로 복구한 후보는 그대로
                    # Analysis에 넘기고, 상태만 fallback으로 감사한다.
                    if suggested:
                        decisions = suggested
                elif advisor_failed or router_rejected_all:
                    self.last_advisor_status = f"agentic_fallback:{status}"
                else:
                    self.last_advisor_status = f"agentic_primary:{status}"
                    decisions = suggested
            else:
                suggested, status = self._advisor_decisions(
                    run, surfaces, evidence, decisions
                )
                self.last_advisor_status = status
                trace = getattr(self._advisor, "last_trace", None)
                self.last_capability_assessments = tuple(
                    getattr(trace, "capabilities", ())
                )
                if trace is not None:
                    self.last_analyzer_coverage = tuple(trace.analyzer_coverage)
                decisions.update(suggested)

        # 우선순위가 높은 분석 대상을 먼저 처리하도록 정렬한다.
        return tuple(
            sorted(decisions.values(), key=lambda item: item.priority, reverse=True)
        )

    def _advisor_decisions(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
        decided: dict[tuple[str, str], RouteDecision],
    ) -> tuple[dict[tuple[str, str], RouteDecision], str]:
        """Advisor 제안을 검증해 Candidate로 바꾼다. 어떤 실패도 Run을 죽이지 않는다.

        Orchestrator에도 Run 격리 검사가 있지만 거기서는 위반 시 ``AgentContractError``로
        Run 전체가 죽는다. Advisor가 한 번 헛짚었다고 나머지 검사까지 버릴 이유가 없으므로
        항목 위반은 여기서 그 항목만 버린다. ``llm_recon_planner``가 항목 위반과 구조
        위반을 나눠 다루는 것과 같은 이유다.
        """

        assert self._advisor is not None
        review_surfaces = self._review_surfaces(surfaces, decided)
        routed_for_advisor = {
            (surface_id, decision.candidate.vulnerability_type)
            for (surface_id, _), decision in decided.items()
        }
        if self._review_policy == "weak":
            # 단일 Surface 규칙 Candidate를 실제로 검토하려면 그 한 조합은 Advisor의
            # already_covered 목록에서 제외해야 한다. 그렇지 않으면 제안 가능한 유형이
            # 하나뿐인 표면에서 Advisor가 호출조차 되지 않아 weak와 ambiguous가 다시
            # 같은 정책이 된다. 병합 단계는 원래 decided를 사용하므로 Rule은 보존된다.
            decisions_by_surface: dict[str, list[tuple[tuple[str, str], RouteDecision]]] = {}
            for key, decision in decided.items():
                decisions_by_surface.setdefault(key[0], []).append((key, decision))
            for items in decisions_by_surface.values():
                if len(items) == 1 and not items[0][1].candidate.evidence_ids:
                    routed_for_advisor.discard((
                        items[0][0][0],
                        items[0][1].candidate.vulnerability_type,
                    ))
        try:
            suggestions = self._advisor.advise(
                run, review_surfaces, evidence, frozenset(routed_for_advisor)
            )
        except Exception as error:  # noqa: BLE001 - Advisor 실패는 Run을 멈추지 않는다
            # 여기서 예외를 올리면 LLM 장애가 곧 Run 실패가 된다. 규칙 결정은 이미
            # decided에 들어 있으므로 그대로 두고 빈 결과를 돌려준다.
            return {}, f"advisor_failed:{type(error).__name__}"

        self.last_advisor_suggestions = tuple(
            item for item in suggestions if isinstance(item, RouteSuggestion)
        )

        by_id = {
            surface.surface_id: surface
            for surface in review_surfaces
            if surface.run_id == run.run_id
        }
        accepted: dict[tuple[str, str], RouteDecision] = {}
        evidence_by_id = {
            item.evidence_id: item
            for item in evidence
            if item.run_id == run.run_id
            and item.evidence_type in {"observation", "http_response"}
        }
        rejected = 0
        outcomes: list[tuple[int, str]] = []
        for index, suggestion in enumerate(suggestions):
            if not isinstance(suggestion, RouteSuggestion):
                rejected += 1
                outcomes.append((index, "invalid_suggestion"))
                continue
            # 다른 Run의 Surface거나 존재하지 않는 Surface면 버린다.
            surface = by_id.get(suggestion.surface_id)
            if surface is None:
                rejected += 1
                outcomes.append((index, "unknown_surface"))
                continue
            # 등록되지 않은 Agent로 보내면 Dispatcher가 Run 전체를 실패시킨다.
            if (suggestion.vulnerability_type, suggestion.agent_type) not in self._allowed_pairs:
                rejected += 1
                outcomes.append((index, "unsupported_route"))
                continue
            # 규칙에 적용하는 안전 기준을 제안에도 똑같이 적용한다.
            if _requires_state_change_approval(surface) and not (
                run.execution_profile.state_changing_approved
            ):
                rejected += 1
                outcomes.append((index, "state_changing_surface"))
                continue
            if not _supports_suggestion(
                surface, suggestion, evidence, self._capabilities
            ):
                rejected += 1
                outcomes.append((index, "incompatible_surface"))
                continue
            if suggestion.reason_code and suggestion.reason_code not in CANDIDATE_REASON_CODES:
                rejected += 1
                outcomes.append((index, "unsupported_reason_code"))
                continue
            if (
                len(set(suggestion.basis_evidence_ids))
                != len(suggestion.basis_evidence_ids)
                or any(
                    evidence_by_id.get(evidence_id) is None
                    or evidence_by_id[evidence_id].surface_id != surface.surface_id
                    for evidence_id in suggestion.basis_evidence_ids
                )
            ):
                rejected += 1
                outcomes.append((index, "invalid_basis_observation"))
                continue
            if (
                len(set(suggestion.required_evidence_types))
                != len(suggestion.required_evidence_types)
                or any(
                    item not in CANDIDATE_EVIDENCE_TYPES
                    for item in suggestion.required_evidence_types
                )
            ):
                rejected += 1
                outcomes.append((index, "unsupported_evidence_type"))
                continue
            key = _decision_key(
                suggestion.surface_id,
                suggestion.vulnerability_type,
                suggestion.capability_id,
            )
            rule_key = key
            # 규칙이 이미 정한 자리와 Advisor가 중복 제안한 자리는 모두 건너뛴다.
            if rule_key in decided or key in accepted:
                outcomes.append(
                    (index, "rule_kept" if rule_key in decided else "duplicate")
                )
                continue
            capability = self._capabilities_by_id.get(suggestion.capability_id)
            if capability is None:
                capability = next(
                    (
                        item
                        for item in self._capabilities
                        if item.agent_type == suggestion.agent_type
                        and item.vulnerability_type == suggestion.vulnerability_type
                        and capability_matches(item, surface, evidence)
                    ),
                    None,
                )
            required_observations = (
                tuple(
                    item.evidence_id
                    for requirement in capability.observation_requirements
                    for item in evidence
                    if item.run_id == run.run_id
                    and item.surface_id == surface.surface_id
                    and item.evidence_type == "observation"
                    and item.observation.get("type") == requirement.observation_type
                    and (
                        requirement.source is None
                        or item.observation.get("source") == requirement.source
                    )
                ) if capability is not None else ()
            )
            candidate = Candidate(
                candidate_id=f"candidate-{self._id_factory()}",
                run_id=run.run_id,
                surface_id=suggestion.surface_id,
                vulnerability_type=suggestion.vulnerability_type,
                hypothesis=(
                    f"{suggestion.vulnerability_type} candidate suggested by router advisor"
                    + (
                        f" ({suggestion.reason_code})"
                        if suggestion.reason_code
                        else ""
                    )
                ),
                assigned_agent=suggestion.agent_type,
                # LLM이 근거를 생략해도 capability가 요구한 직접 관측은 Analyzer에
                # 전달한다. 모든 ID는 현재 Run·Surface에서 재검증한 것뿐이다.
                evidence_ids=tuple(dict.fromkeys((
                    *suggestion.basis_evidence_ids, *required_observations,
                ))),
                exploration_parameters=(
                    exploration_parameters(capability, surface, evidence)
                    if capability is not None
                    else ()
                ),
                required_evidence_types=suggestion.required_evidence_types,
                routing_capability_id=(
                    capability.capability_id if capability is not None else ""
                ),
                routing_confidence=suggestion.confidence,
                routing_priority=suggestion.priority_label,
                analysis_strategy_id=(
                    suggestion.analysis_strategy_id
                    or capability.strategy_ids[0]
                    if capability is not None
                    else ""
                ),
            )
            priority = {
                "high": 0.45,
                "normal": self._advisor_priority,
                "low": max(0.01, self._advisor_priority / 2),
            }.get(suggestion.priority_label, self._advisor_priority)
            accepted[key] = RouteDecision(
                candidate=candidate, priority=priority
            )
            outcomes.append((index, "candidate_added"))
        self.last_advisor_outcomes = tuple(outcomes)
        return accepted, f"advisor_ok:accepted={len(accepted)},rejected={rejected}"

    def _review_surfaces(
        self,
        surfaces: Sequence[Surface],
        decided: dict[tuple[str, str], RouteDecision],
    ) -> tuple[Surface, ...]:
        """CLI review 정책에 따라 Advisor가 실제로 검토할 Surface를 고른다.

        ``ambiguous``는 규칙 결과가 없거나 둘 이상인 표면만 검토한다. ``weak``는
        여기에 Evidence 없는 단일 Surface 탐색 Candidate까지 포함한다. 강한 관측
        하나로 명확히 분류된 표면은 어느 정책에서도 LLM에 다시 보내지 않는다.
        """

        decisions_by_surface: dict[str, list[RouteDecision]] = {}
        for (surface_id, _), decision in decided.items():
            decisions_by_surface.setdefault(surface_id, []).append(decision)

        selected: list[Surface] = []
        for surface in surfaces:
            matches = decisions_by_surface.get(surface.surface_id, ())
            ambiguous = len(matches) != 1
            single_weak = (
                len(matches) == 1 and not matches[0].candidate.evidence_ids
            )
            if ambiguous or (self._review_policy == "weak" and single_weak):
                selected.append(surface)
        return tuple(selected)
