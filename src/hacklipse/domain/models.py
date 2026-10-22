"""시스템 전 계층이 공유하는 최소 도메인 모델과 핵심 불변식."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from collections.abc import Callable
from typing import Mapping
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .errors import DomainInvariantError


def utc_now() -> datetime:
    """Evidence 생성 시각을 비교 가능한 UTC 기준으로 반환한다."""

    return datetime.now(timezone.utc)


class RunPhase(str, Enum):
    """한 번의 점검 Run이 거치는 상위 워크플로 상태."""

    INIT = "init"
    RECON = "recon"
    ROUTE = "route"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    SSRF_REVIEW = "ssrf_review"
    REPORT = "report"
    DONE = "done"
    FAILED = "failed"


class TaskStatus(str, Enum):
    """Task 저장소에서 관리하는 실행 생명주기."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AgentResultStatus(str, Enum):
    """Agent가 Task 수행 후 반환할 수 있는 공통 상태."""

    COMPLETED = "completed"
    NEEDS_EVIDENCE = "needs_evidence"
    FAILED = "failed"


class ValidationVerdict(str, Enum):
    """Validation Agent만 내릴 수 있는 후보 취약점 판정."""

    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    REJECTED = "rejected"
    BLOCKED = "blocked"


class ValidationReasonCode(str, Enum):
    """Validator가 실행한 분기를 나타내는 결정적 코드.

    UNSPECIFIED는 기존 Validator와 저장 데이터의 이행 기간에만 사용한다. 각
    Validation 분기의 구체적인 값 선택은 Validation Agent 구현의 책임이다.
    """

    UNSPECIFIED = "unspecified"
    ANALYSIS_SIGNAL_MISSING = "analysis_signal_missing"
    AUTHENTICATION_REQUIRED = "authentication_required"
    POST_REQUEST_TEMPLATE_MISSING = "post_request_template_missing"
    CONTROL_SIGNAL_PRESENT = "control_signal_present"
    PROBE_SIGNAL_NOT_REPRODUCED = "probe_signal_not_reproduced"
    REPRODUCTION_EXECUTION_ERROR = "reproduction_execution_error"
    COMPARABLE_RESPONSES_MISSING = "comparable_responses_missing"
    FILE_READ_BUDGET_EXHAUSTED = "file_read_budget_exhausted"
    FILE_READ_CONFIGURATION_MISMATCH = "file_read_configuration_mismatch"
    ACCESS_PLAN_MISSING = "access_plan_missing"
    ACCESS_BUDGET_EXHAUSTED = "access_budget_exhausted"
    VALIDATION_SESSION_MISMATCH = "validation_session_mismatch"
    ACCESS_NOT_EXPOSED = "access_not_exposed"
    CLEANUP_FAILED = "cleanup_failed"
    GENERIC_NO_PROOF = "generic_no_proof"
    SSRF_CALLBACK_ONLY = "ssrf_callback_only"
    SSRF_CALLBACK_NOT_OBSERVED = "ssrf_callback_not_observed"
    SSRF_CALLBACK_PROVIDER_UNAVAILABLE = "ssrf_callback_provider_unavailable"
    SSRF_OWNED_RECEIVER_UNAVAILABLE = "ssrf_owned_receiver_unavailable"
    SSRF_OWNED_RECEIVER_NOT_OBSERVED = "ssrf_owned_receiver_not_observed"
    SSRF_OWNED_RECEIVER_ONLY = "ssrf_owned_receiver_only"
    SSRF_CANARY_ANALYSIS_NOT_ESTABLISHED = "ssrf_canary_analysis_not_established"
    SSRF_CANARY_NOT_REPRODUCED = "ssrf_canary_not_reproduced"
    SSRF_DESTINATION_POLICY_MISSING = "ssrf_destination_policy_missing"
    SSRF_DESTINATION_POLICY_MISMATCH = "ssrf_destination_policy_mismatch"
    SSRF_DESTINATION_POLICY_SURFACE_MISMATCH = (
        "ssrf_destination_policy_surface_mismatch"
    )
    SSRF_DESTINATION_POLICY_ORIGIN_MISMATCH = (
        "ssrf_destination_policy_origin_mismatch"
    )
    SSRF_DESTINATION_POLICY_EVIDENCE_INVALID = (
        "ssrf_destination_policy_evidence_invalid"
    )
    SSRF_DESTINATION_POLICY_ALLOWS_ACCESS = (
        "ssrf_destination_policy_allows_access"
    )
    SSRF_CONFIRMED_DESTINATION_POLICY_VIOLATION = (
        "ssrf_confirmed_destination_policy_violation"
    )
    SSRF_PROOF_BUDGET_EXHAUSTED = "ssrf_proof_budget_exhausted"
    SSRF_MANUAL_REVIEW_REQUIRED = "ssrf_manual_review_required"
    CONFIRMED_PROOF = "confirmed_proof"


class ValidationProofType(str, Enum):
    """취약점 유형별 CONFIRMED 판정이 요구하는 구조화된 증명 종류."""

    XSS_EXECUTION = "xss_execution"
    SQLI_EFFECT = "sqli_effect"
    UNAUTHORIZED_OBJECT_ACCESS = "unauthorized_object_access"
    PATH_TRAVERSAL_FILE_READ = "path_traversal_file_read"
    SSTI_EXECUTION = "ssti_execution"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    WORKING_PUBLIC_CREDENTIAL = "working_public_credential"
    GRAPHQL_INTROSPECTION_EXPOSURE = "graphql_introspection_exposure"
    GRAPHQL_FIELD_SUGGESTION_EXPOSURE = "graphql_field_suggestion_exposure"
    SOURCE_MAP_EXPOSURE = "source_map_exposure"
    ERROR_DETAIL_EXPOSURE = "error_detail_exposure"
    OPEN_REDIRECT = "open_redirect"
    ARBITRARY_FILE_READ = "arbitrary_file_read"
    # 선언된 하위 디렉터리를 벗어나 읽은 경우. 같은 Agent가 다루지만 증명하는 사실이
    # 절대 경로 읽기와 달라, 수출 단계에서 같은 CWE로 뭉개지지 않도록 분리한다.
    DIRECTORY_ESCAPE_FILE_READ = "directory_escape_file_read"
    CORS_ORIGIN_REFLECTION = "cors_origin_reflection"
    FILE_UPLOAD_RETRIEVAL = "file_upload_retrieval"
    SSRF_UNAUTHORIZED_FETCH = "ssrf_unauthorized_fetch"


# SQLi boolean 차등에 쓰는 고정 술어 쌍 (이름, 참, 거짓). 문자열 리터럴의 따옴표는
# 대상마다 다르고(MySQL은 홑·쌍을 모두 받는다) 공백이나 `and`를 지우는 입력 필터도
# 흔하다. 한 쌍만 두면 "취약하지 않다"와 "이 모양이 그 대상에서 성립하지 않는다"가
# 구분되지 않는다. 목록이 도메인에 있는 이유는 요청을 만드는 쪽과 불변식이 같은 집합을
# 봐야 하기 때문이다 — 두 곳으로 갈라지면 한쪽만 넓혀도 다른 쪽이 거부한다.
SQLI_NUMERIC_PREDICATES = (
    ("and_spaced", " AND 1=1", " AND 1=2"),
    ("or_tight", "||1=1", "||1=2"),
)
SQLI_STRING_PREDICATES = (
    ("single_and_spaced", "' AND '1'='1", "' AND '1'='2"),
    ("double_and_spaced", '" AND "1"="1', '" AND "1"="2'),
    ("double_or_tight", '"or"1"="1', '"or"1"="2'),
    ("single_or_tight", "'or'1'='1", "'or'1'='2"),
)
SQLI_BOOLEAN_PREDICATES = (*SQLI_NUMERIC_PREDICATES, *SQLI_STRING_PREDICATES)


class SsrfDestinationRule(str, Enum):
    """Closed destination-policy conclusions."""

    FORBIDDEN = "forbidden"
    ALLOWED = "allowed"


class SsrfVerificationStrategy(str, Enum):
    """Operator-approved proof path for one exact SSRF coordinate."""

    PASSIVE = "passive"
    CALLBACK = "callback"
    OWNED_RECEIVER = "owned_receiver"
    INTERNAL_CANARY = "internal_canary"


class SsrfPolicySource(str, Enum):
    """Trusted sources that may attest an SSRF destination rule."""

    OPERATOR_ATTESTATION = "operator_attestation"
    CONFIG_ALLOWLIST = "config_allowlist"
    OPENAPI_ALLOWLIST = "openapi_allowlist"
    # Compatibility names serialize to the canonical three-value contract.
    TRUSTED_CONFIG_ALLOWLIST = "config_allowlist"
    TRUSTED_DEPLOYMENT_POLICY = "config_allowlist"
    TRUSTED_API_POLICY = "openapi_allowlist"


class SsrfPolicyAssertion(str, Enum):
    """Closed security assertion supported by SSRF confirmation."""

    TARGET_MUST_NOT_REACH_DESTINATION = "target_must_not_reach_destination"
    TARGET_MAY_REACH_DESTINATION = "target_may_reach_destination"


class SsrfPolicyEvidenceStatus(str, Enum):
    """How the structured destination rule was established."""

    ATTESTED = "attested"
    VERIFIED = "verified"


class SsrfObservationPhase(str, Enum):
    """Independent passive verification phases."""

    ANALYSIS = "analysis"
    VALIDATION = "validation"


class SsrfObservationSource(str, Enum):
    """Allowed provenance for manually supplied server-request observations."""

    OPERATOR_OWNED_SERVICE = "operator_owned_service"


class SsrfObservationProviderStatus(str, Enum):
    """Availability of the passive observation source."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class SsrfAssessmentReason(str, Enum):
    """Closed reasons for deterministic passive SSRF assessment."""

    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    EXECUTION_APPROVAL_MISSING = "execution_approval_missing"
    EXECUTION_APPROVAL_SURFACE_MISMATCH = "execution_approval_surface_mismatch"
    VERIFICATION_ENDPOINT_MISMATCH = "verification_endpoint_mismatch"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    REQUEST_BUDGET_UNAVAILABLE = "request_budget_unavailable"
    VERIFICATION_SESSION_MISSING = "verification_session_missing"
    OBSERVATION_SOURCE_UNVERIFIED = "observation_source_unverified"
    NO_SERVER_REQUEST_OBSERVED = "no_server_request_observed"
    INDEPENDENT_OBSERVATION_MISSING = "independent_observation_missing"
    SERVER_REQUEST_OBSERVED_WITHOUT_DESTINATION_POLICY = (
        "server_request_observed_without_destination_policy"
    )
    DESTINATION_POLICY_SURFACE_MISMATCH = "destination_policy_surface_mismatch"
    DESTINATION_POLICY_ORIGIN_MISMATCH = "destination_policy_origin_mismatch"
    DESTINATION_POLICY_EVIDENCE_INVALID = "destination_policy_evidence_invalid"
    DESTINATION_POLICY_ALLOWS_ACCESS = "destination_policy_allows_access"
    CONFIRMED_DESTINATION_POLICY_VIOLATION = (
        "confirmed_destination_policy_violation"
    )


class HttpRequestKind(str, Enum):
    """비교 기준 요청과 취약점 탐색 요청을 기계적으로 구분한다."""

    CONTROL = "control"
    PROBE = "probe"
    POSTMESSAGE_CONTROL = "postmessage_control"
    POSTMESSAGE_REFLECTION = "postmessage_reflection"
    POSTMESSAGE_EXECUTION = "postmessage_execution"
    GRAPHQL_QUERY_CONTROL = "graphql_query_control"
    GRAPHQL_QUERY_PROBE = "graphql_query_probe"
    OPEN_REDIRECT_PROBE = "open_redirect_probe"
    SSRF_CONTROL = "ssrf_control"
    SSRF_PROBE = "ssrf_probe"
    SSRF_CANARY_PROBE = "ssrf_canary_probe"
    SSRF_OWNED_RECEIVER_PROBE = "ssrf_owned_receiver_probe"
    SSRF_WORKFLOW_CONTROL = "ssrf_workflow_control"
    SSRF_WORKFLOW_OWNED_PROBE = "ssrf_workflow_owned_probe"
    SSRF_WORKFLOW_SETUP = "ssrf_workflow_setup"
    SSRF_WORKFLOW_TRIGGER = "ssrf_workflow_trigger"
    SSRF_WORKFLOW_CLEANUP = "ssrf_workflow_cleanup"
    SSRF_CSV_UPLOAD_CONTROL = "ssrf_csv_upload_control"
    SSRF_CSV_UPLOAD_PROBE = "ssrf_csv_upload_probe"
    SSRF_CSV_IMPORT_CONTROL = "ssrf_csv_import_control"
    SSRF_CSV_IMPORT_PROBE = "ssrf_csv_import_probe"
    CORS_PROBE = "cors_probe"
    SQLI_BOOLEAN_TRUE = "sqli_boolean_true"
    SQLI_BOOLEAN_FALSE = "sqli_boolean_false"
    PATH_TRAVERSAL_PROBE = "path_traversal_probe"
    # 증명 파일이 정상 경로로도 공개돼 있는지 확인하는 요청. 앱이 원래 공개하는 파일을
    # 읽기 취약점으로 오인하지 않기 위한 대조군이다.
    FILE_READ_PUBLIC_CHECK = "file_read_public_check"
    ACCESS_CONTROL_PROBE = "access_control_probe"
    SSTI_PROBE = "ssti_probe"
    SSTI_CLEANUP = "ssti_cleanup"
    ARBITRARY_FILE_READ_PROBE = "arbitrary_file_read_probe"
    DIRECTORY_ESCAPE_PROBE = "directory_escape_probe"


class AccessPrincipalRole(str, Enum):
    """Access Control 탐침이 지정할 수 있는 인증 주체 역할.

    Agent와 LLM은 credential_ref를 직접 고를 수 없고 역할만 지정한다. 역할에서
    자격증명으로의 해석은 중앙 Collector가 Run에 등록된 매핑으로만 수행하므로,
    Agent는 username·password·Cookie·Authorization을 알 수도 고를 수도 없다.
    """

    ACTOR = "actor"
    OWNER = "owner"


class AccessIdentifierLocation(str, Enum):
    """객체 식별자가 HTTP 요청의 어느 부분에 있는지 나타낸다."""

    QUERY = "query"
    PATH = "path"


_HTTP_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

# PROBE 요청이 쿼리에 실을 수 있는 값의 형태. 영숫자 marker 뒤에 허용된 메타문자만
# 최대 4개까지 붙일 수 있다.
#
# 왜 메타문자를 아예 막지 않는가 — SQLi는 따옴표 없이, 출력 인코딩 여부는 꺾쇠 없이
# 원리적으로 확인할 수 없다. 이 문자들은 구문 오류를 유발하거나 인코딩 적용 여부를
# 드러낼 뿐 실행되지 않고 대상 상태를 바꾸지 않는다(실제 스캐너의 canary 기법).
#
# 왜 그래도 형태를 강제하는가 — 이 검사가 없으면 Agent가, 나중에는 LLM이 임의 문자열을
# 쿼리에 실을 수 있다. 공백·괄호·세미콜론·등호가 막히므로 "' OR 1=1--", "UNION SELECT",
# "; DROP", "../", "<script>alert(1)</script>"는 전부 도메인에서 거부된다.
# 새 탐침 기법이 다른 문자를 필요로 하면 여기를 늘리는 것이 명시적 결정이 된다.
PROBE_METACHARACTERS = "'\"<>"
_PROBE_VALUE = re.compile(r"^[A-Za-z0-9_-]+['\"<>]{0,4}$")
_GRAPHQL_READ_DOCUMENT = re.compile(
    r'query \{ [A-Za-z_][A-Za-z0-9_]{0,79}'
    r'\([A-Za-z_][A-Za-z0-9_]{0,79}: "(hacklipse[A-Za-z0-9]{1,180})(\'?)"\)'
    r'(?: \{ __typename \})? \}\Z'
)
# Path Traversal 자동 검증이 읽을 수 있는 유일한 값이다. 컨테이너에 기본 존재하는
# 비민감 OS 식별 파일을 정확한 상대 경로 하나로 고정해 LLM이나 Agent가 다른 파일
# (예: /etc/passwd)을 선택하지 못하게 한다.
PATH_TRAVERSAL_SAFE_PROBE_PATH = "../../../../../etc/os-release"
# 경로를 그대로 여는 표면에서 쓰는 절대 경로. 같은 비민감 파일을 가리키지만 탈출
# 시퀀스가 없다. ``..``를 거르는 필터는 절대 경로를 막지 못하는 경우가 흔해, 같은
# 파라미터에서 상대 탈출과 결과가 갈린다. 여기서도 읽을 파일을 하나로 고정해
# Agent나 LLM이 /etc/passwd 같은 다른 파일을 고를 수 없게 한다.
ARBITRARY_FILE_READ_SAFE_PROBE_PATH = "/etc/os-release"
# 서버 템플릿의 layout/view 경로가 뷰 디렉터리 밖으로 나가는지 확인할 때만 쓰는
# 별도 저민감 파일. 패키지 메타데이터는 비밀 파일이 아니며 Juice Shop을 포함한
# Node 애플리케이션 루트에 일반적으로 존재한다.
PATH_TRAVERSAL_SAFE_FORM_PROBE_PATH = "../package.json"
# 같은 증명 파일을 가리키는 두 번째 고정 값. 한 번만 훑고 지나가는 필터
# (``str_replace(['../','./','..\\','.\\'], '', $input)`` 같은 것)는 제거 후 남은
# 조각이 다시 붙는 것을 막지 못한다. ``..\/``에서 ``..\``를 떼면 ``../``가 남으므로
# 필터를 통과한 뒤 같은 경로가 복원된다. 가리키는 파일은 첫 값과 동일하고, 값 역시
# 고정이라 Agent나 LLM이 다른 파일을 고를 수는 없다.
PATH_TRAVERSAL_FILTER_BYPASS_PROBE_PATH = (
    "....\\/....\\/....\\/....\\/....\\/etc/os-release"
)

# 선언된 하위 디렉터리 밖으로 나가는지 확인할 때 읽는 고정 파일과, 같은 자리에서
# "없는 파일"을 받아 보는 고정 이름.
#
# 왜 /etc/os-release 로는 부족한가 — 앱이 자기 루트 밖을 전부 거부하면서도 선언한
# 하위 디렉터리(`web_assets/`) 제한은 강제하지 않는 경우가 있다. 그 경우 OS 파일은
# 영영 403이고, 실제 취약점인 "디렉터리 탈출"은 증명되지 않는다.
#
# 왜 README.md 인가 — 프로젝트 루트의 공개 설명 파일이라 비밀이 아니고, 언어 생태계를
# 가리지 않고 가장 흔하다. 없으면 증명하지 못한 채로 남기지, 다른 파일을 고르지 않는다.
DIRECTORY_ESCAPE_PROOF_FILE = "README.md"
# 존재할 리 없는 이름. 같은 자리에서 "파일 없음" 응답이 어떻게 생겼는지 받아 두면,
# 200으로 오류 화면을 돌려주는 앱을 증명으로 오인하지 않는다.
DIRECTORY_ESCAPE_ABSENT_FILE = "hacklipse-absent-proof.md"
# 탈출 탐침의 형태. 앞의 한 세그먼트는 관측된 값의 첫 디렉터리 이름이고 나머지는 고정이다.
# 경로가 어휘적으로 정규화되므로 `X/../README.md`는 X가 무엇이든 base의 README.md 하나만
# 가리킨다 — 즉 앞 세그먼트는 "선언된 디렉터리를 벗어난다"는 형태를 만들 뿐 읽는 파일을
# 바꾸지 못한다. 그래서 이 탐침이 읽을 수 있는 실재 파일은 끝까지 하나뿐이다.
_DIRECTORY_ESCAPE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}/\.\./(?:"
    + "|".join(
        re.escape(name)
        for name in (
            DIRECTORY_ESCAPE_PROOF_FILE,
            DIRECTORY_ESCAPE_ABSENT_FILE,
        )
    )
    + r")"
)
# 확장자 필터를 우회해 서버가 직접 거부한 자기 파일을 읽게 하는 고정 접미사.
# 이미 URL 인코딩된 문자열이므로 재인코딩하지 않고 경로 뒤에 그대로 붙인다.
# Agent나 LLM은 "우회를 적용한다"만 지정할 수 있고 접미사 내용은 고를 수 없다.
PATH_TRAVERSAL_BYPASS_SUFFIX = "%2500.md"
# Access Control 탐침이 식별자 파라미터에 실을 수 있는 값. 숫자만 허용해 LLM이나 Agent가
# 경로·따옴표·와일드카드를 객체 ID 자리에 넣지 못하게 한다.
_OBJECT_IDENTIFIER = re.compile(r"^[0-9]{1,10}$")
# 경로에 `이름=값` 형태로 실린 입력의 이름. query 파라미터명과 같은 수준으로 보수적인
# 식별자만 인정한다. base64 꼬리(`/aGVsbG8=`)처럼 `=`가 들어간 경로를 입력 좌표로
# 오인하면 관측하지 않은 자리에 탐침을 보내게 된다.
_PATH_ASSIGNMENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "accept-encoding",
        "authorization",
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "transfer-encoding",
        "user-agent",
    }
)


# 같은 증명 파일을 가리키는 서로 다른 표기. 필터는 형태로 막는 경우가 많아, 한 형태가
# 거부되는 것만 보고 "읽을 수 없다"고 결론 내면 실제 취약점을 놓친다.
#
# 집합이어도 안전 성질은 그대로다 — 모든 항목이 같은 비민감 파일 하나를 가리키므로,
# Agent도 LLM도 "무엇을 읽을지"는 여전히 고를 수 없고 "어떤 표기로 시도할지"만 달라진다.
# 새 표기를 늘리는 것은 여기서의 명시적 결정이 된다.
#
# 퍼센트 표기가 왜 다른 요청이 되는가 — 직렬화가 `%`를 다시 인코딩하므로, 값에 ``%2f``를
# 두면 대상은 한 번 디코딩한 뒤 ``%2f``를 보게 된다. 경로 API에 그대로 넘기거나 한 번 더
# 디코딩하는 구현에서만 `/`가 되어, 디코딩 전에 형태로 거르는 필터를 지난다.
# 바뀌지 않는 자리에 싣는 고정 marker. Adapter 들이 각자 문자열을 베끼지 않도록
# 도메인에 한 번만 둔다.
CONTROL_MARKER = "hacklipse-control"
PATH_TRAVERSAL_SAFE_PROBE_VALUES = (
    PATH_TRAVERSAL_SAFE_PROBE_PATH,
    PATH_TRAVERSAL_FILTER_BYPASS_PROBE_PATH,
    "../../etc/os-release",
    "..%2f..%2f..%2fetc%2fos-release",
)
ARBITRARY_FILE_READ_SAFE_PROBE_VALUES = (
    ARBITRARY_FILE_READ_SAFE_PROBE_PATH,
    "%2fetc%2fos-release",
)


def is_path_traversal_safe_probe_value(value: str) -> bool:
    """고정된 비민감 증명 파일을 가리키는 상대 표기 중 하나인지 확인한다."""

    return value in PATH_TRAVERSAL_SAFE_PROBE_VALUES


def is_arbitrary_file_read_safe_probe_value(value: str) -> bool:
    """고정된 비민감 증명 파일을 가리키는 절대 표기 중 하나인지 확인한다."""

    return value in ARBITRARY_FILE_READ_SAFE_PROBE_VALUES


def is_path_traversal_safe_form_probe_value(value: str) -> bool:
    """서버 렌더링 폼 전용 고정 패키지 메타데이터 경로인지 확인한다."""

    return value == PATH_TRAVERSAL_SAFE_FORM_PROBE_PATH


def is_directory_escape_value(value: str) -> bool:
    """선언된 하위 디렉터리를 벗어나는 고정 형태의 탐침 값인지 확인한다."""

    return _DIRECTORY_ESCAPE.fullmatch(value) is not None


def is_path_traversal_bypass_suffix(value: str) -> bool:
    """도메인이 고정한 확장자 필터 우회 접미사와 정확히 같은지 확인한다."""

    return value == PATH_TRAVERSAL_BYPASS_SUFFIX


# 경로에 실린 입력의 값을 교체할 수 있는 탐침 종류와, 그 종류가 실을 수 있는 유일한 값.
#
# 왜 종류별로 값을 묶는가 — 두 탐침은 서로 다른 것을 증명한다. 상대 탈출은 "디렉터리
# 밖으로 나갈 수 있는가"를, 절대 경로는 "경로를 그대로 여는가"를 본다. ``..``를 거르는
# 필터가 절대 경로는 막지 못하는 경우가 흔해 같은 자리에서 결과가 갈린다.
#
# 왜 하나로 합치지 않는가 — 값 집합을 종류와 분리해 "둘 중 아무거나"로 두면, 이 필드가
# 곧 "경로 아무 자리에 허용 목록 중 아무 값이나" 넣는 통로가 된다. 종류마다 값이 하나로
# 고정돼야 Agent도 LLM도 무엇이 전송될지 고를 수 없다.
_PATH_ASSIGNMENT_PROBE_VALUES: dict[HttpRequestKind, Callable[[str], bool]] = {
    HttpRequestKind.PATH_TRAVERSAL_PROBE: is_path_traversal_safe_probe_value,
    HttpRequestKind.ARBITRARY_FILE_READ_PROBE: is_arbitrary_file_read_safe_probe_value,
    HttpRequestKind.DIRECTORY_ESCAPE_PROBE: is_directory_escape_value,
}


@dataclass(frozen=True, slots=True)
class RunScope:
    """한 Run에서 접근이 허용된 호스트와 경로 범위."""

    allowed_hosts: frozenset[str]
    allowed_path_prefixes: tuple[str, ...] = ("/",)

    def __post_init__(self) -> None:
        # 비어 있는 범위는 사실상 무제한 또는 오설정으로 해석될 수 있으므로 허용하지 않는다.
        if not self.allowed_hosts:
            raise DomainInvariantError("at least one allowed host is required")
        if any(not prefix.startswith("/") for prefix in self.allowed_path_prefixes):
            raise DomainInvariantError("allowed path prefixes must start with '/'")


_SSRF_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/#-]{0,199}\Z")
_SSRF_SURFACE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_SSRF_PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}(?:\[\])?\Z")


def ssrf_request_parameters(
    method: str, query_parameters: tuple[tuple[str, str], ...],
    headers: tuple[tuple[str, str], ...], body: str | None,
    *, allow_companions: bool = False,
) -> tuple[tuple[str, str], ...]:
    """Read one SSRF input, optionally with a bounded flat JSON workflow body."""

    if method.upper() == "GET":
        if body is not None or headers:
            return ()
        return query_parameters
    if (
        method.upper() != "POST" or query_parameters
        or body is None or len(body) > 4096
    ):
        return ()
    if (
        len(headers) != 1
        or tuple((name.casefold(), value.casefold()) for name, value in headers)
        != (("content-type", "application/json"),)
    ):
        return ()
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        if len(pairs) != len({name for name, _ in pairs}):
            raise ValueError("duplicate JSON input field")
        return dict(pairs)

    try:
        parsed = json.loads(body, object_pairs_hook=unique_object)
    except (TypeError, ValueError):
        return ()
    if not isinstance(parsed, dict):
        return ()
    if allow_companions:
        flattened: list[tuple[str, str]] = []
        def visit(value: object, prefix: str, depth: int) -> bool:
            if depth > 3 or not isinstance(value, dict):
                return False
            for name, item in value.items():
                if not isinstance(name, str) or _SSRF_PARAMETER.fullmatch(name) is None:
                    return False
                coordinate = f"{prefix}.{name}" if prefix else name
                if isinstance(item, dict):
                    if not visit(item, coordinate, depth + 1):
                        return False
                elif isinstance(item, str):
                    if len(item) > (
                        2048 if item.startswith(("http://", "https://")) else 128
                    ):
                        return False
                    flattened.append((coordinate, item))
                else:
                    return False
                if len(flattened) > 12:
                    return False
            return True
        if not visit(parsed, "", 1) or not flattened:
            return ()
        return tuple(flattened)
    if (
        len(parsed) != 1
        or any(not isinstance(name, str) or _SSRF_PARAMETER.fullmatch(name) is None
               or not isinstance(value, str) for name, value in parsed.items())
    ):
        return ()
    return tuple(parsed.items())


def ssrf_csv_upload_parameter(
    method: str, headers: tuple[tuple[str, str], ...], body: str | None,
) -> tuple[str, str] | None:
    """Read one URL coordinate from the bounded category-image CSV upload."""

    if method.upper() != "POST" or body is None or len(body) > 4096 or len(headers) != 1:
        return None
    header_name, header_value = headers[0]
    if header_name.casefold() != "content-type":
        return None
    match = re.fullmatch(
        r"multipart/form-data; boundary=(hacklipse[0-9a-f]{12}(?:control|probe))",
        header_value,
    )
    if match is None:
        return None
    boundary = match.group(1)
    suffix = boundary.removeprefix("hacklipse")
    filename = "hacklipse-" + suffix + ".csv"
    prefix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: text/csv\r\n\r\n"
    )
    trailer = f"\r\n--{boundary}--\r\n"
    if not body.startswith(prefix) or not body.endswith(trailer):
        return None
    csv_line = body[len(prefix):-len(trailer)]
    if csv_line.count("\n") != 1 or not csv_line.endswith("\n") or ";" not in csv_line:
        return None
    category, _, raw_url = csv_line[:-1].partition(";")
    if category != "hacklipse" + suffix or not raw_url or "\r" in raw_url:
        return None
    decoded = unquote(raw_url)
    if decoded != "hacklipse-control":
        try:
            parsed = urlsplit(decoded)
            encoded = urlsplit(raw_url)
            encoded_hostname = encoded.hostname
        except ValueError:
            return None
        if (
            parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or encoded_hostname is None
            or encoded_hostname.casefold() != "".join(
                f"%{ord(char):02x}" for char in parsed.hostname
            )
            or len(decoded) > 2048
        ):
            return None
    return "csv.image", decoded


_SSRF_REFERENCE_JWT = re.compile(
    r"(?:^|[:/#._-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?:$|[:/#._-])"
)
_SSRF_REFERENCE_SECRET_PREFIX = re.compile(
    r"(?i)(?:^|[:/#._-])(?:sk|secret|token|password|passwd|credential|"
    r"api[_-]?key|ghp|github_pat|xox[baprs])[-_:][A-Za-z0-9_-]{8,}"
)
_SSRF_REFERENCE_AWS_KEY = re.compile(r"(?:^|[^A-Z0-9])AKIA[A-Z0-9]{16}(?:$|[^A-Z0-9])")
_SSRF_GENERATED_ENDPOINT_REFERENCE = re.compile(r"endpoint-[0-9a-f]{32}\Z")
_SSRF_LONG_HEX_REFERENCE = re.compile(r"[0-9a-f]{32,}\Z", re.IGNORECASE)
_SSRF_LONG_TOKEN_REFERENCE = re.compile(r"[A-Za-z0-9_-]{24,}\Z")


def _reference_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in (value.count(char) for char in set(value))
    )


def validate_ssrf_opaque_reference(
    value: str, label: str = "SSRF reference", *, reject_secret_like: bool = True,
) -> None:
    """Reject URLs and credential-like material before a reference reaches Evidence."""

    if not isinstance(value, str) or _SSRF_REFERENCE.fullmatch(value) is None:
        raise DomainInvariantError(f"{label} must be a short opaque reference")
    if not reject_secret_like:
        return
    if _SSRF_GENERATED_ENDPOINT_REFERENCE.fullmatch(value) is not None:
        return
    if (
        _SSRF_REFERENCE_JWT.search(value) is not None
        or _SSRF_REFERENCE_SECRET_PREFIX.search(value) is not None
        or _SSRF_REFERENCE_AWS_KEY.search(value) is not None
    ):
        raise DomainInvariantError(f"{label} must not contain secret material")
    for component in re.split(r"[:/#]", value):
        if _SSRF_LONG_HEX_REFERENCE.fullmatch(component) is not None:
            raise DomainInvariantError(f"{label} must not contain secret material")
        if (
            _SSRF_LONG_TOKEN_REFERENCE.fullmatch(component) is not None
            and sum((
                any(char.islower() for char in component),
                any(char.isupper() for char in component),
                any(char.isdigit() for char in component),
            )) >= 2
            and len(set(component)) / len(component) >= 0.55
            and _reference_entropy(component) >= 3.6
        ):
            raise DomainInvariantError(f"{label} must not contain secret material")


def _validate_ssrf_reference(
    value: str, label: str, *, reject_secret_like: bool = False,
) -> None:
    validate_ssrf_opaque_reference(
        value, label, reject_secret_like=reject_secret_like,
    )


def _validate_aware_datetime(value: datetime, label: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise DomainInvariantError(f"{label} must be timezone-aware")


def ssrf_destination_origin(url: str) -> str:
    """Return a normalized HTTP(S) origin without retaining path or credentials."""

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise DomainInvariantError("SSRF destination origin is invalid") from error
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise DomainInvariantError("SSRF destination must have a plain HTTP(S) origin")
    if port is not None and not 0 < port <= 65535:
        raise DomainInvariantError("SSRF destination port is invalid")
    if (parsed.scheme.casefold(), port) in {("http", 80), ("https", 443)}:
        port = None
    rendered_host = f"[{host}]" if ":" in host else host
    return (
        f"{parsed.scheme.casefold()}://{rendered_host}:{port}"
        if port is not None
        else f"{parsed.scheme.casefold()}://{rendered_host}"
    )


@dataclass(frozen=True, slots=True)
class SsrfExecutionApproval:
    """Explicit permission to verify exactly one already-observed Surface."""

    approval_id: str
    surface_id: str
    verification_endpoint_ref: str
    approved_by: str
    approved_at: datetime
    scope: str = "single_surface"

    def __post_init__(self) -> None:
        _validate_ssrf_reference(self.approval_id, "SSRF approval id")
        if _SSRF_SURFACE_ID.fullmatch(self.surface_id) is None:
            raise DomainInvariantError("SSRF approval requires an exact surface id")
        if self.scope != "single_surface":
            raise DomainInvariantError("SSRF execution approval scope must be single_surface")
        _validate_ssrf_reference(
            self.verification_endpoint_ref,
            "SSRF verification endpoint reference",
            reject_secret_like=True,
        )
        _validate_ssrf_reference(
            self.approved_by, "SSRF approval principal", reject_secret_like=True,
        )
        _validate_aware_datetime(self.approved_at, "SSRF approval timestamp")


@dataclass(frozen=True, slots=True, init=False)
class SsrfDestinationPolicy:
    """Trusted destination rule bound to explicit Surfaces and one exact origin."""

    policy_id: str
    surface_ids: tuple[str, ...]
    destination_origin: str
    destination_rule: SsrfDestinationRule
    assertion: SsrfPolicyAssertion | None
    source_type: SsrfPolicySource
    source_reference: str
    approved_by: str
    created_at: datetime
    evidence_status: SsrfPolicyEvidenceStatus | None

    def __init__(
        self,
        policy_id: str,
        destination_rule: SsrfDestinationRule,
        source_type: SsrfPolicySource,
        source_reference: str,
        approved_by: str,
        created_at: datetime,
        *,
        surface_ids: tuple[str, ...] | None = None,
        destination_origin: str = "",
        assertion: SsrfPolicyAssertion | None = None,
        evidence_status: SsrfPolicyEvidenceStatus | None = None,
        surface_id: str | None = None,
    ) -> None:
        """Accept legacy ``surface_id`` only as an unambiguous singleton view."""

        if surface_ids is None:
            surface_ids = () if surface_id is None else (surface_id,)
        elif surface_id is not None and surface_ids != (surface_id,):
            raise DomainInvariantError("SSRF policy surface aliases disagree")
        object.__setattr__(self, "policy_id", policy_id)
        object.__setattr__(self, "surface_ids", surface_ids)
        object.__setattr__(self, "destination_origin", destination_origin)
        object.__setattr__(self, "destination_rule", destination_rule)
        object.__setattr__(self, "assertion", assertion)
        object.__setattr__(self, "source_type", source_type)
        object.__setattr__(self, "source_reference", source_reference)
        object.__setattr__(self, "approved_by", approved_by)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "evidence_status", evidence_status)
        self.__post_init__()

    def __post_init__(self) -> None:
        _validate_ssrf_reference(self.policy_id, "SSRF policy id")
        if (
            not isinstance(self.surface_ids, tuple)
            or not self.surface_ids
            or len(set(self.surface_ids)) != len(self.surface_ids)
            or any(_SSRF_SURFACE_ID.fullmatch(item) is None for item in self.surface_ids)
        ):
            raise DomainInvariantError(
                "SSRF policy requires unique exact surface ids"
            )
        if not isinstance(self.destination_rule, SsrfDestinationRule):
            raise DomainInvariantError(
                "SSRF destination rule must use SsrfDestinationRule"
            )
        if not isinstance(self.source_type, SsrfPolicySource):
            raise DomainInvariantError(
                "SSRF policy source must use the trusted SsrfPolicySource enum"
            )
        _validate_ssrf_reference(
            self.source_reference,
            "SSRF policy source reference",
            reject_secret_like=True,
        )
        required_prefix = {
            SsrfPolicySource.OPERATOR_ATTESTATION: "operator:",
            SsrfPolicySource.CONFIG_ALLOWLIST: "config:",
            SsrfPolicySource.OPENAPI_ALLOWLIST: "openapi:",
        }[self.source_type]
        if not self.source_reference.startswith(required_prefix):
            raise DomainInvariantError(
                "SSRF policy reference does not match its trusted source type"
            )
        _validate_ssrf_reference(
            self.approved_by, "SSRF policy principal", reject_secret_like=True,
        )
        _validate_aware_datetime(self.created_at, "SSRF policy timestamp")
        if self.destination_origin:
            parsed = urlsplit(self.destination_origin)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise DomainInvariantError("SSRF policy destination must be an origin only")
            normalized = ssrf_destination_origin(self.destination_origin)
            object.__setattr__(self, "destination_origin", normalized)
        if self.assertion is not None and not isinstance(
            self.assertion, SsrfPolicyAssertion
        ):
            raise DomainInvariantError("SSRF policy assertion must use the closed enum")
        if self.evidence_status is not None and not isinstance(
            self.evidence_status, SsrfPolicyEvidenceStatus
        ):
            raise DomainInvariantError("SSRF policy evidence status must use the closed enum")
        structured_fields = (
            bool(self.destination_origin),
            self.assertion is not None,
            self.evidence_status is not None,
        )
        if any(structured_fields) and not all(structured_fields):
            raise DomainInvariantError(
                "SSRF destination, assertion, and evidence status must be stored together"
            )
        if all(structured_fields):
            expected_assertion = (
                SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION
                if self.destination_rule is SsrfDestinationRule.FORBIDDEN
                else SsrfPolicyAssertion.TARGET_MAY_REACH_DESTINATION
            )
            if self.assertion is not expected_assertion:
                raise DomainInvariantError(
                    "SSRF destination rule and assertion are inconsistent"
                )
            if (
                self.source_type
                in {
                    SsrfPolicySource.CONFIG_ALLOWLIST,
                    SsrfPolicySource.OPENAPI_ALLOWLIST,
                }
                and self.evidence_status is not SsrfPolicyEvidenceStatus.VERIFIED
            ):
                raise DomainInvariantError(
                    "SSRF config and OpenAPI policies must be verified"
                )

    @property
    def surface_id(self) -> str:
        """Singleton compatibility view for existing per-Surface integrations."""

        if len(self.surface_ids) != 1:
            raise DomainInvariantError("SSRF policy applies to multiple surfaces")
        return self.surface_ids[0]

    def require_surface(self, surface_id: str) -> None:
        """Reject reusing this policy for any other Surface."""

        if surface_id not in self.surface_ids:
            raise DomainInvariantError(
                "SSRF destination policy does not apply to this surface"
            )

    def confirms_for(self, surface_id: str, destination_url: str) -> bool:
        """Return whether this policy can authorize an SSRF CONFIRMED verdict."""

        return (
            surface_id in self.surface_ids
            and self.destination_rule is SsrfDestinationRule.FORBIDDEN
            and self.assertion
            is SsrfPolicyAssertion.TARGET_MUST_NOT_REACH_DESTINATION
            and self.evidence_status
            in {SsrfPolicyEvidenceStatus.ATTESTED, SsrfPolicyEvidenceStatus.VERIFIED}
            and bool(self.destination_origin)
            and self.destination_origin == ssrf_destination_origin(destination_url)
        )


# Public contract name. The SSRF-prefixed alias remains for code that already
# imported the in-progress model while policy consumers migrate in later work.
DestinationPolicy = SsrfDestinationPolicy


@dataclass(frozen=True, slots=True)
class SsrfReviewRegistration:
    """Sanitized approval and optional policy for one observed input coordinate."""

    run_id: str
    parameter: str
    hint_evidence_id: str | None
    execution_approval: SsrfExecutionApproval
    verification_strategy: SsrfVerificationStrategy
    destination_policy: SsrfDestinationPolicy | None = None
    hint_use_approved: bool = False

    @property
    def surface_id(self) -> str:
        return self.execution_approval.surface_id

    def __post_init__(self) -> None:
        _validate_ssrf_reference(self.run_id, "SSRF review Run id")
        if _SSRF_PARAMETER.fullmatch(self.parameter) is None:
            raise DomainInvariantError(
                "SSRF review requires one exact safe parameter name"
            )
        if self.hint_evidence_id is not None:
            _validate_ssrf_reference(
                self.hint_evidence_id, "SSRF review hint Evidence id"
            )
        if type(self.hint_use_approved) is not bool:
            raise DomainInvariantError("SSRF hint-use approval must be boolean")
        if not isinstance(self.verification_strategy, SsrfVerificationStrategy):
            raise DomainInvariantError("SSRF review verification strategy is invalid")
        if self.hint_use_approved and self.hint_evidence_id is None:
            raise DomainInvariantError(
                "SSRF hint-use approval requires one destination hint Evidence"
            )
        if not isinstance(self.execution_approval, SsrfExecutionApproval):
            raise DomainInvariantError("SSRF review requires structured approval")
        if self.destination_policy is not None:
            if not isinstance(self.destination_policy, SsrfDestinationPolicy):
                raise DomainInvariantError("SSRF review policy must be structured")
            self.destination_policy.require_surface(self.surface_id)


@dataclass(frozen=True, slots=True)
class ServerRequestObservation:
    """Sanitized, manually supplied proof that the target server sent a request."""

    observation_id: str
    run_id: str
    surface_id: str
    parameter: str
    verification_endpoint_ref: str
    verification_session_id: str
    phase: SsrfObservationPhase
    observed_at: datetime
    source_verified: bool
    destination_origin: str = ""
    request_method: str = "GET"
    source_type: SsrfObservationSource = SsrfObservationSource.OPERATOR_OWNED_SERVICE

    def __post_init__(self) -> None:
        for value, label in (
            (self.observation_id, "SSRF observation id"),
            (self.run_id, "SSRF observation run id"),
            (self.verification_endpoint_ref, "SSRF verification endpoint reference"),
            (self.verification_session_id, "SSRF verification session id"),
        ):
            _validate_ssrf_reference(
                value,
                label,
                reject_secret_like=label in {
                    "SSRF verification endpoint reference",
                    "SSRF verification session id",
                },
            )
        if _SSRF_SURFACE_ID.fullmatch(self.surface_id) is None:
            raise DomainInvariantError("SSRF observation requires an exact surface id")
        if _SSRF_PARAMETER.fullmatch(self.parameter) is None:
            raise DomainInvariantError("SSRF observation parameter must be an exact safe name")
        try:
            phase = SsrfObservationPhase(self.phase)
            source_type = SsrfObservationSource(self.source_type)
        except (TypeError, ValueError) as error:
            raise DomainInvariantError("unsupported SSRF observation value") from error
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "source_type", source_type)
        if self.request_method != "GET":
            raise DomainInvariantError("passive SSRF observation method must be GET")
        if type(self.source_verified) is not bool:
            raise DomainInvariantError("SSRF observation source flag must be boolean")
        if self.destination_origin:
            parsed = urlsplit(self.destination_origin)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise DomainInvariantError(
                    "SSRF observation destination must be an origin only"
                )
            object.__setattr__(
                self,
                "destination_origin",
                ssrf_destination_origin(self.destination_origin),
            )
        _validate_aware_datetime(self.observed_at, "SSRF observation timestamp")


@dataclass(frozen=True, slots=True)
class SsrfAssessment:
    """Deterministic passive assessment result without raw request material."""

    verdict: ValidationVerdict
    reason_code: SsrfAssessmentReason
    # Provider observation ids are not central Evidence ids and must never be
    # copied into ValidationResult without RuntimeEvidenceCollector mapping.
    observation_ids: tuple[str, ...] = ()
    policy_id: str | None = None

    def __post_init__(self) -> None:
        try:
            verdict = ValidationVerdict(self.verdict)
            reason_code = SsrfAssessmentReason(self.reason_code)
        except (TypeError, ValueError) as error:
            raise DomainInvariantError("unsupported SSRF assessment value") from error
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "reason_code", reason_code)
        expected_verdicts = {
            SsrfAssessmentReason.MANUAL_REVIEW_REQUIRED: ValidationVerdict.SUSPECTED,
            SsrfAssessmentReason.EXECUTION_APPROVAL_MISSING: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.EXECUTION_APPROVAL_SURFACE_MISMATCH: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.VERIFICATION_ENDPOINT_MISMATCH: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.PROVIDER_UNAVAILABLE: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.REQUEST_BUDGET_UNAVAILABLE: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.VERIFICATION_SESSION_MISSING: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.OBSERVATION_SOURCE_UNVERIFIED: ValidationVerdict.BLOCKED,
            SsrfAssessmentReason.NO_SERVER_REQUEST_OBSERVED: ValidationVerdict.REJECTED,
            SsrfAssessmentReason.INDEPENDENT_OBSERVATION_MISSING: (
                ValidationVerdict.SUSPECTED
            ),
            SsrfAssessmentReason.SERVER_REQUEST_OBSERVED_WITHOUT_DESTINATION_POLICY: (
                ValidationVerdict.SUSPECTED
            ),
            SsrfAssessmentReason.DESTINATION_POLICY_SURFACE_MISMATCH: (
                ValidationVerdict.SUSPECTED
            ),
            SsrfAssessmentReason.DESTINATION_POLICY_ORIGIN_MISMATCH: (
                ValidationVerdict.SUSPECTED
            ),
            SsrfAssessmentReason.DESTINATION_POLICY_EVIDENCE_INVALID: (
                ValidationVerdict.SUSPECTED
            ),
            SsrfAssessmentReason.DESTINATION_POLICY_ALLOWS_ACCESS: ValidationVerdict.REJECTED,
            SsrfAssessmentReason.CONFIRMED_DESTINATION_POLICY_VIOLATION: (
                ValidationVerdict.CONFIRMED
            ),
        }
        if expected_verdicts[reason_code] is not verdict:
            raise DomainInvariantError("SSRF assessment verdict does not match its reason")
        if (
            not isinstance(self.observation_ids, tuple)
            or len(set(self.observation_ids)) != len(self.observation_ids)
        ):
            raise DomainInvariantError("SSRF assessment observation ids must be a unique tuple")
        for observation_id in self.observation_ids:
            _validate_ssrf_reference(observation_id, "SSRF assessment observation id")
        if self.policy_id is not None:
            _validate_ssrf_reference(self.policy_id, "SSRF assessment policy id")


@dataclass(frozen=True, slots=True, init=False)
class SsrfCanaryProofTarget:
    """Operator-owned endpoint; execution approval and policy stay separate."""

    url: str
    marker: str
    surface_id: str
    destination_policy: SsrfDestinationPolicy | None
    operator_approved: bool = False

    def __init__(
        self,
        url: str,
        marker: str,
        destination_policy: SsrfDestinationPolicy | None = None,
        operator_approved: bool = False,
        *,
        surface_id: str | None = None,
        policy_reference: str | None = None,
    ) -> None:
        # Accept the legacy keyword only to fail with a domain error that callers
        # can handle. A raw string is never converted into a trusted policy.
        if policy_reference is not None:
            raise DomainInvariantError(
                "SSRF policy_reference is no longer accepted; use DestinationPolicy"
            )
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "marker", marker)
        if surface_id is None and isinstance(
            destination_policy, SsrfDestinationPolicy
        ):
            surface_id = destination_policy.surface_id
        object.__setattr__(self, "surface_id", surface_id)
        object.__setattr__(self, "destination_policy", destination_policy)
        object.__setattr__(self, "operator_approved", operator_approved)
        self.__post_init__()

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        host = (parsed.hostname or "").casefold().rstrip(".")
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False
        try:
            valid_port = parsed.port is None or parsed.port > 0
        except ValueError:
            valid_port = False
        if not self.operator_approved:
            raise DomainInvariantError("SSRF canary requires explicit operator approval")
        if _SSRF_SURFACE_ID.fullmatch(self.surface_id or "") is None:
            raise DomainInvariantError(
                "SSRF canary requires one exact approved surface id"
            )
        if self.destination_policy is not None:
            if not isinstance(self.destination_policy, SsrfDestinationPolicy):
                raise DomainInvariantError("SSRF canary policy must be structured")
            self.destination_policy.require_surface(self.surface_id)
        if (
            parsed.scheme not in {"http", "https"} or not host or not valid_port
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or is_ip_literal
            or re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", host) is None
            or host == "localhost" or host.endswith(".localhost")
            or host == "metadata.google.internal"
        ):
            raise DomainInvariantError("SSRF canary must be an exact HTTP(S) service URL")
        if (
            not isinstance(self.marker, str) or not 16 <= len(self.marker) <= 128
            or re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", self.marker) is None
            or self.marker in self.url
        ):
            raise DomainInvariantError(
                "SSRF canary marker must be a distinct, serialization-safe "
                "16-128 character value"
            )

    @property
    def policy_reference(self) -> str:
        """Read-only compatibility view; raw strings cannot construct a policy."""

        return (
            self.destination_policy.source_reference
            if self.destination_policy is not None
            else ""
        )

    def require_surface(self, surface_id: str) -> None:
        if surface_id != self.surface_id:
            raise DomainInvariantError("SSRF canary does not apply to this surface")
        if self.destination_policy is not None:
            self.destination_policy.require_surface(surface_id)


@dataclass(frozen=True, slots=True)
class RunExecutionProfile:
    """재현·비교를 위해 Run과 함께 영속화하는 실제 실행 조건."""

    # False는 P-2 이전 DB에서 복원한 Run이며, 아래 값을 실행 사실로
    # 해석하면 안 된다는 뜻이다. 구버전 Run을 비교 실험에 섞지 않게 한다.
    recorded: bool = True
    analysis_profile: str = "heuristic"
    recon_mode: str = "heuristic"
    recon_entry_mode: str = "targeted"
    surface_collection_mode: str = "adaptive"
    browser_recon_enabled: bool = False
    router_mode: str = "heuristic"
    router_review: str = "weak"
    compare_routers: bool = False
    orchestrator_mode: str = "heuristic"
    budget_allocation_mode: str = "off"
    # Validation·Report LLM 보조가 연결되기 전에도 계약을 먼저 고정한다.
    validation_mode: str = "heuristic"
    report_mode: str = "heuristic"
    ssrf_analysis_mode: str = "passive"
    ssrf_execution_approval_registered: bool = False
    ssrf_destination_policy_registered: bool = False
    ssrf_destination_policy_source: SsrfPolicySource | None = None
    # Legacy read-compatible fields. These never imply structured approval or policy.
    ssrf_oast_mode: str = "off"
    ssrf_public_oast_consented: bool = False
    ssrf_canary_policy_ref: str = ""
    # 비밀값은 저장하지 않고, 실제 호출에 쓴 provider/model만 남긴다.
    llm_provider: str = ""
    llm_model: str = ""
    llm_rpm_limit: int | None = None
    code_version: str = ""
    # 안전 프로필은 유지하되, 사용자가 이 Run에서 상태 변경 가능 요청을 명시적으로
    # 승인했는지 기록한다. 승인 참조 문자열 자체는 실행 구성에 저장하지 않는다.
    state_changing_approved: bool = False

    def __post_init__(self) -> None:
        try:
            policy_source = (
                None
                if self.ssrf_destination_policy_source is None
                else SsrfPolicySource(self.ssrf_destination_policy_source)
            )
        except (TypeError, ValueError) as error:
            raise DomainInvariantError("unsupported SSRF destination policy source") from error
        object.__setattr__(self, "ssrf_destination_policy_source", policy_source)
        modes = {
            "analysis profile": (self.analysis_profile, {"heuristic", "llm"}),
            "recon mode": (self.recon_mode, {"heuristic", "hybrid", "agentic"}),
            "recon entry mode": (
                self.recon_entry_mode,
                {"targeted", "base-url"},
            ),
            "surface collection mode": (
                self.surface_collection_mode,
                {"adaptive", "deterministic"},
            ),
            "router mode": (
                self.router_mode,
                {"heuristic", "hybrid", "agentic"},
            ),
            "router review": (self.router_review, {"weak", "ambiguous"}),
            "orchestrator mode": (self.orchestrator_mode, {"heuristic", "hybrid"}),
            "budget allocation mode": (
                self.budget_allocation_mode,
                {"off", "heuristic", "hybrid"},
            ),
            "validation mode": (self.validation_mode, {"heuristic", "llm"}),
            "report mode": (self.report_mode, {"heuristic", "llm"}),
            "SSRF analysis mode": (self.ssrf_analysis_mode, {"passive"}),
            "SSRF OAST mode": (
                self.ssrf_oast_mode,
                {"off", "local_test", "public_interactsh", "private_interactsh"},
            ),
        }
        for label, (value, allowed) in modes.items():
            if value not in allowed:
                raise DomainInvariantError(f"unsupported {label}: {value!r}")
        if type(self.recorded) is not bool:
            raise DomainInvariantError("recorded execution profile flag must be boolean")
        if type(self.compare_routers) is not bool:
            raise DomainInvariantError("compare routers flag must be boolean")
        if type(self.browser_recon_enabled) is not bool:
            raise DomainInvariantError("browser recon flag must be boolean")
        for label, value in (
            ("SSRF execution approval registered", self.ssrf_execution_approval_registered),
            ("SSRF destination policy registered", self.ssrf_destination_policy_registered),
        ):
            if type(value) is not bool:
                raise DomainInvariantError(f"{label} flag must be boolean")
        if self.ssrf_destination_policy_registered != (
            self.ssrf_destination_policy_source is not None
        ):
            raise DomainInvariantError(
                "SSRF destination policy and trusted source must be recorded together"
            )
        if type(self.ssrf_public_oast_consented) is not bool:
            raise DomainInvariantError("SSRF public OAST consent flag must be boolean")
        if self.ssrf_oast_mode == "public_interactsh" and not self.ssrf_public_oast_consented:
            raise DomainInvariantError("public SSRF OAST requires explicit consent")
        if self.ssrf_canary_policy_ref:
            if (
                "://" in self.ssrf_canary_policy_ref
                or self.ssrf_canary_policy_ref.startswith("//")
            ):
                raise DomainInvariantError(
                    "legacy SSRF canary policy reference must not contain a URL"
                )
            validate_ssrf_opaque_reference(
                self.ssrf_canary_policy_ref,
                "legacy SSRF canary policy reference",
                reject_secret_like=True,
            )
        if type(self.state_changing_approved) is not bool:
            raise DomainInvariantError(
                "state-changing approval flag must be boolean"
            )
        if (
            self.llm_rpm_limit is not None
            and (type(self.llm_rpm_limit) is not int or self.llm_rpm_limit <= 0)
        ):
            raise DomainInvariantError("LLM RPM limit must be positive")
        for label, value in (
            ("LLM provider", self.llm_provider),
            ("LLM model", self.llm_model),
        ):
            if not isinstance(value, str) or len(value) > 200 or (
                value and (not value.strip() or not value.isprintable())
            ):
                raise DomainInvariantError(f"{label} must be a short printable string")
        if not isinstance(self.code_version, str) or (
            self.code_version and re.fullmatch(r"[A-Za-z0-9._/-]{1,80}", self.code_version) is None
        ):
            raise DomainInvariantError("code version must be a short version or branch label")
        if bool(self.llm_provider) != bool(self.llm_model):
            raise DomainInvariantError("LLM provider and model must be stored together")
        uses_llm = (
            self.analysis_profile == "llm"
            or self.recon_mode in {"hybrid", "agentic"}
            or self.router_mode in {"hybrid", "agentic"}
            or self.compare_routers
            or self.orchestrator_mode == "hybrid"
            or self.budget_allocation_mode == "hybrid"
            or self.validation_mode == "llm"
            or self.report_mode == "llm"
        )
        if uses_llm != bool(self.llm_provider):
            raise DomainInvariantError("LLM execution requires a provider and model")
        if self.llm_rpm_limit is not None and not uses_llm:
            raise DomainInvariantError("LLM RPM limit requires LLM execution")


@dataclass(frozen=True, slots=True)
class RunRequest:
    """사용자가 새로운 점검 Run을 시작할 때 전달하는 입력."""

    target_url: str
    scope: RunScope
    policy_profile: str = "safe"
    request_budget: int = 100
    timeout_seconds: int = 120
    credential_ref: str | None = None
    # 역할 → credential_ref 매핑. Access Control처럼 두 주체가 필요한 검사에서만 채운다.
    # 여기에 등록되지 않은 역할은 중앙 Collector가 거부한다.
    principal_credentials: tuple[tuple[str, str], ...] = ()
    # 취약점 유형 → credential_ref 매핑. 한 Run에서 여러 취약점을 검사할 때 유형마다
    # 필요한 인증이 다르기 때문에 필요하다(SQLi는 인증 없음, SSTI는 실습 계정 token).
    # 비어 있으면 기존 단일 취약점 Run으로 보고 credential_ref를 그대로 쓴다.
    agent_credentials: tuple[tuple[str, str], ...] = ()
    execution_profile: RunExecutionProfile = field(default_factory=RunExecutionProfile)

    def __post_init__(self) -> None:
        # 실행 예산은 이후 Runtime과 Agent 호출을 통제하는 상한선이다.
        if self.request_budget <= 0:
            raise DomainInvariantError("request budget must be positive")
        if self.timeout_seconds <= 0:
            raise DomainInvariantError("run timeout must be positive")
        if self.credential_ref is not None and not self.credential_ref.strip():
            raise DomainInvariantError("credential reference cannot be blank")
        if not isinstance(self.execution_profile, RunExecutionProfile):
            raise DomainInvariantError("run execution profile is invalid")


@dataclass(frozen=True, slots=True)
class Run:
    """워크플로 진행 상태와 생성된 도메인 객체 ID를 보관하는 실행 단위."""

    run_id: str
    target_url: str
    scope: RunScope
    policy_profile: str
    request_budget: int
    timeout_seconds: int = 120
    credential_ref: str | None = None
    # 역할 → credential_ref 매핑. Access Control처럼 두 주체가 필요한 검사에서만 채운다.
    # 여기에 등록되지 않은 역할은 중앙 Collector가 거부한다.
    principal_credentials: tuple[tuple[str, str], ...] = ()
    agent_credentials: tuple[tuple[str, str], ...] = ()
    execution_profile: RunExecutionProfile = field(default_factory=RunExecutionProfile)
    phase: RunPhase = RunPhase.INIT
    evidence_ids: tuple[str, ...] = ()
    surface_ids: tuple[str, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    report_ids: tuple[str, ...] = ()
    # Additional Recon is bounded and survives process restarts. The selected Surface
    # is stored before re-entering RECON so resume cannot ask the advisor again.
    extra_recon_rounds: int = 0
    recon_target_surface_id: str | None = None
    # Callback/owned-receiver A/B proof may unlock one operator-approved
    # internal-canary pass. Persist the bounded round so resume cannot prompt
    # or probe indefinitely.
    ssrf_followup_rounds: int = 0
    last_error: str | None = None
    # The allocation order and protected validation units are decided before
    # ANALYZE and reused on resume. Empty order means allocation is disabled.
    budget_candidate_order: tuple[str, ...] = ()
    budget_candidate_weights: tuple[int, ...] = ()
    budget_validation_reserve: int = 0
    budget_allocation_source: str = ""
    budget_active_candidate_id: str | None = None
    budget_active_phase: str | None = None
    budget_active_floor: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.execution_profile, RunExecutionProfile):
            raise DomainInvariantError("run execution profile is invalid")
        if self.extra_recon_rounds < 0:
            raise DomainInvariantError("extra recon rounds cannot be negative")
        if self.recon_target_surface_id is not None and self.extra_recon_rounds == 0:
            raise DomainInvariantError("targeted recon requires an extra recon round")
        if (
            type(self.ssrf_followup_rounds) is not int
            or not 0 <= self.ssrf_followup_rounds <= 1
        ):
            raise DomainInvariantError("SSRF follow-up rounds must be 0 or 1")
        if type(self.budget_validation_reserve) is not int or self.budget_validation_reserve < 0:
            raise DomainInvariantError("validation reserve cannot be negative")
        if (
            not isinstance(self.budget_candidate_order, tuple)
            or any(not isinstance(item, str) for item in self.budget_candidate_order)
            or not isinstance(self.budget_candidate_weights, tuple)
        ):
            raise DomainInvariantError("budget order and weights must be tuples")
        if self.budget_candidate_order:
            if self.budget_validation_reserve < 1:
                raise DomainInvariantError("budget order requires a validation reserve")
            if self.budget_allocation_source not in {
                "heuristic", "llm", "advisor", "deterministic_fallback"
            }:
                raise DomainInvariantError("budget order requires a known source")
            if (
                len(set(self.budget_candidate_order)) != len(self.budget_candidate_order)
                or set(self.budget_candidate_order) != set(self.candidate_ids)
            ):
                raise DomainInvariantError("budget order must contain every candidate once")
            if (
                len(self.budget_candidate_weights) != len(self.budget_candidate_order)
                or any(type(weight) is not int or not 1 <= weight <= 3
                       for weight in self.budget_candidate_weights)
            ):
                raise DomainInvariantError("budget weights must match the candidate order")
        elif self.budget_validation_reserve:
            raise DomainInvariantError("validation reserve requires a budget order")
        elif self.budget_candidate_weights:
            raise DomainInvariantError("budget weights require a candidate order")
        elif self.budget_allocation_source:
            raise DomainInvariantError("budget source requires a candidate order")
        if any(value is None for value in (
            self.budget_active_candidate_id,
            self.budget_active_phase,
            self.budget_active_floor,
        )) and any(value is not None for value in (
            self.budget_active_candidate_id,
            self.budget_active_phase,
            self.budget_active_floor,
        )):
            raise DomainInvariantError("active budget fields must be stored together")
        if self.budget_active_candidate_id is not None:
            if (
                self.budget_active_candidate_id not in self.budget_candidate_order
                or self.budget_active_phase not in {"analyze", "validate"}
                or type(self.budget_active_floor) is not int
                or self.budget_active_floor < 0
            ):
                raise DomainInvariantError("active budget floor is invalid")

    def with_updates(self, **changes: object) -> Run:
        """불변 dataclass를 직접 수정하지 않고 변경된 복사본을 만든다."""

        return replace(self, **changes)


def credential_for_vulnerability(run: Run, vulnerability_type: str) -> str | None:
    """취약점 유형에 등록된 자격증명만 해석한다.

    ``agent_credentials``가 비어 있으면 기존 단일 취약점 Run이므로 Run 기본 자격증명을
    그대로 쓴다. 등록이 하나라도 있으면 여러 유형을 함께 검사하는 Run이고, 이때
    등록되지 않은 유형은 자격증명 없이 실행한다.

    없을 때 Run 기본값으로 흘려보내지 않는 것이 요점이다. 그렇게 두면 SSTI 실습 계정
    세션이 SQLi 요청에 얹히는 식으로 유형 간 인증이 섞인다.
    """

    if not run.agent_credentials:
        return run.credential_ref
    return dict(run.agent_credentials).get(vulnerability_type)


@dataclass(frozen=True, slots=True)
class HttpRequestSpec:
    """Agent가 공통 HTTP Runtime에 전달하는 구조화된 요청 명세."""

    method: str = "GET"
    query_parameters: tuple[tuple[str, str], ...] = ()
    # application/x-www-form-urlencoded body fields. Keeping these structured
    # lets the domain apply the same probe-value contract used for query input.
    form_parameters: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = field(default=None, repr=False)
    request_kind: HttpRequestKind = HttpRequestKind.CONTROL
    # ACCESS_CONTROL_PROBE에서 값이 바뀌는 유일한 파라미터. 나머지 query는 Recon이 관측한
    # 원본을 그대로 보존해야 하므로 어느 것이 식별자인지 명시적으로 지정한다.
    identifier_parameter: str | None = None
    identifier_location: AccessIdentifierLocation | None = None
    path_identifier_index: int | None = None
    path_identifier_value: str | None = None
    # 경로 끝에 그대로 붙는 도메인 고정 접미사. 값 형태를 도메인이 강제하므로
    # Agent가 임의 경로나 임의 인코딩을 여기로 실을 수 없다.
    path_suffix: str | None = None
    # latin-1 preserves binary multipart bytes while keeping stored specs JSON-compatible.
    body_encoding: str = "utf-8"
    # 경로에 실린 `이름=값` 입력에서 값 부분만 교체하는 좌표. 범위는 Recon이 관측한
    # 것을 그대로 받고, 실을 수 있는 값은 도메인이 고정한 증명 경로 하나뿐이다.
    # 범용 경로 치환 API가 되지 않도록 아래 _validate_path_assignment가 강제한다.
    path_assignment_name: str | None = None
    path_assignment_value_start: int | None = None
    path_assignment_value_end: int | None = None
    path_assignment_value: str | None = None
    # AFR may replace one observed URL segment with an approved safe-file path.
    file_read_path_index: int | None = None
    file_read_path_value: str | None = None
    # Query AFR probes identify the one coordinate that may differ from the
    # observed request template. Policy validation uses this instead of
    # treating every query value as attacker-controlled probe text.
    file_read_parameter: str | None = None

    def __post_init__(self) -> None:
        if not self.method or _HTTP_METHOD.fullmatch(self.method) is None:
            raise DomainInvariantError("HTTP method must be a valid token")
        if not isinstance(self.request_kind, HttpRequestKind):
            raise DomainInvariantError("HTTP request kind must be control or probe")
        if self.body is not None and not isinstance(self.body, str):
            raise DomainInvariantError("HTTP request body must be text")
        if self.body_encoding not in {"utf-8", "latin-1"}:
            raise DomainInvariantError("HTTP body encoding must be utf-8 or latin-1")
        if self.body is not None:
            try:
                self.body.encode(self.body_encoding)
            except UnicodeEncodeError as error:
                raise DomainInvariantError("HTTP body cannot use the selected encoding") from error
        if self.body is not None and self.form_parameters:
            raise DomainInvariantError(
                "HTTP request cannot carry raw body and structured form parameters"
            )

        for name, value in (*self.query_parameters, *self.form_parameters):
            if not isinstance(name, str) or not isinstance(value, str):
                raise DomainInvariantError("HTTP query parameters must be string pairs")
            # 탐침 요청만 값 형태를 강제한다. CONTROL 요청은 대상이 원래 갖고 있던
            # 값(Recon이 수집한 쿼리)을 그대로 실어야 하므로 제한하지 않는다.
            if self.request_kind is HttpRequestKind.PROBE and _PROBE_VALUE.fullmatch(
                value
            ) is None:
                raise DomainInvariantError(
                    "probe query value must be a marker with allowed metacharacters "
                    f"({PROBE_METACHARACTERS}): {value!r}"
                )
            if self.request_kind is HttpRequestKind.OPEN_REDIRECT_PROBE and not (
                value == "/" or re.fullmatch(
                    r"http://127\.0\.0\.1:9/redirect[A-Za-z0-9z]{8,180}", value
                )
            ):
                raise DomainInvariantError(
                    "open redirect probe may only use the fixed loopback destination"
                )
            if (
                self.request_kind is HttpRequestKind.PATH_TRAVERSAL_PROBE
                and _PROBE_VALUE.fullmatch(value) is None
                and not is_path_traversal_safe_probe_value(value)
            ):
                raise DomainInvariantError(
                    "path traversal probe may only use markers and the fixed safe path"
                )
        if self.request_kind in {
            HttpRequestKind.GRAPHQL_QUERY_CONTROL,
            HttpRequestKind.GRAPHQL_QUERY_PROBE,
        }:
            document = (
                self.query_parameters[0][1]
                if len(self.query_parameters) == 1 and self.query_parameters[0][0] == "query"
                else None
            )
            match = _GRAPHQL_READ_DOCUMENT.fullmatch(document or "")
            if (
                self.method.upper() != "GET" or self.headers or self.body is not None
                or match is None
                or bool(match.group(2)) != (
                    self.request_kind is HttpRequestKind.GRAPHQL_QUERY_PROBE
                )
            ):
                raise DomainInvariantError(
                    "GraphQL query probe must be a bounded read-only GET with one marker"
                )
        if self.request_kind in {
            HttpRequestKind.SQLI_BOOLEAN_TRUE,
            HttpRequestKind.SQLI_BOOLEAN_FALSE,
        }:
            index = (
                1 if self.request_kind is HttpRequestKind.SQLI_BOOLEAN_TRUE else 2
            )
            suffixes = tuple(pair[index] for pair in SQLI_BOOLEAN_PREDICATES)
            mutations = [
                value
                for _, value in (*self.query_parameters, *self.form_parameters)
                if value.endswith(suffixes)
            ]
            if len(mutations) != 1:
                raise DomainInvariantError(
                    "SQLi boolean probe must mutate exactly one structured parameter"
                )
            if any(
                token in mutations[0].casefold()
                for token in (";", "--", "/*", "union", "select", "sleep", "benchmark")
            ):
                raise DomainInvariantError("SQLi boolean probe contains a forbidden token")
        if self.path_suffix is not None:
            if self.request_kind is not HttpRequestKind.PATH_TRAVERSAL_PROBE:
                raise DomainInvariantError(
                    "path suffix belongs to the path traversal probe kind only"
                )
            if not is_path_traversal_bypass_suffix(self.path_suffix):
                raise DomainInvariantError(
                    f"path suffix must be the fixed bypass suffix: {self.path_suffix!r}"
                )
        self._validate_path_assignment()
        if (self.file_read_path_index is None) != (self.file_read_path_value is None):
            raise DomainInvariantError("file-read path index and value must be paired")
        if self.file_read_path_index is not None:
            if (self.request_kind not in {
                HttpRequestKind.CONTROL, HttpRequestKind.ARBITRARY_FILE_READ_PROBE
            } or self.file_read_path_index < 1 or not self.file_read_path_value):
                raise DomainInvariantError("invalid file-read path mutation")
            # 값을 비어 있지 않은 문자열로만 묶으면 이 필드가 "경로 세그먼트 아무 데나
            # 아무거나" 넣는 통로가 된다. 다른 좌표와 같은 규칙을 적용한다 — probe 는
            # 고정 증명 표기 중 하나, control 은 고정 marker 하나뿐이다.
            if self.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE:
                if not is_arbitrary_file_read_safe_probe_value(self.file_read_path_value):
                    raise DomainInvariantError(
                        "file-read segment probe may only use a fixed safe path: "
                        f"{self.file_read_path_value!r}"
                    )
            elif self.file_read_path_value != CONTROL_MARKER:
                raise DomainInvariantError(
                    "file-read segment control may only use the fixed marker"
                )
        if self.file_read_parameter is not None:
            if (
                self.request_kind not in {
                    HttpRequestKind.CONTROL,
                    HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                }
                or self.file_read_path_index is not None
                or not self.file_read_parameter
                or sum(
                    name == self.file_read_parameter
                    for name, _ in self.query_parameters
                )
                != 1
            ):
                raise DomainInvariantError("invalid file-read query mutation")
        if self.request_kind is HttpRequestKind.ACCESS_CONTROL_PROBE:
            self._validate_access_control_probe()
        if self.request_kind is HttpRequestKind.OPEN_REDIRECT_PROBE and (
            self.method.upper() != "GET" or self.body is not None or self.headers
            or not any(value.startswith("http://127.0.0.1:9/")
                       for _, value in self.query_parameters)
        ):
            raise DomainInvariantError("open redirect probe must be a bounded GET request")
        if self.request_kind in {HttpRequestKind.SSRF_CONTROL, HttpRequestKind.SSRF_PROBE}:
            ssrf_pairs = ssrf_request_parameters(
                self.method, self.query_parameters, self.headers, self.body,
            )
            callback_values = [
                value for _, value in ssrf_pairs
                if value.startswith((
                    "https://", "http://127.0.0.1:",
                    "http://host.docker.internal:",
                ))
            ]
            if (
                self.method.upper() not in {"GET", "POST"}
                or self.form_parameters or not ssrf_pairs
                or len(callback_values) != (
                    1 if self.request_kind is HttpRequestKind.SSRF_PROBE else 0
                )
                or any(
                    value != "hacklipse-control"
                    and value not in callback_values
                    and re.fullmatch(r"[A-Za-z0-9._~-]{0,128}", value) is None
                    for _, value in ssrf_pairs
                )
            ):
                raise DomainInvariantError(
                    "SSRF request must have one bounded registered callback"
                )
        if self.request_kind is HttpRequestKind.SSRF_CANARY_PROBE:
            urls = [value for _, value in self.query_parameters
                    if value.startswith(("http://", "https://"))]
            if (
                self.method.upper() != "GET" or self.body is not None
                or self.form_parameters or self.headers or len(urls) != 1
                or any(value not in urls and
                       re.fullmatch(r"[A-Za-z0-9._~-]{0,128}", value) is None
                       for _, value in self.query_parameters)
            ):
                raise DomainInvariantError("SSRF canary probe must be a bounded GET")
        if self.request_kind is HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE:
            ssrf_pairs = ssrf_request_parameters(
                self.method, self.query_parameters, self.headers, self.body,
            )
            urls = [value for _, value in ssrf_pairs
                    if value.startswith(("http://", "https://"))]
            if (
                self.method.upper() not in {"GET", "POST"}
                or self.form_parameters or len(urls) != 1
                or any(value not in urls and
                       re.fullmatch(r"[A-Za-z0-9._~-]{0,128}", value) is None
                       for _, value in ssrf_pairs)
            ):
                raise DomainInvariantError(
                    "SSRF owned-receiver probe must have one bounded URL"
                )
        if self.request_kind in {
            HttpRequestKind.SSRF_WORKFLOW_CONTROL,
            HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
        }:
            pairs = ssrf_request_parameters(
                self.method, self.query_parameters, self.headers, self.body,
                allow_companions=True,
            )
            url_fields = [
                (name, value) for name, value in pairs
                if name.casefold().rsplit(".", 1)[-1] in {
                    "url", "uri", "link", "image_url", "feed_url", "webhook", "callback",
                }
            ]
            receiver_urls = [
                value for _, value in pairs
                if value.startswith(("http://", "https://"))
            ]
            expected_url_count = (
                1 if self.request_kind is HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE
                else 0
            )
            if (
                self.method.upper() != "POST" or self.form_parameters
                or len(url_fields) != 1
                or len(receiver_urls) != expected_url_count
                or (expected_url_count == 1
                    and receiver_urls[0] != url_fields[0][1])
                or (self.request_kind is HttpRequestKind.SSRF_WORKFLOW_CONTROL
                    and url_fields[0][1] != "hacklipse-control")
                or any(
                    value not in receiver_urls
                    and re.fullmatch(r"[A-Za-z0-9._~-]{0,128}", value) is None
                    for _, value in pairs
                )
            ):
                raise DomainInvariantError("SSRF workflow POST must bind one URL field")
        if self.request_kind is HttpRequestKind.SSRF_WORKFLOW_TRIGGER and (
            self.method.upper() != "GET" or self.body is not None
            or self.headers or self.query_parameters or self.form_parameters
        ):
            raise DomainInvariantError("SSRF workflow trigger must be a plain GET")
        if self.request_kind is HttpRequestKind.SSRF_WORKFLOW_SETUP:
            try:
                setup = json.loads(self.body or "")
            except ValueError:
                setup = None
            if (
                self.method.upper() != "POST"
                or self.headers != (("Content-Type", "application/json"),)
                or self.query_parameters or self.form_parameters
                or not isinstance(setup, dict)
                or set(setup) != {"id", "name", "type", "provider", "configuration"}
                or not isinstance(setup.get("id"), str)
                or re.fullmatch(r"hacklipse[0-9a-f]{12}", setup["id"]) is None
                or setup.get("name") != setup["id"]
                or setup.get("type") != "webhook"
                or setup.get("provider") != "http"
                or setup.get("configuration") != {"url": "http://127.0.0.1:9/seed"}
            ):
                raise DomainInvariantError("SSRF workflow setup must be a bounded webhook config")
        if self.request_kind is HttpRequestKind.SSRF_WORKFLOW_CLEANUP and (
            self.method.upper() != "DELETE" or self.body is not None
            or self.headers or self.query_parameters or self.form_parameters
        ):
            raise DomainInvariantError("SSRF workflow cleanup must be a plain DELETE")
        if self.request_kind in {
            HttpRequestKind.SSRF_CSV_UPLOAD_CONTROL,
            HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
        }:
            coordinate = ssrf_csv_upload_parameter(
                self.method, self.headers, self.body,
            )
            if (
                self.method.upper() != "POST" or self.form_parameters
                or self.query_parameters != (
                    ("ajax", "1"), ("token", "hacklipse-credential-token"),
                    ("_token", "hacklipse-credential-_token"),
                )
                or coordinate is None
                or (self.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_CONTROL
                    and coordinate[1] != "hacklipse-control")
                or (self.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_PROBE
                    and coordinate[1] == "hacklipse-control")
            ):
                raise DomainInvariantError("SSRF CSV upload must carry one bounded image URL")
        if self.request_kind in {
            HttpRequestKind.SSRF_CSV_IMPORT_CONTROL,
            HttpRequestKind.SSRF_CSV_IMPORT_PROBE,
        }:
            form = dict(self.form_parameters)
            expected_form = {
                "entity": "0", "iso_lang": "en", "truncate": "0",
                "forceIDs": "0", "regenerate": "0", "sendemail": "0",
                "separator": ";", "multiple_value_separator": ",",
                "skip": "0", "type_value[0]": "name",
                "type_value[1]": "image", "crossStepsVars": "{}",
            }
            filename = form.pop("csv", None)
            if (
                self.method.upper() != "POST" or self.body is not None or self.headers
                or self.query_parameters != (
                    ("ajax", "1"), ("action", "import"),
                    ("tab", "AdminImport"), ("offset", "0"),
                    ("limit", "5"),
                    ("token", "hacklipse-credential-token"),
                )
                or len(self.form_parameters) != len(expected_form) + 1
                or form != expected_form
                or not isinstance(filename, str)
                or re.fullmatch(
                    r"[0-9]{14}-hacklipse-[0-9a-f]{12}(?:control|probe)\.csv",
                    filename,
                ) is None
            ):
                raise DomainInvariantError("SSRF CSV import must use a bounded category mapping")
        if self.request_kind is HttpRequestKind.CORS_PROBE and (
            self.method.upper() != "GET" or self.body is not None
            or (
                self.query_parameters
                and (
                    len(self.query_parameters) != 1
                    or not (
                        self.query_parameters == (("query", "query { __typename }"),)
                        or (
                            self.query_parameters[0][0].casefold() in {
                                "q", "query", "search", "term", "keyword"
                            }
                            and self.query_parameters[0][1] == "hacklipse-control"
                        )
                    )
                )
            )
            or len(self.headers) != 1
            or self.headers[0] not in {
                ("Origin", "https://probe-a.invalid"),
                ("Origin", "https://probe-b.invalid"),
            }
        ):
            raise DomainInvariantError("CORS probe must use one fixed nonresident Origin")
        for name, value in self.headers:
            if not isinstance(name, str) or not isinstance(value, str):
                raise DomainInvariantError("HTTP headers must be string pairs")
            lowered = name.casefold()
            if not name or _HTTP_METHOD.fullmatch(name) is None:
                raise DomainInvariantError("HTTP header name must be a valid token")
            if lowered in _FORBIDDEN_REQUEST_HEADERS:
                raise DomainInvariantError(f"HTTP header is controlled by the runtime: {name}")
            if "\r" in value or "\n" in value:
                raise DomainInvariantError("HTTP header value cannot contain line breaks")

    def _validate_path_assignment(self) -> None:
        """경로 내장 입력의 값 교체를 고정된 증명 경로 하나로 제한한다.

        네 필드는 함께 있어야 한다. 하나라도 빠지면 "어디를 바꾸는지"가 불완전해지고,
        실행기가 남은 정보로 자리를 추측하게 된다.

        실을 수 있는 값은 Path Traversal이 쓰는 고정 증명 경로뿐이다. 임의 문자열을
        허용하면 이 필드가 곧 "경로 아무 데나 아무거나 넣는" 통로가 된다. control은
        값을 바꾸지 않고 관측된 URL을 그대로 쓰므로 이 좌표를 싣지 않는다.
        """

        span = (
            self.path_assignment_name,
            self.path_assignment_value_start,
            self.path_assignment_value_end,
            self.path_assignment_value,
        )
        if all(value is None for value in span):
            return
        # 경로를 고치는 좌표가 둘 있다 — 세그먼트 교체와 `이름=값`의 값 교체. 둘은
        # 같은 자리를 다르게 보는 대안이므로 함께 실으면 결과 경로를 어느 쪽도
        # 책임지지 못한다.
        if self.file_read_path_index is not None:
            raise DomainInvariantError(
                "a request may replace a path segment or a path assignment, not both"
            )
        if any(value is None for value in span):
            raise DomainInvariantError(
                "path assignment name, span, and value must be provided together"
            )
        assert self.path_assignment_name is not None
        assert self.path_assignment_value_start is not None
        assert self.path_assignment_value_end is not None
        assert self.path_assignment_value is not None
        accepts_value = _PATH_ASSIGNMENT_PROBE_VALUES.get(self.request_kind)
        if accepts_value is None:
            raise DomainInvariantError(
                "path assignment replacement belongs to a safe-file probe kind only"
            )
        if _PATH_ASSIGNMENT_NAME.fullmatch(self.path_assignment_name) is None:
            raise DomainInvariantError("path assignment name is invalid")
        if (
            type(self.path_assignment_value_start) is not int
            or type(self.path_assignment_value_end) is not int
            or not 0 <= self.path_assignment_value_start < self.path_assignment_value_end
        ):
            raise DomainInvariantError("path assignment span must be a non-empty range")
        if not accepts_value(self.path_assignment_value):
            raise DomainInvariantError(
                "path assignment probe may only use the fixed safe path of its kind: "
                f"{self.path_assignment_value!r}"
            )
        # 같은 경로를 두 규칙이 동시에 고쳐 쓰면 결과 경로를 어느 쪽도 책임지지 못한다.
        if self.path_suffix is not None or self.query_parameters or self.form_parameters:
            raise DomainInvariantError(
                "path assignment probe cannot also change the suffix or structured parameters"
            )
        if self.identifier_location is not None or self.path_identifier_index is not None:
            raise DomainInvariantError(
                "path assignment probe cannot also move a path object identifier"
            )
        if self.body is not None or self.headers or self.method.upper() != "GET":
            raise DomainInvariantError("path assignment probe must be a bare GET request")

    def _validate_access_control_probe(self) -> None:
        """객체 권한 탐침이 식별자 값 하나만 바꾸도록 강제한다.

        다른 사용자의 객체를 읽어보는 요청이므로 표면을 최대한 좁힌다. 헤더·본문을
        금지해 Cookie나 Authorization을 명세로 주입할 수 없게 하고, 값이 바뀌는 자리를
        식별자 파라미터 하나로 한정한다. 나머지 query(action·token 등)는 Recon이 관측한
        원본을 그대로 실어야 대상 페이지가 정상 동작한다.
        """

        if self.method.upper() != "GET":
            raise DomainInvariantError("access control probe must be a GET request")
        if self.headers:
            raise DomainInvariantError("access control probe cannot set request headers")
        if self.body is not None:
            raise DomainInvariantError("access control probe cannot carry a body")
        if not self.identifier_parameter:
            raise DomainInvariantError("access control probe must name its identifier parameter")

        location = self.identifier_location or AccessIdentifierLocation.QUERY
        if not isinstance(location, AccessIdentifierLocation):
            raise DomainInvariantError("access control identifier location must be structured")

        if location is AccessIdentifierLocation.PATH:
            if self.path_identifier_index is None or self.path_identifier_index < 1:
                raise DomainInvariantError(
                    "path access control probe must identify a path segment"
                )
            if (
                self.path_identifier_value is None
                or _OBJECT_IDENTIFIER.fullmatch(self.path_identifier_value) is None
            ):
                raise DomainInvariantError(
                    f"access control object id must be numeric: {self.path_identifier_value!r}"
                )
            return

        if self.path_identifier_index is not None or self.path_identifier_value is not None:
            raise DomainInvariantError(
                "query access control probe cannot carry a path identifier"
            )

        names = [name for name, _ in self.query_parameters]
        if names.count(self.identifier_parameter) != 1:
            raise DomainInvariantError(
                "access control probe identifier must appear exactly once in the query"
            )
        for name, value in self.query_parameters:
            if name != self.identifier_parameter:
                continue
            if _OBJECT_IDENTIFIER.fullmatch(value) is None:
                raise DomainInvariantError(
                    f"access control object id must be numeric: {value!r}"
                )


@dataclass(frozen=True, slots=True)
class EvidenceRequest:
    """Validation 등이 추가 증적이 필요할 때 Orchestrator에 보내는 요청."""

    evidence_type: str
    surface_id: str
    reason: str
    suggested_tool: str
    http_request: HttpRequestSpec | None = None
    target_url_override: str | None = None
    # Agent는 어떤 자격증명을 쓸지 고를 수 없고 역할만 지정한다. 역할 → credential_ref
    # 해석은 중앙 Collector가 Run에 등록된 매핑으로만 수행한다.
    principal_role: AccessPrincipalRole | None = None
    # A read-only exposure check may explicitly require an unauthenticated
    # request even when the Run also has an authorized test session.
    anonymous: bool = False
    # 상태 변경 요청의 승인 참조는 비밀이 아니라 사용자가 부여한 권한의 식별자다.
    # 실제 허용 여부는 Agent가 아니라 중앙 ApprovalGate가 판단한다.
    approval_ref: str | None = None
    # An SSRF workflow can use a separately observed, same-origin GET step.
    # The Orchestrator verifies that this URL is an existing read surface.
    request_target_url: str | None = None

    def __post_init__(self) -> None:
        if self.target_url_override is not None and not self.target_url_override:
            raise DomainInvariantError("evidence target override cannot be blank")
        if self.principal_role is not None and not isinstance(
            self.principal_role, AccessPrincipalRole
        ):
            raise DomainInvariantError("principal role must be a structured role")
        if type(self.anonymous) is not bool or (self.anonymous and self.principal_role is not None):
            raise DomainInvariantError("anonymous request cannot select a principal role")
        if self.approval_ref is not None and not self.approval_ref.strip():
            raise DomainInvariantError("evidence request approval reference cannot be blank")
        if self.request_target_url is not None:
            parsed = urlsplit(self.request_target_url)
            if (
                parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment
                or self.http_request is None
                or self.http_request.request_kind not in {
                    HttpRequestKind.SSRF_WORKFLOW_SETUP,
                    HttpRequestKind.SSRF_WORKFLOW_TRIGGER,
                    HttpRequestKind.SSRF_WORKFLOW_CLEANUP,
                    HttpRequestKind.SSRF_CSV_UPLOAD_CONTROL,
                    HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
                }
            ):
                raise DomainInvariantError("workflow target must be a plain HTTP URL")
        elif (
            self.http_request is not None
            and self.http_request.request_kind in {
                HttpRequestKind.SSRF_WORKFLOW_SETUP,
                HttpRequestKind.SSRF_WORKFLOW_TRIGGER,
                HttpRequestKind.SSRF_WORKFLOW_CLEANUP,
            }
        ):
            raise DomainInvariantError("SSRF workflow step requires an observed target")

    def request_fingerprint(self, target_url: str) -> str:
        """비밀값 없이 동일 EvidenceRequest를 재연결하는 결정적 식별자.

        URL·query·body 원문을 해시하면 짧은 비밀번호나 토큰을 오프라인 추측할 수 있다.
        따라서 대상 origin/path, 파라미터·헤더 *이름*, 요청 목적과 kind만 사용한다.
        probe별 ``reason``에는 대상 파라미터명이 들어가므로 같은 Surface의 여러 probe도
        서로 구분된다.
        """

        request = self.http_request or HttpRequestSpec()
        parsed = urlsplit(target_url)
        target_query_names = tuple(
            name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        )
        canonical = json.dumps(
            {
                "body_present": request.body is not None,
                **({"body_encoding": request.body_encoding} if request.body_encoding != "utf-8" else {}),
                "form_names": [name for name, _ in request.form_parameters],
                "approval_present": self.approval_ref is not None,
                "evidence_type": self.evidence_type,
                "header_names": [name.casefold() for name, _ in request.headers],
                "method": request.method.upper(),
                "purpose": self.reason,
                "principal_role": (
                    self.principal_role.value if self.principal_role is not None else None
                ),
                "anonymous": self.anonymous,
                "query_names": [name for name, _ in request.query_parameters],
                "request_kind": request.request_kind.value,
                "identifier_location": (
                    request.identifier_location.value
                    if request.identifier_location is not None
                    else None
                ),
                "path_identifier_index": request.path_identifier_index,
                "path_identifier_present": request.path_identifier_value is not None,
                # 좌표의 이름과 범위는 비밀이 아니라 "어느 자리를 바꾸는 요청인가"다.
                # 값은 넣지 않는다 — 같은 좌표의 control과 probe는 kind와 purpose로
                # 이미 구분되고, 값까지 해시하면 관측값이 추측 대상이 된다.
                "path_assignment_name": request.path_assignment_name,
                "path_assignment_span": (
                    [request.path_assignment_value_start, request.path_assignment_value_end]
                    if request.path_assignment_name is not None
                    else None
                ),
                "file_read_path_index": request.file_read_path_index,
                "file_read_path_present": request.file_read_path_value is not None,
                "file_read_parameter": request.file_read_parameter,
                "surface_id": self.surface_id,
                "target": [
                    parsed.scheme.casefold(),
                    parsed.netloc.casefold(),
                    parsed.path or "/",
                    target_query_names,
                ],
                "tool": self.suggested_tool,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class TaskEnvelope:
    """Orchestrator가 Agent/Worker에 전달하는 표준 작업 메시지.

    Evidence 원문이나 인증정보 원문 대신 ID와 참조만 전달한다. 과거 Knowledge는
    민감정보와 provenance를 제거한 별도 Hint로만 Analysis에 전달한다.
    """

    task_id: str
    run_id: str
    agent_type: str
    target_url: str | None = None
    surface_id: str | None = None
    candidate_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    # 과거 Knowledge는 현재 Run의 Evidence가 아니다. Analysis에 참고 정보로만
    # 전달하고 Validation·수집 Task에는 넣지 않는다.
    knowledge_hints: tuple[KnowledgeHint, ...] = ()
    finding_ids: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    request_budget: int = 0
    # Optional budget allocation may already reserve Validation requests outside
    # this Task. An Analyzer subtracts only the missing part of its own proof cost.
    validation_request_reserve: int = 0
    policy_profile: str = "safe"
    timeout_seconds: int = 120
    credential_ref: str | None = None
    validation_id: str | None = None
    evidence_request: EvidenceRequest | None = None

    def __post_init__(self) -> None:
        # Task 자체가 유효하지 않으면 Dispatcher에 도달하기 전에 차단한다.
        if self.request_budget < 0:
            raise DomainInvariantError("task request budget cannot be negative")
        if self.validation_request_reserve < 0:
            raise DomainInvariantError("validation request reserve cannot be negative")
        if self.timeout_seconds <= 0:
            raise DomainInvariantError("task timeout must be positive")
        if len(self.knowledge_hints) > 10:
            raise DomainInvariantError("task knowledge context cannot exceed 10 hints")
        case_ids = tuple(item.case_id for item in self.knowledge_hints)
        if len(case_ids) != len(set(case_ids)):
            raise DomainInvariantError("task knowledge hints cannot be duplicated")


@dataclass(frozen=True, slots=True)
class TaskRecord:
    """TaskEnvelope와 현재 실행 상태·시도 횟수를 함께 저장한다."""

    envelope: TaskEnvelope
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    error: str | None = None

    def with_status(
        self, status: TaskStatus, *, attempts: int | None = None, error: str | None = None
    ) -> TaskRecord:
        """상태 갱신용 새 TaskRecord를 반환한다."""

        return replace(
            self,
            status=status,
            attempts=self.attempts if attempts is None else attempts,
            error=error,
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    """현재 대상에서 직접 관찰하거나 실행으로 수집한 증적."""

    evidence_id: str
    run_id: str
    surface_id: str | None
    created_by: str
    evidence_type: str
    source_task_id: str | None = None
    validation_id: str | None = None
    observation: Mapping[str, object] = field(default_factory=dict)
    artifact_refs: Mapping[str, str] = field(default_factory=dict)
    content_hash: str | None = None
    created_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True, slots=True)
class PathAssignment:
    """경로 자체에 ``이름=값``으로 실린 입력 좌표.

    ``/file=web_assets/app.js``처럼 query가 아니라 경로가 입력을 나르는 표면이 있다.
    이런 자리를 query parameter로 기록하면 Analyzer가 ``?file=``을 덧붙인, 대상이
    가진 적 없는 URL을 만든다. 그래서 위치를 별도 좌표로 보존한다.

    ``value_start``/``value_end``는 ``urlsplit(url).path``(퍼센트 인코딩이 풀리지 않은
    원본)의 slice 범위다. 실행기는 이 범위만 교체하므로 경로의 나머지 바이트는 관측된
    그대로 남고, 임의 경로를 만들어낼 수 없다.

    ``source``는 이 좌표를 관측한 구조적 출처다. "URL에 그런 문자열이 있었다"는 사실만
    뜻하며, 서버가 실제로 이를 입력으로 처리한다는 증거가 아니다. 그 판정은 control과
    probe를 비교한 Analysis·Validation만 내린다.
    """

    name: str
    value_start: int
    value_end: int
    observed_value: str
    source: str

    def __post_init__(self) -> None:
        if _PATH_ASSIGNMENT_NAME.fullmatch(self.name) is None:
            raise DomainInvariantError(f"path assignment name is invalid: {self.name!r}")
        if not isinstance(self.source, str) or not self.source:
            raise DomainInvariantError("path assignment must record its observed source")
        if type(self.value_start) is not int or type(self.value_end) is not int:
            raise DomainInvariantError("path assignment span must be integer offsets")
        if not 0 <= self.value_start < self.value_end:
            raise DomainInvariantError("path assignment span must be a non-empty range")
        if not isinstance(self.observed_value, str) or not self.observed_value:
            raise DomainInvariantError("path assignment must record a non-empty value")
        if len(self.observed_value) != self.value_end - self.value_start:
            raise DomainInvariantError(
                "path assignment span length must match its observed value"
            )

    def matches(self, url: str) -> bool:
        """이 좌표가 주어진 URL의 경로에서 실제로 그 값을 가리키는지 확인한다."""

        path = urlsplit(url).path
        return (
            self.value_end <= len(path)
            and path[self.value_start : self.value_end] == self.observed_value
        )


@dataclass(frozen=True, slots=True)
class Surface:
    """Recon이 발견한 공격 표면 하나(URL·메서드·파라미터·인증 요건)."""

    surface_id: str
    run_id: str
    url: str
    method: str
    parameters: tuple[str, ...] = ()
    requires_auth: bool = False
    # Recon이 실제로 관측한 query 값. 이름만으로는 재요청이 성립하지 않는 페이지가 있다
    # (예: action=View Profile, token=...). 식별자만 바꾸고 나머지를 원본 그대로 실으려면
    # 관측 시점의 값이 필요하다.
    observed_query: tuple[tuple[str, str], ...] = ()
    # `/users/17`처럼 식별자가 query가 아니라 경로 세그먼트에 있는 REST 표면.
    # index는 `urlsplit(url).path.split("/")` 기준이며 `/users/17`의 17은 2다.
    path_identifier: str | None = None
    path_identifier_index: int | None = None
    observed_path_identifier: str | None = None
    # `/file=web_assets/app.js`처럼 경로가 `이름=값`으로 입력을 나르는 표면의 좌표.
    # query parameters와 섞지 않는다 — 섞으면 Analyzer가 없던 query를 덧붙인다.
    path_assignment: PathAssignment | None = None
    # Recon이 이 좌표를 처음 발견한 구조적 출처. 추가 Recon 우선순위에만 사용하며
    # 취약점 여부나 Analyzer 판정 근거로 취급하지 않는다.
    discovery_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.discovery_types, tuple)
            or len(set(self.discovery_types)) != len(self.discovery_types)
            or any(
                not isinstance(value, str) or not value
                for value in self.discovery_types
            )
        ):
            raise DomainInvariantError(
                "surface discovery types must be unique non-empty strings"
            )
        self._validate_path_assignment()
        values = (
            self.path_identifier,
            self.path_identifier_index,
            self.observed_path_identifier,
        )
        if all(value is None for value in values):
            return
        if any(value is None for value in values):
            raise DomainInvariantError(
                "path identifier name, index, and observed value must be provided together"
            )
        assert self.path_identifier_index is not None
        assert self.observed_path_identifier is not None
        segments = urlsplit(self.url).path.split("/")
        if not (1 <= self.path_identifier_index < len(segments)):
            raise DomainInvariantError("path identifier index is outside the surface path")
        if _OBJECT_IDENTIFIER.fullmatch(self.observed_path_identifier) is None:
            raise DomainInvariantError("observed path object id must be numeric")
        if segments[self.path_identifier_index] != self.observed_path_identifier:
            raise DomainInvariantError(
                "observed path object id must match the indexed URL segment"
            )

    def _validate_path_assignment(self) -> None:
        """기록된 범위가 이 Surface의 URL에서 그 값을 정확히 가리키는지 확인한다.

        범위를 저장해 두고 실행 시점에 다시 찾지 않는 이유는, 재탐색이 곧 "경로 어딘가의
        비슷한 문자열"을 고르는 추측이 되기 때문이다. URL과 범위가 어긋나면 교체할 자리를
        모르는 것이므로 실행하지 않고 여기서 막는다.
        """

        if self.path_assignment is None:
            return
        if not self.path_assignment.matches(self.url):
            raise DomainInvariantError(
                "path assignment span does not select its observed value in the surface URL"
            )
        if self.path_assignment.name in self.parameters:
            raise DomainInvariantError(
                "path assignment name must not be recorded as a query parameter"
            )


class CandidateStatus(str, Enum):
    """Candidate 하나가 거치는 진행 상태.

    자유 문자열이면 오타가 조용히 통과해 "검사했는데 없었다"가 "검사하지 못했다"로
    잘못 집계될 수 있다. 집계 기준을 손으로 유지하는 곳이 여러 군데라 더 그렇다.

    str을 함께 상속하므로 저장·직렬화와 기존 문자열 비교가 그대로 동작한다.
    """

    ROUTED = "routed"  # Router가 만들었고 아직 분석 전
    ANALYZED = "analyzed"  # 분석을 마쳤고 독립 검증 대기
    CONFIRMED = "confirmed"  # 검증이 proof와 함께 확정
    SUSPECTED = "suspected"  # 판정을 얻지 못함. Finding으로 승격하지 않는다
    REJECTED = "rejected"  # 검증이 재현하지 못함
    BLOCKED = "blocked"  # 정책이나 승인 때문에 검증을 진행할 수 없음
    FAILED = "failed"  # 검사하다 실패했다
    SKIPPED_BUDGET = "skipped_budget"  # 예산이 없어 시작조차 못 했다


@dataclass(frozen=True, slots=True)
class Candidate:
    """아직 독립 검증을 통과하지 않은 취약점 가설."""

    candidate_id: str
    run_id: str
    surface_id: str
    vulnerability_type: str
    hypothesis: str
    assigned_agent: str
    evidence_ids: tuple[str, ...]
    status: CandidateStatus = CandidateStatus.ROUTED
    # 이 Candidate만 실패했을 때의 사유. 다른 Candidate는 계속 진행하므로 실패를
    # Run 전체가 아니라 Candidate에 남겨야 무엇이 검사되지 않았는지 알 수 있다.
    last_error: str | None = None
    # Validation 판정의 구조화된 분기 코드. 자유형 응답 문자열이나 증적 원문은
    # Candidate와 비교 산출물에 저장하지 않는다.
    validation_reason_code: ValidationReasonCode | None = None
    # 예산 때문에 건너뛴 Candidate가 어느 단계에서 멈췄는지. 재개할 때 이 값으로
    # 분석부터 다시 할지 검증만 다시 할지 정한다. 이것이 없으면 검증 직전에 멈춘
    # Candidate를 재개 시 처음부터 다시 분석하게 된다.
    resume_status: CandidateStatus | None = None
    # Router가 관측된 Surface에서 고른 탐색 입력 이름. 관측/성공 Evidence가 아니다.
    # Analyzer는 사용 전에 실제 Surface 소속과 실행 정책을 다시 검증해야 한다.
    exploration_parameters: tuple[str, ...] = ()
    # Agentic Router가 이 가설을 검증하려면 필요하다고 제안한 Evidence 종류다.
    # 실행 요청이나 proof가 아니라 감사 가능한 계획 메타데이터이며, 실제 Analyzer와
    # Validation은 기존 정책·proof 계약을 독립적으로 적용한다.
    required_evidence_types: tuple[str, ...] = ()
    # Router LLM의 판단을 실행 결과와 분리해 보존하는 계획 메타데이터다. 실제 probe와
    # 최종 판정 권한은 Analysis/Validation 계약에 그대로 남는다.
    routing_capability_id: str = ""
    routing_confidence: str = ""
    routing_priority: str = ""
    analysis_strategy_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.exploration_parameters, tuple) or any(
            not isinstance(name, str) or not name or not name.isprintable()
            for name in self.exploration_parameters
        ):
            raise DomainInvariantError("candidate exploration parameters must be names")
        if len(set(self.exploration_parameters)) != len(self.exploration_parameters):
            raise DomainInvariantError("candidate exploration parameters must be unique")
        if not isinstance(self.required_evidence_types, tuple) or any(
            not isinstance(name, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) is None
            for name in self.required_evidence_types
        ):
            raise DomainInvariantError("candidate required evidence types must be names")
        if len(set(self.required_evidence_types)) != len(
            self.required_evidence_types
        ):
            raise DomainInvariantError(
                "candidate required evidence types must be unique"
            )
        if self.routing_confidence not in {"", "low", "medium", "high"}:
            raise DomainInvariantError("candidate routing confidence is invalid")
        if self.routing_priority not in {"", "low", "normal", "high"}:
            raise DomainInvariantError("candidate routing priority is invalid")
        for field_name in ("routing_capability_id", "analysis_strategy_id"):
            value = getattr(self, field_name)
            if value and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", value) is None:
                raise DomainInvariantError(f"candidate {field_name} is invalid")
        # 저장소에서 문자열로 복원한 값도 같은 검사를 통과시킨다. 알 수 없는 상태는
        # 조용히 통과시키지 않고 여기서 막는다.
        for field_name in ("status", "resume_status"):
            value = getattr(self, field_name)
            if value is None:
                continue
            try:
                object.__setattr__(self, field_name, CandidateStatus(value))
            except ValueError as error:
                raise DomainInvariantError(
                    f"unknown candidate status: {value!r}"
                ) from error
        if self.validation_reason_code is not None:
            try:
                object.__setattr__(
                    self,
                    "validation_reason_code",
                    ValidationReasonCode(self.validation_reason_code),
                )
            except ValueError as error:
                raise DomainInvariantError(
                    f"unknown validation reason code: {self.validation_reason_code!r}"
                ) from error

    def add_evidence(self, evidence_ids: tuple[str, ...]) -> Candidate:
        """기존 순서를 유지하면서 중복 없이 Evidence 참조를 합친다."""

        merged = tuple(dict.fromkeys((*self.evidence_ids, *evidence_ids)))
        return replace(self, evidence_ids=merged)

    def set_status(
        self, status: CandidateStatus, *, reason: str | None = None,
        validation_reason_code: ValidationReasonCode | None = None,
    ) -> Candidate:
        """분석·검증 진행 상태가 변경된 Candidate 복사본을 만든다.

        정상 전이가 일어났다는 것은 이전에 남긴 실패·건너뜀 정보가 더 이상 현재를
        설명하지 않는다는 뜻이므로 함께 지운다. 다만 BLOCKED처럼 판정은 끝났지만
        검증을 완료하지 못한 상태는 일반화된 사유를 명시적으로 보존할 수 있다.
        """

        return replace(
            self, status=status, last_error=reason, resume_status=None,
            validation_reason_code=validation_reason_code,
        )

    def fail(self, reason: str) -> Candidate:
        """이 Candidate만 실패로 표시한다.

        "검사했는데 없었다"와 "검사하지 못했다"를 결과에서 구분하기 위해 사유를 함께
        남긴다. 사유가 없으면 실패한 Candidate가 안전한 Candidate처럼 보인다.
        """

        return replace(
            self, status=CandidateStatus.FAILED, last_error=reason,
            validation_reason_code=None,
        )

    def skip_for_budget(self, reason: str) -> Candidate:
        """예산이 모자라 시도조차 하지 못한 Candidate로 표시한다.

        실패와 구분해야 한다. 실패는 "검사했는데 대상이 응답하지 않았다"이고 이쪽은
        "검사를 시작조차 못 했다"이다. 둘을 뭉뚱그리면 보고서를 읽는 사람이 검사 범위를
        오해한다.
        """

        # 이미 건너뛴 Candidate를 다시 건너뛸 때 원래 단계 정보를 잃지 않는다.
        origin = (
            self.resume_status
            if self.status is CandidateStatus.SKIPPED_BUDGET
            else self.status
        )
        return replace(
            self,
            status=CandidateStatus.SKIPPED_BUDGET,
            last_error=reason,
            resume_status=origin,
            validation_reason_code=None,
        )


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """Router가 생성한 Candidate와 분석 우선순위."""

    candidate: Candidate
    priority: float


@dataclass(frozen=True, slots=True)
class ValidationProof:
    """CONFIRMED 판정을 뒷받침하는 취약점별 증명과 직접 Evidence 참조."""

    proof_type: ValidationProofType
    evidence_ids: tuple[str, ...]
    summary: str
    # A multi-step proof may use an observed second Surface (for example a
    # public script and the login endpoint that consumes its literal account).
    # The Orchestrator still checks Run ownership, origin, and session provenance.
    related_surface_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.proof_type, ValidationProofType):
            raise DomainInvariantError("validation proof type must be structured")
        if not self.evidence_ids:
            raise DomainInvariantError("validation proof must reference evidence")
        if not self.summary.strip():
            raise DomainInvariantError("validation proof must explain the reproduced effect")
        if any(not value for value in self.related_surface_ids) or len(set(self.related_surface_ids)) != len(self.related_surface_ids):
            raise DomainInvariantError("related proof surfaces must be distinct IDs")


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Candidate에 대한 독립 검증 결과와 근거 Evidence."""

    validation_id: str
    run_id: str
    candidate_id: str
    verdict: ValidationVerdict
    evidence_ids: tuple[str, ...]
    reason: str
    reproduction_count: int = 0
    proof: ValidationProof | None = None
    reason_code: ValidationReasonCode = ValidationReasonCode.UNSPECIFIED

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, ValidationVerdict):
            raise DomainInvariantError("validation verdict must be structured")
        if not isinstance(self.reason_code, ValidationReasonCode):
            raise DomainInvariantError("validation reason code must be structured")
        if not self.validation_id:
            raise DomainInvariantError("validation result must identify its session")
        if not self.reason.strip():
            raise DomainInvariantError("validation result must explain its verdict")
        if self.reproduction_count < 0:
            raise DomainInvariantError("validation reproduction count cannot be negative")
        if self.verdict is ValidationVerdict.CONFIRMED:
            if self.proof is None:
                raise DomainInvariantError(
                    "confirmed validation requires vulnerability-specific proof"
                )
            if not set(self.proof.evidence_ids).issubset(self.evidence_ids):
                raise DomainInvariantError(
                    "validation proof evidence must be included in validation evidence"
                )


@dataclass(frozen=True, slots=True)
class Finding:
    """Validation을 통과하여 보고 가능한 확정 취약점."""

    finding_id: str
    run_id: str
    candidate_id: str
    validation_id: str
    vulnerability_type: str
    surface_id: str
    evidence_ids: tuple[str, ...]
    severity: str = "unrated"
    status: str = "confirmed"
    remediation_refs: tuple[str, ...] = ()
    proof_type: ValidationProofType | None = None
    reproduction_count: int = 0

    def __post_init__(self) -> None:
        # Finding Store에 들어가기 전 도메인 객체 자체에서도 핵심 규칙을 보장한다.
        if self.status != "confirmed":
            raise DomainInvariantError("a finding must represent a confirmed verdict")
        if not self.evidence_ids:
            raise DomainInvariantError("a finding must reference supporting evidence")
        if self.proof_type is not None and not isinstance(
            self.proof_type, ValidationProofType
        ):
            raise DomainInvariantError("finding proof type must be structured")
        if self.reproduction_count < 0:
            raise DomainInvariantError("finding reproduction count cannot be negative")
        if self.proof_type is None and self.reproduction_count != 0:
            raise DomainInvariantError("finding without proof type cannot claim reproductions")
        if self.proof_type is not None and self.reproduction_count == 0:
            raise DomainInvariantError("finding proof type requires a reproduction")

    @classmethod
    def from_confirmed(
        cls,
        *,
        finding_id: str,
        candidate: Candidate,
        validation: ValidationResult,
        severity: str = "unrated",
    ) -> Finding:
        """검증된 Candidate만 Finding으로 승격한다."""

        # Candidate와 Validation의 소유 Run/ID가 다르면 증적 추적성이 깨진다.
        if validation.verdict is not ValidationVerdict.CONFIRMED:
            raise DomainInvariantError("only confirmed validation can create a finding")
        if validation.run_id != candidate.run_id:
            raise DomainInvariantError("candidate and validation must belong to the same run")
        if validation.candidate_id != candidate.candidate_id:
            raise DomainInvariantError("validation must refer to the candidate")
        if not validation.evidence_ids:
            raise DomainInvariantError("confirmed validation must reference evidence")
        proof = validation.proof
        if proof is None:
            raise DomainInvariantError("confirmed validation must have proof")
        return cls(
            finding_id=finding_id,
            run_id=candidate.run_id,
            candidate_id=candidate.candidate_id,
            validation_id=validation.validation_id,
            vulnerability_type=candidate.vulnerability_type,
            surface_id=candidate.surface_id,
            evidence_ids=tuple(dict.fromkeys(validation.evidence_ids)),
            severity=severity,
            proof_type=proof.proof_type,
            reproduction_count=validation.reproduction_count,
        )


@dataclass(frozen=True, slots=True)
class ReportArtifact:
    """Report Agent가 생성한 출력물의 포맷과 내용."""

    report_id: str
    run_id: str
    format: str
    content: str


@dataclass(frozen=True, slots=True)
class AgentResult:
    """모든 Agent/Worker가 공통으로 반환하는 결과 봉투."""

    task_id: str
    status: AgentResultStatus
    new_evidence_ids: tuple[str, ...] = ()
    surface_ids: tuple[str, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    validation: ValidationResult | None = None
    evidence_requests: tuple[EvidenceRequest, ...] = ()
    reports: tuple[ReportArtifact, ...] = ()
    message: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """정책과 예산 검사를 거쳐 Execution Runtime으로 보낼 실행 요청."""

    execution_id: str
    run_id: str
    task_id: str
    tool: str
    target_url: str
    surface_id: str | None
    purpose: str
    method: str = "GET"
    query_parameters: tuple[tuple[str, str], ...] = ()
    form_parameters: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = field(default=None, repr=False)
    request_kind: HttpRequestKind = HttpRequestKind.CONTROL
    identifier_parameter: str | None = None
    identifier_location: AccessIdentifierLocation | None = None
    path_identifier_index: int | None = None
    path_identifier_value: str | None = None
    path_suffix: str | None = None
    path_assignment_name: str | None = None
    path_assignment_value_start: int | None = None
    path_assignment_value_end: int | None = None
    path_assignment_value: str | None = None
    file_read_path_index: int | None = None
    file_read_path_value: str | None = None
    file_read_parameter: str | None = None
    validation_id: str | None = None
    timeout_seconds: float = 120.0
    credential_ref: str | None = None
    approval_ref: str | None = None
    scope: RunScope | None = None
    body_encoding: str = "utf-8"

    def __post_init__(self) -> None:
        # Runtime 직전 객체도 동일한 명세 검증을 통과시켜 직접 생성 경로의 우회를 막는다.
        HttpRequestSpec(
            method=self.method,
            query_parameters=self.query_parameters,
            form_parameters=self.form_parameters,
            headers=self.headers,
            body=self.body,
            body_encoding=self.body_encoding,
            request_kind=self.request_kind,
            identifier_parameter=self.identifier_parameter,
            identifier_location=self.identifier_location,
            path_identifier_index=self.path_identifier_index,
            path_identifier_value=self.path_identifier_value,
            path_suffix=self.path_suffix,
            path_assignment_name=self.path_assignment_name,
            path_assignment_value_start=self.path_assignment_value_start,
            path_assignment_value_end=self.path_assignment_value_end,
            path_assignment_value=self.path_assignment_value,
            file_read_path_index=self.file_read_path_index,
            file_read_path_value=self.file_read_path_value,
            file_read_parameter=self.file_read_parameter,
        )
        if self.timeout_seconds <= 0:
            raise DomainInvariantError("execution timeout must be positive")
        if self.credential_ref is not None and not self.credential_ref.strip():
            raise DomainInvariantError("execution credential reference cannot be blank")
        if self.approval_ref is not None and not self.approval_ref.strip():
            raise DomainInvariantError("execution approval reference cannot be blank")

    @property
    def resolved_url(self) -> str:
        """기존 query를 보존하면서 구조화 파라미터를 인코딩한 실제 요청 URL."""

        parsed = urlsplit(self.target_url)
        path = parsed.path
        if self.identifier_location is AccessIdentifierLocation.PATH:
            segments = path.split("/")
            index = self.path_identifier_index
            if index is None or not (1 <= index < len(segments)):
                raise DomainInvariantError("path identifier index is outside the target URL")
            assert self.path_identifier_value is not None
            segments[index] = quote(self.path_identifier_value, safe="")
            path = "/".join(segments)
        if self.path_suffix is not None:
            # 도메인이 고정한 접미사이며 이미 인코딩된 문자열이다. 다시 quote하면
            # `%25`가 `%2525`가 되어 우회가 성립하지 않는다.
            path = f"{path}{self.path_suffix}"
        if self.path_assignment_name is not None:
            path = self._replace_path_assignment(path)
        if self.file_read_path_index is not None:
            segments = path.split("/")
            index = self.file_read_path_index
            if not (1 <= index < len(segments)):
                raise DomainInvariantError("file-read path index is outside the target URL")
            assert self.file_read_path_value is not None
            segments[index] = quote(self.file_read_path_value, safe="")
            path = "/".join(segments)
        encoded = urlencode(self.query_parameters)
        query = "" if self.request_kind in {
            HttpRequestKind.SSRF_CONTROL, HttpRequestKind.SSRF_PROBE,
            HttpRequestKind.SSRF_CANARY_PROBE,
            HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
        } else parsed.query
        if encoded:
            query = f"{query}&{encoded}" if query else encoded
        # URL fragment는 HTTP 요청 대상에 포함되지 않는다.
        return urlunsplit((parsed.scheme, parsed.netloc, path, query, ""))

    def _replace_path_assignment(self, path: str) -> str:
        """경로에 실린 입력에서 기록된 범위만 증명 값으로 바꾼다.

        범위 밖은 관측된 바이트 그대로 남는다. 새 세그먼트를 붙이거나 query를 덧붙이지
        않으므로, 대상이 실제로 제공한 경로 구조에서 값 하나만 달라진 요청이 된다.

        ``safe="/"``로 인코딩한다. 경로에 실린 파일 입력은 구분자 ``/``를 값 안에 포함하는
        것이 정상이고, 서버는 그 전체를 하나의 경로로 읽는다. ``/``까지 ``%2F``로 바꾸면
        정상 요청과 다른 형태가 되어 control 비교가 성립하지 않는다. 나머지 문자는
        인코딩되므로 값이 경로 밖 요소(query·fragment)로 넘어갈 수 없다.
        """

        start = self.path_assignment_value_start
        end = self.path_assignment_value_end
        assert start is not None and end is not None
        assert self.path_assignment_value is not None
        if not 0 <= start < end <= len(path):
            raise DomainInvariantError(
                "path assignment span is outside the target URL path"
            )
        return path[:start] + quote(self.path_assignment_value, safe="/") + path[end:]

@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Runtime 실행 결과 중 Evidence로 변환할 데이터."""

    execution_id: str
    evidence_type: str
    observation: Mapping[str, object]
    artifact_refs: Mapping[str, str] = field(default_factory=dict)
    content_hash: str | None = None


class ProgressEventKind(str, Enum):
    """Run 진행 중 밖으로 알릴 수 있는 사건.

    Notion 목록의 VALIDATION_* 은 AGENT_* 에 agent_type 으로 담기고, EVIDENCE_REQUESTED 는
    수집이 끝난 시점만 알리면 충분하므로 EVIDENCE_COLLECTED 하나로 둔다. 예산은 별도
    사건이 아니라 모든 이벤트가 함께 싣는다. 소비자가 없는 종류를 미리 만들지 않는다.
    """

    RUN_STARTED = "run_started"
    PHASE_CHANGED = "phase_changed"
    CANDIDATE_QUEUED = "candidate_queued"
    ORCHESTRATION_DECIDED = "orchestration_decided"
    BUDGET_ALLOCATED = "budget_allocated"
    KNOWLEDGE_RETRIEVED = "knowledge_retrieved"
    KNOWLEDGE_RETRIEVAL_FAILED = "knowledge_retrieval_failed"
    AGENT_STARTED = "agent_started"
    AGENT_COMPLETED = "agent_completed"
    EVIDENCE_COLLECTED = "evidence_collected"
    FINDING_CREATED = "finding_created"
    CANDIDATE_FAILED = "candidate_failed"
    CANDIDATE_SKIPPED = "candidate_skipped"
    RUN_COMPLETED = "run_completed"


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """진행 상황 하나. 무엇이 일어났는지만 담고 응답 내용은 담지 않는다.

    Cookie·Authorization·API Key·비밀번호·응답 본문은 넣지 않는다. surface 는 경로만
    남기고 query 값은 제거한다. 진행 화면은 여러 사람이 함께 보거나 로그로 남으므로
    Evidence 보다 더 좁게 잡는다.

    sequence 는 Run 안에서 단조 증가한다. 순서를 복원하고 중복을 걸러내는 기준이다.
    """

    run_id: str
    sequence: int
    kind: ProgressEventKind
    phase: str
    agent_type: str | None = None
    candidate_id: str | None = None
    vulnerability_type: str | None = None
    # 경로만 남긴 대상. query 값은 제거한 뒤 넣는다.
    surface_path: str | None = None
    detail: str | None = None
    budget_used: int = 0
    budget_total: int = 0
    # Run 시작 이후 경과 시간. 벽시계 시각이 아니라 경과값이라 재현 실행 사이에 비교할
    # 수 있고, 두 이벤트를 빼면 그 구간에 걸린 시간이 나온다. 브라우저 검증처럼 비싼
    # 단계의 비용을 재는 근거가 된다.
    elapsed_ms: int = 0

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise DomainInvariantError("progress event sequence cannot be negative")
        if self.elapsed_ms < 0:
            raise DomainInvariantError("progress event elapsed time cannot be negative")
        if self.surface_path is not None and (
            "?" in self.surface_path or "#" in self.surface_path
        ):
            raise DomainInvariantError(
                "progress event surface must not carry a query or fragment"
            )


@dataclass(frozen=True, slots=True)
class UncheckedCandidate:
    """검사를 끝내지 못한 Candidate 하나의 요약."""

    vulnerability_type: str
    status: str
    reason: str | None


@dataclass(frozen=True, slots=True)
class ProgressSnapshot:
    """Run 진행 상태의 파생 뷰.

    Store가 유일한 사실 원천이고 이 객체는 그 계산 결과다. 진행 상태를 따로 누적하면
    실제 저장 내용과 어긋나 완료되지 않은 작업을 완료로 표시할 수 있다.

    표시 방식은 담지 않는다. 문구·색·기호는 CLI나 웹 UI가 정하고, 여기에는 숫자와
    식별자만 둔다. 그래야 같은 스냅샷을 두 화면이 함께 쓸 수 있다.
    """

    run_id: str
    phase: str
    surface_count: int = 0
    parameter_count: int = 0
    # 아래 매핑들은 JSON 직렬화가 가능하도록 쌍의 튜플로 둔다.
    candidates_by_type: tuple[tuple[str, int], ...] = ()
    candidates_by_status: tuple[tuple[str, int], ...] = ()
    evidence_count: int = 0
    # Analysis가 남긴 Observation 종류별 개수. 표시 문구가 아니라 원본 type 값이다.
    signals_by_type: tuple[tuple[str, int], ...] = ()
    validated_count: int = 0
    findings_by_type: tuple[tuple[str, int], ...] = ()
    budget_used: int = 0
    budget_total: int = 0
    llm_calls: int = 0
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    unchecked: tuple[UncheckedCandidate, ...] = ()
    last_error: str | None = None

    @property
    def candidate_count(self) -> int:
        return sum(count for _, count in self.candidates_by_type)

    @property
    def finding_count(self) -> int:
        return sum(count for _, count in self.findings_by_type)


@dataclass(frozen=True, slots=True)
class KnowledgeQuery:
    """별도 Knowledge Plane에 전달하는 최소 검색 조건."""

    category: str
    text: str
    limit: int = 5


@dataclass(frozen=True, slots=True)
class KnowledgeCase:
    """민감정보 제거·일반화 후 재사용할 수 있는 지식 단위."""

    case_id: str
    category: str
    summary: str
    provenance_refs: tuple[str, ...]
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class KnowledgeHint:
    """Analysis에만 전달하는 provenance 없는 일반화 Knowledge 참고 정보."""

    case_id: str
    category: str
    summary: str
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", self.case_id):
            raise DomainInvariantError("knowledge hint case_id has an invalid format")
        if not self.category.strip() or len(self.category) > 80:
            raise DomainInvariantError("knowledge hint category must be non-blank and bounded")
        if not self.summary.strip() or len(self.summary) > 500:
            raise DomainInvariantError("knowledge hint summary must be non-blank and bounded")
        if len(self.metadata) > 16:
            raise DomainInvariantError("knowledge hint metadata has too many entries")
        for key, value in self.metadata.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise DomainInvariantError("knowledge hint metadata must contain strings")
            if not key or len(key) > 80 or len(value) > 500:
                raise DomainInvariantError("knowledge hint metadata is not bounded")
