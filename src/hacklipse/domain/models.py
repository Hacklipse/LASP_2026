"""시스템 전 계층이 공유하는 최소 도메인 모델과 핵심 불변식."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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


class ValidationProofType(str, Enum):
    """취약점 유형별 CONFIRMED 판정이 요구하는 구조화된 증명 종류."""

    XSS_EXECUTION = "xss_execution"
    SQLI_EFFECT = "sqli_effect"
    UNAUTHORIZED_OBJECT_ACCESS = "unauthorized_object_access"
    PATH_TRAVERSAL_FILE_READ = "path_traversal_file_read"
    SSTI_EXECUTION = "ssti_execution"


class HttpRequestKind(str, Enum):
    """비교 기준 요청과 취약점 탐색 요청을 기계적으로 구분한다."""

    CONTROL = "control"
    PROBE = "probe"
    PATH_TRAVERSAL_PROBE = "path_traversal_probe"
    ACCESS_CONTROL_PROBE = "access_control_probe"
    SSTI_PROBE = "ssti_probe"
    SSTI_CLEANUP = "ssti_cleanup"


class AccessPrincipalRole(str, Enum):
    """Access Control 탐침이 지정할 수 있는 인증 주체 역할.

    Agent와 LLM은 credential_ref를 직접 고를 수 없고 역할만 지정한다. 역할에서
    자격증명으로의 해석은 중앙 Collector가 Run에 등록된 매핑으로만 수행하므로,
    Agent는 username·password·Cookie·Authorization을 알 수도 고를 수도 없다.
    """

    ACTOR = "actor"
    OWNER = "owner"


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
# Path Traversal 자동 검증이 읽을 수 있는 유일한 값이다. 컨테이너에 기본 존재하는
# 비민감 OS 식별 파일을 정확한 상대 경로 하나로 고정해 LLM이나 Agent가 다른 파일
# (예: /etc/passwd)을 선택하지 못하게 한다.
PATH_TRAVERSAL_SAFE_PROBE_PATH = "../../../../../etc/os-release"
# Access Control 탐침이 식별자 파라미터에 실을 수 있는 값. 숫자만 허용해 LLM이나 Agent가
# 경로·따옴표·와일드카드를 객체 ID 자리에 넣지 못하게 한다.
_OBJECT_IDENTIFIER = re.compile(r"^[0-9]{1,10}$")
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


def is_path_traversal_safe_probe_value(value: str) -> bool:
    """고정된 비민감 증명 파일 상대 경로와 정확히 같은지 확인한다."""

    return value == PATH_TRAVERSAL_SAFE_PROBE_PATH


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

    def __post_init__(self) -> None:
        # 실행 예산은 이후 Runtime과 Agent 호출을 통제하는 상한선이다.
        if self.request_budget <= 0:
            raise DomainInvariantError("request budget must be positive")
        if self.timeout_seconds <= 0:
            raise DomainInvariantError("run timeout must be positive")
        if self.credential_ref is not None and not self.credential_ref.strip():
            raise DomainInvariantError("credential reference cannot be blank")


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
    phase: RunPhase = RunPhase.INIT
    evidence_ids: tuple[str, ...] = ()
    surface_ids: tuple[str, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    report_ids: tuple[str, ...] = ()
    last_error: str | None = None

    def with_updates(self, **changes: object) -> Run:
        """불변 dataclass를 직접 수정하지 않고 변경된 복사본을 만든다."""

        return replace(self, **changes)


@dataclass(frozen=True, slots=True)
class HttpRequestSpec:
    """Agent가 공통 HTTP Runtime에 전달하는 구조화된 요청 명세."""

    method: str = "GET"
    query_parameters: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None
    request_kind: HttpRequestKind = HttpRequestKind.CONTROL
    # ACCESS_CONTROL_PROBE에서 값이 바뀌는 유일한 파라미터. 나머지 query는 Recon이 관측한
    # 원본을 그대로 보존해야 하므로 어느 것이 식별자인지 명시적으로 지정한다.
    identifier_parameter: str | None = None

    def __post_init__(self) -> None:
        if not self.method or _HTTP_METHOD.fullmatch(self.method) is None:
            raise DomainInvariantError("HTTP method must be a valid token")
        if not isinstance(self.request_kind, HttpRequestKind):
            raise DomainInvariantError("HTTP request kind must be control or probe")
        if self.body is not None and not isinstance(self.body, str):
            raise DomainInvariantError("HTTP request body must be text")

        for name, value in self.query_parameters:
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
            if (
                self.request_kind is HttpRequestKind.PATH_TRAVERSAL_PROBE
                and _PROBE_VALUE.fullmatch(value) is None
                and not is_path_traversal_safe_probe_value(value)
            ):
                raise DomainInvariantError(
                    "path traversal probe may only use markers and the fixed safe path"
                )
        if self.request_kind is HttpRequestKind.ACCESS_CONTROL_PROBE:
            self._validate_access_control_probe()

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
    # Agent는 어떤 자격증명을 쓸지 고를 수 없고 역할만 지정한다. 역할 → credential_ref
    # 해석은 중앙 Collector가 Run에 등록된 매핑으로만 수행한다.
    principal_role: AccessPrincipalRole | None = None
    # 상태 변경 요청의 승인 참조는 비밀이 아니라 사용자가 부여한 권한의 식별자다.
    # 실제 허용 여부는 Agent가 아니라 중앙 ApprovalGate가 판단한다.
    approval_ref: str | None = None

    def __post_init__(self) -> None:
        if self.principal_role is not None and not isinstance(
            self.principal_role, AccessPrincipalRole
        ):
            raise DomainInvariantError("principal role must be a structured role")
        if self.approval_ref is not None and not self.approval_ref.strip():
            raise DomainInvariantError("evidence request approval reference cannot be blank")

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
                "approval_present": self.approval_ref is not None,
                "evidence_type": self.evidence_type,
                "header_names": [name.casefold() for name, _ in request.headers],
                "method": request.method.upper(),
                "purpose": self.reason,
                "principal_role": (
                    self.principal_role.value if self.principal_role is not None else None
                ),
                "query_names": [name for name, _ in request.query_parameters],
                "request_kind": request.request_kind.value,
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

    Evidence 원문이나 인증정보 원문 대신 ID와 참조만 전달한다.
    """

    task_id: str
    run_id: str
    agent_type: str
    target_url: str | None = None
    surface_id: str | None = None
    candidate_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    request_budget: int = 0
    policy_profile: str = "safe"
    timeout_seconds: int = 120
    credential_ref: str | None = None
    validation_id: str | None = None
    evidence_request: EvidenceRequest | None = None

    def __post_init__(self) -> None:
        # Task 자체가 유효하지 않으면 Dispatcher에 도달하기 전에 차단한다.
        if self.request_budget < 0:
            raise DomainInvariantError("task request budget cannot be negative")
        if self.timeout_seconds <= 0:
            raise DomainInvariantError("task timeout must be positive")


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
    status: str = "routed"

    def add_evidence(self, evidence_ids: tuple[str, ...]) -> Candidate:
        """기존 순서를 유지하면서 중복 없이 Evidence 참조를 합친다."""

        merged = tuple(dict.fromkeys((*self.evidence_ids, *evidence_ids)))
        return replace(self, evidence_ids=merged)

    def set_status(self, status: str) -> Candidate:
        """분석·검증 진행 상태가 변경된 Candidate 복사본을 만든다."""

        return replace(self, status=status)


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

    def __post_init__(self) -> None:
        if not isinstance(self.proof_type, ValidationProofType):
            raise DomainInvariantError("validation proof type must be structured")
        if not self.evidence_ids:
            raise DomainInvariantError("validation proof must reference evidence")
        if not self.summary.strip():
            raise DomainInvariantError("validation proof must explain the reproduced effect")


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

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, ValidationVerdict):
            raise DomainInvariantError("validation verdict must be structured")
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

    def __post_init__(self) -> None:
        # Finding Store에 들어가기 전 도메인 객체 자체에서도 핵심 규칙을 보장한다.
        if self.status != "confirmed":
            raise DomainInvariantError("a finding must represent a confirmed verdict")
        if not self.evidence_ids:
            raise DomainInvariantError("a finding must reference supporting evidence")

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
        return cls(
            finding_id=finding_id,
            run_id=candidate.run_id,
            candidate_id=candidate.candidate_id,
            validation_id=validation.validation_id,
            vulnerability_type=candidate.vulnerability_type,
            surface_id=candidate.surface_id,
            evidence_ids=tuple(dict.fromkeys(validation.evidence_ids)),
            severity=severity,
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
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None
    request_kind: HttpRequestKind = HttpRequestKind.CONTROL
    identifier_parameter: str | None = None
    validation_id: str | None = None
    timeout_seconds: float = 120.0
    credential_ref: str | None = None
    approval_ref: str | None = None
    scope: RunScope | None = None

    def __post_init__(self) -> None:
        # Runtime 직전 객체도 동일한 명세 검증을 통과시켜 직접 생성 경로의 우회를 막는다.
        HttpRequestSpec(
            method=self.method,
            query_parameters=self.query_parameters,
            headers=self.headers,
            body=self.body,
            request_kind=self.request_kind,
            identifier_parameter=self.identifier_parameter,
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
        encoded = urlencode(self.query_parameters)
        query = parsed.query
        if encoded:
            query = f"{query}&{encoded}" if query else encoded
        # URL fragment는 HTTP 요청 대상에 포함되지 않는다.
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))

@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Runtime 실행 결과 중 Evidence로 변환할 데이터."""

    execution_id: str
    evidence_type: str
    observation: Mapping[str, object]
    artifact_refs: Mapping[str, str] = field(default_factory=dict)
    content_hash: str | None = None


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
