"""시스템 전 계층이 공유하는 최소 도메인 모델과 핵심 불변식."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping

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

    def __post_init__(self) -> None:
        # 실행 예산은 이후 Runtime과 Agent 호출을 통제하는 상한선이다.
        if self.request_budget <= 0:
            raise DomainInvariantError("request budget must be positive")


@dataclass(frozen=True, slots=True)
class Run:
    """워크플로 진행 상태와 생성된 도메인 객체 ID를 보관하는 실행 단위."""

    run_id: str
    target_url: str
    scope: RunScope
    policy_profile: str
    request_budget: int
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
class EvidenceRequest:
    """Validation 등이 추가 증적이 필요할 때 Orchestrator에 보내는 요청."""

    evidence_type: str
    surface_id: str
    reason: str
    suggested_tool: str


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
    observation: Mapping[str, object] = field(default_factory=dict)
    artifact_refs: Mapping[str, str] = field(default_factory=dict)
    content_hash: str | None = None
    created_at: datetime = field(default_factory=utc_now)


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
class ValidationResult:
    """Candidate에 대한 독립 검증 결과와 근거 Evidence."""

    validation_id: str
    run_id: str
    candidate_id: str
    verdict: ValidationVerdict
    evidence_ids: tuple[str, ...]
    reason: str
    reproduction_count: int = 0
    evidence_requests: tuple[EvidenceRequest, ...] = ()


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
