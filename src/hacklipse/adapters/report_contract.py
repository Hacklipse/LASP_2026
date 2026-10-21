"""Report v2와 Narrator가 공유하는 불변 사실 계약. Store/LLM 의존성은 없다.

JSON은 UTF-8, 정렬된 object key, 공백 없는 separator를 사용한다. 상태는 enum 순서,
Finding은 finding_id 순서다. fingerprint는 ID뿐 아니라 모든 사실 값과 명시적인
비민감 narrator 설정을 포함한다. 이 규칙을 바꾸면 CONTRACT_VERSION도 올린다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import math
import re
from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

from hacklipse.domain import CandidateStatus, SsrfPolicySource, ValidationProofType


# v5: callback과 internal-canary 상태를 독립 필드로 추가했다. 한 전략의
# 장애가 다른 전략의 성공 관측을 덮지 않게 하는 사실 계약 변경이다.
CONTRACT_VERSION = "report-facts-v5"
MAX_PATH_HINT_LENGTH = 160
PROOF_DESCRIPTIONS = MappingProxyType({
    ValidationProofType.CORS_ORIGIN_REFLECTION:
        "독립 GET 요청에서 외부 Origin 반사와 credential 허용 확인",
    ValidationProofType.XSS_EXECUTION:
        "독립 browser control/probe 비교에서 probe 실행 신호 확인",
    ValidationProofType.SQLI_EFFECT:
        "독립 control/probe 비교에서 SQL 오류 차이 확인",
    ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS:
        "분리된 주체 세션에서 다른 소유자의 객체 접근 확인",
    ValidationProofType.PATH_TRAVERSAL_FILE_READ:
        "제한된 safe-file control/probe 비교에서 파일 읽기 확인",
    ValidationProofType.SSTI_EXECUTION:
        "고정 산술 control/probe 비교에서 서버 측 평가 확인",
    ValidationProofType.SENSITIVE_DATA_EXPOSURE:
        "독립 클라이언트 콘텐츠 재요청에서 자격증명 노출 확인",
    ValidationProofType.WORKING_PUBLIC_CREDENTIAL:
        "독립 공개 스크립트 재요청과 승인된 로그인 재현으로 유효한 자격증명 확인",
    ValidationProofType.GRAPHQL_INTROSPECTION_EXPOSURE:
        "독립 무인증 읽기 전용 요청에서 GraphQL 스키마 조회 가능 확인",
    ValidationProofType.GRAPHQL_FIELD_SUGGESTION_EXPOSURE:
        "독립 무인증 읽기 전용 요청에서 GraphQL 필드 이름 제안 확인",
    ValidationProofType.SOURCE_MAP_EXPOSURE:
        "독립 GET 재요청에서 공개 source map의 원본 소스 확인",
    ValidationProofType.ERROR_DETAIL_EXPOSURE:
        "독립 GET 재요청에서 오류 응답의 내부 스택 프레임 확인",
    ValidationProofType.OPEN_REDIRECT:
        "독립 control/probe 비교에서 외부 origin 이동 대상 확인",
    ValidationProofType.SSRF_UNAUTHORIZED_FETCH:
        "독립 callback 재현과 승인된 내부 canary의 금지 목적지 접근 확인",
})
PROOF_UNAVAILABLE = "검증 상세를 사용할 수 없음"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PATH_SEGMENT = re.compile(r"[a-z][a-z._-]{0,31}\Z")
_SENSITIVE_SEGMENT = re.compile(
    r"(?:token|secret|password|passwd|credential|authorization|cookie|api[-_]?key|sk-)",
    re.IGNORECASE,
)


def surface_path_hint(url: str) -> str:
    """query/fragment/host를 버리고 값처럼 보이는 경로 세그먼트를 일반화한다.

    percent-encoded, 숫자, UUID, 긴 문자열, 대문자 혼합 token도 그대로 노출하지
    않는다. 민감 필드명 다음 세그먼트는 짧은 영문 값이어도 숨긴다.
    """

    try:
        path = urlsplit(url).path
    except ValueError:
        return "/{value}"
    result: list[str] = []
    hide_next = False
    for segment in path.split("/"):
        if not segment:
            continue
        sensitive = bool(_SENSITIVE_SEGMENT.search(segment))
        safe = (
            not hide_next and not sensitive
            and segment not in (".", "..")
            and _PATH_SEGMENT.fullmatch(segment) is not None
        )
        result.append(segment if safe else "{value}")
        hide_next = sensitive
        if len("/" + "/".join(result)) > MAX_PATH_HINT_LENGTH:
            result.pop()
            while result and len("/" + "/".join((*result, "{value}"))) > MAX_PATH_HINT_LENGTH:
                result.pop()
            result.append("{value}")
            break
    return "/" + "/".join(result)


def _identifier(value: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("report identifier must be a bounded internal identifier")


def _count(value: int) -> None:
    if type(value) is not int or value < 0:
        raise ValueError("report count must be a nonnegative integer")


def finding_fact_id(finding_id: str) -> str:
    _identifier(finding_id)
    return "finding:" + sha256(finding_id.encode("utf-8")).hexdigest()


def ssrf_callback_surface_fact_id(surface_id: str) -> str:
    _identifier(surface_id)
    return "run:ssrf-callback:" + sha256(surface_id.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class FindingReportFact:
    fact_id: str
    finding_id: str
    vulnerability_type: str
    surface_path_hint: str
    proof_type: ValidationProofType | None
    reproduction_count: int

    def __post_init__(self) -> None:
        _identifier(self.fact_id)
        _identifier(self.finding_id)
        if not self.fact_id.startswith("finding:"):
            raise ValueError("finding facts must use the finding namespace")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,63}", self.vulnerability_type):
            raise ValueError("invalid report vulnerability label")
        if (not self.surface_path_hint.startswith("/")
                or surface_path_hint(self.surface_path_hint) != self.surface_path_hint):
            raise ValueError("report path must already be generalized")
        _count(self.reproduction_count)
        if self.proof_type is None:
            if self.reproduction_count:
                raise ValueError("missing proof cannot claim reproductions")
        elif not isinstance(self.proof_type, ValidationProofType) or not self.reproduction_count:
            raise ValueError("report proof requires a structured type and reproductions")

    @property
    def proof_description(self) -> str:
        if self.proof_type is ValidationProofType.SSRF_UNAUTHORIZED_FETCH:
            return (
                "independent server-request observation and an exact-Surface "
                "destination-policy violation were reproduced"
            )
        return PROOF_UNAVAILABLE if self.proof_type is None else PROOF_DESCRIPTIONS[self.proof_type]


@dataclass(frozen=True, slots=True)
class SsrfCallbackSurfaceFact:
    """A/B callback reproduction without a destination-policy verdict."""

    fact_id: str
    surface_path_hint: str
    analysis_http_callbacks: int
    validation_http_callbacks: int

    def __post_init__(self) -> None:
        _identifier(self.fact_id)
        if not self.fact_id.startswith("run:ssrf-callback:"):
            raise ValueError("SSRF callback facts must use the callback namespace")
        if (
            not self.surface_path_hint.startswith("/")
            or surface_path_hint(self.surface_path_hint) != self.surface_path_hint
        ):
            raise ValueError("report path must already be generalized")
        _count(self.analysis_http_callbacks)
        _count(self.validation_http_callbacks)
        if not self.analysis_http_callbacks or not self.validation_http_callbacks:
            raise ValueError("SSRF callback surface requires independent A/B HTTP observations")


SSRF_REVIEW_STATUSES = frozenset({
    "NOT_TESTED",
    "REVIEW_REQUIRED",
    "CALLBACK_OBSERVED",
    "CANARY_OBSERVED_POLICY_PENDING",
    "CONFIRMED_POLICY_VIOLATION",
    "CALLBACK_PROVIDER_BLOCKED",
    "OBSERVATION_PROVIDER_BLOCKED",
    "EXECUTION_APPROVAL_PENDING",
    "POLICY_EVIDENCE_PENDING",
    "VALIDATION_BUDGET_INSUFFICIENT",
    "ALLOWED_DESTINATION",
    "CALLBACK_NOT_OBSERVED",
    "CALLBACK_ANALYSIS_OBSERVED",
    "CALLBACK_NOT_REPRODUCED",
    "CANARY_ANALYSIS_OBSERVED",
    "CANARY_NOT_REPRODUCED",
    "OWNED_RECEIVER_OBSERVED_POLICY_PENDING",
    "OWNED_RECEIVER_ANALYSIS_OBSERVED",
    "OWNED_RECEIVER_NOT_REPRODUCED",
    "OWNED_RECEIVER_NOT_OBSERVED",
    "OWNED_RECEIVER_PROVIDER_BLOCKED",
})

SSRF_CALLBACK_STATUSES = frozenset({
    "NOT_CONFIGURED",
    "NOT_RUN",
    "NO_HTTP_CALLBACK",
    "ANALYSIS_OBSERVED",
    "VALIDATION_REPRODUCED",
    "VALIDATION_NOT_REPRODUCED",
    "PROVIDER_BLOCKED",
    "VALIDATION_BUDGET_INSUFFICIENT",
})

SSRF_CANARY_STATUSES = frozenset({
    "NOT_CONFIGURED",
    "NOT_RUN",
    "NO_CANARY_MARKER",
    "ANALYSIS_OBSERVED",
    "VALIDATION_NOT_REPRODUCED",
    "ACCESS_OBSERVED_POLICY_PENDING",
    "POLICY_MISMATCH",
    "ALLOWED_DESTINATION",
    "CONFIRMED_POLICY_VIOLATION",
    "PROVIDER_BLOCKED",
    "EXECUTION_APPROVAL_PENDING",
    "VALIDATION_BUDGET_INSUFFICIENT",
})

SSRF_OWNED_RECEIVER_STATUSES = frozenset({
    "NOT_CONFIGURED",
    "NOT_RUN",
    "NO_REQUEST_OBSERVED",
    "ANALYSIS_OBSERVED",
    "VALIDATION_NOT_REPRODUCED",
    "ACCESS_OBSERVED_POLICY_PENDING",
    "POLICY_MISMATCH",
    "ALLOWED_DESTINATION",
    "CONFIRMED_POLICY_VIOLATION",
    "PROVIDER_BLOCKED",
    "VALIDATION_BUDGET_INSUFFICIENT",
})


@dataclass(frozen=True, slots=True)
class SsrfReviewFact:
    """Bounded SSRF assessment facts safe to offer to the report narrator."""

    url_surface_count: int
    manual_analysis_completed: bool
    execution_approval_registered: bool
    destination_policy_registered: bool
    destination_policy_source: str
    observation_recorded: bool
    verification_performed: bool
    final_status: str
    reason_code: str
    callback_status: str = "NOT_CONFIGURED"
    canary_status: str = "NOT_CONFIGURED"
    owned_receiver_status: str = "NOT_CONFIGURED"
    destination_hint_use_approved: bool = False
    approved_surface_id: str = ""

    def __post_init__(self) -> None:
        _count(self.url_surface_count)
        for value in (
            self.manual_analysis_completed,
            self.execution_approval_registered,
            self.destination_policy_registered,
            self.observation_recorded,
            self.verification_performed,
            self.destination_hint_use_approved,
        ):
            if type(value) is not bool:
                raise ValueError("SSRF review flags must be booleans")
        allowed_sources = {"", *(item.value for item in SsrfPolicySource)}
        if self.destination_policy_source not in allowed_sources:
            raise ValueError("SSRF review policy source must be a trusted closed value")
        if self.destination_policy_registered != bool(self.destination_policy_source):
            raise ValueError("SSRF review policy registration and source must agree")
        if self.final_status not in SSRF_REVIEW_STATUSES:
            raise ValueError("unsupported SSRF review status")
        if self.callback_status not in SSRF_CALLBACK_STATUSES:
            raise ValueError("unsupported SSRF callback strategy status")
        if self.canary_status not in SSRF_CANARY_STATUSES:
            raise ValueError("unsupported SSRF canary strategy status")
        if self.owned_receiver_status not in SSRF_OWNED_RECEIVER_STATUSES:
            raise ValueError("unsupported SSRF owned-receiver strategy status")
        if self.approved_surface_id:
            _identifier(self.approved_surface_id)
            if not self.execution_approval_registered:
                raise ValueError("SSRF approved Surface requires execution approval")
        if re.fullmatch(r"ssrf_[a-z0-9_]{1,95}", self.reason_code) is None:
            raise ValueError("SSRF review requires a stable reason code")
        if self.final_status == "CONFIRMED_POLICY_VIOLATION" and not (
            self.observation_recorded
            and self.verification_performed
            and self.execution_approval_registered
            and bool(self.approved_surface_id)
            and self.destination_policy_registered
            and (
                self.canary_status == "CONFIRMED_POLICY_VIOLATION"
                or self.owned_receiver_status == "CONFIRMED_POLICY_VIOLATION"
            )
        ):
            raise ValueError(
                "confirmed SSRF review requires observation, verification and policy"
            )
        if self.final_status == "ALLOWED_DESTINATION" and not (
            self.observation_recorded
            and self.verification_performed
            and self.execution_approval_registered
            and bool(self.approved_surface_id)
            and self.destination_policy_registered
            and (
                self.canary_status == "ALLOWED_DESTINATION"
                or self.owned_receiver_status == "ALLOWED_DESTINATION"
            )
        ):
            raise ValueError(
                "allowed SSRF destination requires observation, verification and policy"
            )


@dataclass(frozen=True, slots=True)
class RunReportFacts:
    run_id: str
    format_version: Literal["v2"]
    candidate_counts: tuple[tuple[CandidateStatus, int], ...]
    findings: tuple[FindingReportFact, ...]
    ssrf_callback_surfaces: tuple[SsrfCallbackSurfaceFact, ...] = ()
    ssrf_destination_hint_count: int = 0
    ssrf_review: SsrfReviewFact | None = None
    request_budget_total: int | None = None
    request_budget_used: int | None = None
    # 실제 발견 범위의 수치만 추가한다. URL/파라미터 원문은 계약에 넣지 않는다.
    surface_count: int | None = None
    parameter_count: int | None = None
    # Run 전체의 LLM 사용량. prompt/응답 원문이 아니라 세 숫자만 담는다. 셋은 한
    # 계측기에서 같이 나오므로 전부 있거나 전부 없어야 한다.
    llm_calls: int | None = None
    llm_input_tokens: int | None = None
    llm_output_tokens: int | None = None

    def __post_init__(self) -> None:
        _identifier(self.run_id)
        if self.format_version != "v2":
            raise ValueError("report facts require format v2")
        if (
            not isinstance(self.candidate_counts, tuple)
            or not isinstance(self.findings, tuple)
            or not isinstance(self.ssrf_callback_surfaces, tuple)
        ):
            raise ValueError("report collections must be immutable tuples")
        counts = {}
        for entry in self.candidate_counts:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise ValueError("invalid candidate count entry")
            status, count = entry
            if not isinstance(status, CandidateStatus) or status in counts:
                raise ValueError("candidate status must be unique and structured")
            _count(count)
            counts[status] = count
        if set(counts) != set(CandidateStatus):
            raise ValueError("all candidate statuses must be counted")
        if any(not isinstance(item, FindingReportFact) for item in self.findings):
            raise ValueError("findings must be report facts")
        if any(
            not isinstance(item, SsrfCallbackSurfaceFact)
            for item in self.ssrf_callback_surfaces
        ):
            raise ValueError("SSRF callback surfaces must be report facts")
        if self.ssrf_review is not None and not isinstance(self.ssrf_review, SsrfReviewFact):
            raise ValueError("SSRF review must use the structured report fact")
        for field in ("finding_id", "fact_id"):
            ids = [getattr(item, field) for item in self.findings]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate report finding or fact identifier")
        callback_ids = [item.fact_id for item in self.ssrf_callback_surfaces]
        if len(callback_ids) != len(set(callback_ids)):
            raise ValueError("duplicate SSRF callback surface fact identifier")
        usage = (self.llm_calls, self.llm_input_tokens, self.llm_output_tokens)
        for value in (self.request_budget_total, self.request_budget_used,
                      self.surface_count, self.parameter_count,
                      self.ssrf_destination_hint_count, *usage):
            if value is not None:
                _count(value)
        if (self.request_budget_total is not None and self.request_budget_used is not None
                and self.request_budget_used > self.request_budget_total):
            raise ValueError("used request budget exceeds total")
        if len({value is None for value in usage}) != 1:
            # 일부만 센 사용량은 "적게 썼다"로 읽힌다. 모르면 셋 다 모르는 것이다.
            raise ValueError("llm usage facts must be measured together or not at all")
        if self.llm_calls == 0 and any(usage[1:]):
            raise ValueError("llm usage cannot report tokens without a call")
        object.__setattr__(self, "candidate_counts", tuple((s, counts[s]) for s in CandidateStatus))
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=lambda f: f.finding_id)))
        object.__setattr__(
            self, "ssrf_callback_surfaces",
            tuple(sorted(self.ssrf_callback_surfaces, key=lambda item: item.fact_id)),
        )

    @property
    def fact_ids(self) -> tuple[str, ...]:
        return (
            "run:scope", "run:request-budget", "run:llm-usage",
            "run:ssrf-destination-hints",
            *(("run:ssrf-review",) if self.ssrf_review is not None else ()),
            *(f"run:candidates:{status.value}" for status in CandidateStatus),
            *(item.fact_id for item in self.ssrf_callback_surfaces),
            *(finding.fact_id for finding in self.findings),
        )


@dataclass(frozen=True, slots=True)
class NarratorFingerprintConfig:
    """향후 Narrator의 재사용 키에 포함할 설정만 명시한다. 인증/endpoint는 제외."""

    model: str
    prompt_version: str
    max_output_tokens: int = 1200
    temperature: float = 0.0
    run_summary_max_chars: int = 800
    finding_summary_max_chars: int = 400

    def __post_init__(self) -> None:
        for value in (self.model, self.prompt_version):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}", value):
                raise ValueError("invalid narrator configuration label")
        for value in (self.max_output_tokens, self.run_summary_max_chars,
                      self.finding_summary_max_chars):
            _count(value)
            if not value:
                raise ValueError("narrator limits must be positive")
        if type(self.temperature) not in (int, float) or not math.isfinite(self.temperature):
            raise ValueError("invalid narrator temperature")
        if not 0 <= self.temperature <= 2:
            raise ValueError("invalid narrator temperature")
        object.__setattr__(self, "temperature", float(self.temperature))


def _facts_payload(facts: RunReportFacts) -> dict[str, object]:
    return {
        "contract_version": CONTRACT_VERSION,
        "run_id": facts.run_id,
        "format_version": facts.format_version,
        "fact_ids": facts.fact_ids,
        "candidate_counts": [(status.value, count) for status, count in facts.candidate_counts],
        "ssrf_callback_surfaces": [
            asdict(item) for item in facts.ssrf_callback_surfaces
        ],
        "ssrf_destination_hint_count": facts.ssrf_destination_hint_count,
        "ssrf_review": asdict(facts.ssrf_review) if facts.ssrf_review is not None else None,
        "findings": [
            {**asdict(finding), "proof_type": finding.proof_type.value if finding.proof_type else None,
             "proof_description": finding.proof_description}
            for finding in facts.findings
        ],
        "request_budget_total": facts.request_budget_total,
        "request_budget_used": facts.request_budget_used,
        "surface_count": facts.surface_count,
        "parameter_count": facts.parameter_count,
        "llm_calls": facts.llm_calls,
        "llm_input_tokens": facts.llm_input_tokens,
        "llm_output_tokens": facts.llm_output_tokens,
    }


def _json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def serialize_report_facts(facts: RunReportFacts) -> str:
    """raw domain/Evidence 없이 구조화 JSON만 반환한다."""
    return _json(_facts_payload(facts))


def report_facts_hash(facts: RunReportFacts) -> str:
    """Narrator 설정과 무관하게 사실 보존을 검사하는 SHA-256.

    한 Run 안에서 요약을 껐을 때와 켰을 때를 비교하는 값이다. run_id와 Finding ID가
    들어 있어 서로 다른 Run 사이에서는 절대 같아지지 않는다 - 그 비교에는
    comparable_report_facts_hash를 쓴다.
    """
    return sha256(serialize_report_facts(facts).encode("utf-8")).hexdigest()


def _comparable_payload(facts: RunReportFacts) -> dict[str, object]:
    """Run마다 새로 생기는 식별자를 뺀 사실.

    run_id와 finding_id/fact_id는 Run마다 새로 만들어진다. 그대로 두면 같은 대상을
    같은 조건으로 두 번 검사해도 해시가 절대 같아지지 않아, 두 Run을 비교하는 축이
    항상 "사실이 다르다"로 읽힌다. Router 비교가 생성 ID를 제외한 정규화 manifest를
    쓰는 것과 같은 이유다.

    Finding은 ID 없이도 순서가 정해져야 하므로 내용으로 정렬한다.
    """

    findings = [
        {
            "vulnerability_type": finding.vulnerability_type,
            "surface_path_hint": finding.surface_path_hint,
            "proof_type": finding.proof_type.value if finding.proof_type else None,
            "proof_description": finding.proof_description,
            "reproduction_count": finding.reproduction_count,
        }
        for finding in facts.findings
    ]
    callback_surfaces = [
        {
            "surface_path_hint": item.surface_path_hint,
            "analysis_http_callbacks": item.analysis_http_callbacks,
            "validation_http_callbacks": item.validation_http_callbacks,
        }
        for item in facts.ssrf_callback_surfaces
    ]
    return {
        "contract_version": CONTRACT_VERSION,
        "format_version": facts.format_version,
        "candidate_counts": [(status.value, count) for status, count in facts.candidate_counts],
        "ssrf_callback_surfaces": sorted(callback_surfaces, key=_json),
        "ssrf_destination_hint_count": facts.ssrf_destination_hint_count,
        "ssrf_review": asdict(facts.ssrf_review) if facts.ssrf_review is not None else None,
        "findings": sorted(findings, key=_json),
        "request_budget_total": facts.request_budget_total,
        "request_budget_used": facts.request_budget_used,
        "surface_count": facts.surface_count,
        "parameter_count": facts.parameter_count,
        "llm_calls": facts.llm_calls,
        "llm_input_tokens": facts.llm_input_tokens,
        "llm_output_tokens": facts.llm_output_tokens,
    }


def comparable_report_facts_hash(facts: RunReportFacts) -> str:
    """생성 ID를 뺀 사실 해시. 서로 다른 두 Run의 사실이 같은지 비교한다."""
    return sha256(_json(_comparable_payload(facts)).encode("utf-8")).hexdigest()


def report_input_fingerprint(
    facts: RunReportFacts, config: NarratorFingerprintConfig | None = None,
) -> str:
    payload = {"facts": _facts_payload(facts), "narrator_config": asdict(config) if config else None}
    return sha256(_json(payload).encode("utf-8")).hexdigest()
