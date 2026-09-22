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

from hacklipse.domain import CandidateStatus, ValidationProofType


# v2: run LLM 사용량 세 값과 run:llm-usage fact를 계약에 넣었다. fact_ids 순서가
# 바뀌므로 이전 버전의 fingerprint와 섞이지 않게 버전을 올린다.
CONTRACT_VERSION = "report-facts-v2"
MAX_PATH_HINT_LENGTH = 160
PROOF_DESCRIPTIONS = MappingProxyType({
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
        return PROOF_UNAVAILABLE if self.proof_type is None else PROOF_DESCRIPTIONS[self.proof_type]


@dataclass(frozen=True, slots=True)
class RunReportFacts:
    run_id: str
    format_version: Literal["v2"]
    candidate_counts: tuple[tuple[CandidateStatus, int], ...]
    findings: tuple[FindingReportFact, ...]
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
        if not isinstance(self.candidate_counts, tuple) or not isinstance(self.findings, tuple):
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
        for field in ("finding_id", "fact_id"):
            ids = [getattr(item, field) for item in self.findings]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate report finding or fact identifier")
        usage = (self.llm_calls, self.llm_input_tokens, self.llm_output_tokens)
        for value in (self.request_budget_total, self.request_budget_used,
                      self.surface_count, self.parameter_count, *usage):
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

    @property
    def fact_ids(self) -> tuple[str, ...]:
        return (
            "run:scope", "run:request-budget", "run:llm-usage",
            *(f"run:candidates:{status.value}" for status in CandidateStatus),
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
    return {
        "contract_version": CONTRACT_VERSION,
        "format_version": facts.format_version,
        "candidate_counts": [(status.value, count) for status, count in facts.candidate_counts],
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
