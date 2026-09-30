"""Surface를 LLM으로 해석해 라우팅 제안과 전수 판정 trace를 만드는 Advisor.

역할은 구조적으로 분리한다.

    Rule    설명 가능한 Observation·Surface 규칙으로 Candidate를 만든다 (routing.py, 결정적)
    Hybrid  규칙이 비워 둔 자리에 한해 조사할 유형을 제안
    Agentic 현재 Run의 모든 Surface를 Analyzer 실행 계약으로 분류하고, 실행 가능한
            Surface/유형 조합은 빠짐없이 Analysis로 전달한다. LLM 판단은 감사용 진단
            신호일 뿐 Candidate를 제거하지 않는다.

LLM은 Candidate를 만들지 않고, 담당 Agent도 고르지 않는다. 고르는 것은 이미 존재하는
``surface_id``와 취약점 유형 두 가지뿐이며, ``agent_type`` 해석은 표면 모양(fragment 여부)을
보고 Python이 결정한다. 실제 Candidate 생성·priority 부여·저장은 여전히
``RuleBasedVulnerabilityRouter``와 Orchestrator가 수행한다.

``probing.py``의 ``validate_probe_selection()``은 참고하지 않는다. 그 함수는 Analysis Agent가
실행 대상(파라미터 값)을 확정하는 계약이라 존재하지 않는 선택을 ``AgentContractError``로
올리는 것이 맞다. 여기 선택은 실행 값이 아니라 "무엇을 검사 대상으로 볼지"에 대한 제안일
뿐이라, 잘못된 개별 항목 때문에 나머지 유효한 제안까지 버릴 이유가 없다. 그래서
``llm_recon_planner``와 같은 방식으로 구조 위반과 항목 위반을 나눠 다룬다.

    구조 위반(응답이 객체가 아님, suggestions가 배열이 아님) → 전체를 버리고 빈 제안 반환
    항목 위반(없는 surface_id, 해석 불가 유형, 중복)         → 그 항목만 버리고 계속

프롬프트 위생 — Surface 메타데이터와 구조화된 Observation 유형만 싣는다. 응답 본문,
관측된 query 값(``observed_query``), 자격증명은 어느 것도 프롬프트에 들어가지 않는다.
``observed_query``에는 token 같은 값이 실제로 담기므로 이름만 골라 쓴다.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from hacklipse.domain import Evidence, Run, Surface
from hacklipse.ports import AnalyzerCapability
from hacklipse.ports.errors import (
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmClient, LlmMessage, LlmRequest, LlmUsage

from .request_safety import has_state_changing_parameters
from .llm_parameter_names import alias_parameter_names
from .analyzer_capabilities import (
    DEFAULT_ANALYZER_CAPABILITIES,
    capability_matches,
)
from .routing import (
    CANDIDATE_EVIDENCE_TYPES,
    CANDIDATE_REASON_CODES,
    RouteSuggestion,
)

# Evidence.created_by에 쓸 고정 식별자. selection_source(llm/rule)와 별개로 "이 판단을
# 만든 컴포넌트가 무엇인가"는 항상 이 값으로 고정한다.
ROUTER_ADVISOR = "llm_router_advisor"

# 한 호출에서 LLM에게 보여 줄 Surface 상한. Hybrid에서는 전체 비용 상한이고,
# Agentic exhaustive에서는 모든 호환 Surface를 보되 이 크기로 나누는 batch 상한이다.
DEFAULT_MAX_SURFACES = 40
_AGENTIC_CACHE_LIMIT = 32

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z_-]{0,63}(?:\.[A-Za-z]{1,10})?$")

_SUGGESTION_SCHEMA = {
    "type": "object",
    "properties": {
        "suggestions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "surface_id": {"type": "string"},
                    "vulnerability_type": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["surface_id", "vulnerability_type", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["suggestions"],
    "additionalProperties": False,
}

_AGENTIC_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "surface_id": {"type": "string"},
                    "capability_id": {"type": "string"},
                    "confidence": {
                        "type": "string", "enum": ["low", "medium", "high"]
                    },
                    "priority": {
                        "type": "string", "enum": ["low", "normal", "high"]
                    },
                    "basis_observation_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "reason_code": {
                        "type": "string",
                        "enum": sorted(CANDIDATE_REASON_CODES),
                    },
                    "required_evidence_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": sorted(CANDIDATE_EVIDENCE_TYPES),
                        },
                    },
                    "analysis_strategy_id": {"type": "string"},
                },
                "required": [
                    "surface_id",
                    "capability_id",
                    "confidence",
                    "priority",
                    "basis_observation_ids",
                    "reason_code",
                    "required_evidence_types",
                    "analysis_strategy_id",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["hypotheses"],
    "additionalProperties": False,
}

_SYSTEM = (
    "You review endpoints of a single authorized security assessment that the "
    "deterministic rules could not classify, and say which vulnerability type is worth "
    "investigating on each. You never invent endpoints, parameters, or payloads: you only "
    "pair a surface_id that was offered to you with one of the vulnerability types that "
    "was offered to you. Judge from the endpoint path, the parameter names, and the "
    "structured observation types. A surface whose name and inputs suggest the server "
    "fetches, reads, renders, or looks up something on behalf of the caller is worth a "
    "suggestion; a plain navigation link is not. Return an empty list when none of the "
    "offered surfaces are worth spending analysis budget on. Do not repeat a pairing that "
    "is already listed as covered."
)

_AGENTIC_SYSTEM = (
    "You rank executable analyzer hypotheses for one authorized security assessment "
    "from only the structured surfaces and observations offered to you. Do not assume a known "
    "vulnerable endpoint, target-specific payload, expected finding, or ground truth. "
    "Return exactly one hypothesis for every offered surface_id and capability_id pair; "
    "never omit a pair. For each hypothesis, copy the offered identifiers and choose "
    "confidence and execution priority, "
    "zero or more short observation ref values (e.g. o1), not their kind labels, "
    "belonging to that surface in basis_observation_ids, "
    "one hypothesis reason code, generic evidence types needed for Analysis, and one "
    "analysis_strategy_id offered by that capability. Your confidence and priority rank "
    "work but never suppress an executable assignment; Analysis performs the security test. "
    "A parameterized server-side route can justify a "
    "testable, low-confidence hypothesis from its path and input names even before an HTTP "
    "response has been observed; review server and client routes independently rather than "
    "stopping after one plausible hypothesis. If a surface has observation_refs=[(none)], "
    "use basis_observation_ids=[]; never borrow a ref from another surface. "
    "Never invent or omit an endpoint, capability, parameter, observation ref, reason code, "
    "evidence type, strategy, payload, or credential. Return an empty hypotheses list only "
    "when no surface/capability pair was offered."
)


@dataclass(frozen=True, slots=True)
class AnalyzerChoice:
    """제안 가능한 취약점 유형 하나와 그것을 맡을 Agent.

    ``client_route``는 이 Agent가 SPA fragment 표면(``/#/search``)을 다룰 수 있는지다.
    fragment는 서버로 전송되지 않으므로 HTTP 기반 Analyzer가 받으면 매번 같은 루트
    문서만 받아 신호 없이 예산만 쓴다. Router의 ``SurfaceRoutingRule``과 같은 기준이다.
    """

    vulnerability_type: str
    agent_type: str
    client_route: bool = False


@dataclass(frozen=True, slots=True)
class _OfferedSurface:
    """LLM에게 보여 줄 Surface 하나. 값이 아니라 이름과 구조만 담는다."""

    surface_id: str
    method: str
    path: str
    client_route: bool
    client_route_path: str | None
    parameter_names: tuple[str, ...]
    observation_types: tuple[str, ...]
    observations: tuple[tuple[str, str, str], ...]
    covered_types: tuple[str, ...]
    allowed_types: tuple[str, ...]
    allowed_capability_ids: tuple[str, ...]
    reviewable_types: tuple[str, ...]
    execution_blocker: str | None = None


@dataclass(frozen=True, slots=True)
class RouterHypothesis:
    """Agentic LLM이 실행 가능한 capability에 부여한 분석 계획.

    실제 Analysis 전달 여부는 이 값이 아니라 Analyzer capability가 정한다. 모델이 항목을
    누락하거나 계약을 위반하면 코드가 ``unanswered``를 합성해 감사 가능성을 유지한다.
    """

    surface_id: str
    vulnerability_type: str
    agent_type: str
    status: Literal["planned", "unanswered"]
    reason_code: str
    basis_evidence_ids: tuple[str, ...] = ()
    required_evidence_types: tuple[str, ...] = ()
    capability_id: str = ""
    confidence: Literal["low", "medium", "high"] = "low"
    priority: Literal["low", "normal", "high"] = "normal"
    analysis_strategy_id: str = ""


@dataclass(frozen=True, slots=True)
class SurfaceCapability:
    """Surface가 현재 Analyzer 계약으로 실행 가능한지 나타내는 coverage 항목."""

    surface_id: str
    status: Literal["routable", "blocked", "unsupported", "excluded"]
    reason_code: str
    routable_types: tuple[str, ...] = ()
    missing_requirements: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RouterAdvisorTrace:
    """감사 로그가 원문 prompt/응답 없이 읽는 마지막 호출의 계측 결과."""

    suggestions: tuple[RouteSuggestion, ...] = ()
    hypotheses: tuple[RouterHypothesis, ...] = ()
    capabilities: tuple[SurfaceCapability, ...] = ()
    rejected_items: tuple[tuple[int, str], ...] = ()
    offered_surface_ids: tuple[str, ...] = ()
    offered_pair_count: int = 0
    excluded_surfaces: tuple[tuple[str, str], ...] = ()
    source: Literal["llm", "cache", "deterministic_fallback", "skipped"] = "skipped"
    status: str = "not_called"
    llm_calls: int = 0
    usage: LlmUsage = field(default_factory=LlmUsage)
    usage_available: bool = False
    model: str = ""
    elapsed_ms: float | None = None


class LlmRouterAdvisor:
    """LLM 판단을 검증하고 Analyzer capability를 라우팅 결과로 돌려주는 구현.

    Agentic 모드의 confidence/priority는 실행 순서 메타데이터이고, 실행 가능한 모든
    조합은 ``RouteSuggestion``이 된다. Router 단계에서는 대상 HTTP 요청이나 Analysis
    Agent를 호출하지 않는다.
    """

    def __init__(
        self,
        *,
        llm_client: LlmClient,
        analyzers: Sequence[AnalyzerChoice] = (),
        capabilities: Sequence[AnalyzerCapability] = (),
        max_surfaces: int = DEFAULT_MAX_SURFACES,
        timeout_seconds: float = 60.0,
        hypothesis_mode: bool = False,
    ) -> None:
        if max_surfaces <= 0:
            raise ValueError("router advisor batch size must be positive")
        self._llm = llm_client
        self._analyzers = tuple(analyzers)
        if capabilities:
            self._capabilities = tuple(capabilities)
        else:
            requested = {
                (choice.vulnerability_type, choice.agent_type, choice.client_route)
                for choice in analyzers
            }
            self._capabilities = tuple(
                capability
                for capability in DEFAULT_ANALYZER_CAPABILITIES
                if (
                    capability.vulnerability_type,
                    capability.agent_type,
                    capability.surface_kind == "client",
                )
                in requested
            )
        self._capabilities_by_id = {
            capability.capability_id: capability
            for capability in self._capabilities
        }
        if not self._analyzers:
            self._analyzers = tuple(
                AnalyzerChoice(
                    capability.vulnerability_type,
                    capability.agent_type,
                    capability.surface_kind == "client",
                )
                for capability in self._capabilities
            )
        self._max_surfaces = max_surfaces
        self._timeout_seconds = timeout_seconds
        self._hypothesis_mode = hypothesis_mode
        # 같은 Run의 추가 Recon이 비실행 Surface만 관찰했다면 실행 가능한 조합의
        # LLM 입력은 그대로다. Run별 마지막 성공 결과 하나만 보관해 중복 호출을 막는다.
        self._agentic_cache: dict[
            str, tuple[tuple[_OfferedSurface, ...], RouterAdvisorTrace]
        ] = {}
        self.last_trace = RouterAdvisorTrace()

    def advise(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
        routed: frozenset[tuple[str, str]],
    ) -> Sequence[RouteSuggestion]:
        offered, excluded_surfaces, capabilities = self._offer(
            run, surfaces, evidence, routed
        )
        offered_pair_count = sum(
            len(item.allowed_capability_ids) for item in offered
        )
        if not offered or not self._capabilities:
            # 보여 줄 표면이 없거나 제안 가능한 유형이 없다는 사실은 결정적이다.
            # LLM을 부를 이유가 없다.
            self.last_trace = RouterAdvisorTrace(
                offered_surface_ids=tuple(item.surface_id for item in offered),
                offered_pair_count=offered_pair_count,
                excluded_surfaces=excluded_surfaces,
                capabilities=capabilities,
                status="no_candidates" if not offered else "no_routes",
            )
            return ()

        if self._hypothesis_mode:
            cached = self._agentic_cache.get(run.run_id)
            if cached is not None and cached[0] == offered:
                started = time.monotonic()
                previous = cached[1]
                self.last_trace = RouterAdvisorTrace(
                    suggestions=previous.suggestions,
                    hypotheses=previous.hypotheses,
                    rejected_items=previous.rejected_items,
                    offered_surface_ids=tuple(
                        item.surface_id for item in offered
                    ),
                    offered_pair_count=offered_pair_count,
                    excluded_surfaces=excluded_surfaces,
                    capabilities=capabilities,
                    source="cache",
                    status="cache_hit",
                    llm_calls=0,
                    model=previous.model,
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )
                return self.last_trace.suggestions
            return self._advise_exhaustive(
                run.run_id, offered, routed, excluded_surfaces, capabilities
            )

        started = time.monotonic()
        try:
            response = self._llm.complete(
                LlmRequest(
                    messages=(
                        LlmMessage(role="user", content=self._prompt(offered)),
                    ),
                    system=_AGENTIC_SYSTEM if self._hypothesis_mode else _SYSTEM,
                    response_schema=(
                        _AGENTIC_HYPOTHESIS_SCHEMA
                        if self._hypothesis_mode
                        else _SUGGESTION_SCHEMA
                    ),
                    timeout_seconds=self._timeout_seconds,
                )
            )
        except (LlmTimeout, LlmTransportError, LlmResponseFormatError, LlmRefused) as error:
            # 호출 실패는 규칙 결과를 그대로 두는 것으로 흡수한다. Router가 예외를 다시
            # 잡아 주지만, 여기서 먼저 처리해야 "왜 빈 제안인가"가 이 계층에 남는다.
            #
            # LlmCredentialsMissing은 일부러 잡지 않는다 - 키 없이 Advisor를 배선한 것은
            # 실행 중 장애가 아니라 구성 오류이며, 조용히 규칙만 돌면 "LLM을 켰는데
            # 규칙 결과가 나왔다"는 오독을 만든다. 다만 Router가 모든 예외를 흡수하므로
            # 이 구분이 실제로 살아나려면 bootstrap이 배선 시점에 키를 확인해야 한다.
            status = {
                LlmTimeout: "timeout",
                LlmResponseFormatError: "invalid_response",
                LlmRefused: "refused",
                LlmTransportError: "transport_error",
            }.get(type(error), "llm_error")
            self.last_trace = RouterAdvisorTrace(
                offered_surface_ids=tuple(item.surface_id for item in offered),
                offered_pair_count=offered_pair_count,
                excluded_surfaces=excluded_surfaces,
                capabilities=capabilities,
                source="deterministic_fallback",
                status=status,
                llm_calls=1,
                elapsed_ms=(time.monotonic() - started) * 1000,
            )
            return ()

        suggestions, rejected, status = self._parse(response.payload, offered, routed)
        self.last_trace = RouterAdvisorTrace(
            suggestions=suggestions,
            rejected_items=rejected,
            offered_surface_ids=tuple(item.surface_id for item in offered),
            offered_pair_count=offered_pair_count,
            excluded_surfaces=excluded_surfaces,
            capabilities=capabilities,
            source=(
                "deterministic_fallback"
                if status in {"invalid_response", "all_rejected"}
                else "llm"
            ),
            status=status,
            llm_calls=1,
            usage=response.usage,
            usage_available=True,
            model=response.model,
            elapsed_ms=(time.monotonic() - started) * 1000,
        )
        return suggestions

    def _advise_exhaustive(
        self,
        run_id: str,
        offered: tuple[_OfferedSurface, ...],
        routed: frozenset[tuple[str, str]],
        excluded_surfaces: tuple[tuple[str, str], ...],
        capabilities: tuple[SurfaceCapability, ...],
    ) -> tuple[RouteSuggestion, ...]:
        """실행 가능한 모든 조합을 보존하고 LLM 판단은 감사 근거로만 쓴다."""

        started = time.monotonic()
        capability_suggestions = self._capability_suggestions(offered)
        suggestion_overrides: dict[tuple[str, str], RouteSuggestion] = {}
        batches = tuple(
            offered[index : index + self._max_surfaces]
            for index in range(0, len(offered), self._max_surfaces)
        )
        hypotheses: list[RouterHypothesis] = []
        rejected_items: list[tuple[int, str]] = []
        statuses: list[str] = []
        usage = LlmUsage()
        model = ""
        calls = 0
        raw_index_offset = 0

        for batch_index, batch in enumerate(batches):
            calls += 1
            try:
                response = self._llm.complete(
                    LlmRequest(
                        messages=(LlmMessage(role="user", content=self._prompt(batch)),),
                        system=_AGENTIC_SYSTEM,
                        response_schema=_AGENTIC_HYPOTHESIS_SCHEMA,
                        max_output_tokens=8192,
                        timeout_seconds=self._timeout_seconds,
                    )
                )
            except (LlmTimeout, LlmTransportError, LlmResponseFormatError, LlmRefused) as error:
                status = {
                    LlmTimeout: "timeout",
                    LlmResponseFormatError: "invalid_response",
                    LlmRefused: "refused",
                    LlmTransportError: "transport_error",
                }.get(type(error), "llm_error")
                for remaining in batches[batch_index:]:
                    hypotheses.extend(
                        self._unanswered_hypotheses(remaining, status)
                    )
                final_suggestions = self._merge_capability_suggestions(
                    capability_suggestions, suggestion_overrides
                )
                self.last_trace = RouterAdvisorTrace(
                    suggestions=final_suggestions,
                    hypotheses=tuple(hypotheses),
                    rejected_items=tuple(rejected_items),
                    offered_surface_ids=tuple(item.surface_id for item in offered),
                    offered_pair_count=sum(
                        len(item.allowed_capability_ids) for item in offered
                    ),
                    excluded_surfaces=excluded_surfaces,
                    capabilities=capabilities,
                    source="deterministic_fallback",
                    status=status,
                    llm_calls=calls,
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )
                return final_suggestions

            (
                batch_hypotheses,
                _batch_surface_assessments,
                _batch_suggestions,
                rejected,
                status,
            ) = (
                self._parse_hypotheses(response.payload, batch)
            )
            hypotheses.extend(batch_hypotheses)
            # LLM의 confidence/priority는 취약점 진위 판정이 아니다. 실행 가능한 조합은
            # 하나도 자르지 않고 Analysis가 자체 control/probe로 판정하게 한다.
            suggestion_overrides.update(
                {
                    (item.surface_id, item.capability_id): item
                    for item in _batch_suggestions
                }
            )
            rejected_items.extend(
                (raw_index_offset + index, reason) for index, reason in rejected
            )
            raw = response.payload.get("hypotheses")
            raw_index_offset += max(
                len(raw) if isinstance(raw, list) else 0,
                sum(len(item.allowed_capability_ids) for item in batch),
            )
            statuses.append(status)
            usage = _add_usage(usage, response.usage)
            model = model or response.model

            if status in {"invalid_response", "all_rejected"}:
                for remaining in batches[batch_index + 1 :]:
                    hypotheses.extend(
                        self._unanswered_hypotheses(remaining, status)
                    )
                final_suggestions = self._merge_capability_suggestions(
                    capability_suggestions, suggestion_overrides
                )
                self.last_trace = RouterAdvisorTrace(
                    suggestions=final_suggestions,
                    hypotheses=tuple(hypotheses),
                    rejected_items=tuple(rejected_items),
                    offered_surface_ids=tuple(item.surface_id for item in offered),
                    offered_pair_count=sum(
                        len(item.allowed_capability_ids) for item in offered
                    ),
                    excluded_surfaces=excluded_surfaces,
                    capabilities=capabilities,
                    source="deterministic_fallback",
                    status=status,
                    llm_calls=calls,
                    usage=usage,
                    usage_available=True,
                    model=model,
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )
                return final_suggestions

        overall_status = "partial" if "partial" in statuses else "ok"
        final_suggestions = self._merge_capability_suggestions(
            capability_suggestions, suggestion_overrides
        )
        self.last_trace = RouterAdvisorTrace(
            suggestions=final_suggestions,
            hypotheses=tuple(hypotheses),
            rejected_items=tuple(rejected_items),
            offered_surface_ids=tuple(item.surface_id for item in offered),
            offered_pair_count=sum(
                len(item.allowed_capability_ids) for item in offered
            ),
            excluded_surfaces=excluded_surfaces,
            capabilities=capabilities,
            source="llm",
            status=overall_status,
            llm_calls=calls,
            usage=usage,
            usage_available=True,
            model=model,
            elapsed_ms=(time.monotonic() - started) * 1000,
        )
        if overall_status == "ok":
            if (
                run_id not in self._agentic_cache
                and len(self._agentic_cache) >= _AGENTIC_CACHE_LIMIT
            ):
                self._agentic_cache.pop(next(iter(self._agentic_cache)))
            self._agentic_cache[run_id] = (offered, self.last_trace)
        return final_suggestions

    def _capability_suggestions(
        self, offered: tuple[_OfferedSurface, ...]
    ) -> tuple[RouteSuggestion, ...]:
        """Analyzer 실행 계약을 만족한 모든 조합을 Analysis 후보로 만든다."""

        values: list[RouteSuggestion] = []
        for surface in offered:
            for capability_id in surface.allowed_capability_ids:
                capability = self._capabilities_by_id.get(capability_id)
                if capability is None:
                    continue
                values.append(RouteSuggestion(
                    surface_id=surface.surface_id,
                    vulnerability_type=capability.vulnerability_type,
                    agent_type=capability.agent_type,
                    reason="analyzer_contract_satisfied",
                    reason_code="analyzer_contract_satisfied",
                    capability_id=capability.capability_id,
                    confidence="low",
                    priority_label="normal",
                    analysis_strategy_id=capability.strategy_ids[0],
                ))
        return tuple(values)

    @staticmethod
    def _merge_capability_suggestions(
        capability_suggestions: tuple[RouteSuggestion, ...],
        overrides: dict[tuple[str, str], RouteSuggestion],
    ) -> tuple[RouteSuggestion, ...]:
        """LLM route 근거는 보존하되 defer/reject가 capability를 제거하지 못하게 한다."""

        return tuple(
            overrides.get(
                (item.surface_id, item.capability_id), item
            )
            for item in capability_suggestions
        )

    # ------------------------------------------------------------------
    # 제안 대상 선정
    # ------------------------------------------------------------------

    def _offer(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
        routed: frozenset[tuple[str, str]],
    ) -> tuple[
        tuple[_OfferedSurface, ...],
        tuple[tuple[str, str], ...],
        tuple[SurfaceCapability, ...],
    ]:
        """실행 가능한 조합만 LLM에 싣고 Agentic coverage는 모든 Surface에 남긴다."""

        observations = self._observations_by_surface(run, evidence)
        observation_records = self._observation_records_by_surface(run, evidence)
        offered: list[_OfferedSurface] = []
        excluded: list[tuple[str, str]] = []
        capabilities: list[SurfaceCapability] = []
        for surface in surfaces:
            if surface.run_id != run.run_id:
                excluded.append((surface.surface_id, "foreign_run"))
                if self._hypothesis_mode:
                    capabilities.append(SurfaceCapability(
                        surface_id=surface.surface_id,
                        status="excluded",
                        reason_code="foreign_run",
                    ))
                continue
            parameter_names = alias_parameter_names(surface.parameters).prompt_names
            parsed = urlsplit(surface.url)
            client_route = bool(parsed.fragment)
            state_changing = has_state_changing_parameters(surface.parameters)
            reviewable_types = tuple(sorted({
                capability.vulnerability_type
                for capability in self._capabilities
                if (capability.surface_kind == "client") is client_route
            }))
            # 후속 Analyzer의 메서드·파라미터·POST 안전 계약을 실제로 통과할 수 있는
            # 유형만 LLM에 제시한다. 구조적으로 실행 불가능한 조합은 LLM 판단 대상이
            # 아니며 capability ledger에 blocked/unsupported 사유로 남긴다.
            assignable_capabilities = () if state_changing else tuple(
                capability
                for capability in self._capabilities
                if capability_matches(capability, surface, evidence)
            )
            assignable = {
                capability.vulnerability_type
                for capability in assignable_capabilities
            }
            covered = {
                vulnerability_type
                for surface_id, vulnerability_type in routed
                if surface_id == surface.surface_id
            }
            allowed_types = tuple(sorted(assignable - covered))
            allowed_capability_ids = tuple(
                capability.capability_id
                for capability in assignable_capabilities
                if capability.vulnerability_type not in covered
            )
            execution_blocker = None
            if not allowed_capability_ids:
                execution_blocker = (
                    "state_changing_surface"
                    if state_changing
                    else "already_covered"
                    if assignable
                    else "no_compatible_route"
                )
                excluded.append((surface.surface_id, execution_blocker))
                if self._hypothesis_mode:
                    has_http_observation = any(
                        kind.startswith("http_response_")
                        for _, _, kind in observation_records.get(
                            surface.surface_id, ()
                        )
                    )
                    if state_changing:
                        capabilities.append(SurfaceCapability(
                            surface_id=surface.surface_id,
                            status="unsupported",
                            reason_code="approval_required",
                            missing_requirements=("state_change_approval",),
                        ))
                    elif assignable:
                        capabilities.append(SurfaceCapability(
                            surface_id=surface.surface_id,
                            status="routable",
                            reason_code="already_covered",
                            routable_types=tuple(sorted(assignable)),
                        ))
                    elif (
                        surface.method.upper() == "GET"
                        and not client_route
                        and not has_http_observation
                    ):
                        capabilities.append(SurfaceCapability(
                            surface_id=surface.surface_id,
                            status="blocked",
                            reason_code="missing_http_observation",
                            missing_requirements=(
                                "http_observation",
                                "supported_input_coordinate",
                            ),
                        ))
                    else:
                        capabilities.append(SurfaceCapability(
                            surface_id=surface.surface_id,
                            status="unsupported",
                            reason_code="no_supported_input_coordinate",
                        ))
                    continue
                # Hybrid는 기존 호출량과 동작을 유지한다.
                continue
            if self._hypothesis_mode:
                capabilities.append(SurfaceCapability(
                    surface_id=surface.surface_id,
                    status="routable",
                    reason_code="analyzer_contract_satisfied",
                    routable_types=allowed_types,
                ))
            offered.append(
                _OfferedSurface(
                    surface_id=surface.surface_id,
                    method=surface.method.upper(),
                    path=_path_hint(parsed.path or "/"),
                    client_route=client_route,
                    client_route_path=(
                        _path_hint(parsed.fragment.split("?", 1)[0])
                        if client_route else None
                    ),
                    parameter_names=parameter_names,
                    observation_types=observations.get(surface.surface_id, ()),
                    observations=observation_records.get(surface.surface_id, ()),
                    covered_types=tuple(sorted(covered)),
                    allowed_types=allowed_types,
                    allowed_capability_ids=allowed_capability_ids,
                    reviewable_types=reviewable_types,
                    execution_blocker=execution_blocker,
                )
            )

        # 규칙이 아무것도 만들지 못한 표면이 이 기능의 본래 대상이다. 조용히 검사에서
        # 빠지는 쪽을 먼저 보여 주고, 남는 자리에 일부만 채워진 표면을 싣는다.
        offered.sort(
            key=lambda item: (
                bool(item.covered_types),
                item.client_route,
                item.path,
                item.method,
                item.parameter_names,
                item.observation_types,
                item.allowed_types,
                item.allowed_capability_ids,
            )
        )
        # Hybrid에서는 기존 비용 상한을 유지한다. Agentic exhaustive에서는 같은 값을
        # 탈락 상한이 아니라 batch 크기로 사용하므로 모든 호환 Surface를 반환한다.
        selected = offered if self._hypothesis_mode else offered[: self._max_surfaces]
        excluded.extend(
            (item.surface_id, "prompt_limit")
            for item in offered[len(selected) :]
        )
        return tuple(selected), tuple(excluded), tuple(capabilities)

    @staticmethod
    def _observations_by_surface(
        run: Run, evidence: Sequence[Evidence]
    ) -> dict[str, tuple[str, ...]]:
        """Surface별 관측 유형 목록. 관측 '값'이 아니라 유형 이름만 모은다."""

        collected: dict[str, list[str]] = {}
        for item in evidence:
            if item.run_id != run.run_id or item.surface_id is None:
                continue
            if item.evidence_type != "observation":
                continue
            observation_type = item.observation.get("type")
            if (
                not isinstance(observation_type, str)
                or _NAME.fullmatch(observation_type) is None
            ):
                continue
            seen = collected.setdefault(item.surface_id, [])
            if observation_type not in seen:
                seen.append(observation_type)
        return {key: tuple(value) for key, value in collected.items()}

    @staticmethod
    def _observation_records_by_surface(
        run: Run, evidence: Sequence[Evidence]
    ) -> dict[str, tuple[tuple[str, str, str], ...]]:
        """LLM이 선택할 수 있는 Surface별 짧은 참조, Evidence ID와 안전한 유형.

        HTTP 본문·헤더·관측값은 전달하지 않는다. 응답은 status와 content-type만
        정규화한 label로 바꿔 API/HTML/인증 경계 정도만 판단할 수 있게 한다.
        """

        collected: dict[str, list[tuple[str, str, str]]] = {}
        for item in evidence:
            if (
                item.run_id != run.run_id
                or item.surface_id is None
            ):
                continue
            if item.evidence_type == "http_response":
                status = item.observation.get("status")
                status_label = (
                    str(status)
                    if type(status) is int and 100 <= status <= 599
                    else "unknown"
                )
                content_type = item.observation.get("content_type")
                media_type = (
                    content_type.split(";", 1)[0].strip().casefold()
                    if isinstance(content_type, str)
                    else "unknown"
                )
                media_label = re.sub(r"[^a-z0-9]+", "_", media_type).strip("_")
                observation_type = (
                    f"http_response_{status_label}_{media_label or 'unknown'}"
                )
            elif item.evidence_type == "observation":
                observation_type = item.observation.get("type")
                if (
                    not isinstance(observation_type, str)
                    or _NAME.fullmatch(observation_type) is None
                ):
                    continue
            else:
                continue
            records = collected.setdefault(item.surface_id, [])
            records.append((f"o{len(records) + 1}", item.evidence_id, observation_type))
        return {key: tuple(value) for key, value in collected.items()}

    # ------------------------------------------------------------------
    # 프롬프트
    # ------------------------------------------------------------------

    def _prompt(self, offered: tuple[_OfferedSurface, ...]) -> str:
        types = sorted({choice.vulnerability_type for choice in self._analyzers})
        lines = [
            "Vulnerability types you may suggest: " + ", ".join(types),
            "",
            "Surfaces:",
        ]
        for item in offered:
            parameters = ", ".join(item.parameter_names) or "(none)"
            observations = ", ".join(item.observation_types) or "(none)"
            covered = ", ".join(item.covered_types) or "(none)"
            allowed = ", ".join(item.allowed_types) or "(none)"
            capability_plans = ", ".join(
                (
                    f'{{"capability_id":"{capability_id}",'
                    f'"vulnerability_type":"{capability.vulnerability_type}",'
                    f'"agent_type":"{capability.agent_type}",'
                    f'"evidence_types":{list(capability.supported_evidence_types)},'
                    f'"strategy_ids":{list(capability.strategy_ids)}}}'
                )
                for capability_id in item.allowed_capability_ids
                if (capability := self._capabilities_by_id.get(capability_id))
                is not None
            ) or "(none)"
            reviewable = ", ".join(item.reviewable_types) or "(none)"
            blocker = item.execution_blocker or "(none)"
            location = "client_route" if item.client_route else "server_route"
            route = (
                f" client_route_path={item.client_route_path}"
                if item.client_route_path else ""
            )
            observation_records = ", ".join(
                f'{{"ref":"{ref}","kind":"{kind}"}}'
                for ref, _, kind in item.observations
            ) or "(none)"
            lines.append(
                f"- surface_id={item.surface_id} method={item.method} "
                f"path={item.path} kind={location}{route} parameters=[{parameters}] "
                f"observations=[{observations}] "
                + (
                    f"observation_refs=[{observation_records}] "
                    if self._hypothesis_mode
                    else ""
                )
                + f"already_covered=[{covered}] "
                f"allowed_types=[{allowed}] reviewable_types=[{reviewable}] "
                + (
                    f"allowed_capabilities=[{capability_plans}] "
                    if self._hypothesis_mode
                    else ""
                )
                + f"execution_blocker={blocker}"
            )
        lines.append("")
        if self._hypothesis_mode:
            lines.extend(
                [
                    "Hypothesis reason codes: "
                    + ", ".join(sorted(CANDIDATE_REASON_CODES)),
                    "Evidence types: "
                    + ", ".join(sorted(CANDIDATE_EVIDENCE_TYPES)),
                    "Return one hypothesis for every allowed_capabilities entry. "
                    "Confidence and priority rank Analysis work; they never remove it.",
                ]
            )
        else:
            lines.append(
                "Pair each surface_id worth investigating with one vulnerability type "
                "from the list above."
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 응답 검증
    # ------------------------------------------------------------------

    def _parse(
        self,
        payload: object,
        offered: tuple[_OfferedSurface, ...],
        routed: frozenset[tuple[str, str]],
    ) -> tuple[
        tuple[RouteSuggestion, ...], tuple[tuple[int, str], ...], str
    ]:
        """구조 위반은 전체를 버리고, 항목 위반은 해당 항목만 버린다."""

        if not isinstance(payload, dict):
            return (), (), "invalid_response"
        raw = payload.get("suggestions")
        if not isinstance(raw, list):
            return (), (), "invalid_response"

        by_id = {item.surface_id: item for item in offered}
        accepted: list[RouteSuggestion] = []
        rejected: list[tuple[int, str]] = []
        taken: set[tuple[str, str]] = set()
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                rejected.append((index, "invalid_item"))
                continue
            surface_id = entry.get("surface_id")
            vulnerability_type = entry.get("vulnerability_type")
            if not isinstance(surface_id, str) or not isinstance(vulnerability_type, str):
                rejected.append((index, "invalid_item"))
                continue
            # 보여 주지 않은 표면은 제안 대상이 아니다. 다른 Run의 Surface도 여기서 걸린다.
            surface = by_id.get(surface_id)
            if surface is None:
                rejected.append((index, "unknown_surface"))
                continue
            key = (surface_id, vulnerability_type)
            # 규칙이 이미 정한 자리와 같은 응답 안의 중복은 만들지 않는다. Router도
            # 같은 검사를 하지만, 쓸모없는 제안을 여기서 걸러야 무엇이 실제로 새로
            # 제안됐는지가 이 계층의 결과로 남는다.
            if key in routed or key in taken:
                rejected.append((index, "duplicate_or_covered"))
                continue
            if vulnerability_type not in surface.allowed_types:
                rejected.append((index, "unsupported_route"))
                continue
            agent_type = self._resolve_agent(vulnerability_type, surface.client_route)
            if agent_type is None:
                rejected.append((index, "unsupported_route"))
                continue
            reason = entry.get("reason")
            basis_evidence_ids: tuple[str, ...] = ()
            reason_code = ""
            required_evidence_types: tuple[str, ...] = ()
            if self._hypothesis_mode:
                raw_basis = entry.get("basis_observation_ids")
                raw_reason_code = entry.get("reason_code")
                raw_required = entry.get("required_evidence_types")
                if (
                    not isinstance(raw_basis, list)
                    or any(not isinstance(item, str) for item in raw_basis)
                    or len(set(raw_basis)) != len(raw_basis)
                    or not isinstance(raw_reason_code, str)
                    or raw_reason_code not in CANDIDATE_REASON_CODES
                    or not isinstance(raw_required, list)
                    or any(not isinstance(item, str) for item in raw_required)
                    or len(set(raw_required)) != len(raw_required)
                    or any(
                        item not in CANDIDATE_EVIDENCE_TYPES
                        for item in raw_required
                    )
                ):
                    rejected.append((index, "invalid_hypothesis_contract"))
                    continue
                allowed_observations = {
                    ref: evidence_id for ref, evidence_id, _ in surface.observations
                }
                if any(item not in allowed_observations for item in raw_basis):
                    rejected.append((index, "unknown_observation"))
                    continue
                basis_evidence_ids = tuple(allowed_observations[item] for item in raw_basis)
                reason_code = raw_reason_code
                required_evidence_types = tuple(raw_required)
            accepted.append(
                RouteSuggestion(
                    surface_id=surface_id,
                    vulnerability_type=vulnerability_type,
                    agent_type=agent_type,
                    reason=(
                        reason_code
                        if self._hypothesis_mode
                        else reason if isinstance(reason, str) else ""
                    ),
                    basis_evidence_ids=basis_evidence_ids,
                    reason_code=reason_code,
                    required_evidence_types=required_evidence_types,
                )
            )
            taken.add(key)
        status = "all_rejected" if raw and not accepted else "partial" if rejected else "ok"
        return tuple(accepted), tuple(rejected), status

    def _parse_hypotheses(
        self,
        payload: object,
        offered: tuple[_OfferedSurface, ...],
    ) -> tuple[
        tuple[RouterHypothesis, ...],
        tuple[object, ...],
        tuple[RouteSuggestion, ...],
        tuple[tuple[int, str], ...],
        str,
    ]:
        """Capability별 우선순위 계획을 검증한다. 실행 가능 조합은 절대 제거하지 않는다."""

        expected: dict[tuple[str, str], tuple[_OfferedSurface, AnalyzerCapability]] = {}
        for surface in offered:
            for capability_id in surface.allowed_capability_ids:
                capability = self._capabilities_by_id.get(capability_id)
                if capability is not None:
                    expected[(surface.surface_id, capability_id)] = (
                        surface,
                        capability,
                    )

        if not isinstance(payload, dict) or not isinstance(
            payload.get("hypotheses"), list
        ):
            return (
                self._unanswered_hypotheses(offered, "invalid_response"),
                (),
                (),
                (),
                "invalid_response",
            )

        raw = payload["hypotheses"]
        valid: dict[tuple[str, str], RouterHypothesis] = {}
        suggestions: dict[tuple[str, str], RouteSuggestion] = {}
        rejected: list[tuple[int, str]] = []
        invalid_expected: set[tuple[str, str]] = set()
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                rejected.append((index, "invalid_item"))
                continue
            surface_id = entry.get("surface_id")
            capability_id = entry.get("capability_id")
            if not isinstance(surface_id, str) or not isinstance(capability_id, str):
                rejected.append((index, "invalid_item"))
                continue
            key = (surface_id, capability_id)
            expected_item = expected.get(key)
            if expected_item is None:
                rejected.append((index, "unsupported_capability"))
                continue
            if key in valid:
                rejected.append((index, "duplicate_capability"))
                continue
            surface, capability = expected_item
            confidence = entry.get("confidence")
            priority = entry.get("priority")
            reason_code = entry.get("reason_code")
            raw_basis = entry.get("basis_observation_ids")
            raw_required = entry.get("required_evidence_types")
            strategy_id = entry.get("analysis_strategy_id")
            if (
                confidence not in {"low", "medium", "high"}
                or priority not in {"low", "normal", "high"}
                or reason_code not in CANDIDATE_REASON_CODES
                or not isinstance(raw_basis, list)
                or any(not isinstance(value, str) for value in raw_basis)
                or len(set(raw_basis)) != len(raw_basis)
                or not isinstance(raw_required, list)
                or any(not isinstance(value, str) for value in raw_required)
                or len(set(raw_required)) != len(raw_required)
                or any(
                    value not in capability.supported_evidence_types
                    for value in raw_required
                )
                or strategy_id not in capability.strategy_ids
            ):
                rejected.append((index, "invalid_hypothesis_contract"))
                invalid_expected.add(key)
                continue
            allowed_observations = {
                ref: evidence_id for ref, evidence_id, _ in surface.observations
            }
            if any(value not in allowed_observations for value in raw_basis):
                rejected.append((index, "unknown_observation"))
                invalid_expected.add(key)
                continue
            evidence_ids = tuple(
                allowed_observations[value] for value in raw_basis
            )
            assessment = RouterHypothesis(
                surface_id=surface_id,
                vulnerability_type=capability.vulnerability_type,
                agent_type=capability.agent_type,
                status="planned",
                reason_code=reason_code,
                basis_evidence_ids=evidence_ids,
                required_evidence_types=tuple(raw_required),
                capability_id=capability_id,
                confidence=confidence,
                priority=priority,
                analysis_strategy_id=strategy_id,
            )
            valid[key] = assessment
            suggestions[key] = RouteSuggestion(
                surface_id=surface_id,
                vulnerability_type=capability.vulnerability_type,
                agent_type=capability.agent_type,
                reason=reason_code,
                basis_evidence_ids=evidence_ids,
                reason_code=reason_code,
                required_evidence_types=tuple(raw_required),
                capability_id=capability_id,
                confidence=confidence,
                priority_label=priority,
                analysis_strategy_id=strategy_id,
            )

        assessments: list[RouterHypothesis] = []
        for key, (surface, capability) in expected.items():
            assessment = valid.get(key)
            if assessment is None:
                assessment = RouterHypothesis(
                    surface_id=surface.surface_id,
                    vulnerability_type=capability.vulnerability_type,
                    agent_type=capability.agent_type,
                    status="unanswered",
                    reason_code=(
                        "invalid_hypothesis"
                        if key in invalid_expected
                        else "missing_hypothesis"
                    ),
                    capability_id=capability.capability_id,
                    confidence="low",
                    priority="normal",
                    analysis_strategy_id=capability.strategy_ids[0],
                )
            assessments.append(assessment)

        if expected and not valid:
            status = "all_rejected"
        elif rejected or len(valid) != len(expected):
            status = "partial"
        else:
            status = "ok"
        return (
            tuple(assessments),
            (),
            tuple(suggestions.values()),
            tuple(rejected),
            status,
        )

    def _unanswered_hypotheses(
        self,
        offered: tuple[_OfferedSurface, ...],
        reason_code: str,
    ) -> tuple[RouterHypothesis, ...]:
        values: list[RouterHypothesis] = []
        for surface in offered:
            for capability_id in surface.allowed_capability_ids:
                capability = self._capabilities_by_id.get(capability_id)
                if capability is None:
                    continue
                values.append(RouterHypothesis(
                    surface_id=surface.surface_id,
                    vulnerability_type=capability.vulnerability_type,
                    agent_type=capability.agent_type,
                    status="unanswered",
                    reason_code=reason_code,
                    capability_id=capability.capability_id,
                    confidence="low",
                    priority="normal",
                    analysis_strategy_id=capability.strategy_ids[0],
                ))
        return tuple(values)

    def _resolve_agent(self, vulnerability_type: str, client_route: bool) -> str | None:
        """유형과 표면 모양으로 담당 Agent를 결정한다. LLM은 이 선택에 관여하지 않는다.

        XSS처럼 담당 Analyzer가 둘인 유형이 있으므로 이름만으로는 정할 수 없다.
        서버 반사는 ``xss_analyzer``, SPA의 DOM sink는 ``browser_xss_analyzer``가 맡는
        것과 같은 기준을 여기서도 표면 모양으로 적용한다.
        """

        for choice in self._analyzers:
            if (
                choice.vulnerability_type == vulnerability_type
                and choice.client_route is client_route
            ):
                return choice.agent_type
        return None


def surface_routing_summary(
    surface: Surface, evidence: Sequence[Evidence]
) -> dict[str, object]:
    """동적 ID와 관측값을 제외한 실제 Router 입력의 안전한 구조 요약."""

    parsed = urlsplit(surface.url)
    return {
        "surface_id": surface.surface_id,
        "path": _path_hint(parsed.path or "/"),
        "client_route": bool(parsed.fragment),
        "client_route_path": (
            _path_hint(parsed.fragment.split("?", 1)[0]) if parsed.fragment else None
        ),
        "method": surface.method.upper(),
        "parameter_names": list(alias_parameter_names(surface.parameters).prompt_names),
        "requires_auth": surface.requires_auth,
        "has_path_identifier": surface.path_identifier is not None,
        "observation_types": sorted(
            {
                kind
                for item in evidence
                if item.surface_id == surface.surface_id
                and item.evidence_type == "observation"
                and isinstance((kind := item.observation.get("type")), str)
                and _NAME.fullmatch(kind)
            }
        ),
    }


def _path_hint(path: str) -> str:
    return "/".join(
        segment if not segment or _PATH_SEGMENT.fullmatch(segment) else "{value}"
        for segment in path.split("/")
    )


def _add_usage(left: LlmUsage, right: LlmUsage) -> LlmUsage:
    """여러 exhaustive batch의 공급자 사용량을 한 trace로 합친다."""

    return LlmUsage(
        input_tokens=left.input_tokens + right.input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
        cache_read_input_tokens=(
            left.cache_read_input_tokens + right.cache_read_input_tokens
        ),
        cache_creation_input_tokens=(
            left.cache_creation_input_tokens + right.cache_creation_input_tokens
        ),
    )
