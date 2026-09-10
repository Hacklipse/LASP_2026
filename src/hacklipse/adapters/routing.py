"""Observation 유형을 전문 Analysis Agent로 연결하는 규칙 기반 Router."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.domain import Candidate, Evidence, RouteDecision, Run, Surface

from .request_safety import (
    has_state_changing_parameters,
    object_identifier_parameters,
)


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


@dataclass(frozen=True, slots=True)
class SurfaceRoutingRule:
    """구조화된 Surface만으로 탐색용 Candidate를 만드는 낮은 우선순위 규칙."""

    vulnerability_type: str
    agent_type: str
    methods: tuple[str, ...] = ("GET",)
    requires_parameters: bool = True
    parameter_hints: tuple[str, ...] = ()
    priority: float = 0.25

    # SPA 클라이언트 라우트(`/#/search`)는 HTTP 요청 대상이 아니다. fragment 는
    # 서버로 전송되지 않으므로 HTTP 기반 Analyzer 가 받으면 매번 같은 루트 문서만
    # 받아 신호 없이 예산만 쓴다. 브라우저 도구를 쓰는 규칙만 opt-in 한다.
    client_route: bool = False

    def matches(self, surface: Surface) -> bool:
        if surface.method.upper() not in self.methods:
            return False
        if bool(urlsplit(surface.url).fragment) is not self.client_route:
            return False
        # GET 폼이어도 비밀번호 변경·삭제 등은 상태를 바꿀 수 있다. 자동 Analysis
        # Candidate를 만들지 않되 Surface 자체는 Recon 결과로 보존한다.
        if has_state_changing_parameters(surface.parameters):
            return False
        if self.requires_parameters and not surface.parameters:
            return False
        if self.parameter_hints:
            offered = {name.casefold() for name in surface.parameters}
            if not offered.intersection(hint.casefold() for hint in self.parameter_hints):
                return False
        return True


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
        # 비밀번호 변경·삭제처럼 상태를 바꾸는 GET 폼은 자동 탐침 대상에서 제외한다.
        if has_state_changing_parameters(surface.parameters):
            return False
        return bool(
            object_identifier_parameters(surface.parameters)
            or surface.path_identifier is not None
        )


# 첫 버전은 설명 가능하고 재현하기 쉬운 명시적 규칙으로 라우팅한다.
DEFAULT_RULES = (
    RoutingRule("reflection", "XSS", "xss_analyzer", 0.8),
    RoutingRule("sql_error", "SQLi", "sqli_analyzer", 0.8),
    RoutingRule("object_id_auth", "Access Control", "access_control_analyzer", 0.8),
    RoutingRule(
        "url_or_file_parameter",
        "Path Traversal",
        "path_traversal_analyzer",
        0.6,
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
    SurfaceRoutingRule("XSS", "xss_analyzer", priority=0.30),
    # SPA 라우트의 DOM sink 는 브라우저로만 관측된다.
    SurfaceRoutingRule(
        "XSS", "browser_xss_analyzer", client_route=True, priority=0.40
    ),
    SurfaceRoutingRule("SQLi", "sqli_analyzer", priority=0.30),
    SurfaceRoutingRule(
        "SSTI",
        "ssti_analyzer",
        methods=("POST",),
        parameter_hints=("username",),
        priority=0.20,
    ),
    IdentifierSurfaceRoutingRule(
        "Access Control", "access_control_analyzer", priority=0.35
    ),
)


# 규칙이 만든 어떤 Candidate보다도 낮다(현재 규칙 최저값은 SSTI 탐색의 0.20).
# priority는 예산이 모자랄 때 무엇을 포기하는지에 대한 결정이므로, 설명 가능한 규칙
# 판정이 LLM 제안 때문에 잘리는 일이 없어야 한다.
ADVISOR_PRIORITY = 0.15


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
    ) -> None:
        self._rules = {rule.observation_type: rule for rule in rules}
        self._surface_rules = tuple(surface_rules)
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._advisor = advisor
        self._advisor_priority = advisor_priority
        # 제안의 유효 범위를 규칙 목록에서 그대로 끌어온다. 별도 허용 목록을 두면
        # `standard_router()`의 `--vuln` 필터와 `IMPLEMENTED_ANALYZERS` 필터를 두 번
        # 관리하게 되고, 어긋나는 순간 Dispatcher가 AgentUnavailable로 Run을 죽인다.
        self._allowed_pairs = frozenset(
            (rule.vulnerability_type, rule.agent_type)
            for rule in (*rules, *surface_rules)
        )
        # fragment 표면을 다룰 수 있는 Agent. 규칙과 같은 기준을 제안에도 적용한다.
        self._client_route_agents = frozenset(
            rule.agent_type
            for rule in surface_rules
            if getattr(rule, "client_route", False)
        )

    def route(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
    ) -> tuple[RouteDecision, ...]:
        """Surface와 Evidence를 대조해 중복 없는 Candidate를 만든다."""

        decisions: dict[tuple[str, str], RouteDecision] = {}
        for item in evidence:
            observation_type = str(item.observation.get("type", ""))
            rule = self._rules.get(observation_type)
            if rule is None or item.surface_id is None:
                continue
            if rule.methods is not None:
                surface = next(
                    (
                        candidate_surface
                        for candidate_surface in surfaces
                        if candidate_surface.surface_id == item.surface_id
                        and candidate_surface.run_id == run.run_id
                    ),
                    None,
                )
                if surface is None or surface.method.upper() not in rule.methods:
                    continue
            key = (item.surface_id, rule.vulnerability_type)
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
            )
            decisions[key] = RouteDecision(candidate=candidate, priority=rule.priority)

        for surface in surfaces:
            if surface.run_id != run.run_id:
                continue
            for rule in self._surface_rules:
                if not rule.matches(surface):
                    continue
                key = (surface.surface_id, rule.vulnerability_type)
                # 같은 취약점에 강한 Evidence 규칙이 이미 매칭됐다면 그것을 유지한다.
                if key in decisions:
                    continue
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
                )
                decisions[key] = RouteDecision(candidate=candidate, priority=rule.priority)

        # 3단계. 규칙이 비워 둔 자리만 Advisor 제안으로 채운다. 이미 들어 있는 키는
        # 건드리지 않으므로 "LLM이 Rule을 덮어쓰지 않는다"가 검사 한 줄이 아니라 병합
        # 순서 자체로 보장된다.
        if self._advisor is not None:
            suggested, _status = self._advisor_decisions(
                run, surfaces, evidence, decisions
            )
            decisions.update(suggested)
            # _status는 Advisor 호출 결과 요약이다. Evidence로 남기는 배선은 아직 하지
            # 않았다 - Router는 Agent가 아니라 Evidence Store에 쓸 통로가 없고, 어디에
            # 기록할지(RouteDecision 확장 vs Port 반환 타입 변경)가 미결정이다.

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
        try:
            suggestions = self._advisor.advise(
                run, surfaces, evidence, frozenset(decided)
            )
        except Exception as error:  # noqa: BLE001 - Advisor 실패는 Run을 멈추지 않는다
            # 여기서 예외를 올리면 LLM 장애가 곧 Run 실패가 된다. 규칙 결정은 이미
            # decided에 들어 있으므로 그대로 두고 빈 결과를 돌려준다.
            return {}, f"advisor_failed:{type(error).__name__}"

        by_id = {
            surface.surface_id: surface
            for surface in surfaces
            if surface.run_id == run.run_id
        }
        accepted: dict[tuple[str, str], RouteDecision] = {}
        rejected = 0
        for suggestion in suggestions:
            if not isinstance(suggestion, RouteSuggestion):
                rejected += 1
                continue
            # 다른 Run의 Surface거나 존재하지 않는 Surface면 버린다.
            surface = by_id.get(suggestion.surface_id)
            if surface is None:
                rejected += 1
                continue
            # 등록되지 않은 Agent로 보내면 Dispatcher가 Run 전체를 실패시킨다.
            if (suggestion.vulnerability_type, suggestion.agent_type) not in self._allowed_pairs:
                rejected += 1
                continue
            # 규칙에 적용하는 안전 기준을 제안에도 똑같이 적용한다.
            if has_state_changing_parameters(surface.parameters):
                rejected += 1
                continue
            is_client_route = bool(urlsplit(surface.url).fragment)
            if is_client_route is not (suggestion.agent_type in self._client_route_agents):
                rejected += 1
                continue
            key = (suggestion.surface_id, suggestion.vulnerability_type)
            # 규칙이 이미 정한 자리와 Advisor가 중복 제안한 자리는 모두 건너뛴다.
            if key in decided or key in accepted:
                continue
            candidate = Candidate(
                candidate_id=f"candidate-{self._id_factory()}",
                run_id=run.run_id,
                surface_id=suggestion.surface_id,
                vulnerability_type=suggestion.vulnerability_type,
                hypothesis=(
                    f"{suggestion.vulnerability_type} candidate suggested by router advisor"
                ),
                assigned_agent=suggestion.agent_type,
                # Advisor의 판단은 Claim이므로 관측 Evidence를 근거로 달지 않는다.
                evidence_ids=(),
            )
            accepted[key] = RouteDecision(
                candidate=candidate, priority=self._advisor_priority
            )
        return accepted, f"advisor_ok:accepted={len(accepted)},rejected={rejected}"
