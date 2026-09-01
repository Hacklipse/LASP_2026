"""Observation 유형을 전문 Analysis Agent로 연결하는 규칙 기반 Router."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class SurfaceRoutingRule:
    """구조화된 Surface만으로 탐색용 Candidate를 만드는 낮은 우선순위 규칙."""

    vulnerability_type: str
    agent_type: str
    methods: tuple[str, ...] = ("GET",)
    requires_parameters: bool = True
    parameter_hints: tuple[str, ...] = ()
    priority: float = 0.25

    def matches(self, surface: Surface) -> bool:
        if surface.method.upper() not in self.methods:
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
    RoutingRule("url_or_file_parameter", "Path Traversal", "path_traversal_analyzer", 0.6),
    RoutingRule("template_error", "SSTI", "ssti_analyzer", 0.7),
    RoutingRule("template_execution", "SSTI", "ssti_analyzer", 0.9),
)

# Observation이 아직 없어도 입력 가능한 Surface를 담당 Analyzer까지 보낸다.
# 실제 취약점 판정이 아니라 탐색 대상을 만드는 규칙이므로 기존 Evidence 규칙보다
# 낮은 priority를 사용한다.
DEFAULT_SURFACE_RULES = (
    SurfaceRoutingRule("XSS", "xss_analyzer", priority=0.30),
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


class RuleBasedVulnerabilityRouter:
    """Surface 탐색 규칙과 강한 Observation 규칙을 함께 사용하는 결정적 Router."""

    def __init__(
        self,
        rules: Sequence[RoutingRule] = DEFAULT_RULES,
        surface_rules: Sequence[SurfaceRoutingRule] = DEFAULT_SURFACE_RULES,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._rules = {rule.observation_type: rule for rule in rules}
        self._surface_rules = tuple(surface_rules)
        self._id_factory = id_factory or (lambda: str(uuid4()))

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

        # 우선순위가 높은 분석 대상을 먼저 처리하도록 정렬한다.
        return tuple(
            sorted(decisions.values(), key=lambda item: item.priority, reverse=True)
        )
