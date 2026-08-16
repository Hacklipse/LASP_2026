"""Observation 유형을 전문 Analysis Agent로 연결하는 규칙 기반 Router."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import uuid4

from hacklipse.domain import Candidate, Evidence, RouteDecision, Run


@dataclass(frozen=True, slots=True)
class RoutingRule:
    """Observation 유형 하나에 대응하는 취약점 유형·Agent·우선순위."""

    observation_type: str
    vulnerability_type: str
    agent_type: str
    priority: float = 0.5


# 첫 버전은 설명 가능하고 재현하기 쉬운 명시적 규칙으로 라우팅한다.
DEFAULT_RULES = (
    RoutingRule("reflection", "XSS", "xss_analyzer", 0.8),
    RoutingRule("sql_error", "SQLi", "sqli_analyzer", 0.8),
    RoutingRule("object_id_auth", "Access Control", "access_control_analyzer", 0.8),
    RoutingRule("url_or_file_parameter", "Path Traversal", "path_traversal_analyzer", 0.6),
    RoutingRule("template_error", "SSTI", "ssti_analyzer", 0.7),
)


class RuleBasedVulnerabilityRouter:
    """결정적인 초기 Router이며 모호한 사례는 향후 다른 구현으로 교체할 수 있다."""

    def __init__(
        self,
        rules: Sequence[RoutingRule] = DEFAULT_RULES,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._rules = {rule.observation_type: rule for rule in rules}
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def route(self, run: Run, evidence: Sequence[Evidence]) -> tuple[RouteDecision, ...]:
        """Evidence Observation을 규칙과 대조해 중복 없는 Candidate를 만든다."""

        decisions: list[RouteDecision] = []
        routed: set[tuple[str, str]] = set()
        for item in evidence:
            observation_type = str(item.observation.get("type", ""))
            rule = self._rules.get(observation_type)
            if rule is None or item.surface_id is None:
                continue
            key = (item.surface_id, rule.vulnerability_type)
            # 동일 Surface와 취약점 유형 조합은 하나의 Candidate만 생성한다.
            if key in routed:
                continue
            routed.add(key)
            candidate = Candidate(
                candidate_id=f"candidate-{self._id_factory()}",
                run_id=run.run_id,
                surface_id=item.surface_id,
                vulnerability_type=rule.vulnerability_type,
                hypothesis=f"{rule.vulnerability_type} candidate from {observation_type}",
                assigned_agent=rule.agent_type,
                evidence_ids=(item.evidence_id,),
            )
            decisions.append(RouteDecision(candidate=candidate, priority=rule.priority))
        # 우선순위가 높은 분석 대상을 먼저 처리하도록 정렬한다.
        return tuple(sorted(decisions, key=lambda item: item.priority, reverse=True))
