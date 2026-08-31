"""Agent 호출과 취약점 라우팅에 필요한 추상 계약."""

from __future__ import annotations

from typing import Protocol, Sequence

from hacklipse.domain import AgentResult, Evidence, RouteDecision, Run, Surface, TaskEnvelope


class Agent(Protocol):
    """역할별 Worker 계약. Agent 간 통신은 Task/Result 데이터로만 수행한다."""

    def handle(self, task: TaskEnvelope) -> AgentResult: ...


class TaskDispatcher(Protocol):
    """Application이 Agent 또는 Worker를 호출할 때 사용하는 유일한 경계."""

    def dispatch(self, task: TaskEnvelope) -> AgentResult: ...


class VulnerabilityRouter(Protocol):
    """Surface와 Observation을 Candidate·담당 Analysis Agent 결정으로 변환한다."""

    def route(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
    ) -> tuple[RouteDecision, ...]: ...
