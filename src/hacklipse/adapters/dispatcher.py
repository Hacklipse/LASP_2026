"""현재 프로세스 안에서 Agent를 선택·호출하는 Dispatcher Adapter."""

from __future__ import annotations

from hacklipse.domain import AgentResult, TaskEnvelope
from hacklipse.ports import Agent
from hacklipse.ports.errors import AgentToolNotAllowed, AgentUnavailable, DuplicateRecord


class LocalTaskDispatcher:
    """로컬 개발과 테스트에 사용하는 프로세스 내부 Dispatcher."""

    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}
        self._tool_grants: dict[str, frozenset[str]] = {}

    def register(
        self, agent_type: str, agent: Agent, *, allowed_tools: tuple[str, ...] = ()
    ) -> None:
        """Agent 유형과 구현체를 한 번만 등록한다."""

        if agent_type in self._agents:
            raise DuplicateRecord(f"agent already registered: {agent_type}")
        self._agents[agent_type] = agent
        self._tool_grants[agent_type] = frozenset(allowed_tools)

    def dispatch(self, task: TaskEnvelope) -> AgentResult:
        """Task의 agent_type에 맞는 구현을 찾아 호출한다."""

        try:
            agent = self._agents[task.agent_type]
        except KeyError as error:
            raise AgentUnavailable(task.agent_type) from error
        granted = self._tool_grants[task.agent_type]
        requested = frozenset(task.allowed_tools)
        if not requested.issubset(granted):
            denied = ", ".join(sorted(requested - granted))
            raise AgentToolNotAllowed(
                f"agent {task.agent_type} is not registered for tools: {denied}"
            )
        return agent.handle(task)
