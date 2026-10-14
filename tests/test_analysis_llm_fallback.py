"""Analysis LLM 지연은 결정적 분석으로 복구하고 그 사실을 보존한다."""

from __future__ import annotations

import unittest
from dataclasses import replace

from hacklipse.adapters.analysis_llm_fallback import (
    BoundedAnalysisLlmClient,
    FallbackAnalysisAgent,
)
from hacklipse.adapters.memory import InMemoryEvidenceStore
from hacklipse.application.errors import AgentContractError, LlmOutputContractError
from hacklipse.domain import AgentResult, AgentResultStatus, TaskEnvelope
from hacklipse.ports.errors import LlmTimeout, PolicyViolation
from hacklipse.ports.llm import LlmMessage, LlmRequest, LlmResponse


class _Llm:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.timeouts.append(request.timeout_seconds)
        return LlmResponse(payload={})


class _Agent:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def handle(self, task: TaskEnvelope) -> AgentResult:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)


class AnalysisLlmFallbackTests(unittest.TestCase):
    def test_call_timeout_leaves_room_for_task_recovery(self) -> None:
        delegate = _Llm()
        client = BoundedAnalysisLlmClient(delegate)
        request = LlmRequest(messages=(LlmMessage(role="user", content="test"),))
        client.complete(replace(request, timeout_seconds=120))
        client.complete(replace(request, timeout_seconds=20))
        self.assertEqual(delegate.timeouts, [60.0, 10.0])

    def test_timeout_falls_back_once_and_resume_keeps_fallback(self) -> None:
        evidence = InMemoryEvidenceStore()
        primary = _Agent(LlmTimeout("provider was slow"))
        fallback = _Agent()
        agent = FallbackAnalysisAgent(primary, fallback, evidence)
        task = TaskEnvelope(
            task_id="task-1", run_id="run-1", agent_type="xss_analyzer",
            surface_id="surface-1", candidate_id="candidate-1",
        )

        first = agent.handle(task)
        self.assertEqual(first.status, AgentResultStatus.COMPLETED)
        self.assertEqual(len(first.new_evidence_ids), 1)
        marker = evidence.get(task.run_id, first.new_evidence_ids[0])
        self.assertEqual(marker.observation["reason"], "LlmTimeout")
        self.assertEqual(marker.observation["source"], "deterministic_fallback")

        agent.handle(replace(task, task_id="task-2", evidence_ids=first.new_evidence_ids))
        self.assertEqual(primary.calls, 1)
        self.assertEqual(fallback.calls, 2)

    def test_policy_failure_does_not_fallback(self) -> None:
        primary = _Agent(PolicyViolation("outside scope"))
        fallback = _Agent()
        agent = FallbackAnalysisAgent(primary, fallback, InMemoryEvidenceStore())
        with self.assertRaises(PolicyViolation):
            agent.handle(TaskEnvelope(
                task_id="task-1", run_id="run-1", agent_type="xss_analyzer",
            ))
        self.assertEqual(fallback.calls, 0)

    def test_only_llm_output_contract_errors_are_recoverable(self) -> None:
        task = TaskEnvelope(
            task_id="task-1", run_id="run-1", agent_type="xss_analyzer",
            surface_id="surface-1", candidate_id="candidate-1",
        )
        for error, should_fallback in (
            (LlmOutputContractError("invented parameter"), True),
            (AgentContractError("task and surface differ"), False),
        ):
            with self.subTest(error=type(error).__name__):
                primary, fallback = _Agent(error), _Agent()
                agent = FallbackAnalysisAgent(primary, fallback, InMemoryEvidenceStore())
                if should_fallback:
                    result = agent.handle(task)
                    self.assertEqual(fallback.calls, 1)
                    self.assertEqual(len(result.new_evidence_ids), 1)
                else:
                    with self.assertRaises(AgentContractError):
                        agent.handle(task)
                    self.assertEqual(fallback.calls, 0)


if __name__ == "__main__":
    unittest.main()
