"""SSRF 확인 주소는 실행 경계 밖에 저장하지 않는다."""

from __future__ import annotations

import sqlite3
import json
import tempfile
import unittest
from pathlib import Path

from hacklipse.adapters import (
    BoundedRetryPolicy,
    InMemoryBudgetManager,
    LocalTaskDispatcher,
    MemoryStoreBundle,
    SQLiteStoreBundle,
)
from hacklipse.application import TaskExecutor
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    TaskEnvelope,
)


class _RecordingAgent:
    def __init__(self) -> None:
        self.tasks: list[TaskEnvelope] = []

    def handle(self, task: TaskEnvelope) -> AgentResult:
        self.tasks.append(task)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)


def _ssrf_task(
    *, task_id: str, request_kind: HttpRequestKind, endpoint: str,
) -> TaskEnvelope:
    return TaskEnvelope(
        task_id=task_id,
        run_id="run-ssrf-secret",
        agent_type="worker",
        surface_id="surface-fetch",
        evidence_request=EvidenceRequest(
            evidence_type="http_response",
            surface_id="surface-fetch",
            reason="bounded SSRF verification",
            suggested_tool="http_get",
            http_request=HttpRequestSpec(
                method="GET",
                query_parameters=(("url", endpoint), ("mode", "original-value")),
                request_kind=request_kind,
            ),
        ),
    )


def _executor(task_store, agent: _RecordingAgent, *, progress=None) -> TaskExecutor:
    budget = InMemoryBudgetManager()
    budget.open_run("run-ssrf-secret", 4)
    dispatcher = LocalTaskDispatcher()
    dispatcher.register("worker", agent, allowed_tools=())
    return TaskExecutor(
        dispatcher=dispatcher,
        task_store=task_store,
        budget_manager=budget,
        retry_policy=BoundedRetryPolicy(),
        progress_callback=progress,
    )


class TaskExecutorSsrfSecretTests(unittest.TestCase):
    def test_json_post_probe_body_is_redacted_in_task_store(self) -> None:
        secret_endpoint = "https://callback.example/session/json-secret"
        task = TaskEnvelope(
            task_id="task-json", run_id="run-ssrf-secret", agent_type="worker",
            surface_id="surface-fetch",
            evidence_request=EvidenceRequest(
                evidence_type="http_response", surface_id="surface-fetch",
                reason="bounded JSON SSRF verification", suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST", headers=(("Content-Type", "application/json"),),
                    body=json.dumps({"url": secret_endpoint}),
                    request_kind=HttpRequestKind.SSRF_PROBE,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tasks.sqlite3"
            with SQLiteStoreBundle(path) as stores:
                agent = _RecordingAgent()
                _executor(stores.tasks, agent).execute(task)
                with sqlite3.connect(path) as connection:
                    serialized = connection.execute(
                        "SELECT data FROM tasks WHERE task_id = ?", (task.task_id,)
                    ).fetchone()[0]
                self.assertNotIn(secret_endpoint, serialized)
                self.assertIn("protected-ssrf-endpoint.invalid", serialized)
                self.assertIn(secret_endpoint, agent.tasks[0].evidence_request.http_request.body)

    def test_memory_store_and_progress_hide_callback_but_worker_receives_it(self) -> None:
        secret_endpoint = "https://callback.example/session/analysis-secret"
        task = _ssrf_task(
            task_id="task-callback",
            request_kind=HttpRequestKind.SSRF_PROBE,
            endpoint=secret_endpoint,
        )
        stores = MemoryStoreBundle()
        agent = _RecordingAgent()
        progress: list[TaskEnvelope] = []

        _executor(
            stores.tasks,
            agent,
            progress=lambda _event, envelope, _attempt, _elapsed: progress.append(
                envelope
            ),
        ).execute(task)

        self.assertIs(agent.tasks[0], task)
        self.assertEqual(
            agent.tasks[0].evidence_request.http_request.query_parameters[0][1],
            secret_endpoint,
        )
        persisted = stores.tasks.get(task.task_id).envelope
        persisted_text = repr(persisted)
        self.assertNotIn(secret_endpoint, persisted_text)
        self.assertNotIn("original-value", persisted_text)
        self.assertIn("protected-ssrf-endpoint.invalid", persisted_text)
        self.assertTrue(progress)
        self.assertTrue(all(secret_endpoint not in repr(item) for item in progress))

    def test_sqlite_store_never_serializes_exact_canary_endpoint(self) -> None:
        secret_endpoint = "https://canary.example/private/canary-secret"
        task = _ssrf_task(
            task_id="task-canary",
            request_kind=HttpRequestKind.SSRF_CANARY_PROBE,
            endpoint=secret_endpoint,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tasks.sqlite3"
            with SQLiteStoreBundle(path) as stores:
                agent = _RecordingAgent()
                _executor(stores.tasks, agent).execute(task)
                persisted = stores.tasks.get(task.task_id).envelope

                self.assertEqual(
                    agent.tasks[0].evidence_request.http_request.query_parameters[0][1],
                    secret_endpoint,
                )
                self.assertNotIn(secret_endpoint, repr(persisted))
                with sqlite3.connect(path) as connection:
                    serialized = connection.execute(
                        "SELECT data FROM tasks WHERE task_id = ?", (task.task_id,)
                    ).fetchone()[0]
                self.assertNotIn(secret_endpoint, serialized)
                self.assertNotIn("original-value", serialized)
                self.assertIn("protected-ssrf-endpoint.invalid", serialized)

    def test_non_ssrf_task_is_persisted_and_reported_unchanged(self) -> None:
        task = TaskEnvelope(
            task_id="task-normal",
            run_id="run-ssrf-secret",
            agent_type="worker",
            evidence_request=EvidenceRequest(
                evidence_type="http_response",
                surface_id="surface-normal",
                reason="normal control",
                suggested_tool="http_get",
                http_request=HttpRequestSpec(
                    query_parameters=(("q", "ordinary-value"),),
                    request_kind=HttpRequestKind.CONTROL,
                ),
            ),
        )
        stores = MemoryStoreBundle()
        agent = _RecordingAgent()
        progress: list[TaskEnvelope] = []

        _executor(
            stores.tasks,
            agent,
            progress=lambda _event, envelope, _attempt, _elapsed: progress.append(
                envelope
            ),
        ).execute(task)

        self.assertEqual(stores.tasks.get(task.task_id).envelope, task)
        self.assertTrue(all(item is task for item in progress))


if __name__ == "__main__":
    unittest.main()
