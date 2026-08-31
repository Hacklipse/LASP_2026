"""DVWA 실행기의 디버그 출력이 유용하면서 민감 데이터를 노출하지 않는지 검증한다."""

from __future__ import annotations

import unittest

from scripts.run_dvwa_baseline import (
    _DebugAuditLog,
    _DebugProgress,
    _ProgressLlmClient,
    _safe_llm_content,
    _safe_log_value,
)
from hacklipse.ports import (
    ExecutionAuditEvent,
    LlmMessage,
    LlmRequest,
    LlmResponse,
    LlmUsage,
)


class _FakeLlmClient:
    def complete(self, request: LlmRequest) -> LlmResponse:
        del request
        return LlmResponse(
            payload={"parameters": ["name"], "reason": "reflected"},
            usage=LlmUsage(input_tokens=17, output_tokens=9),
            model="fake-model",
            stop_reason="completed",
        )


class DvwaDebugTests(unittest.TestCase):
    def test_llm_progress_reports_timing_and_usage_without_request_content(self) -> None:
        messages: list[str] = []
        progress = _DebugProgress(True, writer=messages.append)
        client = _ProgressLlmClient(
            _FakeLlmClient(),
            provider="gemini",
            model="gemini-test",
            progress=progress,
            heartbeat_seconds=60.0,
        )
        secret_prompt = "cookie-secret-and-api-key-must-not-appear"

        response = client.complete(
            LlmRequest(
                messages=(LlmMessage(role="user", content=secret_prompt),),
                response_schema={"type": "object"},
                timeout_seconds=5.0,
            )
        )

        output = "\n".join(messages)
        self.assertEqual(response.payload["parameters"], ["name"])
        self.assertIn("LLM 호출 #1 시작", output)
        self.assertIn("provider=gemini", output)
        self.assertIn("입력 17 tokens", output)
        self.assertIn("출력 9 tokens", output)
        self.assertNotIn(secret_prompt, output)
        self.assertNotIn("reflected", output)

    def test_explicit_content_debug_reports_prompt_and_structured_response(self) -> None:
        messages: list[str] = []
        progress = _DebugProgress(True, writer=messages.append)
        client = _ProgressLlmClient(
            _FakeLlmClient(),
            provider="gemini",
            model="gemini-test",
            progress=progress,
            heartbeat_seconds=60.0,
            show_content=True,
        )

        client.complete(
            LlmRequest(
                messages=(
                    LlmMessage(role="user", content="inspect the name parameter"),
                ),
                system="return a bounded plan",
                response_schema={"type": "object"},
                timeout_seconds=5.0,
            )
        )

        output = "\n".join(messages)
        self.assertIn("LLM 호출 #1 입력", output)
        self.assertIn("[system]", output)
        self.assertIn("[user #1]", output)
        self.assertIn("return a bounded plan", output)
        self.assertIn("inspect the name parameter", output)
        self.assertIn("LLM 호출 #1 응답", output)
        self.assertIn('"parameters": [', output)
        self.assertIn('"reason": "reflected"', output)

    def test_audit_progress_omits_query_values(self) -> None:
        messages: list[str] = []
        progress = _DebugProgress(True, writer=messages.append)
        audit = _DebugAuditLog(progress)
        secret_query = "do-not-log-this-query-value"

        audit.append(
            ExecutionAuditEvent(
                execution_id="exec-1",
                run_id="run-1",
                task_id="task-1",
                tool="http_get",
                method="GET",
                target=f"http://127.0.0.1/search?name={secret_query}",
                request_kind="probe",
                outcome="completed",
                status_code=200,
            )
        )

        output = "\n".join(messages)
        self.assertIn("http_get GET /search", output)
        self.assertIn("status=200", output)
        self.assertNotIn(secret_query, output)
        self.assertNotIn("?name=", output)
        self.assertEqual(len(audit.list_by_run("run-1")), 1)

    def test_log_values_neutralize_terminal_control_characters(self) -> None:
        self.assertEqual(_safe_log_value("model\n\x1b[31m"), "model??[31m")

    def test_llm_content_is_json_escaped_and_bounded(self) -> None:
        rendered = _safe_llm_content({"content": "line1\n\x1b[31m" + "a" * 9_000})

        self.assertIn("line1\\n\\u001b[31m", rendered)
        self.assertLessEqual(len(rendered), 8_003)


if __name__ == "__main__":
    unittest.main()
