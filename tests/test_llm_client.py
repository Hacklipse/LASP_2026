"""AnthropicLlmClient를 로컬 stdlib 서버로 검증한다 (외부 API 호출 없음).

여기서 지키려는 계약은 네 가지다.
1. 요청 직렬화 — 모델·메시지·system·스키마·헤더가 약속대로 나간다.
2. 구조화 응답만 통과 — 자유 텍스트나 깨진 JSON은 Port를 못 넘는다.
3. 실패 유형 구분 — timeout / rate limit / transport / format / refusal이 서로 다르다.
4. 자격증명 비노출 — API 키가 어떤 예외 문자열에도 나타나지 않는다.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hacklipse.adapters import AnthropicLlmClient
from hacklipse.ports.errors import (
    LlmRateLimited,
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmMessage, LlmRequest

_API_KEY = "sk-ant-test-do-not-leak-0123456789"
_MODEL = "claude-opus-5"

# 서버가 마지막으로 받은 요청. 직렬화 검증에 쓴다.
RECEIVED: dict[str, object] = {}


def _ok(payload: dict[str, object]) -> bytes:
    """구조화 JSON 하나를 담은 정상 Messages API 응답."""

    return json.dumps(
        {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": _MODEL,
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7, "cache_read_input_tokens": 3},
        }
    ).encode()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        RECEIVED.clear()
        RECEIVED["body"] = json.loads(raw)
        RECEIVED["headers"] = {key.lower(): value for key, value in self.headers.items()}

        path = self.path
        if path == "/ok":
            self._send(200, _ok({"verdict": "reflected", "parameter": "name"}))
        elif path == "/not-json":
            self._send(200, self._envelope([{"type": "text", "text": "확실히 취약합니다"}]))
        elif path == "/json-array":
            self._send(200, self._envelope([{"type": "text", "text": "[1, 2, 3]"}]))
        elif path == "/no-text-block":
            self._send(200, self._envelope([{"type": "thinking", "thinking": ""}]))
        elif path == "/broken-envelope":
            self._send(200, b"<html>gateway</html>")
        elif path == "/refusal":
            self._send(
                200,
                json.dumps(
                    {
                        "id": "msg_r",
                        "type": "message",
                        "model": _MODEL,
                        "content": [],
                        "stop_reason": "refusal",
                        "stop_details": {"type": "refusal", "category": "cyber"},
                    }
                ).encode(),
            )
        elif path == "/rate-limited":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "17")
            self.end_headers()
            self.wfile.write(
                b'{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}'
            )
        elif path == "/bad-request":
            self._send(
                400,
                b'{"type":"error","error":{"type":"invalid_request_error","message":"bad model"}}',
            )
        elif path == "/slow":
            time.sleep(1.0)
            self._send(200, _ok({"verdict": "late"}))
        else:
            self._send(404, b'{"type":"error","error":{"type":"not_found_error"}}')

    @staticmethod
    def _envelope(content: list[dict[str, object]]) -> bytes:
        return json.dumps(
            {"id": "msg_x", "model": _MODEL, "content": content, "stop_reason": "end_turn"}
        ).encode()

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # 테스트 출력 소음 제거
        pass


class AnthropicLlmClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def _client(self, path: str) -> AnthropicLlmClient:
        return AnthropicLlmClient(
            api_key=_API_KEY,
            model=_MODEL,
            endpoint=f"http://127.0.0.1:{self.port}{path}",
        )

    @staticmethod
    def _request(**overrides) -> LlmRequest:
        defaults: dict[str, object] = {
            "messages": (LlmMessage(role="user", content="analyze this surface"),),
            "system": "You are an analysis agent.",
            "max_output_tokens": 512,
            "timeout_seconds": 5.0,
        }
        defaults.update(overrides)
        return LlmRequest(**defaults)  # type: ignore[arg-type]

    # --- 1. 요청 직렬화 ---

    def test_serializes_model_messages_and_system(self) -> None:
        self._client("/ok").complete(self._request())

        body = RECEIVED["body"]
        assert isinstance(body, dict)
        self.assertEqual(body["model"], _MODEL)
        self.assertEqual(body["max_tokens"], 512)
        self.assertEqual(body["system"], "You are an analysis agent.")
        self.assertEqual(
            body["messages"], [{"role": "user", "content": "analyze this surface"}]
        )
        # 현행 모델이 400을 돌려주는 파라미터는 아예 실리지 않아야 한다.
        for removed in ("temperature", "top_p", "top_k"):
            self.assertNotIn(removed, body)

    def test_sends_required_auth_and_version_headers(self) -> None:
        self._client("/ok").complete(self._request())

        headers = RECEIVED["headers"]
        assert isinstance(headers, dict)
        self.assertEqual(headers["x-api-key"], _API_KEY)
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertEqual(headers["content-type"], "application/json")

    def test_response_schema_becomes_output_config_format(self) -> None:
        schema = {
            "type": "object",
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
            "additionalProperties": False,
        }
        self._client("/ok").complete(self._request(response_schema=schema))

        body = RECEIVED["body"]
        assert isinstance(body, dict)
        self.assertEqual(
            body["output_config"], {"format": {"type": "json_schema", "schema": schema}}
        )

    def test_omits_output_config_when_no_schema_requested(self) -> None:
        self._client("/ok").complete(self._request())

        body = RECEIVED["body"]
        assert isinstance(body, dict)
        self.assertNotIn("output_config", body)

    # --- 2. 구조화 응답 파싱 ---

    def test_returns_parsed_payload_and_usage(self) -> None:
        response = self._client("/ok").complete(self._request())

        self.assertEqual(response.payload, {"verdict": "reflected", "parameter": "name"})
        self.assertEqual(response.model, _MODEL)
        self.assertEqual(response.stop_reason, "end_turn")
        self.assertEqual(response.usage.input_tokens, 11)
        self.assertEqual(response.usage.output_tokens, 7)
        self.assertEqual(response.usage.cache_read_input_tokens, 3)

    def test_free_text_response_is_a_format_error(self) -> None:
        with self.assertRaises(LlmResponseFormatError):
            self._client("/not-json").complete(self._request())

    def test_json_array_response_is_a_format_error(self) -> None:
        # 배열은 유효한 JSON이지만 계약은 객체다. Agent가 키 접근을 못 하면 안 된다.
        with self.assertRaises(LlmResponseFormatError):
            self._client("/json-array").complete(self._request())

    def test_response_without_text_block_is_a_format_error(self) -> None:
        with self.assertRaises(LlmResponseFormatError):
            self._client("/no-text-block").complete(self._request())

    def test_non_json_envelope_is_a_format_error(self) -> None:
        with self.assertRaises(LlmResponseFormatError):
            self._client("/broken-envelope").complete(self._request())

    # --- 3. 실패 유형 구분 ---

    def test_refusal_is_distinct_from_a_format_error(self) -> None:
        with self.assertRaises(LlmRefused) as caught:
            self._client("/refusal").complete(self._request())
        self.assertEqual(caught.exception.category, "cyber")

    def test_rate_limit_carries_status_and_retry_after(self) -> None:
        with self.assertRaises(LlmRateLimited) as caught:
            self._client("/rate-limited").complete(self._request())
        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(caught.exception.retry_after_seconds, 17.0)

    def test_client_error_becomes_transport_error_with_status(self) -> None:
        with self.assertRaises(LlmTransportError) as caught:
            self._client("/bad-request").complete(self._request())
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("invalid_request_error", str(caught.exception))

    def test_timeout_is_reported_as_timeout(self) -> None:
        with self.assertRaises(LlmTimeout):
            self._client("/slow").complete(self._request(timeout_seconds=0.2))

    def test_unreachable_endpoint_becomes_transport_error(self) -> None:
        client = AnthropicLlmClient(
            api_key=_API_KEY, model=_MODEL, endpoint="http://127.0.0.1:1/v1/messages"
        )
        with self.assertRaises(LlmTransportError):
            client.complete(self._request())

    # --- 4. 자격증명 비노출 ---

    def test_api_key_never_appears_in_error_messages(self) -> None:
        """모든 실패 경로의 예외 문자열과 표현에 키가 없어야 한다."""

        failures = [
            ("/not-json", LlmResponseFormatError),
            ("/broken-envelope", LlmResponseFormatError),
            ("/refusal", LlmRefused),
            ("/rate-limited", LlmRateLimited),
            ("/bad-request", LlmTransportError),
        ]
        for path, expected in failures:
            with self.subTest(path=path):
                client = self._client(path)
                with self.assertRaises(expected) as caught:
                    client.complete(self._request())
                self.assertNotIn(_API_KEY, str(caught.exception))
                self.assertNotIn(_API_KEY, repr(caught.exception))
                self.assertNotIn(_API_KEY, repr(client))

    def test_missing_credentials_fail_before_any_request(self) -> None:
        with self.assertRaises(ValueError):
            AnthropicLlmClient(api_key="", model=_MODEL)
        with self.assertRaises(ValueError):
            AnthropicLlmClient(api_key=_API_KEY, model="")


if __name__ == "__main__":
    unittest.main()
