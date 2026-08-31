"""GeminiLlmClient를 로컬 서버로 검증한다. 외부 Gemini API는 호출하지 않는다."""

from __future__ import annotations

import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hacklipse.adapters import GeminiLlmClient
from hacklipse.bootstrap import (
    DEFAULT_GEMINI_LLM_MODEL,
    GEMINI_API_KEY_ENV,
    build_gemini_llm_client_from_env,
)
from hacklipse.ports.errors import (
    LlmCredentialsMissing,
    LlmRateLimited,
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmMessage, LlmRequest

_API_KEY = "gemini-test-key-do-not-leak-0123456789"
_MODEL = "gemini-3.7-flash"
RECEIVED: dict[str, object] = {}


def _interaction(payload: object) -> bytes:
    return json.dumps(
        {
            "id": "interaction-test",
            "object": "interaction",
            "model": _MODEL,
            "status": "completed",
            "steps": [
                {
                    "type": "model_output",
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                }
            ],
            "usage": {
                "total_input_tokens": 13,
                "total_output_tokens": 8,
                "total_cached_tokens": 2,
            },
        }
    ).encode()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        RECEIVED.clear()
        RECEIVED["body"] = json.loads(self.rfile.read(length))
        RECEIVED["headers"] = {
            key.lower(): value for key, value in self.headers.items()
        }

        if self.path == "/ok":
            self._send(200, _interaction({"parameters": ["name"], "reason": "reflected"}))
        elif self.path == "/not-json":
            self._send(200, self._with_text("확실히 취약합니다"))
        elif self.path == "/json-array":
            self._send(200, self._with_text("[1, 2, 3]"))
        elif self.path == "/no-model-output":
            self._send(
                200,
                json.dumps(
                    {
                        "model": _MODEL,
                        "status": "completed",
                        "steps": [{"type": "thought", "summary": []}],
                    }
                ).encode(),
            )
        elif self.path == "/refusal":
            self._send(
                200,
                json.dumps(
                    {"model": _MODEL, "status": "cancelled", "steps": []}
                ).encode(),
            )
        elif self.path == "/rate-limited":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "9")
            self.end_headers()
            self.wfile.write(
                b'{"error":{"code":429,"message":"slow down",'
                b'"status":"RESOURCE_EXHAUSTED"}}'
            )
        elif self.path == "/bad-request":
            self._send(
                400,
                b'{"error":{"code":400,"message":"bad model",'
                b'"status":"INVALID_ARGUMENT"}}',
            )
        elif self.path == "/slow":
            time.sleep(1.0)
            self._send(200, _interaction({"verdict": "late"}))
        else:
            self._send(404, b'{"error":{"status":"NOT_FOUND"}}')

    @staticmethod
    def _with_text(text: str) -> bytes:
        return json.dumps(
            {
                "model": _MODEL,
                "status": "completed",
                "steps": [
                    {
                        "type": "model_output",
                        "content": [{"type": "text", "text": text}],
                    }
                ],
            }
        ).encode()

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            # timeout 테스트에서 Client가 먼저 연결을 닫는 것은 정상이다.
            pass

    def log_message(self, *args) -> None:
        pass


class GeminiLlmClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _client(self, path: str) -> GeminiLlmClient:
        return GeminiLlmClient(
            api_key=_API_KEY,
            model=_MODEL,
            endpoint=f"http://127.0.0.1:{self.port}{path}",
        )

    @staticmethod
    def _request(**overrides) -> LlmRequest:
        defaults: dict[str, object] = {
            "messages": (
                LlmMessage(role="user", content="inspect q"),
                LlmMessage(role="assistant", content="q may reflect"),
                LlmMessage(role="user", content="return the plan"),
            ),
            "system": "You are an XSS analysis agent.",
            "max_output_tokens": 512,
            "timeout_seconds": 5.0,
        }
        defaults.update(overrides)
        return LlmRequest(**defaults)  # type: ignore[arg-type]

    def test_serializes_stateless_interaction_and_messages(self) -> None:
        self._client("/ok").complete(self._request())

        body = RECEIVED["body"]
        assert isinstance(body, dict)
        self.assertEqual(body["model"], _MODEL)
        self.assertIs(body["store"], False)
        self.assertEqual(body["system_instruction"], "You are an XSS analysis agent.")
        self.assertEqual(
            body["generation_config"],
            {"max_output_tokens": 512, "thinking_summaries": "none"},
        )
        self.assertEqual(
            [step["type"] for step in body["input"]],
            ["user_input", "model_output", "user_input"],
        )
        self.assertEqual(
            body["input"][0]["content"],
            [{"type": "text", "text": "inspect q"}],
        )

    def test_sends_api_key_only_in_required_header(self) -> None:
        self._client("/ok").complete(self._request())

        headers = RECEIVED["headers"]
        body = RECEIVED["body"]
        assert isinstance(headers, dict)
        self.assertEqual(headers["x-goog-api-key"], _API_KEY)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertNotIn(_API_KEY, json.dumps(body))

    def test_response_schema_becomes_interactions_response_format(self) -> None:
        schema = {
            "type": "object",
            "properties": {"parameters": {"type": "array", "items": {"type": "string"}}},
            "required": ["parameters"],
            "additionalProperties": False,
        }
        self._client("/ok").complete(self._request(response_schema=schema))

        body = RECEIVED["body"]
        assert isinstance(body, dict)
        self.assertEqual(
            body["response_format"],
            {"type": "text", "mime_type": "application/json", "schema": schema},
        )

    def test_omits_response_format_without_schema(self) -> None:
        self._client("/ok").complete(self._request())
        body = RECEIVED["body"]
        assert isinstance(body, dict)
        self.assertNotIn("response_format", body)

    def test_returns_payload_model_status_and_usage(self) -> None:
        response = self._client("/ok").complete(self._request())

        self.assertEqual(response.payload["parameters"], ["name"])
        self.assertEqual(response.model, _MODEL)
        self.assertEqual(response.stop_reason, "completed")
        self.assertEqual(response.usage.input_tokens, 13)
        self.assertEqual(response.usage.output_tokens, 8)
        self.assertEqual(response.usage.cache_read_input_tokens, 2)

    def test_free_text_and_json_array_do_not_cross_the_port(self) -> None:
        for path in ("/not-json", "/json-array"):
            with self.subTest(path=path):
                with self.assertRaises(LlmResponseFormatError):
                    self._client(path).complete(self._request())

    def test_missing_model_output_is_a_format_error(self) -> None:
        with self.assertRaises(LlmResponseFormatError):
            self._client("/no-model-output").complete(self._request())

    def test_non_completed_response_is_a_refusal(self) -> None:
        with self.assertRaises(LlmRefused) as caught:
            self._client("/refusal").complete(self._request())
        self.assertEqual(caught.exception.category, "cancelled")

    def test_rate_limit_carries_status_and_retry_after(self) -> None:
        with self.assertRaises(LlmRateLimited) as caught:
            self._client("/rate-limited").complete(self._request())
        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(caught.exception.retry_after_seconds, 9.0)
        self.assertIn("RESOURCE_EXHAUSTED", str(caught.exception))

    def test_client_error_carries_http_and_google_status(self) -> None:
        with self.assertRaises(LlmTransportError) as caught:
            self._client("/bad-request").complete(self._request())
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("INVALID_ARGUMENT", str(caught.exception))

    def test_timeout_and_unreachable_endpoint_have_distinct_errors(self) -> None:
        with self.assertRaises(LlmTimeout):
            self._client("/slow").complete(self._request(timeout_seconds=0.2))

        client = GeminiLlmClient(
            api_key=_API_KEY,
            model=_MODEL,
            endpoint="http://127.0.0.1:1/v1beta/interactions",
        )
        with self.assertRaises(LlmTransportError):
            client.complete(self._request())

    def test_api_key_never_appears_in_failures_or_repr(self) -> None:
        failures = [
            ("/not-json", LlmResponseFormatError),
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

    def test_missing_credentials_or_model_fail_before_request(self) -> None:
        with self.assertRaises(ValueError):
            GeminiLlmClient(api_key="", model=_MODEL)
        with self.assertRaises(ValueError):
            GeminiLlmClient(api_key=_API_KEY, model="")


class GeminiCredentialInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = os.environ.get(GEMINI_API_KEY_ENV)

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop(GEMINI_API_KEY_ENV, None)
        else:
            os.environ[GEMINI_API_KEY_ENV] = self._saved

    def test_missing_or_blank_key_fails_loudly(self) -> None:
        os.environ.pop(GEMINI_API_KEY_ENV, None)
        with self.assertRaises(LlmCredentialsMissing):
            build_gemini_llm_client_from_env()

        os.environ[GEMINI_API_KEY_ENV] = "   "
        with self.assertRaises(LlmCredentialsMissing):
            build_gemini_llm_client_from_env()

    def test_key_from_environment_builds_client_without_leaking(self) -> None:
        os.environ[GEMINI_API_KEY_ENV] = _API_KEY
        client = build_gemini_llm_client_from_env(model=_MODEL)
        self.assertIsInstance(client, GeminiLlmClient)
        self.assertNotIn(_API_KEY, repr(client))

    def test_experiment_default_is_gemini_35_flash_lite(self) -> None:
        self.assertEqual(DEFAULT_GEMINI_LLM_MODEL, "gemini-3.5-flash-lite")


if __name__ == "__main__":
    unittest.main()
