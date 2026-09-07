"""표준 라이브러리로 Gemini Interactions API를 호출하는 LlmClient Adapter.

Agent는 공급자 중립 ``LlmClient`` Port만 사용한다. 이 Adapter는 Gemini 고유의
요청·응답 형식, API Key 헤더, 구조화 출력, 사용량과 오류만 변환한다.

Interactions API에는 ``store=false``를 명시한다. 서버 측 대화 상태를 사용하지 않고
매 호출을 독립적으로 보내므로, Run 사이에 프롬프트 상태가 섞이지 않는다. API Key는
비공개 속성에만 보관하고 예외 문자열이나 객체 표현에 포함하지 않는다.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Mapping, Sequence

from hacklipse.ports.errors import (
    LlmRateLimited,
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmMessage, LlmRequest, LlmResponse, LlmUsage

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/interactions"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class GeminiLlmClient:
    """Gemini Interactions API를 구조화 JSON 응답 계약으로 감싼 Adapter."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        endpoint: str = DEFAULT_ENDPOINT,
    ) -> None:
        if not api_key:
            raise ValueError("gemini llm client requires an api key")
        if not model:
            raise ValueError("gemini llm client requires a model id")
        self._api_key = api_key
        self._model = model
        self._endpoint = endpoint
        # 프롬프트가 환경변수에 설정된 외부 프록시를 경유하지 않게 한다.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def complete(self, request: LlmRequest) -> LlmResponse:
        """요청을 보내고 구조화 payload만 Port 응답으로 반환한다."""

        body = json.dumps(self._build_body(request)).encode("utf-8")
        http_request = urllib.request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={
                "x-goog-api-key": self._api_key,
                "content-type": "application/json",
                "accept-encoding": "identity",
            },
        )

        try:
            with self._opener.open(
                http_request, timeout=request.timeout_seconds
            ) as response:
                raw = response.read(_MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as error:
            try:
                raise self._status_error(error)
            finally:
                error.close()
        except TimeoutError as error:
            raise LlmTimeout(
                f"llm request exceeded {request.timeout_seconds}s"
            ) from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise LlmTimeout(
                    f"llm request exceeded {request.timeout_seconds}s"
                ) from error
            raise LlmTransportError(f"llm request failed: {error.reason}") from error

        return self._parse(raw)

    def _build_body(self, request: LlmRequest) -> dict[str, object]:
        body: dict[str, object] = {
            "model": self._model,
            "input": _input_steps(request.messages),
            # 서버 측 대화 상태를 만들지 않는다. 각 Agent 호출은 Evidence 기반 독립 요청이다.
            "store": False,
            "generation_config": {
                "max_output_tokens": request.max_output_tokens,
                "thinking_summaries": "none",
            },
        }
        if request.system:
            body["system_instruction"] = request.system
        if request.response_schema is not None:
            body["response_format"] = {
                "type": "text",
                "mime_type": "application/json",
                "schema": dict(request.response_schema),
            }
        return body

    def _status_error(self, error: urllib.error.HTTPError) -> LlmTransportError:
        status = getattr(error, "code", None) or getattr(error, "status", None)
        detail = _error_detail(error)
        if status == 429:
            return LlmRateLimited(
                f"llm rate limited: {detail}",
                status_code=status,
                retry_after_seconds=_retry_after(error),
            )
        return LlmTransportError(
            f"llm request returned {status}: {detail}", status_code=status
        )

    @staticmethod
    def _parse(raw: bytes) -> LlmResponse:
        try:
            envelope = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as error:
            raise LlmResponseFormatError("llm response was not valid json") from error
        if not isinstance(envelope, dict):
            raise LlmResponseFormatError("llm response envelope was not an object")

        status = str(envelope.get("status") or "")
        text = _last_model_text(envelope.get("steps"))
        if text is None:
            if status in {"failed", "cancelled", "requires_action", "incomplete"}:
                raise LlmRefused("llm did not complete the request", category=status)
            raise LlmResponseFormatError(
                f"llm response carried no model text (status={status or 'unknown'})"
            )

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise LlmResponseFormatError("llm response content was not valid json") from error
        if not isinstance(payload, dict):
            raise LlmResponseFormatError("llm response content was not a json object")

        return LlmResponse(
            payload=payload,
            usage=_usage(envelope.get("usage")),
            model=str(envelope.get("model") or ""),
            stop_reason=status,
        )


def _input_steps(messages: Sequence[LlmMessage]) -> list[dict[str, object]]:
    """벤더 중립 user/assistant 메시지를 stateless Interaction steps로 바꾼다."""

    steps: list[dict[str, object]] = []
    for message in messages:
        steps.append(
            {
                "type": "user_input" if message.role == "user" else "model_output",
                "content": [{"type": "text", "text": message.content}],
            }
        )
    return steps


def _last_model_text(steps: object) -> str | None:
    """마지막 model_output step의 text 블록들을 API 순서대로 합친다."""

    if not isinstance(steps, list):
        return None
    for step in reversed(steps):
        if not isinstance(step, dict) or step.get("type") != "model_output":
            continue
        content = step.get("content")
        if not isinstance(content, list):
            return None
        parts = [
            item.get("text")
            for item in content
            if isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        ]
        joined = "".join(parts)
        return joined if joined.strip() else None
    return None


def _usage(raw: object) -> LlmUsage:
    if not isinstance(raw, dict):
        return LlmUsage()
    return LlmUsage(
        input_tokens=_int(raw.get("total_input_tokens")),
        output_tokens=_int(raw.get("total_output_tokens")),
        cache_read_input_tokens=_int(raw.get("total_cached_tokens")),
    )


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _error_detail(error: urllib.error.HTTPError) -> str:
    """Google 오류의 상태 이름만 남기고 요청·자격증명·본문은 노출하지 않는다."""

    try:
        parsed = json.loads(error.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError, ValueError):
        return "(unreadable error body)"
    if isinstance(parsed, dict):
        detail = parsed.get("error")
        if isinstance(detail, dict):
            api_status = detail.get("status")
            if isinstance(api_status, str) and api_status:
                return api_status
    return "(unstructured error body)"


def _retry_after(error: urllib.error.HTTPError) -> float | None:
    headers: Mapping[str, str] | None = getattr(error, "headers", None)
    if headers is None:
        return None
    try:
        return float(headers.get("retry-after", ""))
    except (TypeError, ValueError):
        return None
