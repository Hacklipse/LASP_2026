"""표준 라이브러리만으로 Anthropic Messages API를 호출하는 LlmClient 구현.

이 파일이 벤더를 아는 유일한 지점이다. Agent는 `ports.LlmClient`만 알고, 공급자를
바꾸려면 같은 Port를 구현한 다른 Adapter를 bootstrap에서 갈아끼우면 된다.

프로젝트 의존성 정책이 "표준 라이브러리 외 런타임 의존성 없음"(README)이라 공식 SDK
대신 urllib을 쓴다. endpoint·model·자격증명·제한시간은 전부 주입받으며 하드코딩하지
않는다.

자격증명 취급 — API 키는 비공개 속성에만 두고 예외 메시지·문자열 표현 어디에도 싣지
않는다. 실패 보고에는 상태 코드와 API가 돌려준 오류 유형만 남긴다.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Mapping

from hacklipse.ports.errors import (
    LlmRateLimited,
    LlmRefused,
    LlmResponseFormatError,
    LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmRequest, LlmResponse, LlmUsage

DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_API_VERSION = "2023-06-01"
# 응답 본문 상한. 구조화 JSON 하나가 이보다 클 이유가 없고, 상한 없이 read()하면
# 비정상 응답 하나로 메모리가 무한정 늘어난다.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class AnthropicLlmClient:
    """Anthropic Messages API를 구조화 JSON 응답 계약으로 감싼 Adapter."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        endpoint: str = DEFAULT_ENDPOINT,
        api_version: str = DEFAULT_API_VERSION,
    ) -> None:
        if not api_key:
            raise ValueError("anthropic llm client requires an api key")
        if not model:
            raise ValueError("anthropic llm client requires a model id")
        self._api_key = api_key
        self._model = model
        self._endpoint = endpoint
        self._api_version = api_version
        # 환경변수 프록시를 무시한다. 프롬프트가 외부 프록시를 경유하지 않게 한다.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def complete(self, request: LlmRequest) -> LlmResponse:
        """요청을 보내고 구조화 payload만 담긴 응답을 돌려준다."""

        body = json.dumps(self._build_body(request)).encode("utf-8")
        http_request = urllib.request.Request(
            self._endpoint,
            data=body,
            method="POST",
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": self._api_version,
                "content-type": "application/json",
                "accept-encoding": "identity",
            },
        )

        try:
            with self._opener.open(http_request, timeout=request.timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as error:
            try:
                raise self._status_error(error)
            finally:
                error.close()
        except TimeoutError as error:
            raise LlmTimeout(f"llm request exceeded {request.timeout_seconds}s") from error
        except urllib.error.URLError as error:
            # 소켓 타임아웃은 URLError.reason으로 감싸져 올라오기도 한다.
            if isinstance(error.reason, TimeoutError):
                raise LlmTimeout(f"llm request exceeded {request.timeout_seconds}s") from error
            raise LlmTransportError(f"llm request failed: {error.reason}") from error

        return self._parse(raw)

    def _build_body(self, request: LlmRequest) -> dict[str, object]:
        """Messages API 본문을 만든다.

        temperature·top_p·top_k는 넣지 않는다 — 현행 모델에서 400을 돌려준다.
        thinking도 지정하지 않고 모델 기본값을 따른다.
        """

        body: dict[str, object] = {
            "model": self._model,
            "max_tokens": request.max_output_tokens,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
        }
        if request.system:
            body["system"] = request.system
        if request.response_schema is not None:
            # 모델 쪽에서 JSON 형식을 강제한다. 파싱 실패를 Agent까지 올려보내지 않기 위한 1차 방어.
            body["output_config"] = {
                "format": {"type": "json_schema", "schema": dict(request.response_schema)}
            }
        return body

    def _status_error(self, error: urllib.error.HTTPError) -> LlmTransportError:
        """오류 응답을 자격증명 노출 없이 예외로 바꾼다."""

        status = getattr(error, "code", None) or getattr(error, "status", None)
        detail = _error_detail(error)
        if status == 429:
            return LlmRateLimited(
                f"llm rate limited: {detail}",
                status_code=status,
                retry_after_seconds=_retry_after(error),
            )
        return LlmTransportError(f"llm request returned {status}: {detail}", status_code=status)

    @staticmethod
    def _parse(raw: bytes) -> LlmResponse:
        """응답 본문에서 구조화 payload와 사용량을 뽑는다."""

        try:
            envelope = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as error:
            raise LlmResponseFormatError("llm response was not valid json") from error
        if not isinstance(envelope, dict):
            raise LlmResponseFormatError("llm response envelope was not an object")

        stop_reason = str(envelope.get("stop_reason") or "")
        if stop_reason == "refusal":
            # 거부는 content가 비어 온다. 파싱 오류로 뭉뚱그리면 원인을 잘못 짚게 된다.
            details = envelope.get("stop_details")
            category = (
                str(details.get("category")) if isinstance(details, dict) and details.get("category") else None
            )
            raise LlmRefused("llm declined the request", category=category)

        text = _first_text_block(envelope.get("content"))
        if text is None:
            raise LlmResponseFormatError(
                f"llm response carried no text block (stop_reason={stop_reason or 'unknown'})"
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
            stop_reason=stop_reason,
        )


def _first_text_block(content: object) -> str | None:
    """content 블록 목록에서 첫 text 블록의 문자열을 찾는다."""

    if not isinstance(content, list):
        return None
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        text = block.get("text")
        if isinstance(text, str) and text.strip():
            return text
    return None


def _usage(raw: object) -> LlmUsage:
    """사용량 필드를 원시값 그대로 담는다. 비용 환산은 상위 계층 몫이다."""

    if not isinstance(raw, dict):
        return LlmUsage()
    return LlmUsage(
        input_tokens=_int(raw.get("input_tokens")),
        output_tokens=_int(raw.get("output_tokens")),
        cache_read_input_tokens=_int(raw.get("cache_read_input_tokens")),
        cache_creation_input_tokens=_int(raw.get("cache_creation_input_tokens")),
    )


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _error_detail(error: urllib.error.HTTPError) -> str:
    """API가 돌려준 오류 유형만 뽑는다. 요청 헤더·본문은 절대 포함하지 않는다."""

    try:
        parsed = json.loads(error.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError, ValueError):
        return "(unreadable error body)"
    if isinstance(parsed, dict):
        detail = parsed.get("error")
        if isinstance(detail, dict):
            return f"{detail.get('type', 'error')}: {detail.get('message', '')}".strip()
    return "(unstructured error body)"


def _retry_after(error: urllib.error.HTTPError) -> float | None:
    headers: Mapping[str, str] | None = getattr(error, "headers", None)
    if headers is None:
        return None
    try:
        return float(headers.get("retry-after", ""))
    except (TypeError, ValueError):
        return None
