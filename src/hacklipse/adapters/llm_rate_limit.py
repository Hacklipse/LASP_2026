"""여러 Agent가 공유하는 LLM 호출 수를 rolling window로 제한한다."""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from threading import Lock

from hacklipse.ports.llm import LlmClient, LlmRequest, LlmResponse


class SlidingWindowLlmClient:
    """한 프로세스의 모든 LLM 호출 시작 시각에 공통 RPM 상한을 적용한다.

    호출이 실패해도 공급자 측 한도를 소비했을 수 있으므로 시도 자체를 센다. 잠금은
    대기와 슬롯 예약을 함께 감싸 병렬 Agent가 같은 슬롯을 중복으로 쓰지 못하게 한다.
    """

    def __init__(
        self,
        delegate: LlmClient,
        *,
        max_calls: int,
        window_seconds: float = 60.0,
        boundary_margin_seconds: float = 0.1,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_calls <= 0:
            raise ValueError("llm rate limit max_calls must be positive")
        if window_seconds <= 0:
            raise ValueError("llm rate limit window_seconds must be positive")
        if boundary_margin_seconds < 0:
            raise ValueError("llm rate limit boundary margin cannot be negative")
        self._delegate = delegate
        self._max_calls = max_calls
        self._window_seconds = window_seconds
        self._boundary_margin_seconds = boundary_margin_seconds
        self._clock = clock
        self._sleeper = sleeper
        self._starts: deque[float] = deque()
        self._lock = Lock()

    def complete(self, request: LlmRequest) -> LlmResponse:
        self._reserve_slot()
        return self._delegate.complete(request)

    def _reserve_slot(self) -> None:
        effective_window = self._window_seconds + self._boundary_margin_seconds
        with self._lock:
            while True:
                now = self._clock()
                cutoff = now - effective_window
                while self._starts and self._starts[0] <= cutoff:
                    self._starts.popleft()
                if len(self._starts) < self._max_calls:
                    self._starts.append(now)
                    return
                wait_seconds = self._starts[0] + effective_window - now
                self._sleeper(max(wait_seconds, 0.0))
