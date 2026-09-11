"""공유 LLM rolling-window 제한기의 결정적 테스트."""

from __future__ import annotations

import unittest

from hacklipse.adapters.llm_rate_limit import SlidingWindowLlmClient
from hacklipse.ports.llm import LlmMessage, LlmRequest, LlmResponse


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class _Delegate:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.calls += 1
        if self.error is not None:
            error, self.error = self.error, None
            raise error
        return LlmResponse(payload={"ok": True}, model="fake")


_REQUEST = LlmRequest(messages=(LlmMessage(role="user", content="test"),))


class SlidingWindowLlmClientTests(unittest.TestCase):
    def test_fifteenth_call_waits_after_fourteen_immediate_calls(self) -> None:
        clock = _Clock()
        delegate = _Delegate()
        client = SlidingWindowLlmClient(
            delegate,
            max_calls=14,
            clock=clock,
            sleeper=clock.sleep,
        )

        for _ in range(15):
            client.complete(_REQUEST)

        self.assertEqual(delegate.calls, 15)
        self.assertEqual(len(clock.sleeps), 1)
        self.assertAlmostEqual(clock.sleeps[0], 60.1)

    def test_only_the_remaining_part_of_the_window_is_slept(self) -> None:
        clock = _Clock()
        delegate = _Delegate()
        client = SlidingWindowLlmClient(
            delegate,
            max_calls=2,
            window_seconds=10,
            boundary_margin_seconds=0.1,
            clock=clock,
            sleeper=clock.sleep,
        )

        client.complete(_REQUEST)
        clock.now = 4.0
        client.complete(_REQUEST)
        clock.now = 9.0
        client.complete(_REQUEST)

        self.assertEqual(len(clock.sleeps), 1)
        self.assertAlmostEqual(clock.sleeps[0], 1.1)

    def test_failed_attempt_still_consumes_a_rate_limit_slot(self) -> None:
        clock = _Clock()
        delegate = _Delegate(error=RuntimeError("provider rejected request"))
        client = SlidingWindowLlmClient(
            delegate,
            max_calls=1,
            window_seconds=10,
            boundary_margin_seconds=0,
            clock=clock,
            sleeper=clock.sleep,
        )

        with self.assertRaises(RuntimeError):
            client.complete(_REQUEST)
        client.complete(_REQUEST)

        self.assertEqual(delegate.calls, 2)
        self.assertEqual(clock.sleeps, [10.0])

    def test_invalid_limits_are_rejected(self) -> None:
        delegate = _Delegate()
        for kwargs in (
            {"max_calls": 0},
            {"max_calls": 1, "window_seconds": 0},
            {"max_calls": 1, "boundary_margin_seconds": -1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SlidingWindowLlmClient(delegate, **kwargs)


if __name__ == "__main__":
    unittest.main()
