"""정책, 예산, 재시도처럼 Control Plane을 보조하는 계약."""

from __future__ import annotations

from typing import Protocol

from hacklipse.domain import (
    ExecutionRequest,
    ProgressEvent,
    Run,
    RunRequest,
    TaskEnvelope,
)


class PolicyGate(Protocol):
    """Run 입력과 실제 실행 요청이 승인된 범위인지 판정한다."""

    def validate_run(self, request: RunRequest) -> None: ...

    def validate_execution(self, run: Run, request: ExecutionRequest) -> None: ...


class BudgetManager(Protocol):
    """Run별 실행 예산을 등록·확인·차감한다."""

    def open_run(self, run_id: str, total_units: int) -> None: ...

    def ensure_available(self, task: TaskEnvelope) -> None: ...

    def consume(self, run_id: str, units: int) -> None: ...

    def remaining(self, run_id: str) -> int: ...


class RetryPolicy(Protocol):
    """실패 유형과 현재 시도 횟수를 기준으로 재시도 여부를 결정한다."""

    def should_retry(self, attempt: int, error: Exception) -> bool: ...


class ProgressSink(Protocol):
    """Run 진행 사건을 받는 경계.

    Agent는 화면에 직접 출력하지 않는다. 중앙에서만 사건을 만들어야 순서가 보장되고
    민감정보 제거 규칙을 한곳에서 지킬 수 있다.
    """

    def emit(self, event: ProgressEvent) -> None: ...
