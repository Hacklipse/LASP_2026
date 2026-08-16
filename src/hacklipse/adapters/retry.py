"""실패 종류와 시도 횟수로 재실행을 제한하는 Retry Adapter."""

from __future__ import annotations

from hacklipse.ports.errors import (
    AgentUnavailable,
    BudgetExceeded,
    ExternalExecutionDisabled,
    PolicyViolation,
)


class BoundedRetryPolicy:
    """지정한 최대 시도 횟수 안에서 복구 가능한 오류만 재시도한다."""

    def __init__(self, max_attempts: int = 1) -> None:
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        self._max_attempts = max_attempts

    def should_retry(self, attempt: int, error: Exception) -> bool:
        """정책·예산·구성 오류를 제외한 실패의 재시도 가능 여부를 반환한다."""

        # 재시도해도 조건이 바뀌지 않는 오류는 즉시 호출자에게 전파한다.
        non_retryable = (
            AgentUnavailable,
            BudgetExceeded,
            ExternalExecutionDisabled,
            PolicyViolation,
        )
        return attempt < self._max_attempts and not isinstance(error, non_retryable)
