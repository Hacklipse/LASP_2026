"""외부 인프라 없이 Run별 요청 단위를 추적하는 예산 Adapter."""

from __future__ import annotations

from hacklipse.domain import TaskEnvelope
from hacklipse.ports.errors import BudgetExceeded, DuplicateRecord, RecordNotFound


class InMemoryBudgetManager:
    """최소 요청 단위만 계산하며 향후 비용·시간 기반 구현으로 교체할 수 있다."""

    def __init__(self) -> None:
        self._total: dict[str, int] = {}
        self._used: dict[str, int] = {}

    def open_run(self, run_id: str, total_units: int) -> None:
        """새 Run의 전체 예산을 등록한다."""

        if run_id in self._total:
            raise DuplicateRecord(run_id)
        self._total[run_id] = total_units
        self._used[run_id] = 0

    def ensure_available(self, task: TaskEnvelope) -> None:
        """예산을 사용하는 Task를 시작할 최소 잔여량이 있는지 확인한다."""

        if task.request_budget > 0 and self.remaining(task.run_id) <= 0:
            raise BudgetExceeded(f"request budget exhausted for {task.run_id}")

    def consume(self, run_id: str, units: int) -> None:
        """실제 외부 실행에 사용한 예산 단위를 차감한다."""

        if units < 0:
            raise ValueError("budget consumption cannot be negative")
        remaining = self.remaining(run_id)
        if units > remaining:
            raise BudgetExceeded(f"request budget exceeded for {run_id}")
        self._used[run_id] += units

    def remaining(self, run_id: str) -> int:
        """Run에 남아 있는 요청 단위를 반환한다."""

        try:
            return self._total[run_id] - self._used[run_id]
        except KeyError as error:
            raise RecordNotFound(run_id) from error
