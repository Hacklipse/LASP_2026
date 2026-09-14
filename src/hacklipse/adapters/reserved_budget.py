"""Keep a Run-wide request budget while reserving units for later candidates."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Iterator

from hacklipse.domain import TaskEnvelope
from hacklipse.ports import BudgetManager
from hacklipse.ports.errors import BudgetExceeded


class ReservedBudgetManager:
    """Apply a temporary request floor around one synchronous candidate task.

    The delegate remains the authority for the Run-wide cap. The floor is scoped
    to the current execution context, so an Agent cannot spend units reserved for
    later validation through the shared collector.
    """

    def __init__(self, delegate: BudgetManager) -> None:
        self._delegate = delegate
        self._floor: ContextVar[tuple[str, int] | None] = ContextVar(
            "reserved_budget_floor", default=None
        )

    def open_run(self, run_id: str, total_units: int) -> None:
        self._delegate.open_run(run_id, total_units)

    def global_remaining(self, run_id: str) -> int:
        return self._delegate.remaining(run_id)

    def remaining(self, run_id: str) -> int:
        remaining = self.global_remaining(run_id)
        scope = self._floor.get()
        if scope is not None and scope[0] == run_id:
            return max(0, remaining - scope[1])
        return remaining

    def ensure_available(self, task: TaskEnvelope) -> None:
        if task.request_budget > 0 and self.remaining(task.run_id) <= 0:
            raise BudgetExceeded("reserved request budget exhausted")
        self._delegate.ensure_available(task)

    def consume(self, run_id: str, units: int) -> None:
        if units > self.remaining(run_id):
            raise BudgetExceeded("reserved request budget exceeded")
        self._delegate.consume(run_id, units)

    @contextmanager
    def limited_to_floor(self, run_id: str, floor: int) -> Iterator[None]:
        if floor < 0:
            raise ValueError("reserved request floor cannot be negative")
        if self._floor.get() is not None:
            raise ValueError("nested request budget reservation is not supported")
        token = self._floor.set((run_id, floor))
        try:
            yield
        finally:
            self._floor.reset(token)
