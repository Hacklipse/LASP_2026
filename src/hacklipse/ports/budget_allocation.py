"""Optional advice about which routed candidates receive scarce requests first."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from hacklipse.domain import Candidate, Run


@dataclass(frozen=True, slots=True)
class BudgetAllocationDecision:
    candidate_ids: tuple[str, ...]
    validation_reserve_per_candidate: int = 1
    source: str = "advisor"
    candidate_weights: tuple[int, ...] = ()


class BudgetAllocationAdvisor(Protocol):
    def decide(
        self,
        run: Run,
        candidates: Sequence[Candidate],
        remaining_budget: int,
    ) -> BudgetAllocationDecision: ...
