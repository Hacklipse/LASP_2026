"""Optional workflow advice; execution remains in the application layer."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from hacklipse.domain import Run, Surface


@dataclass(frozen=True, slots=True)
class OrchestrationDecision:
    """Choose an existing surface for one extra Recon pass, or continue."""

    action: str
    surface_id: str | None = None
    source: str = "advisor"


class OrchestrationAdvisor(Protocol):
    def decide(
        self,
        run: Run,
        options: Sequence[Surface],
        remaining_budget: int,
    ) -> OrchestrationDecision: ...
