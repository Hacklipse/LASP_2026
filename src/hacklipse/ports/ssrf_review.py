"""Mutable same-Run review gate used between Recon and routing."""

from __future__ import annotations

from typing import Protocol

from hacklipse.domain import SsrfReviewRegistration


class SsrfReviewRegistry(Protocol):
    def register(self, registration: SsrfReviewRegistration) -> None: ...

    def skip(self, run_id: str) -> None: ...

    def get(
        self, *, run_id: str, surface_id: str, parameter: str,
    ) -> SsrfReviewRegistration | None: ...

    def get_for_surface(
        self, *, run_id: str, surface_id: str,
    ) -> SsrfReviewRegistration | None: ...

    def get_for_run(self, run_id: str) -> SsrfReviewRegistration | None: ...

    def discard(self, run_id: str) -> None: ...

    def wait_for_review(
        self, run_id: str, *, timeout_seconds: float | None = None,
    ) -> str: ...
