"""Mutable same-Run review gate used between Recon and routing."""

from __future__ import annotations

from typing import Protocol

from hacklipse.domain import SsrfReviewRegistration, SsrfVerificationStrategy


class SsrfReviewRegistry(Protocol):
    def register(self, registration: SsrfReviewRegistration) -> None: ...

    def skip(
        self, run_id: str,
        strategy: SsrfVerificationStrategy = SsrfVerificationStrategy.PASSIVE,
    ) -> None: ...

    def get(
        self, *, run_id: str, surface_id: str, parameter: str,
        strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None: ...

    def get_for_surface(
        self, *, run_id: str, surface_id: str,
        strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None: ...

    def get_for_run(
        self, run_id: str, strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None: ...

    def list_for_run(self, run_id: str) -> tuple[SsrfReviewRegistration, ...]: ...

    def discard(self, run_id: str) -> None: ...

    def wait_for_review(
        self, run_id: str, *, strategy: SsrfVerificationStrategy | None = None,
        timeout_seconds: float | None = None,
    ) -> str: ...
