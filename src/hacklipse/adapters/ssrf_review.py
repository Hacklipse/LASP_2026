"""Thread-safe registration for one exact SSRF review decision per Run."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from threading import Condition, RLock
from time import monotonic

from hacklipse.domain import (
    Evidence,
    RouteDecision,
    Run,
    SsrfReviewRegistration,
    SsrfVerificationStrategy,
    Surface,
)
from hacklipse.ports import VulnerabilityRouter

from .ssrf_analysis import ssrf_candidate_verification_strategy


class InMemorySsrfReviewRegistry:
    """Coordinate a same-Run post-Recon review without persisting raw URLs."""

    def __init__(self) -> None:
        self._condition = Condition(RLock())
        self._registrations: dict[
            tuple[str, SsrfVerificationStrategy], SsrfReviewRegistration
        ] = {}
        self._skipped: set[tuple[str, SsrfVerificationStrategy]] = set()

    def register(self, registration: SsrfReviewRegistration) -> None:
        """Register one immutable coordinate per verification strategy."""

        if not isinstance(registration, SsrfReviewRegistration):
            raise TypeError("SSRF review must use SsrfReviewRegistration")
        key = (registration.run_id, registration.verification_strategy)
        with self._condition:
            if key in self._skipped:
                raise ValueError("SSRF review strategy was already skipped for this Run")
            existing = self._registrations.get(key)
            if existing is not None and existing != registration:
                raise ValueError("SSRF review strategy already has a different registration")
            self._registrations[key] = registration
            self._condition.notify_all()

    def skip(
        self, run_id: str,
        strategy: SsrfVerificationStrategy = SsrfVerificationStrategy.PASSIVE,
    ) -> None:
        """Release one strategy gate without enabling its validation path."""

        key = (run_id, strategy)
        with self._condition:
            if key in self._registrations:
                raise ValueError("SSRF review strategy is already registered for this Run")
            self._skipped.add(key)
            self._condition.notify_all()

    def get(
        self, *, run_id: str, surface_id: str, parameter: str,
        strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None:
        """Return only an exact coordinate match; never fall back to another Surface."""

        with self._condition:
            return next((
                item for item in self._registrations.values()
                if item.run_id == run_id
                and item.surface_id == surface_id
                and item.parameter == parameter
                and (strategy is None or item.verification_strategy is strategy)
            ), None)

    def get_for_surface(
        self, *, run_id: str, surface_id: str,
        strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None:
        """Return the Run's single registration when it targets this Surface."""

        with self._condition:
            return next((
                item for item in self._registrations.values()
                if item.run_id == run_id and item.surface_id == surface_id
                and (strategy is None or item.verification_strategy is strategy)
            ), None)

    def get_for_run(
        self, run_id: str, strategy: SsrfVerificationStrategy | None = None,
    ) -> SsrfReviewRegistration | None:
        """Return one exact strategy, or the sole registration for legacy callers."""

        with self._condition:
            if strategy is not None:
                return self._registrations.get((run_id, strategy))
            matches = tuple(
                item for item in self._registrations.values()
                if item.run_id == run_id
            )
            return matches[0] if len(matches) == 1 else None

    def list_for_run(self, run_id: str) -> tuple[SsrfReviewRegistration, ...]:
        with self._condition:
            return tuple(
                item for item in self._registrations.values()
                if item.run_id == run_id
            )

    def discard(self, run_id: str) -> None:
        """Forget the in-memory review gate state for a terminal Run."""

        with self._condition:
            for key in tuple(self._registrations):
                if key[0] == run_id:
                    self._registrations.pop(key, None)
            self._skipped = {key for key in self._skipped if key[0] != run_id}
            self._condition.notify_all()

    def wait_for_review(
        self, run_id: str, *, strategy: SsrfVerificationStrategy | None = None,
        timeout_seconds: float | None = None,
    ) -> str:
        """Wait for `registered` or `skipped`; raise on an explicit deadline."""

        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("SSRF review timeout must be positive")
        deadline = None if timeout_seconds is None else monotonic() + timeout_seconds
        with self._condition:
            def resolved() -> str | None:
                registered = any(
                    key[0] == run_id and (strategy is None or key[1] is strategy)
                    for key in self._registrations
                )
                skipped = any(
                    key[0] == run_id and (strategy is None or key[1] is strategy)
                    for key in self._skipped
                )
                return "registered" if registered else "skipped" if skipped else None

            while resolved() is None:
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("SSRF review wait timed out")
                self._condition.wait(remaining)
            return resolved() or "skipped"


class SsrfReviewAwareRouter:
    """Add only the exact approved SSRF coordinate to an existing Router."""

    def __init__(
        self,
        delegate: VulnerabilityRouter,
        ssrf_router: VulnerabilityRouter,
        registry: InMemorySsrfReviewRegistry,
        *,
        preserve_unregistered_ssrf: bool = False,
        enable_registered_ssrf: bool = True,
        owned_receiver_enabled: bool = False,
        registration_loader: Callable[[str], SsrfReviewRegistration | None]
        | None = None,
        canary_loader: Callable[[str], object | None] | None = None,
    ) -> None:
        self._delegate = delegate
        self._ssrf_router = ssrf_router
        self._registry = registry
        self._preserve_unregistered_ssrf = preserve_unregistered_ssrf
        self._enable_registered_ssrf = enable_registered_ssrf
        self._owned_receiver_enabled = owned_receiver_enabled
        self._registration_loader = registration_loader
        self._canary_loader = canary_loader

    def __getattr__(self, name: str):
        """Preserve routing audit/capability telemetry from the wrapped Router."""

        return getattr(self._delegate, name)

    def route(
        self,
        run: Run,
        surfaces: Sequence[Surface],
        evidence: Sequence[Evidence],
    ) -> tuple[RouteDecision, ...]:
        delegated = tuple(self._delegate.route(run, surfaces, evidence))
        registrations = self._registry.list_for_run(run.run_id)
        if not registrations and self._registration_loader is not None:
            self._registration_loader(run.run_id)
            registrations = self._registry.list_for_run(run.run_id)
        if not registrations:
            if self._preserve_unregistered_ssrf:
                return delegated
            return tuple(
                item for item in delegated
                if item.candidate.vulnerability_type != "SSRF"
            )
        base = tuple(
            item for item in delegated
            if item.candidate.vulnerability_type != "SSRF"
        )
        preserved = tuple(
            item for item in delegated
            if self._preserve_unregistered_ssrf
            and all(
                registration.verification_strategy
                is not SsrfVerificationStrategy.PASSIVE
                for registration in registrations
            )
            and item.candidate.vulnerability_type == "SSRF"
        )
        canary = (
            self._canary_loader(run.run_id)
            if self._canary_loader is not None else None
        )
        if not self._enable_registered_ssrf:
            return base
        selected: list[RouteDecision] = []
        combined = (
            *self._ssrf_router.route(run, surfaces, evidence),
            *(item for item in delegated if item.candidate.vulnerability_type == "SSRF"),
        )
        review_decisions = tuple({
            (
                item.candidate.surface_id,
                item.candidate.routing_capability_id,
                item.candidate.analysis_strategy_id,
            ): item
            for item in combined
        }.values())
        for registration in registrations:
            wanted = registration.verification_strategy
            for decision in review_decisions:
                candidate = decision.candidate
                if (
                    candidate.vulnerability_type != "SSRF"
                    or candidate.surface_id != registration.surface_id
                ):
                    continue
                actual = ssrf_candidate_verification_strategy(candidate)
                if actual is not wanted:
                    continue
                if (
                    wanted is SsrfVerificationStrategy.OWNED_RECEIVER
                    and not self._owned_receiver_enabled
                ):
                    continue
                elif (
                    wanted is SsrfVerificationStrategy.INTERNAL_CANARY
                    and canary is None
                ):
                    continue
                selected.append(replace(
                    decision,
                    candidate=replace(
                        candidate,
                        exploration_parameters=(registration.parameter,),
                    ),
                ))
        ssrf = {
            (
                item.candidate.surface_id,
                item.candidate.routing_capability_id,
                item.candidate.analysis_strategy_id,
            ): item
            for item in (*preserved, *selected)
        }
        return (*base, *ssrf.values())
