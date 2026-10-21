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
    Surface,
)
from hacklipse.ports import VulnerabilityRouter

from .ssrf_analysis import (
    SSRF_CANARY_CAPABILITY, SSRF_CANARY_DECLARED_CAPABILITY,
    SSRF_OWNED_RECEIVER_CAPABILITY, SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY,
)


class InMemorySsrfReviewRegistry:
    """Coordinate a same-Run post-Recon review without persisting raw URLs."""

    def __init__(self) -> None:
        self._condition = Condition(RLock())
        self._registrations: dict[str, SsrfReviewRegistration] = {}
        self._skipped: set[str] = set()

    def register(self, registration: SsrfReviewRegistration) -> None:
        """Register exactly one immutable coordinate and release the Run gate."""

        if not isinstance(registration, SsrfReviewRegistration):
            raise TypeError("SSRF review must use SsrfReviewRegistration")
        with self._condition:
            if registration.run_id in self._skipped:
                raise ValueError("SSRF review was already skipped for this Run")
            existing = self._registrations.get(registration.run_id)
            if existing is not None and existing != registration:
                raise ValueError("SSRF review Run already has a different registration")
            self._registrations[registration.run_id] = registration
            self._condition.notify_all()

    def skip(self, run_id: str) -> None:
        """Release the Run gate without enabling observation-based validation."""

        with self._condition:
            if run_id in self._registrations:
                raise ValueError("SSRF review is already registered for this Run")
            self._skipped.add(run_id)
            self._condition.notify_all()

    def get(
        self, *, run_id: str, surface_id: str, parameter: str,
    ) -> SsrfReviewRegistration | None:
        """Return only an exact coordinate match; never fall back to another Surface."""

        with self._condition:
            registration = self._registrations.get(run_id)
            if registration is None:
                return None
            if (
                registration.surface_id != surface_id
                or registration.parameter != parameter
            ):
                return None
            return registration

    def get_for_surface(
        self, *, run_id: str, surface_id: str,
    ) -> SsrfReviewRegistration | None:
        """Return the Run's single registration when it targets this Surface."""

        with self._condition:
            registration = self._registrations.get(run_id)
            if registration is None or registration.surface_id != surface_id:
                return None
            return registration

    def get_for_run(self, run_id: str) -> SsrfReviewRegistration | None:
        """Return the Run's single immutable registration, if one was approved."""

        with self._condition:
            return self._registrations.get(run_id)

    def discard(self, run_id: str) -> None:
        """Forget the in-memory review gate state for a terminal Run."""

        with self._condition:
            self._registrations.pop(run_id, None)
            self._skipped.discard(run_id)
            self._condition.notify_all()

    def wait_for_review(
        self, run_id: str, *, timeout_seconds: float | None = None,
    ) -> str:
        """Wait for `registered` or `skipped`; raise on an explicit deadline."""

        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("SSRF review timeout must be positive")
        deadline = None if timeout_seconds is None else monotonic() + timeout_seconds
        with self._condition:
            while run_id not in self._registrations and run_id not in self._skipped:
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("SSRF review wait timed out")
                self._condition.wait(remaining)
            return "registered" if run_id in self._registrations else "skipped"


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
        registration = self._registry.get_for_run(run.run_id)
        if registration is None and self._registration_loader is not None:
            registration = self._registration_loader(run.run_id)
        if registration is None:
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
        callback = tuple(
            replace(
                item,
                candidate=replace(
                    item.candidate,
                    exploration_parameters=(registration.parameter,),
                ),
            )
            if item.candidate.surface_id == registration.surface_id else item
            for item in delegated
            if (
                item.candidate.vulnerability_type == "SSRF"
                and item.candidate.surface_id == registration.surface_id
            )
        ) if self._preserve_unregistered_ssrf else ()
        if not self._enable_registered_ssrf:
            return (*base, *callback)
        canary = (
            self._canary_loader(run.run_id)
            if self._canary_loader is not None else None
        )
        selected: list[RouteDecision] = []
        for decision in self._ssrf_router.route(run, surfaces, evidence):
            candidate = decision.candidate
            if (
                candidate.vulnerability_type != "SSRF"
                or candidate.surface_id != registration.surface_id
            ):
                continue
            is_canary = candidate.routing_capability_id in {
                SSRF_CANARY_CAPABILITY, SSRF_CANARY_DECLARED_CAPABILITY,
            }
            is_owned_receiver = candidate.routing_capability_id in {
                SSRF_OWNED_RECEIVER_CAPABILITY,
                SSRF_OWNED_RECEIVER_DECLARED_CAPABILITY,
            }
            if is_owned_receiver:
                if not self._owned_receiver_enabled:
                    continue
            elif is_canary:
                if canary is not None:
                    pass
                elif self._owned_receiver_enabled or callback:
                    continue
                else:
                    # With no active verifier, keep the existing passive
                    # reviewed-coordinate flow for manual observations.
                    candidate = replace(
                        candidate,
                        routing_capability_id="",
                        analysis_strategy_id="",
                    )
            elif canary is not None or self._owned_receiver_enabled:
                continue
            selected.append(replace(
                decision,
                candidate=replace(
                    candidate,
                    exploration_parameters=(registration.parameter,),
                ),
            ))
        return (*base, *callback, *selected)
