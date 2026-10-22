"""Network-free provider for operator-owned SSRF request observations."""

from __future__ import annotations

from collections.abc import Iterable
from threading import RLock

from hacklipse.domain import (
    ServerRequestObservation,
    SsrfObservationProviderStatus,
)


class InMemoryServerRequestObservationProvider:
    """Store sanitized observations and deduplicate idempotent submissions."""

    def __init__(
        self,
        observations: Iterable[ServerRequestObservation] = (),
        *,
        status: SsrfObservationProviderStatus = SsrfObservationProviderStatus.AVAILABLE,
    ) -> None:
        self._lock = RLock()
        self._status = SsrfObservationProviderStatus(status)
        self._observations: dict[str, ServerRequestObservation] = {}
        for observation in observations:
            self.add(observation)

    @property
    def status(self) -> SsrfObservationProviderStatus:
        with self._lock:
            return self._status

    def set_status(self, status: SsrfObservationProviderStatus) -> None:
        with self._lock:
            self._status = SsrfObservationProviderStatus(status)

    def add(self, observation: ServerRequestObservation) -> None:
        if not isinstance(observation, ServerRequestObservation):
            raise TypeError("SSRF observation must use the sanitized domain contract")
        with self._lock:
            existing = self._observations.get(observation.observation_id)
            if existing is not None and existing != observation:
                raise ValueError("SSRF observation id already has different content")
            self._observations[observation.observation_id] = observation

    def list_observations(
        self, *, run_id: str, surface_id: str, parameter: str
    ) -> tuple[ServerRequestObservation, ...]:
        with self._lock:
            matches = (
                item
                for item in self._observations.values()
                if item.run_id == run_id
                and item.surface_id == surface_id
                and item.parameter == parameter
            )
            return tuple(sorted(matches, key=lambda item: (item.observed_at, item.observation_id)))
