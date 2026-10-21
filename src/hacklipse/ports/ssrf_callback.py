"""운영자가 등록한 SSRF callback 서비스의 최소 계약."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, Sequence
from urllib.parse import urlsplit

from hacklipse.domain import ServerRequestObservation, SsrfObservationProviderStatus


@dataclass(frozen=True, slots=True)
class SsrfCallbackTicket:
    token: str
    url: str
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class SsrfCallbackHit:
    event_id: str
    token: str
    protocol: Literal["http", "dns"]
    received_at: datetime
    method: str = ""
    source: str = ""


class SsrfCallbackService(Protocol):
    """issue는 같은 key에 같은 ticket을 돌려줘야 재개 시 탐침이 바뀌지 않는다."""

    origin: str

    def issue(self, idempotency_key: str) -> SsrfCallbackTicket: ...

    def poll(self, token: str, *, timeout_seconds: float) -> Sequence[SsrfCallbackHit]: ...

    def discard(self, token: str) -> None: ...


class OwnedSsrfReceiverService(Protocol):
    """Operator-controlled receiver used only for explicit internal research.

    The shape intentionally mirrors :class:`SsrfCallbackService`, but the
    separate Port is a trust boundary: a public OAST client must never become a
    verified internal receiver merely because it happens to implement
    ``issue`` and ``poll``.
    """

    origin: str

    @property
    def operator_owned(self) -> bool: ...

    def issue(self, idempotency_key: str) -> SsrfCallbackTicket: ...

    def poll(self, token: str, *, timeout_seconds: float) -> Sequence[SsrfCallbackHit]: ...

    def discard(self, token: str) -> None: ...


class ServerRequestObservationProvider(Protocol):
    """Read sanitized operator observations without initiating network activity."""

    @property
    def status(self) -> SsrfObservationProviderStatus: ...

    def list_observations(
        self, *, run_id: str, surface_id: str, parameter: str
    ) -> Sequence[ServerRequestObservation]: ...


def callback_url_matches_origin(url: str, origin: str) -> bool:
    """Allow an exact origin or its HTTPS subdomain; never a lookalike suffix."""

    try:
        callback, registered = urlsplit(url), urlsplit(origin)
        host, base = (callback.hostname or "").casefold(), (registered.hostname or "").casefold()
        if (
            not host or not base or callback.scheme != registered.scheme
            or callback.port != registered.port or callback.username is not None
            or callback.password is not None or callback.query or callback.fragment
        ):
            return False
        return host == base or (
            registered.scheme == "https" and host.endswith("." + base)
        )
    except ValueError:
        return False
