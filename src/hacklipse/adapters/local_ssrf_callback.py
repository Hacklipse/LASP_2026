"""Local callback receiver for explicitly authorized SSRF tests."""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, ip_address
from urllib.parse import urlsplit
from uuid import uuid4

from hacklipse.ports.ssrf_callback import SsrfCallbackHit, SsrfCallbackTicket


class LocalSsrfCallbackService:
    """Own the callback listener; the Analysis LLM never receives server access."""

    def __init__(
        self, *, port: int = 0, ticket_ttl_seconds: int = 300,
        advertised_host: str = "127.0.0.1", bind_host: str = "127.0.0.1",
    ) -> None:
        try:
            bind_address = ip_address(bind_host)
        except ValueError as error:
            raise ValueError("local SSRF listener bind host must be an IPv4 address") from error
        if (
            not 0 <= port <= 65535 or not 1 <= ticket_ttl_seconds <= 3600
            or advertised_host not in {"127.0.0.1", "host.docker.internal"}
            or not isinstance(bind_address, IPv4Address)
            or bind_address.is_unspecified
            or not (bind_address.is_loopback or bind_address.is_private)
            or (advertised_host == "127.0.0.1" and bind_host != "127.0.0.1")
        ):
            raise ValueError("invalid local SSRF callback listener settings")
        self._condition = threading.Condition()
        self._tickets: dict[str, SsrfCallbackTicket] = {}
        self._tokens: dict[str, SsrfCallbackTicket] = {}
        self._hits: dict[str, list[SsrfCallbackHit]] = {}
        self._ttl = timedelta(seconds=ticket_ttl_seconds)
        self._closed = False
        self._issue_calls = 0
        self._poll_calls = 0
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                service._receive(self)

            def do_HEAD(self) -> None:
                service._receive(self)

            def do_POST(self) -> None:
                self.send_error(405)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer((bind_host, port), Handler)
        self._server.daemon_threads = True
        # Docker Desktop can forward to loopback; Linux can bind a bridge address.
        self.origin = f"http://{advertised_host}:{self._server.server_port}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="ssrf-callback", daemon=True,
        )
        self._thread.start()

    @property
    def public_oast(self) -> bool:
        return False

    @property
    def operator_owned(self) -> bool:
        """Permit explicit reuse as a local-research owned receiver.

        Merely constructing this service as the public callback provider does
        not enable that path; bootstrap requires a separate explicit
        ``ssrf_owned_receiver_service`` injection.
        """

        return True

    def issue(self, idempotency_key: str) -> SsrfCallbackTicket:
        if not idempotency_key:
            raise ValueError("callback ticket key is required")
        with self._condition:
            if self._closed:
                raise OSError("callback listener is closed")
            if self._issue_calls >= 256:
                raise OSError("callback issue call limit reached")
            self._issue_calls += 1
            existing = self._tickets.get(idempotency_key)
            if existing is not None:
                return existing
            if len(self._tickets) >= 256:
                raise OSError("callback ticket limit reached")
            token = secrets.token_urlsafe(24)
            ticket = SsrfCallbackTicket(
                token=token, url=f"{self.origin}/ssrf/{token}",
                issued_at=datetime.now(timezone.utc),
            )
            self._tickets[idempotency_key] = ticket
            self._tokens[token] = ticket
            return ticket

    def poll(self, token: str, *, timeout_seconds: float) -> tuple[SsrfCallbackHit, ...]:
        if not 0 < timeout_seconds <= 2:
            raise ValueError("callback poll deadline must be at most two seconds")
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            if self._poll_calls >= 256:
                raise TimeoutError("callback poll call limit reached")
            self._poll_calls += 1
            while not self._hits.get(token):
                self._require_live_ticket(token)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            self._require_live_ticket(token)
            return tuple(self._hits.get(token, ()))

    @property
    def usage(self) -> tuple[int, int]:
        """Return issue/poll calls separately from target HTTP request budget."""

        with self._condition:
            return self._issue_calls, self._poll_calls

    def discard(self, token: str) -> None:
        """Forget one terminal Run ticket and any received callback metadata."""

        with self._condition:
            self._tokens.pop(token, None)
            self._hits.pop(token, None)
            for key, ticket in tuple(self._tickets.items()):
                if ticket.token == token:
                    self._tickets.pop(key, None)
            self._condition.notify_all()

    def _require_live_ticket(self, token: str) -> None:
        ticket = self._tokens.get(token)
        if self._closed or ticket is None or datetime.now(timezone.utc) > ticket.issued_at + self._ttl:
            raise TimeoutError("callback ticket is unavailable or expired")

    def _receive(self, handler: BaseHTTPRequestHandler) -> None:
        path = urlsplit(handler.path)
        token = path.path.removeprefix("/ssrf/") if path.path.startswith("/ssrf/") else ""
        with self._condition:
            ticket = self._tokens.get(token)
            valid = (
                not self._closed and ticket is not None
                and path.path == f"/ssrf/{token}" and not path.query and not path.fragment
                and datetime.now(timezone.utc) <= ticket.issued_at + self._ttl
            )
            if valid:
                hits = self._hits.setdefault(token, [])
                if len(hits) < 8:
                    hits.append(SsrfCallbackHit(
                        event_id=f"event-{uuid4()}", token=token, protocol="http",
                        received_at=datetime.now(timezone.utc), method=handler.command,
                        source=handler.client_address[0],
                    ))
                    self._condition.notify_all()
        handler.send_response(204 if valid else 404)
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._tickets.clear()
            self._tokens.clear()
            self._hits.clear()
            self._condition.notify_all()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def __enter__(self) -> LocalSsrfCallbackService:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
