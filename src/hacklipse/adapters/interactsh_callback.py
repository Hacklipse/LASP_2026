"""Bounded Interactsh CLI bridge; raw OAST traffic never enters agent context."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from hacklipse.ports.ssrf_callback import (
    SsrfCallbackHit, SsrfCallbackTicket, callback_url_matches_origin,
)

_HOST = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z")
_MAX_TICKETS = 64
_MAX_LINE = 65536


class InteractshCliCallbackService:
    """Own one registered Interactsh session and preallocated unique hostnames.

    The external client is only started after an explicit Run-level OAST choice.
    A lost client session is an error, never evidence of a healthy no-hit.
    """

    poll_wait_seconds = 10.0

    def __init__(
        self, *, server: str, callback_domain: str | None = None,
        token: str = "", binary: str = "interactsh-client",
        startup_timeout_seconds: float = 20.0,
    ) -> None:
        parsed = urlsplit(server if "://" in server else f"https://{server}")
        domain = (parsed.hostname or "").casefold()
        callback_domain = (callback_domain or domain).casefold()
        try:
            is_ip = bool(ip_address(domain)) or bool(ip_address(callback_domain))
        except ValueError:
            is_ip = False
        if (
            parsed.scheme != "https" or parsed.port is not None or not _HOST.fullmatch(domain)
            or is_ip or domain.endswith((".local", ".localhost"))
            or callback_domain.endswith((".local", ".localhost"))
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or not _HOST.fullmatch(callback_domain) or not 0 < startup_timeout_seconds <= 30
            or len(token) > 4096 or any(char in token for char in "\n\r\x00")
        ):
            raise ValueError("Interactsh requires a single HTTPS DNS server and callback domain")
        resolved_binary = shutil.which(binary)
        if resolved_binary is None:
            raise OSError("interactsh-client is not installed")
        self.origin = f"https://{callback_domain}"
        self._condition = threading.Condition()
        self._tickets: dict[str, SsrfCallbackTicket] = {}
        self._hits: dict[str, list[SsrfCallbackHit]] = {}
        self._closed = False
        self._reader_closed = False
        self._provider_failed = False
        self._issue_calls = 0
        self._poll_calls = 0
        self._temp = tempfile.TemporaryDirectory(prefix="hacklipse-interactsh-")
        payload_path = Path(self._temp.name) / "payloads"
        config_path = Path(self._temp.name) / "config.yaml"
        # Config keeps the protected-server token out of the process command line.
        descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            if token:
                stream.write("token: " + json.dumps(token) + "\n")
        args = [
            resolved_binary, "-server", domain, "-auth=false", "-config", str(config_path),
            "-disable-update-check", "-no-http-fallback", "-json",
            "-poll-interval", "1", "-number", str(_MAX_TICKETS),
            "-payload-store", "-payload-store-file", str(payload_path),
        ]
        try:
            self._process = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1,
            )
            deadline = time.monotonic() + startup_timeout_seconds
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    raise OSError("Interactsh registration failed")
                if payload_path.exists():
                    hosts = payload_path.read_text(encoding="utf-8").splitlines()
                    if len(hosts) == _MAX_TICKETS:
                        break
                time.sleep(0.05)
            else:
                raise TimeoutError("Interactsh registration timed out")
            if len(set(hosts)) != _MAX_TICKETS or any(
                not _HOST.fullmatch(host) or not host.endswith("." + callback_domain)
                or not callback_url_matches_origin(f"https://{host}/", self.origin)
                for host in hosts
            ):
                raise OSError("Interactsh issued an unexpected callback domain")
            self._available = tuple(hosts)
            self._reader = threading.Thread(
                target=self._read_stdout, name="interactsh-events", daemon=True,
            )
            self._error_reader = threading.Thread(
                target=self._read_stderr, name="interactsh-status", daemon=True,
            )
            self._reader.start()
            self._error_reader.start()
        except BaseException:
            self.close()
            raise
        finally:
            config_path.unlink(missing_ok=True)
            payload_path.unlink(missing_ok=True)

    def issue(self, idempotency_key: str) -> SsrfCallbackTicket:
        if not idempotency_key:
            raise ValueError("callback ticket key is required")
        with self._condition:
            self._require_healthy()
            if self._issue_calls >= 256:
                raise OSError("Interactsh issue call limit reached")
            self._issue_calls += 1
            existing = self._tickets.get(idempotency_key)
            if existing is not None:
                return existing
            if len(self._tickets) >= len(self._available):
                raise OSError("Interactsh ticket limit reached")
            assigned = {
                urlsplit(item.url).hostname for item in self._tickets.values()
            }
            host = next(item for item in self._available if item not in assigned)
            ticket = SsrfCallbackTicket(
                token=host.split(".", 1)[0], url=f"https://{host}/",
                issued_at=datetime.now(timezone.utc),
            )
            self._tickets[idempotency_key] = ticket
            return ticket

    def poll(self, token: str, *, timeout_seconds: float) -> tuple[SsrfCallbackHit, ...]:
        if not 0 < timeout_seconds <= self.poll_wait_seconds:
            raise ValueError("callback poll deadline exceeds the Interactsh limit")
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            if token not in {item.token for item in self._tickets.values()}:
                raise TimeoutError("unknown Interactsh ticket")
            if self._poll_calls >= 256:
                raise TimeoutError("Interactsh poll call limit reached")
            self._poll_calls += 1
            # A DNS lookup often precedes the HTTP fetch; keep waiting for HTTP.
            while not any(hit.protocol == "http" for hit in self._hits.get(token, ())):
                self._require_healthy()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            self._require_healthy()
            return tuple(self._hits.get(token, ()))

    @property
    def usage(self) -> tuple[int, int]:
        with self._condition:
            return self._issue_calls, self._poll_calls

    def discard(self, token: str) -> None:
        """Forget one terminal Run ticket and buffered OAST metadata."""

        with self._condition:
            self._hits.pop(token, None)
            discarded_hosts: set[str] = set()
            for key, ticket in tuple(self._tickets.items()):
                if ticket.token == token:
                    host = urlsplit(ticket.url).hostname
                    if host is not None:
                        discarded_hosts.add(host)
                    self._tickets.pop(key, None)
            self._available = tuple(
                host for host in self._available if host not in discarded_hosts
            )
            self._condition.notify_all()

    def _require_healthy(self) -> None:
        if (
            self._closed or self._reader_closed or self._provider_failed
            or self._process.poll() is not None
        ):
            raise OSError("Interactsh callback session is unavailable")

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        while True:
            line = self._process.stderr.readline(_MAX_LINE + 1)
            if not line:
                return
            if "ERR" in line or "FTL" in line:
                with self._condition:
                    self._provider_failed = True
                    self._condition.notify_all()

    def _read_stdout(self) -> None:
        try:
            assert self._process.stdout is not None
            while True:
                line = self._process.stdout.readline(_MAX_LINE + 1)
                if not line:
                    break
                if len(line) > _MAX_LINE or not line.endswith("\n"):
                    while line and not line.endswith("\n"):
                        line = self._process.stdout.readline(_MAX_LINE + 1)
                    continue
                self._record_interaction(line)
        finally:
            with self._condition:
                self._reader_closed = True
                self._condition.notify_all()

    def _record_interaction(self, line: str) -> None:
        try:
            record = json.loads(line)
            token = record["full-id"]
            protocol = record["protocol"]
            if protocol not in {"http", "https", "dns"}:
                return
            when = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
            if when.tzinfo is None:
                return
            raw_request = record.get("raw-request", "")
            method = raw_request.split(" ", 1)[0] if protocol in {"http", "https"} else ""
            if protocol in {"http", "https"} and method not in {"GET", "HEAD"}:
                return
            source = record.get("remote-address", "")
            if not isinstance(token, str) or not isinstance(source, str):
                return
            hit = SsrfCallbackHit(
                event_id=hashlib.sha256(line.encode()).hexdigest(), token=token,
                protocol="http" if protocol in {"http", "https"} else "dns",
                received_at=when, method=method, source=source,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return
        with self._condition:
            if token not in {item.token for item in self._tickets.values()}:
                return
            hits = self._hits.setdefault(token, [])
            if all(item.event_id != hit.event_id for item in hits):
                if len(hits) < 8:
                    hits.append(hit)
                elif hit.protocol == "http" and not any(item.protocol == "http" for item in hits):
                    # DNS chatter must not consume every evidence slot before HTTP arrives.
                    hits[-1] = hit
                else:
                    return
                self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._tickets.clear()
            self._hits.clear()
            self._available = ()
            self._condition.notify_all()
        process = getattr(self, "_process", None)
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        reader = getattr(self, "_reader", None)
        if reader is not None:
            reader.join(timeout=2)
        error_reader = getattr(self, "_error_reader", None)
        if error_reader is not None:
            error_reader.join(timeout=2)
        self._temp.cleanup()

    def __enter__(self) -> InteractshCliCallbackService:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
