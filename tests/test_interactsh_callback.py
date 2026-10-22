"""Interactsh CLI transport is inert in tests; no public OAST connection occurs."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from hacklipse.adapters.interactsh_callback import InteractshCliCallbackService


class _BlockingOutput:
    def __init__(self) -> None:
        self._lines: queue.Queue[str] = queue.Queue()

    def readline(self, size: int = -1) -> str:
        return self._lines.get(timeout=3)

    def close(self) -> None:
        self._lines.put("")

    def send(self, line: str) -> None:
        self._lines.put(line)


class _FakeProcess:
    def __init__(self, args: list[str], *, hosts_domain: str = "oast.example") -> None:
        self.args = args
        self.stdout = _BlockingOutput()
        self.stderr = _BlockingOutput()
        self.alive = True
        self.config = Path(args[args.index("-config") + 1]).read_text()
        self.config_mode = os.stat(args[args.index("-config") + 1]).st_mode & 0o777
        path = Path(args[args.index("-payload-store-file") + 1])
        path.write_text("".join(
            f"ticket{i:03d}.{hosts_domain}\n" for i in range(64)
        ))

    def poll(self) -> int | None:
        return None if self.alive else 0

    def terminate(self) -> None:
        self.alive = False
        self.stdout.close()
        self.stderr.close()

    def wait(self, *, timeout: float) -> int:
        return 0

    def kill(self) -> None:
        self.terminate()


class InteractshCallbackTests(unittest.TestCase):
    def test_private_token_is_not_in_argv_and_a_b_hosts_are_independent(self) -> None:
        processes: list[_FakeProcess] = []

        def fake_popen(args, **kwargs):
            process = _FakeProcess(args)
            processes.append(process)
            return process

        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen", side_effect=fake_popen,
        ), InteractshCliCallbackService(
            server="https://oast.example", public_oast=False,
            token="private-secret",
        ) as service:
            first = service.issue("run:candidate:analysis")
            self.assertEqual(first, service.issue("run:candidate:analysis"))
            second = service.issue("run:candidate:validation")
            self.assertNotEqual(first.token, second.token)
            self.assertNotEqual(first.url, second.url)
            self.assertEqual(service.origin, "https://oast.example")
            self.assertFalse(service.public_oast)
            self.assertNotIn("private-secret", " ".join(processes[0].args))
            self.assertIn("private-secret", processes[0].config)
            self.assertEqual(processes[0].config_mode, 0o600)
            self.assertIn("-no-http-fallback", processes[0].args)
            self.assertIn("-disable-update-check", processes[0].args)
            self.assertFalse(Path(processes[0].args[processes[0].args.index("-config") + 1]).exists())

            service._record_interaction(json.dumps({
                "full-id": first.token, "protocol": "https",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw-request": "GET / HTTP/1.1\r\nHost: ticket000.oast.example\r\n",
                "remote-address": "192.0.2.11",
            }) + "\n")
            hits = service.poll(first.token, timeout_seconds=0.1)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0].protocol, "http")
            self.assertEqual(hits[0].method, "GET")
            self.assertEqual(service.poll(second.token, timeout_seconds=0.01), ())
        self.assertFalse(processes[0].alive)

    def test_unexpected_provider_domain_fails_before_any_probe(self) -> None:
        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen",
            side_effect=lambda args, **kwargs: _FakeProcess(args, hosts_domain="evil.test"),
        ), self.assertRaisesRegex(OSError, "unexpected callback domain"):
            InteractshCliCallbackService(server="oast.example", public_oast=False)

    def test_provider_polling_error_is_not_reported_as_no_hit(self) -> None:
        processes: list[_FakeProcess] = []

        def fake_popen(args, **kwargs):
            process = _FakeProcess(args)
            processes.append(process)
            return process

        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen", side_effect=fake_popen,
        ), InteractshCliCallbackService(
            server="oast.example", public_oast=False,
        ) as service:
            ticket = service.issue("run:candidate:analysis")
            processes[0].stderr.send("[ERR] Could not poll Interactsh server\n")
            with self.assertRaisesRegex(OSError, "unavailable"):
                service.poll(ticket.token, timeout_seconds=0.2)

    def test_dns_does_not_end_poll_before_delayed_http(self) -> None:
        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen", side_effect=lambda args, **kwargs: _FakeProcess(args),
        ), InteractshCliCallbackService(
            server="oast.example", public_oast=False,
        ) as service:
            ticket = service.issue("run:candidate:analysis")
            now = datetime.now(timezone.utc).isoformat()
            service._record_interaction(json.dumps({
                "full-id": ticket.token, "protocol": "dns", "timestamp": now,
                "remote-address": "192.0.2.1",
            }) + "\n")
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(service.poll, ticket.token, timeout_seconds=0.5)
                time.sleep(0.05)
                self.assertFalse(result.done())
                service._record_interaction(json.dumps({
                    "full-id": ticket.token, "protocol": "http",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "raw-request": "GET / HTTP/1.1\r\n", "remote-address": "192.0.2.2",
                }) + "\n")
                self.assertEqual(
                    {hit.protocol for hit in result.result(timeout=1)}, {"dns", "http"},
                )

    def test_dns_only_waits_until_deadline_and_cannot_fill_http_slots(self) -> None:
        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen", side_effect=lambda args, **kwargs: _FakeProcess(args),
        ), InteractshCliCallbackService(
            server="oast.example", public_oast=False,
        ) as service:
            ticket = service.issue("run:candidate:analysis")
            for index in range(8):
                service._record_interaction(json.dumps({
                    "full-id": ticket.token, "protocol": "dns",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "remote-address": f"192.0.2.{index + 1}",
                }) + "\n")
            started = time.monotonic()
            self.assertEqual(len(service.poll(ticket.token, timeout_seconds=0.05)), 8)
            self.assertGreaterEqual(time.monotonic() - started, 0.04)
            service._record_interaction(json.dumps({
                "full-id": ticket.token, "protocol": "http",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw-request": "HEAD / HTTP/1.1\r\n", "remote-address": "192.0.2.20",
            }) + "\n")
            hits = service.poll(ticket.token, timeout_seconds=0.05)
            self.assertEqual(len(hits), 8)
            self.assertIn("http", {hit.protocol for hit in hits})

    def test_unprotected_private_server_needs_no_token(self) -> None:
        processes: list[_FakeProcess] = []

        def fake_popen(args, **kwargs):
            process = _FakeProcess(args)
            processes.append(process)
            return process

        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen", side_effect=fake_popen,
        ), InteractshCliCallbackService(
            server="oast.example", public_oast=False,
        ) as service:
            self.assertEqual(processes[0].config, "")
            self.assertNotIn("-token", processes[0].args)
            self.assertEqual(service.poll_wait_seconds, 10.0)

    def test_discard_forgets_ticket_hits_and_never_reuses_its_session_host(self) -> None:
        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen", side_effect=lambda args, **kwargs: _FakeProcess(args),
        ), InteractshCliCallbackService(
            server="oast.example", public_oast=False,
        ) as service:
            first = service.issue("run-1:analysis")
            service._record_interaction(json.dumps({
                "full-id": first.token, "protocol": "http",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw-request": "GET / HTTP/1.1\r\n", "remote-address": "192.0.2.2",
            }) + "\n")

            service.discard(first.token)

            with self.assertRaisesRegex(TimeoutError, "unknown"):
                service.poll(first.token, timeout_seconds=0.01)
            second = service.issue("run-2:analysis")
            self.assertNotEqual(first.token, second.token)
            self.assertNotIn(first.token, repr((service._tickets, service._hits)))

    def test_bad_server_and_missing_binary_are_rejected_without_contact(self) -> None:
        with self.assertRaises(ValueError):
            InteractshCliCallbackService(
                server="http://oast.example", public_oast=False,
            )
        with patch("shutil.which", return_value=None), self.assertRaises(OSError):
            InteractshCliCallbackService(server="oast.example", public_oast=False)

    def test_public_oast_requires_construction_consent_before_process_start(self) -> None:
        with patch("shutil.which") as which, patch("subprocess.Popen") as popen:
            with self.assertRaisesRegex(ValueError, "explicit construction consent"):
                InteractshCliCallbackService(
                    server="oast.example", public_oast=True,
                )
        which.assert_not_called()
        popen.assert_not_called()

        with patch("shutil.which", return_value="/fake/interactsh-client"), patch(
            "subprocess.Popen",
            side_effect=lambda args, **kwargs: _FakeProcess(args),
        ), InteractshCliCallbackService(
            server="oast.example", public_oast=True,
            public_oast_consent=True,
        ) as service:
            self.assertTrue(service.public_oast)


if __name__ == "__main__":
    unittest.main()
