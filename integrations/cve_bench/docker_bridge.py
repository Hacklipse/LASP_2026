"""Expose one container TCP endpoint on loopback without Docker port publishing.

Docker Desktop can accept a Compose ``ports`` declaration without making the
port reachable from macOS.  This bridge keeps that compatibility concern in the
benchmark adapter: each local connection is relayed through ``docker exec nc``.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import socket
import socketserver
import subprocess
import threading
from dataclasses import dataclass


class _BridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, container: str, remote_host: str, remote_port: int):
        self.container = container
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.http_host = f"{remote_host}:{remote_port}".encode("ascii")
        super().__init__(("127.0.0.1", 0), _BridgeHandler)


class _BridgeHandler(socketserver.BaseRequestHandler):
    server: _BridgeServer

    def handle(self) -> None:
        command = [
            "docker",
            "exec",
            "-i",
            self.server.container,
            "nc",
            self.server.remote_host,
            str(self.server.remote_port),
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert process.stdin is not None
        assert process.stdout is not None

        def client_to_container() -> None:
            try:
                first = True
                buffered = bytearray()
                while data := self.request.recv(64 * 1024):
                    if first:
                        buffered.extend(data)
                        if b"\r\n\r\n" not in buffered and len(buffered) <= 64 * 1024:
                            continue
                        data = bytes(buffered)
                        header, separator, rest = data.partition(b"\r\n\r\n")
                        header = re.sub(
                            rb"(?im)^Host:[ \t]*[^\r\n]+(?=\r?$)",
                            b"Host: " + self.server.http_host,
                            header,
                            count=1,
                        )
                        data = header + separator + rest
                        first = False
                    process.stdin.write(data)
                    process.stdin.flush()
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    process.stdin.close()

        upload = threading.Thread(target=client_to_container, daemon=True)
        upload.start()
        try:
            while data := os.read(process.stdout.fileno(), 64 * 1024):
                self.request.sendall(data)
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                self.request.shutdown(socket.SHUT_RDWR)
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=2)
            if process.poll() is None:
                process.kill()


@dataclass
class DockerTcpBridge:
    """Lifecycle wrapper for a loopback-only container TCP bridge."""

    container: str
    remote_port: int
    remote_host: str = "127.0.0.1"

    def __post_init__(self) -> None:
        if shutil.which("docker") is None:
            raise RuntimeError("docker executable is required")
        self._server = _BridgeServer(
            self.container, self.remote_host, self.remote_port
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"docker-bridge-{self.container}-{self.remote_port}",
            daemon=True,
        )

    @property
    def local_port(self) -> int:
        return int(self._server.server_address[1])

    def __enter__(self) -> "DockerTcpBridge":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3)
