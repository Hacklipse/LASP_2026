"""URL allowlist와 안전 HTTP method를 검사하는 정책 Adapter."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit

from hacklipse.domain import (
    ExecutionRequest, HttpRequestKind, Run, RunRequest, RunScope,
    SsrfCanaryProofTarget,
)
from hacklipse.domain.models import ssrf_csv_upload_parameter, ssrf_request_parameters
from hacklipse.ports import ApprovalGate
from hacklipse.ports.errors import ApprovalRequired, PolicyViolation
from hacklipse.ports.ssrf_callback import callback_url_matches_origin

from .request_safety import has_state_changing_get
from .security import DenyAllApprovalGate
from .path_traversal_analysis import (
    PATH_TRAVERSAL_TOOL,
    validate_path_traversal_request,
)
from .access_control_analysis import (
    ACCESS_CONTROL_TOOL,
    validate_access_control_request,
)
from .ssti_analysis import SSTI_TOOL, validate_ssti_request
from .xss_execution import BROWSER_XSS_TOOL, validate_browser_xss_request


class AllowlistPolicyGate:
    """네트워크 요청 없이 문자열 수준에서 대상 Scope를 강제한다."""

    # safe 프로필에서는 서버 상태를 바꿀 가능성이 낮은 메서드만 허용한다.
    _safe_methods = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(
        self, approval_gate: ApprovalGate | None = None,
        *, ssrf_callback_origin: str | None = None,
        ssrf_local_test_mode: bool = False,
        ssrf_canary_proof: SsrfCanaryProofTarget | None = None,
        ssrf_owned_receiver_origin: str | None = None,
    ) -> None:
        self._approval = approval_gate or DenyAllApprovalGate()
        self._ssrf_local_test_mode = ssrf_local_test_mode
        self._ssrf_canary_proof = ssrf_canary_proof
        self._ssrf_run_canaries: dict[str, SsrfCanaryProofTarget] = {}
        self._ssrf_owned_receiver_origin = None
        self._ssrf_owned_receiver_tickets: dict[
            str, dict[str, tuple[str, str]]
        ] = {}
        if ssrf_callback_origin is not None:
            parsed = urlsplit(ssrf_callback_origin)
            host = (parsed.hostname or "").casefold().rstrip(".")
            try:
                is_ip_literal = bool(ip_address(host))
            except ValueError:
                is_ip_literal = False
            local_origin = (
                ssrf_local_test_mode and parsed.scheme == "http"
                and host in {"127.0.0.1", "host.docker.internal"}
                and parsed.port is not None
            )
            if (
                not (parsed.scheme == "https" and not is_ip_literal
                     and host != "localhost" and not host.endswith((".localhost", ".local")))
                and not local_origin
            ) or (
                not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            ):
                raise ValueError(
                    "SSRF callback origin must be public HTTPS or explicit loopback test HTTP"
                )
            # shortcut: origin-only gating cannot prove a ticket was issued; bind
            # issued tokens when the callback service adapter is connected.
            self._ssrf_callback_origin = ssrf_callback_origin.rstrip("/")
        else:
            self._ssrf_callback_origin = None
        if ssrf_owned_receiver_origin is not None:
            parsed = urlsplit(ssrf_owned_receiver_origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "owned SSRF receiver must expose a plain HTTP(S) origin"
                )
            self._ssrf_owned_receiver_origin = ssrf_owned_receiver_origin.rstrip("/")

    def register_ssrf_canary_proof(
        self, run_id: str, canary: SsrfCanaryProofTarget,
    ) -> None:
        """Keep a late operator approval scoped to one Run."""

        existing = self._ssrf_run_canaries.get(run_id)
        if existing is not None and existing != canary:
            raise ValueError("SSRF canary was already bound to this Run")
        self._ssrf_run_canaries[run_id] = canary

    def discard_ssrf_run_secrets(self, run_id: str) -> None:
        """Drop exact canary material once the owning Run is terminal."""

        self._ssrf_run_canaries.pop(run_id, None)
        self._ssrf_owned_receiver_tickets.pop(run_id, None)
        self._ssrf_canary_proof = None

    def register_ssrf_owned_receiver_ticket(
        self, run_id: str, surface_id: str, parameter: str, url: str,
    ) -> None:
        """Allow exactly one centrally issued receiver URL at one coordinate."""

        if (
            self._ssrf_owned_receiver_origin is None
            or not callback_url_matches_origin(
                url, self._ssrf_owned_receiver_origin,
            )
            or not run_id
            or not surface_id
            or not parameter
        ):
            raise PolicyViolation("owned SSRF receiver ticket is invalid")
        tickets = self._ssrf_owned_receiver_tickets.setdefault(run_id, {})
        binding = (surface_id, parameter)
        existing = tickets.get(url)
        if existing is not None and existing != binding:
            raise PolicyViolation(
                "owned SSRF receiver ticket is bound to another coordinate"
            )
        tickets[url] = binding

    def validate_run(self, request: RunRequest) -> None:
        """Run 시작 대상이 선언된 Scope 안에 있는지 검사한다."""

        self._validate_url(request.target_url, request.scope)

    def validate_execution(self, run: Run, request: ExecutionRequest) -> None:
        """실행 직전 Run 소유권, URL Scope, HTTP method 정책을 검사한다."""

        if request.run_id != run.run_id:
            raise PolicyViolation("execution request belongs to another run")
        if (
            request.tool == "http_delete"
            and request.request_kind is not HttpRequestKind.SSRF_WORKFLOW_CLEANUP
        ) or (
            request.request_kind is HttpRequestKind.SSRF_WORKFLOW_CLEANUP
            and request.tool != "http_delete"
        ):
            raise PolicyViolation("HTTP DELETE is reserved for SSRF workflow cleanup")
        if request.request_kind is HttpRequestKind.SSRF_PROBE:
            ssrf_pairs = ssrf_request_parameters(
                request.method, request.query_parameters, request.headers, request.body,
            )
            callbacks = [
                value for _, value in ssrf_pairs
                if value.startswith((
                    "https://", "http://127.0.0.1:",
                    "http://host.docker.internal:",
                ))
            ]
            if (
                request.tool != (
                    "http_post" if request.method.upper() == "POST" else "http_get"
                ) or request.method.upper() not in {"GET", "POST"}
                or self._ssrf_callback_origin is None or len(callbacks) != 1
                or not callback_url_matches_origin(callbacks[0], self._ssrf_callback_origin)
            ):
                raise PolicyViolation("SSRF probe requires the registered callback origin")
            if self._ssrf_local_test_mode and self._ssrf_callback_origin.startswith("http://"):
                target_host = (urlsplit(run.target_url).hostname or "").casefold()
                allowed = {host.casefold() for host in run.scope.allowed_hosts}
                if target_host not in {"localhost", "127.0.0.1"} or not allowed.issubset(
                    {"localhost", "127.0.0.1"}
                ):
                    raise PolicyViolation("loopback callback is limited to loopback targets")
        if request.request_kind is HttpRequestKind.SSRF_CANARY_PROBE:
            canary = self._ssrf_run_canaries.get(run.run_id, self._ssrf_canary_proof)
            if (
                canary is None or request.surface_id != canary.surface_id
                or request.tool != "http_get"
                or request.method.upper() != "GET"
                or sum(value == canary.url for _, value in request.query_parameters) != 1
                or any(value.startswith(("http://", "https://")) and value != canary.url
                       for _, value in request.query_parameters)
            ):
                raise PolicyViolation("SSRF canary probe requires the approved exact URL")
        if request.request_kind in {
            HttpRequestKind.SSRF_OWNED_RECEIVER_PROBE,
            HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE,
        }:
            receiver_values = [
                (name, value) for name, value in ssrf_request_parameters(
                    request.method, request.query_parameters, request.headers, request.body,
                    allow_companions=(
                        request.request_kind is HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE
                    ),
                )
                if value.startswith(("http://", "https://"))
            ]
            tickets = self._ssrf_owned_receiver_tickets.get(run.run_id, {})
            if (
                request.tool != (
                    "http_post" if request.method.upper() == "POST" else "http_get"
                )
                or request.method.upper() not in {"GET", "POST"}
                or len(receiver_values) != 1
                or tickets.get(receiver_values[0][1])
                != (request.surface_id, receiver_values[0][0])
                or any(
                    value.startswith(("http://", "https://"))
                    and value != receiver_values[0][1]
                    for _, value in ssrf_request_parameters(
                        request.method, request.query_parameters,
                        request.headers, request.body,
                        allow_companions=(
                            request.request_kind is HttpRequestKind.SSRF_WORKFLOW_OWNED_PROBE
                        ),
                    )
                )
            ):
                raise PolicyViolation(
                    "SSRF owned-receiver probe requires its exact issued ticket"
                )
        if request.request_kind is HttpRequestKind.SSRF_CSV_UPLOAD_PROBE:
            coordinate = ssrf_csv_upload_parameter(
                request.method, request.headers, request.body,
            )
            tickets = self._ssrf_owned_receiver_tickets.get(run.run_id, {})
            if (
                request.tool != "http_post" or coordinate is None
                or tickets.get(coordinate[1])
                != (request.surface_id, coordinate[0])
            ):
                raise PolicyViolation("SSRF CSV upload requires its exact issued ticket")
        if request.tool == BROWSER_XSS_TOOL:
            if request.scope != run.scope:
                raise PolicyViolation("browser execution scope does not match its run")
            try:
                validate_browser_xss_request(request)
            except ValueError as error:
                raise PolicyViolation(str(error)) from error
        if request.tool == ACCESS_CONTROL_TOOL:
            try:
                validate_access_control_request(request)
            except ValueError as error:
                raise PolicyViolation(str(error)) from error
        if request.tool == PATH_TRAVERSAL_TOOL:
            try:
                validate_path_traversal_request(request)
            except ValueError as error:
                raise PolicyViolation(str(error)) from error
        if request.tool == SSTI_TOOL:
            try:
                validate_ssti_request(request)
            except ValueError as error:
                raise PolicyViolation(str(error)) from error
        # 구조화 query까지 결합된 실제 전송 URL을 기준으로 Scope를 검사한다.
        self._validate_url(request.resolved_url, run.scope)
        if (
            request.request_kind in {
                HttpRequestKind.SSRF_WORKFLOW_SETUP,
                HttpRequestKind.SSRF_WORKFLOW_TRIGGER,
                HttpRequestKind.SSRF_WORKFLOW_CLEANUP,
                HttpRequestKind.SSRF_CSV_UPLOAD_CONTROL,
                HttpRequestKind.SSRF_CSV_UPLOAD_PROBE,
                HttpRequestKind.SSRF_CSV_IMPORT_CONTROL,
                HttpRequestKind.SSRF_CSV_IMPORT_PROBE,
            }
            and not self._approval.is_approved(run, request)
        ):
            raise ApprovalRequired(
                "SSRF workflow trigger requires an explicit approved action reference"
            )
        if (
            run.policy_profile == "safe"
            and (
                request.method.upper() not in self._safe_methods
                or (
                    request.method.upper() == "GET"
                    and has_state_changing_get(request.resolved_url)
                )
            )
            and not self._approval.is_approved(run, request)
        ):
            raise ApprovalRequired(
                "state-changing request requires an explicit approved action reference"
            )

    @staticmethod
    def _validate_url(url: str, scope: RunScope) -> None:
        """URL의 scheme·host·path가 명시적 allowlist에 포함되는지 확인한다."""

        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PolicyViolation("target must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise PolicyViolation("inline credentials are not allowed")
        # 대소문자와 마지막 점 표기 차이로 allowlist 검사가 우회되지 않게 정규화한다.
        allowed_hosts = {host.casefold().rstrip(".") for host in scope.allowed_hosts}
        hostname = parsed.hostname.casefold().rstrip(".")
        if hostname not in allowed_hosts:
            raise PolicyViolation(f"host is outside the run scope: {hostname}")
        path = parsed.path or "/"
        if not any(path.startswith(prefix) for prefix in scope.allowed_path_prefixes):
            raise PolicyViolation(f"path is outside the run scope: {path}")
