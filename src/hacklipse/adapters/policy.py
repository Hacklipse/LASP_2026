"""URL allowlist와 안전 HTTP method를 검사하는 정책 Adapter."""

from __future__ import annotations

from urllib.parse import urlsplit

from hacklipse.domain import ExecutionRequest, Run, RunRequest, RunScope
from hacklipse.ports import ApprovalGate
from hacklipse.ports.errors import ApprovalRequired, PolicyViolation

from .request_safety import has_state_changing_parameters
from .security import DenyAllApprovalGate


class AllowlistPolicyGate:
    """네트워크 요청 없이 문자열 수준에서 대상 Scope를 강제한다."""

    # safe 프로필에서는 서버 상태를 바꿀 가능성이 낮은 메서드만 허용한다.
    _safe_methods = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(self, approval_gate: ApprovalGate | None = None) -> None:
        self._approval = approval_gate or DenyAllApprovalGate()

    def validate_run(self, request: RunRequest) -> None:
        """Run 시작 대상이 선언된 Scope 안에 있는지 검사한다."""

        self._validate_url(request.target_url, request.scope)

    def validate_execution(self, run: Run, request: ExecutionRequest) -> None:
        """실행 직전 Run 소유권, URL Scope, HTTP method 정책을 검사한다."""

        if request.run_id != run.run_id:
            raise PolicyViolation("execution request belongs to another run")
        # 구조화 query까지 결합된 실제 전송 URL을 기준으로 Scope를 검사한다.
        self._validate_url(request.resolved_url, run.scope)
        if (
            run.policy_profile == "safe"
            and (
                request.method.upper() not in self._safe_methods
                or (
                    request.method.upper() == "GET"
                    and has_state_changing_parameters(
                        tuple(name for name, _ in request.query_parameters)
                    )
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
