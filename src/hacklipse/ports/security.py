"""인증정보·승인·마스킹·감사처럼 실행 경계를 보강하는 Port."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, Sequence

from hacklipse.domain import ExecutionRequest, ExecutionResult, Run

_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


@dataclass(frozen=True, slots=True)
class FormLoginSpec:
    """중앙 인증 Worker가 수행할 일반 HTML form 로그인 명세."""

    login_url: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str | None = None
    extra_fields: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    success_statuses: tuple[int, ...] = (200, 302, 303)
    failure_marker: str | None = None
    verification_url: str | None = None
    verification_success_statuses: tuple[int, ...] = (200,)
    verification_marker: str | None = None
    approval_ref: str = ""

    def __post_init__(self) -> None:
        if not self.login_url:
            raise ValueError("form login requires a login URL")
        if not self.username_field or not self.password_field:
            raise ValueError("form login field names cannot be empty")
        if not self.success_statuses:
            raise ValueError("form login requires at least one success status")
        if any(
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 100 <= status <= 599
            for status in self.success_statuses
        ):
            raise ValueError("form login success statuses must be HTTP status codes")
        if self.verification_url is not None and not self.verification_url.strip():
            raise ValueError("form login verification URL cannot be empty")
        if self.verification_url is not None and not self.verification_success_statuses:
            raise ValueError("form login verification requires at least one success status")
        if any(
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 100 <= status <= 599
            for status in self.verification_success_statuses
        ):
            raise ValueError("form login verification statuses must be HTTP status codes")
        if not self.approval_ref:
            raise ValueError("form login POST requires an explicit approval reference")


@dataclass(frozen=True, slots=True)
class ResolvedHttpCredential:
    """Resolver 밖으로만 잠시 나오는 HTTP 인증정보. Task나 Store에는 저장하지 않는다."""

    authorization: str | None = field(default=None, repr=False)
    cookies: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    form_login: FormLoginSpec | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.authorization is not None and (
            "\r" in self.authorization or "\n" in self.authorization
        ):
            raise ValueError("authorization value cannot contain line breaks")
        names: set[str] = set()
        for name, value in self.cookies:
            if _COOKIE_NAME.fullmatch(name) is None:
                raise ValueError("credential cookie name must be a valid token")
            if name in names:
                raise ValueError("credential cookie names cannot be duplicated")
            if "\r" in value or "\n" in value:
                raise ValueError("credential cookie value cannot contain line breaks")
            names.add(name)
        if self.authorization is None and not self.cookies and self.form_login is None:
            raise ValueError("resolved HTTP credential cannot be empty")

    def secret_values(self) -> tuple[str, ...]:
        values = [value for _, value in self.cookies if value]
        if self.authorization:
            values.append(self.authorization)
        if self.form_login is not None:
            values.extend((self.form_login.username, self.form_login.password))
            values.extend(value for _, value in self.form_login.extra_fields if value)
        return tuple(dict.fromkeys(value for value in values if value))


class CredentialResolver(Protocol):
    """비밀 원문이 아닌 참조 ID를 실제 인증정보로 해석한다."""

    def resolve(self, credential_ref: str) -> ResolvedHttpCredential: ...


class EvidenceSanitizer(Protocol):
    """Runtime 원문을 Evidence Store에 넣기 전에 민감정보를 제거한다."""

    def sanitize(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> ExecutionResult: ...


@dataclass(frozen=True, slots=True)
class ExecutionAuditEvent:
    """비밀·query 값을 제외한 외부 실행 감사 이벤트."""

    execution_id: str
    run_id: str
    task_id: str
    tool: str
    method: str
    target: str
    request_kind: str
    outcome: str
    status_code: int | None = None
    detail: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionAuditLog(Protocol):
    """모든 외부 실행 시도와 허용·차단·완료 결과를 기록한다."""

    def append(self, event: ExecutionAuditEvent) -> None: ...

    def list_by_run(self, run_id: str) -> Sequence[ExecutionAuditEvent]: ...


class ApprovalGate(Protocol):
    """상태 변경 가능 요청이 사전에 승인됐는지 확인한다."""

    def is_approved(self, run: Run, request: ExecutionRequest) -> bool: ...
