"""credential_ref를 해석해 중앙 수집 경계로 form 로그인하는 Worker."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlencode

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    EvidenceRequest,
    HttpRequestKind,
    HttpRequestSpec,
    TaskEnvelope,
)
from hacklipse.ports import CredentialResolver, FormLoginSpec
from hacklipse.ports.errors import AuthenticationFailed

AUTHENTICATION_WORKER = "session_authenticator"


class FormLoginWorker:
    """비밀을 Task에 넣지 않고 GET-CSRF-POST 로그인으로 Run 세션을 확립한다."""

    def __init__(
        self, *, credential_resolver: CredentialResolver, collector: RuntimeEvidenceCollector
    ) -> None:
        self._credentials = credential_resolver
        self._collector = collector

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.credential_ref is None:
            raise AgentContractError("authentication task is missing credential_ref")
        if "http_get" not in task.allowed_tools or "http_post" not in task.allowed_tools:
            raise AgentContractError("authentication task lacks its fixed HTTP tools")

        credential = self._credentials.resolve(task.credential_ref)
        login = credential.form_login
        if login is None:
            # 사전 발급 Cookie/Authorization만 있는 경우 Runtime이 첫 요청에 중앙 주입한다.
            return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED)

        evidence_ids: list[str] = []
        fields = list(login.extra_fields)
        if login.csrf_field is not None:
            preflight_id, preflight = self._collector.collect_with_result(
                task.run_id,
                login.login_url,
                EvidenceRequest(
                    evidence_type="authentication_preflight",
                    surface_id="authentication",
                    reason="form login CSRF preflight",
                    suggested_tool="http_get",
                    http_request=HttpRequestSpec(method="GET"),
                ),
                task_id=task.task_id,
                timeout_seconds=task.timeout_seconds,
            )
            evidence_ids.append(preflight_id)
            body = preflight.observation.get("body")
            csrf = _hidden_input_value(body, login.csrf_field)
            if csrf is None:
                raise AuthenticationFailed(
                    f"login preflight did not provide the configured CSRF field: {login.csrf_field}"
                )
            fields.append((login.csrf_field, csrf))

        fields.extend(
            (
                (login.username_field, login.username),
                (login.password_field, login.password),
            )
        )
        login_id, response = self._collector.collect_with_result(
            task.run_id,
            login.login_url,
            EvidenceRequest(
                evidence_type="authentication_response",
                surface_id="authentication",
                reason="approved form login",
                suggested_tool="http_post",
                http_request=HttpRequestSpec(
                    method="POST",
                    headers=(
                        ("Content-Type", "application/x-www-form-urlencoded"),
                    ),
                    body=urlencode(fields),
                    request_kind=HttpRequestKind.CONTROL,
                ),
            ),
            task_id=task.task_id,
            timeout_seconds=task.timeout_seconds,
            approval_ref=login.approval_ref,
        )
        evidence_ids.append(login_id)
        _require_login_success(login, response.observation)
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            new_evidence_ids=tuple(evidence_ids),
        )


class _HiddenInputParser(HTMLParser):
    def __init__(self, field_name: str) -> None:
        super().__init__()
        self._field_name = field_name
        self.value: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "input" or self.value is not None:
            return
        values = {name.casefold(): value for name, value in attrs if value is not None}
        if values.get("name") == self._field_name:
            self.value = values.get("value")


def _hidden_input_value(body: object, field_name: str) -> str | None:
    if not isinstance(body, str):
        return None
    parser = _HiddenInputParser(field_name)
    parser.feed(body)
    parser.close()
    return parser.value


def _require_login_success(login: FormLoginSpec, observation) -> None:
    status = observation.get("status")
    if status not in login.success_statuses:
        raise AuthenticationFailed(f"form login returned an unexpected status: {status}")
    body = observation.get("body")
    if (
        login.failure_marker is not None
        and isinstance(body, str)
        and login.failure_marker in body
    ):
        raise AuthenticationFailed("form login response contained its failure marker")
