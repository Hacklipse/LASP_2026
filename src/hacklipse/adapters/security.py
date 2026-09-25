"""Phase 8 안전 통제의 로컬 Adapter 구현."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from hacklipse.domain import ExecutionRequest, ExecutionResult, Run
from hacklipse.ports import (
    ExecutionAuditEvent,
    ResolvedHttpCredential,
)
from hacklipse.ports.errors import CredentialNotFound

_REDACTED = "<redacted>"
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_EMAIL = re.compile(
    r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])"
)
# 앞자리 0(또는 +82 국가번호)을 필수로 둔다. 0을 선택으로 두면 "1"로 시작하는 9자리
# 숫자열이 전부 전화번호로 잡혀, UUID·주문번호·오류 메시지 안의 숫자가 삭제된다.
# 관측 훼손은 탐지 누락으로 이어진다 — 취약한 대상을 안전하다고 보고하게 된다.
_PHONE = re.compile(
    r"(?<!\d)(?:\+?82[- ]?0?|0)1[016789][- ]?\d{3,4}[- ]?\d{4}(?!\d)"
)
# Review text is optional, so reject plausible international numbers too. This
# broader check is not used to sanitize runtime Evidence, where false positives
# could remove a signal needed for validation.
_REVIEW_PHONE = re.compile(r"(?<![A-Za-z0-9])\+?(?:\d[\s().-]*){9,19}(?![A-Za-z0-9])")
_KOREAN_RRN = re.compile(r"(?<!\d)\d{6}[- ]?[1-4]\d{6}(?!\d)")
_FORM_SECRET = re.compile(
    r"(?i)(\b(?:password|passwd|csrf|token|secret|session(?:id)?)\b[^=&\r\n]{0,40}=)([^&\s<>\"']+)"
)
_JSON_SECRET = re.compile(
    r'''(?i)(["'](?:password|passwd|csrf|token|secret|session(?:id)?)["']'''
    r'''\s*:\s*["'])([^"']*)(["'])'''
)
_HTML_SECRET = re.compile(
    r"(?i)(name=[\"'](?:[^\"']*(?:csrf|token|password|session)[^\"']*)[\"'][^>]*value=[\"'])([^\"']*)([\"'])"
)
_HTML_SECRET_VALUE_FIRST = re.compile(
    r"(?i)(value=[\"'])([^\"']*)([\"'][^>]*name=[\"']"
    r"[^\"']*(?:csrf|token|password|session)[^\"']*[\"'])"
)
_SENSITIVE_HEADER_NAMES = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie"}
)
_SENSITIVE_FIELD_HINTS = (
    "password",
    "passwd",
    "csrf",
    "token",
    "secret",
    "session",
)
_REQUEST_SECRET_FIELD_HINTS = (*_SENSITIVE_FIELD_HINTS, "username", "email")


def contains_personal_data(value: str) -> bool:
    """Detect personal data before storing free-form LLM review text."""

    return any(
        pattern.search(value)
        for pattern in (_EMAIL, _PHONE, _REVIEW_PHONE, _KOREAN_RRN)
    )


class InMemoryCredentialResolver:
    """호출자가 명시적으로 주입한 참조만 해석하는 비영속 Credential Resolver.

    비밀 원문은 이 객체의 메모리에만 머물고 Store에는 참조만 기록한다. 선택적으로
    credential을 HTTP origin에 묶을 수 있으며, Run 종료 시 ``revoke``로 참조를
    제거한다. origin 제한은 Redirect를 포함해 다른 host로 인증정보가 재사용되는 것을
    막는 Runtime의 마지막 방어선이다.
    """

    def __init__(self, credentials: Mapping[str, ResolvedHttpCredential]) -> None:
        self._credentials = {
            reference: (credential, frozenset())
            for reference, credential in credentials.items()
        }
        self._lock = threading.RLock()

    def resolve(self, credential_ref: str) -> ResolvedHttpCredential:
        with self._lock:
            try:
                credential, _ = self._credentials[credential_ref]
            except KeyError as error:
                raise CredentialNotFound(
                    f"credential reference is not configured: {credential_ref}"
                ) from error
            return credential

    def resolve_for(
        self, credential_ref: str, *, target_url: str
    ) -> ResolvedHttpCredential:
        """대상 origin 제한을 확인한 뒤 credential을 반환한다."""

        with self._lock:
            try:
                credential, allowed_origins = self._credentials[credential_ref]
            except KeyError as error:
                raise CredentialNotFound(
                    f"credential reference is not configured: {credential_ref}"
                ) from error
            if allowed_origins and _credential_origin(target_url) not in allowed_origins:
                raise CredentialNotFound(
                    "credential reference is not available for the requested origin"
                )
            return credential

    def add(
        self,
        credential_ref: str,
        credential: ResolvedHttpCredential,
        *,
        allowed_origins: Sequence[str] = (),
    ) -> None:
        """중앙 인증 Worker가 발급받은 단기 자격증명을 메모리에만 등록한다."""

        if not credential_ref.strip():
            raise ValueError("credential reference cannot be blank")
        origins = frozenset(_credential_origin(value) for value in allowed_origins)
        with self._lock:
            if credential_ref in self._credentials:
                raise ValueError(
                    f"credential reference is already configured: {credential_ref}"
                )
            self._credentials[credential_ref] = (credential, origins)

    def revoke(self, credential_ref: str) -> bool:
        """단기 credential 참조를 폐기한다. 원문이나 존재 여부를 로그로 남기지 않는다."""

        with self._lock:
            return self._credentials.pop(credential_ref, None) is not None

    def clear(self) -> None:
        """이 Resolver가 보유한 모든 credential 참조를 폐기한다."""

        with self._lock:
            self._credentials.clear()


def _credential_origin(url: str) -> str:
    """HTTP URL을 scheme/host/effective-port origin으로 정규화한다."""

    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    hostname = (parsed.hostname or "").casefold()
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("credential origin must be an absolute HTTP(S) URL")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("credential origin contains an invalid port") from error
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{rendered_host}:{effective_port}"


class SensitiveDataSanitizer:
    """Cookie·Authorization·토큰·주입된 비밀을 Evidence 저장 전에 제거한다."""

    def __init__(self, credential_resolver=None) -> None:
        self._credentials = credential_resolver

    def sanitize(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> ExecutionResult:
        secrets: tuple[str, ...] = _request_secret_values(request)
        if request.credential_ref is not None and self._credentials is not None:
            secrets = tuple(
                dict.fromkeys(
                    (*secrets, *self._credentials.resolve(request.credential_ref).secret_values())
                )
            )
        observation = self._sanitize_mapping(dict(result.observation), secrets)
        artifacts = {
            key: self._sanitize_text(value, secrets)
            for key, value in result.artifact_refs.items()
        }
        return ExecutionResult(
            execution_id=result.execution_id,
            evidence_type=result.evidence_type,
            observation=observation,
            artifact_refs=artifacts,
            # 원문 무결성 hash는 비밀 원문을 복원할 수 없으므로 그대로 보존한다.
            content_hash=result.content_hash,
        )

    def _sanitize_mapping(
        self, value: Mapping[str, object], secrets: Sequence[str]
    ) -> dict[str, object]:
        sanitized: dict[str, object] = {}
        for key, item in value.items():
            lowered = key.casefold().replace("-", "_")
            if lowered in {"authorization", "cookie", "set_cookie"}:
                sanitized[key] = _REDACTED
            elif lowered == "headers" and isinstance(item, (list, tuple)):
                sanitized[key] = self._sanitize_headers(item, secrets)
            else:
                sanitized[key] = self._sanitize_value(item, secrets)
        return sanitized

    def _sanitize_headers(
        self, headers: Sequence[object], secrets: Sequence[str]
    ) -> list[object]:
        sanitized: list[object] = []
        for pair in headers:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                sanitized.append(self._sanitize_value(pair, secrets))
                continue
            name, value = pair
            if isinstance(name, str) and name.casefold() in _SENSITIVE_HEADER_NAMES:
                sanitized.append([name, _REDACTED])
            else:
                sanitized.append([name, self._sanitize_value(value, secrets)])
        return sanitized

    def _sanitize_value(self, value: object, secrets: Sequence[str]) -> object:
        if isinstance(value, str):
            return self._sanitize_text(value, secrets)
        if isinstance(value, Mapping):
            return self._sanitize_mapping(value, secrets)
        if isinstance(value, (list, tuple)):
            return [self._sanitize_value(item, secrets) for item in value]
        return value

    @staticmethod
    def _sanitize_text(value: str, secrets: Sequence[str]) -> str:
        # URL은 query 구조를 보존하는 전용 경로로 먼저 처리한다. 일반 FORM 정규식을
        # URL 전체에 적용하면 `/csrf/?q=marker`의 경로 `csrf`를 필드명으로 오인해
        # marker를 지우고, Analyzer가 자신의 Evidence를 다시 찾지 못한다.
        url_sanitized = _sanitize_url_query(value, secrets)
        if url_sanitized is not None:
            return url_sanitized

        # HTML 태그 안의 name/type 같은 구조는 Recon의 입력이다. 자격증명 값이 흔한
        # 단어(`password`)라는 이유로 전역 replace하면 name="password_new"까지
        # 훼손된다. 민감 input value는 전용 패턴으로 지우고, 알려진 비밀 원문 치환은
        # 태그 바깥 텍스트에만 적용한다.
        if _looks_like_html(value):
            sanitized = _HTML_SECRET.sub(r"\1<redacted>\3", value)
            sanitized = _HTML_SECRET_VALUE_FIRST.sub(r"\1<redacted>\3", sanitized)
            parts = re.split(r"(<[^>]*>)", sanitized)
            return "".join(
                _sanitize_html_tag(part, secrets)
                if part.startswith("<") and part.endswith(">")
                else _sanitize_plain_text(part, secrets)
                for part in parts
            )

        return _sanitize_plain_text(value, secrets)


def _request_secret_values(request: ExecutionRequest) -> tuple[str, ...]:
    """로그인 요청의 민감 필드 값을 응답 마스킹용 일회성 목록으로 추출한다."""

    body = request.body
    if not body:
        return ()
    values: list[str] = []
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        payload = None
    if isinstance(payload, Mapping):
        _collect_sensitive_values(payload, values)
    for name, value in parse_qsl(body, keep_blank_values=True):
        if _is_sensitive_field(name) and value:
            values.append(value)
    return tuple(dict.fromkeys(values))


def _collect_sensitive_values(value: object, output: list[str]) -> None:
    if isinstance(value, Mapping):
        for name, item in value.items():
            if _is_sensitive_field(str(name)) and isinstance(item, str) and item:
                output.append(item)
            else:
                _collect_sensitive_values(item, output)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_sensitive_values(item, output)


def _is_sensitive_field(name: str) -> bool:
    normalized = name.casefold().replace("-", "_")
    return any(hint in normalized for hint in _REQUEST_SECRET_FIELD_HINTS)


def _sanitize_plain_text(value: str, secrets: Sequence[str]) -> str:
    sanitized = _replace_known_secrets(value, secrets)
    sanitized = _BEARER.sub("Bearer <redacted>", sanitized)
    sanitized = _JWT.sub(_REDACTED, sanitized)
    sanitized = _EMAIL.sub("<redacted-email>", sanitized)
    sanitized = _PHONE.sub("<redacted-phone>", sanitized)
    sanitized = _KOREAN_RRN.sub("<redacted-id>", sanitized)
    sanitized = _FORM_SECRET.sub(r"\1<redacted>", sanitized)
    sanitized = _JSON_SECRET.sub(r"\1<redacted>\3", sanitized)
    return sanitized


def _replace_known_secrets(value: str, secrets: Sequence[str]) -> str:
    """알려진 비밀값을 지우되 구조화 필드명으로 쓰인 동일 문자열은 보존한다."""

    sanitized = value
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        pattern = re.compile(re.escape(secret))

        def replace(match: re.Match[str]) -> str:
            tail = sanitized[match.end() :]
            # form/JSON key와 식별자 일부는 데이터 구조이지 비밀값이 아니다.
            if tail.startswith(("_", "-")) or re.match(r'''^["']?\s*[:=]''', tail):
                return match.group(0)
            return _REDACTED

        sanitized = pattern.sub(replace, sanitized)
    return sanitized


def _looks_like_html(value: str) -> bool:
    return bool(re.search(r"<[A-Za-z!/][^>]*>", value))


def _sanitize_html_tag(tag: str, secrets: Sequence[str]) -> str:
    """HTML 구조 속성은 보존하고, 일반 속성의 알려진 비밀값만 지운다."""

    sanitized = tag
    structural = frozenset({"class", "for", "id", "name", "type"})
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        pattern = re.compile(
            rf'''(\b([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*["']){re.escape(secret)}(["'])'''
        )

        def replace(match: re.Match[str]) -> str:
            if match.group(2).casefold() in structural:
                return match.group(0)
            return f"{match.group(1)}{_REDACTED}{match.group(3)}"

        sanitized = pattern.sub(replace, sanitized)
    return sanitized


class DenyAllApprovalGate:
    """명시적인 승인 Adapter가 없을 때 모든 위험 요청을 거부한다."""

    def is_approved(self, run: Run, request: ExecutionRequest) -> bool:
        return False


class StaticApprovalGate:
    """호출자가 명시한 불투명 승인 참조만 허용하는 로컬 구현."""

    def __init__(self, approved_refs: Sequence[str]) -> None:
        self._approved = frozenset(approved_refs)

    def is_approved(self, run: Run, request: ExecutionRequest) -> bool:
        return request.approval_ref is not None and request.approval_ref in self._approved


class InMemoryExecutionAuditLog:
    """테스트와 단일 프로세스 실행용 감사 로그."""

    def __init__(self) -> None:
        self._events: list[ExecutionAuditEvent] = []
        self._lock = threading.Lock()

    def append(self, event: ExecutionAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def list_by_run(self, run_id: str) -> tuple[ExecutionAuditEvent, ...]:
        with self._lock:
            return tuple(event for event in self._events if event.run_id == run_id)


class SQLiteExecutionAuditLog:
    """재시작 뒤에도 남는 append-only SQLite 감사 로그."""

    def __init__(self, database_path: str | Path) -> None:
        self._connection = sqlite3.connect(str(database_path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    data TEXT NOT NULL
                )
                """
            )

    def append(self, event: ExecutionAuditEvent) -> None:
        data = asdict(event)
        data["created_at"] = event.created_at.isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO execution_audit(run_id, data) VALUES (?, ?)",
                (event.run_id, json.dumps(data, ensure_ascii=False, sort_keys=True)),
            )

    def list_by_run(self, run_id: str) -> tuple[ExecutionAuditEvent, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT data FROM execution_audit WHERE run_id = ? ORDER BY seq", (run_id,)
            ).fetchall()
        events = []
        for row in rows:
            value = json.loads(row["data"])
            value["created_at"] = datetime.fromisoformat(value["created_at"])
            events.append(ExecutionAuditEvent(**value))
        return tuple(events)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _sanitize_url_query(value: str, secrets: Sequence[str]) -> str | None:
    """절대 HTTP(S) URL이면 이름을 보존하고 민감 query 값만 치환한다."""

    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if not parsed.query:
        return value
    secret_set = set(secrets)
    query = tuple(
        (
            name,
            _REDACTED
            if item in secret_set or _is_sensitive_field_name(name)
            else item,
        )
        for name, item in parse_qsl(parsed.query, keep_blank_values=True)
    )
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def _is_sensitive_field_name(name: str) -> bool:
    lowered = name.casefold()
    return any(hint in lowered for hint in _SENSITIVE_FIELD_HINTS)
