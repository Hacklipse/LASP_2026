"""Detect reproducible credential material delivered to a web client.

Only field paths are retained as observations. Values stay in the normal,
access-controlled HTTP evidence and never enter a routing claim or report.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable
from urllib.parse import urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup

from hacklipse.application.errors import AgentContractError
from hacklipse.domain import AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec, TaskEnvelope
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import BudgetExceeded
from .probing import matching_evidence


EXPOSURE_TYPE = "Sensitive Data Exposure"
EXPOSURE_OBSERVATION = "sensitive_json_exposure"
CONFIG_ROUTE_OBSERVATION = "credential_config_route_candidate"
TRUSTED_EXPOSURE_FIELDS = "verified_sensitive_field_paths"
_CONFIG_PATH_TOKENS = frozenset({
    "config", "configuration", "settings", "credentials", "secrets",
    "debug", "diagnostic", "diagnostics", "trace", "traces",
})
_SERVER_KEY_CONTEXT = frozenset({
    "backend", "internal", "llm", "private", "server", "service",
})
_SENSITIVE_FIELD = re.compile(
    r"(?:^|[_-])(?:client[_-]?secret|signing[_-]?secret|"
    r"jwt[_-]?secret|session[_-]?secret|private[_-]?key|"
    r"admin[_-]?token|smtp[_-]?password)(?:$|[_-])",
    re.I,
)
_MAX_HTML = 2 * 1024 * 1024
_MAX_JSON = 128 * 1024
_MAX_SCRIPT = 2 * 1024 * 1024
_JS_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?<![\w$])(?:[\"']?)([A-Za-z][A-Za-z0-9_-]{0,63})(?:[\"']?)"
    r"\s*[:=]\s*([\"'`])([^\"'`\\\r\n]{16,256})\2",
)
# A public bundle may pass a hard-coded Basic credential directly to fetch.
# Require a concrete same-origin path and a headers object in that same call;
# an isolated documentation string or an encoded UI setting is not proof.
_JS_FETCH_BASIC_AUTH = re.compile(
    r"\bfetch\s*\(\s*(?P<path_quote>[\"'`])"
    r"(?P<path>/[A-Za-z0-9][A-Za-z0-9._~/?=&-]{0,159})"
    r"(?P=path_quote)\s*,\s*\{[^{}]{0,300}?"
    r"\bheaders\s*:\s*\{[^{}]{0,300}?"
    r"(?:\bauthorization\b|[\"']authorization[\"'])\s*:\s*"
    r"(?P<value_quote>[\"'])(?P<value>Basic [A-Za-z0-9+/=]{8,256})"
    r"(?P=value_quote)", re.I,
)
# A login widget may ship literal accounts in a public bundle. Keep the
# values only in the execution call frame; a field-name signal by itself is
# never a finding because sample accounts may be invalid.
_JS_LOGIN_PAIR = re.compile(
    r"(?:\{|,)\s*(?:[\"']?email[\"']?)\s*:\s*([\"'])([^\"'\\\r\n]{3,160})\1"
    r"\s*,\s*(?:[\"']?password[\"']?)\s*:\s*([\"'])([^\"'\\\r\n]{4,160})\3",
    re.I,
)
TRUSTED_LOGIN_PAIR_COUNT = "verified_public_login_pair_count"
_PLACEHOLDER = re.compile(
    r"(?:example|placeholder|dummy|sample|redacted|fake|not[-_ ]?real)", re.I,
)


def _credential_field(path: tuple[str, ...]) -> bool:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", path[-1]).lower()
    parent = path[-2].lower() if len(path) > 1 else ""
    return bool(_SENSITIVE_FIELD.search(name) or
                (name in {"pass", "password", "passwd"} and parent in {"smtp", "mail", "database", "db"}))


def credential_config_route_candidate(url: str) -> bool:
    """Sample observed, literal settings or diagnostic routes with a GET."""

    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"} or not parsed.netloc
        or parsed.query or parsed.fragment or len(parsed.path) > 240
        or parsed.path.endswith((".js", ".mjs", ".map"))
    ):
        return False
    return bool(_CONFIG_PATH_TOKENS.intersection(
        token.casefold() for token in re.split(r"[/._-]+", parsed.path) if token
    ))


def _server_credential_field(path: tuple[str, ...], value: str) -> bool:
    if _credential_field(path):
        return True
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", path[-1]).casefold()
    parent = path[-2].casefold() if len(path) > 1 else ""
    if parent in {"client", "frontend", "public"} or name.startswith((
        "client_", "frontend_", "public_",
    )):
        return False
    # Common server-side signing keys can be embedded in a client config
    # block. Require a substantial non-placeholder value so ordinary labels
    # and development defaults do not become findings.
    if name in {"secret_key", "secret_key_base"}:
        return (
            len(value) >= 32 and len(set(value)) >= 10
            and sum(char.isdigit() for char in value) >= 4
        )
    if name.endswith("_api_key"):
        context = name[:-len("_api_key")]
        return (
            (context in _SERVER_KEY_CONTEXT or parent in _SERVER_KEY_CONTEXT)
            and len(value) >= 20 and len(set(value)) >= 8
        )
    if name.endswith("_credential"):
        context = name[:-len("_credential")]
        return context in _SERVER_KEY_CONTEXT and len(value) >= 10 and len(set(value)) >= 6
    if name in {"database_url", "db_url", "redis_url", "dsn"}:
        try:
            parsed = urlsplit(value)
            return bool(
                parsed.scheme and parsed.hostname and parsed.password
                and len(parsed.password) >= 6
            )
        except ValueError:
            return False
    return False


def _json_credential_signals(document: object) -> tuple[tuple[str, str], ...]:
    found: dict[str, str] = {}
    pending: list[tuple[object, tuple[str, ...], int]] = [(document, (), 0)]
    visited = 0
    while pending and visited < 300:
        value, path, depth = pending.pop()
        visited += 1
        if depth >= 6 or not isinstance(value, dict):
            continue
        for key, child in list(value.items())[:100]:
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", key):
                continue
            child_path = (*path, key)
            if isinstance(child, dict):
                pending.append((child, child_path, depth + 1))
            elif (
                isinstance(child, str) and len(child) >= 8
                and len(child) <= 4096 and child.strip() == child
                and not _PLACEHOLDER.search(child)
                and child.lower() not in {"undefined", "null"}
                and _server_credential_field(child_path, child)
            ):
                found[".".join(child_path)] = child
    return tuple(sorted(found.items()))[:32]


def _embedded_basic_authorizations(body: str) -> tuple[str, ...]:
    """Return literal Basic headers used in fetch, only for ephemeral redaction."""

    found: list[str] = []
    for match in _JS_FETCH_BASIC_AUTH.finditer(body):
        value = match.group("value")
        try:
            decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        user, separator, password = decoded.partition(":")
        if (
            not separator or not 3 <= len(user) <= 100 or not 3 <= len(password) <= 200
            or any(char.isspace() or ord(char) < 32 for char in decoded)
            or _PLACEHOLDER.search(decoded)
        ):
            continue
        if value not in found:
            found.append(value)
        if len(found) >= 4:
            break
    return tuple(found)


def client_login_pairs(observation: dict) -> tuple[tuple[str, str], ...]:
    """Extract bounded literal account pairs from a delivered JS response.

    This is a private, transient parser. Callers must not persist its values.
    It does not establish whether an account can authenticate.
    """

    body = observation.get("body")
    status = observation.get("status")
    media = observation.get("content_type", "")
    url = observation.get("requested_url")
    if (
        type(status) is not int or not 200 <= status < 300
        or not isinstance(body, str) or not 0 < len(body) <= _MAX_SCRIPT
        or not isinstance(media, str) or not isinstance(url, str)
        or observation.get("truncated")
    ):
        return ()
    media_type = media.split(";", 1)[0].strip().casefold()
    if media_type not in {
        "application/javascript", "text/javascript", "application/x-javascript",
    } and not (not media_type and urlsplit(url).path.casefold().endswith((".js", ".mjs"))):
        return ()
    pairs: list[tuple[str, str]] = []
    for match in _JS_LOGIN_PAIR.finditer(body):
        email, password = match.group(2), match.group(4)
        if (
            re.fullmatch(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,100}\.[A-Za-z]{2,24}", email)
            and not _PLACEHOLDER.search(email)
            and not _PLACEHOLDER.search(password)
            and not any(char.isspace() or ord(char) < 32 for char in password)
            and (email, password) not in pairs
        ):
            pairs.append((email, password))
        if len(pairs) >= 8:
            break
    return tuple(pairs)


def client_credential_signals(
    observation: dict,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return bounded field paths and ephemeral values from delivered content.

    Only the sanitizer consumes values; downstream agents receive field paths.
    """

    status = observation.get("status")
    media = observation.get("content_type", "")
    body = observation.get("body")
    if (type(status) is not int or not 200 <= status < 300
            or not isinstance(media, str) or not isinstance(body, str)
            or observation.get("truncated")):
        return (), ()
    trusted = observation.get(TRUSTED_EXPOSURE_FIELDS)
    if isinstance(trusted, list) and 0 < len(trusted) <= 32 and all(
        isinstance(path, str) and re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z][A-Za-z0-9_-]{0,63}){0,5}",
            path,
        ) for path in trusted
    ):
        return tuple(sorted(set(trusted))), ()
    media_type = media.split(";", 1)[0].strip().casefold()
    source = observation.get("requested_url")
    script_response = media_type in {
        "application/javascript", "text/javascript", "application/x-javascript",
    } or (not media_type and isinstance(source, str)
          and source.split("?", 1)[0].casefold().endswith((".js", ".mjs")))
    if script_response:
        if len(body) > _MAX_SCRIPT:
            return (), ()
        found: dict[str, str] = {}
        for match in _JS_CREDENTIAL_ASSIGNMENT.finditer(body):
            name, value = match.group(1), match.group(3)
            if (
                _credential_field((name,))
                and len(set(value)) >= 8
                and sum(char.isdigit() for char in value) >= 2
                and not any(char.isspace() for char in value)
                and not value.startswith(("http://", "https://", "/"))
                and not _PLACEHOLDER.search(value)
            ):
                found[name] = value
            if len(found) >= 32:
                break
        for value in _embedded_basic_authorizations(body):
            found["fetch.authorization"] = value
        pairs = tuple(sorted(found.items()))
        return tuple(name for name, _ in pairs), tuple(value for _, value in pairs)
    if media_type == "application/json" or media_type.endswith("+json"):
        if len(body) > _MAX_JSON:
            return (), ()
        try:
            document = json.loads(body)
        except (TypeError, ValueError):
            return (), ()
        # API declarations can contain sample values; they are not a runtime
        # credential response even when an example key looks sensitive.
        if (isinstance(document, dict) and isinstance(document.get("paths"), dict)
                and ("openapi" in document or "swagger" in document)):
            return (), ()
        pairs = _json_credential_signals(document)
        return tuple(name for name, _ in pairs), tuple(value for _, value in pairs)
    if media_type != "text/html" or len(body) > _MAX_HTML:
        return (), ()
    soup = BeautifulSoup(body, "html.parser")
    found: dict[str, str] = {}
    for script in soup.select('script[type="application/json"]')[:32]:
        raw = script.string
        if not isinstance(raw, str) or len(raw) > _MAX_JSON:
            continue
        try:
            document = json.loads(raw)
        except (TypeError, ValueError):
            continue
        found.update(_json_credential_signals(document))
    pairs = tuple(sorted(found.items()))[:32]
    return tuple(name for name, _ in pairs), tuple(value for _, value in pairs)


def exposed_json_field_paths(observation: dict) -> tuple[str, ...]:
    """Return only credential field paths, never secret values."""

    return client_credential_signals(observation)[0]


class SensitiveExposureAnalyzer:
    """Re-fetch candidate client content and record field names only."""

    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, id_factory: Callable[[], str] | None = None):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._id_factory = id_factory or (lambda: str(uuid4()))

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None:
            raise AgentContractError("sensitive exposure task has no candidate")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if candidate.vulnerability_type != EXPOSURE_TYPE or task.surface_id != surface.surface_id or surface.method != "GET":
            raise AgentContractError("invalid sensitive exposure analysis surface")
        request = EvidenceRequest(
            evidence_type="sensitive_exposure_analysis", surface_id=surface.surface_id,
            reason="recheck client-delivered credential field names", suggested_tool="http_get",
            http_request=HttpRequestSpec(method="GET"),
        )
        evidence = self._evidence.get_many(task.run_id, task.evidence_ids)
        response = matching_evidence(evidence, surface.url, request)
        if response is None:
            if task.request_budget < 1:
                raise BudgetExceeded("sensitive exposure analysis needs one read-only fetch")
            return AgentResult(
                task_id=task.task_id, status=AgentResultStatus.NEEDS_EVIDENCE,
                candidate_ids=(candidate.candidate_id,),
                evidence_requests=(request,),
            )
        names = exposed_json_field_paths(response.observation)
        new_ids: tuple[str, ...] = ()
        if names:
            evidence_id = f"evi-{self._id_factory()}"
            self._evidence.append(Evidence(
                evidence_id=evidence_id, run_id=task.run_id,
                surface_id=surface.surface_id, created_by="sensitive_exposure_analyzer",
                evidence_type="observation", source_task_id=task.task_id,
                observation={"type": EXPOSURE_OBSERVATION, "field_paths": list(names),
                             "response_evidence_id": response.evidence_id},
            ))
            new_ids = (evidence_id,)
        return AgentResult(task_id=task.task_id, status=AgentResultStatus.COMPLETED,
                           new_evidence_ids=new_ids, candidate_ids=(candidate.candidate_id,))
