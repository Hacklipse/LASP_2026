"""Verify literal client login accounts through an observed, approved login shape.

No account value is stored in a Task, Evidence, Finding, or report. The shared
collector enforces scope, approval, budget, and response redaction for each call.
"""

from __future__ import annotations

import json
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

from hacklipse.application import RuntimeEvidenceCollector
from hacklipse.application.errors import AgentContractError
from hacklipse.domain import (
    AgentResult, AgentResultStatus, Evidence, EvidenceRequest, HttpRequestSpec,
    TaskEnvelope,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.errors import ApprovalRequired, BudgetExceeded, PolicyViolation

from .sensitive_exposure import client_login_pairs


PUBLIC_LOGIN_TYPE = "Exposed Working Credentials"
PUBLIC_LOGIN_OBSERVATION = "public_login_literal_pair"
PUBLIC_LOGIN_VERIFIED = "public_login_accepted"
PUBLIC_LOGIN_UNVERIFIABLE = "public_login_unverifiable"
_ALLOWED_MEDIA = frozenset({"application/json", "application/x-www-form-urlencoded"})
_LOGIN_PATH_PARTS = frozenset({"login", "signin", "sign-in", "session", "sessions"})


def _origin(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    return parsed.scheme.casefold(), parsed.netloc.casefold()


def observed_login_target(run_id: str, script_url: str, surfaces: SurfaceStore,
                          evidence: EvidenceStore) -> tuple[str, str, str] | None:
    """Use only a captured same-origin POST carrying exactly two login fields."""

    observations = evidence.list_by_run(run_id)
    by_surface: dict[str, list[Evidence]] = {}
    for item in observations:
        if item.surface_id is not None:
            by_surface.setdefault(item.surface_id, []).append(item)
    eligible: list[tuple[str, str, str]] = []
    for surface in surfaces.list_by_run(run_id):
        if surface.method != "POST" or _origin(surface.url) != _origin(script_url):
            continue
        if not _LOGIN_PATH_PARTS.intersection(
            part.casefold() for part in urlsplit(surface.url).path.split("/")
        ):
            continue
        for item in by_surface.get(surface.surface_id, ()):
            data = item.observation
            if (
                item.evidence_type == "observation"
                and data.get("type") == "browser_request_structure"
                and data.get("source") == "playwright_network"
                and data.get("method") == "POST"
                and data.get("content_type") in _ALLOWED_MEDIA
                and set(data.get("body_parameter_names", ())) == {"email", "password"}
                and not data.get("query_parameter_names")
            ):
                eligible.append((surface.surface_id, surface.url, data["content_type"]))
    return sorted(set(eligible), key=lambda item: item[1])[0] if eligible else None


def _login_accepted(observation: dict) -> bool:
    """Require a session artifact and a positive body signal, not a 2xx alone."""

    if observation.get("type") != "http_response" or observation.get("status") not in {200, 201}:
        return False
    headers = observation.get("headers")
    has_session_cookie = isinstance(headers, list) and any(
        isinstance(row, (list, tuple)) and len(row) == 2
        and str(row[0]).casefold() == "set-cookie"
        and isinstance(row[1], str) and "=" in row[1].split(";", 1)[0]
        and row[1].split("=", 1)[1].split(";", 1)[0]
        for row in headers
    )
    if not has_session_cookie:
        return False
    body = observation.get("body")
    if not isinstance(body, str) or len(body) > 32768:
        return False
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return False
    if not isinstance(payload, dict) or payload.get("error") or payload.get("errors"):
        return False
    return bool(
        payload.get("authenticated") is True
        or isinstance(payload.get("user"), dict) and payload["user"]
        or isinstance(payload.get("role"), str) and payload["role"]
        or isinstance(payload.get("token"), str) and payload["token"]
        or isinstance(payload.get("access_token"), str) and payload["access_token"]
    )


def replay_public_login(
    collector: RuntimeEvidenceCollector, task: TaskEnvelope, script_url: str,
    login_target: tuple[str, str, str], *, validation_id: str | None = None,
) -> tuple[bool, tuple[str, ...], str]:
    """Fetch a fresh script and submit its literals using the observed body shape."""

    if task.request_budget < 2:
        raise BudgetExceeded("public login verification needs a script and a login control")
    if "http_get" not in task.allowed_tools or "http_post" not in task.allowed_tools:
        return False, (), "tool_not_allowed"
    script_surface_id = task.surface_id
    script_id, script_response = collector.collect_with_result(
        task.run_id, script_url,
        EvidenceRequest(
            evidence_type="public_login_script", surface_id=script_surface_id,
            reason="independent public login script fetch", suggested_tool="http_get",
            anonymous=True, http_request=HttpRequestSpec(method="GET"),
        ),
        task_id=task.task_id, validation_id=validation_id,
        timeout_seconds=min(task.timeout_seconds, 8.0),
    )
    pairs = client_login_pairs(script_response.observation)
    if not pairs:
        return False, (script_id,), "script_pair_absent"
    login_surface_id, login_url, media = login_target
    evidence_ids = [script_id]
    for email, password in pairs[:min(4, task.request_budget - 1)]:
        body = (
            json.dumps({"email": email, "password": password}, separators=(",", ":"))
            if media == "application/json" else
            urlencode({"email": email, "password": password})
        )
        # The body exists only in this call frame. Never place it in a Task or
        # AgentResult; the collector redacts it before writing Evidence.
        try:
            response_id, response = collector.collect_with_result(
                task.run_id, login_url,
                EvidenceRequest(
                    evidence_type="public_login_control", surface_id=login_surface_id,
                    reason="approved observed login control", suggested_tool="http_post",
                    anonymous=True,
                    http_request=HttpRequestSpec(
                        method="POST", headers=(("Content-Type", media),), body=body,
                    ),
                ),
                task_id=task.task_id, validation_id=validation_id,
                timeout_seconds=min(task.timeout_seconds, 8.0),
            )
        except (ApprovalRequired, PolicyViolation):
            return False, tuple(evidence_ids), "approval_or_policy_blocked"
        evidence_ids.append(response_id)
        if _login_accepted(response.observation):
            return True, tuple(evidence_ids), "verified"
    return False, tuple(evidence_ids), "login_not_accepted"


class PublicLoginCredentialsAnalyzer:
    def __init__(self, *, candidate_store: CandidateStore, surface_store: SurfaceStore,
                 evidence_store: EvidenceStore, collector: RuntimeEvidenceCollector):
        self._candidates = candidate_store
        self._surfaces = surface_store
        self._evidence = evidence_store
        self._collector = collector

    def handle(self, task: TaskEnvelope) -> AgentResult:
        if task.candidate_id is None:
            raise AgentContractError("public login analysis requires a candidate")
        candidate = self._candidates.get(task.run_id, task.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        if candidate.vulnerability_type != PUBLIC_LOGIN_TYPE or surface.method != "GET":
            raise AgentContractError("invalid public login credential candidate")
        target = observed_login_target(task.run_id, surface.url, self._surfaces, self._evidence)
        if target is None:
            verified, collected, reason = False, (), "observed_login_shape_missing"
        else:
            verified, collected, reason = replay_public_login(
                self._collector, task, surface.url, target,
            )
        observation_id = f"evi-{uuid4()}"
        self._evidence.append(Evidence(
            evidence_id=observation_id, run_id=task.run_id,
            surface_id=surface.surface_id, created_by="public_login_credentials_analyzer",
            evidence_type="observation", source_task_id=task.task_id,
            observation={
                "type": PUBLIC_LOGIN_VERIFIED if verified else PUBLIC_LOGIN_UNVERIFIABLE,
                "reason": reason, "login_surface_id": target[0] if target else None,
            },
        ))
        return AgentResult(
            task_id=task.task_id, status=AgentResultStatus.COMPLETED,
            candidate_ids=(candidate.candidate_id,),
            new_evidence_ids=(*collected, observation_id),
        )
