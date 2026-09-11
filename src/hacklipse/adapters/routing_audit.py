"""Router 판단을 실행별 JSONL로 남기는 외곽 Adapter. 라우팅 결과는 바꾸지 않는다."""

from __future__ import annotations

import json
import hashlib
import math
import os
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from hacklipse.domain import Evidence, RouteDecision, Run, Surface
from hacklipse.ports.agents import VulnerabilityRouter

from .llm_router_advisor import surface_routing_summary
from .routing import ADVISOR_PRIORITY, RuleBasedVulnerabilityRouter


class RoutingAuditSink(Protocol):
    def append(self, record: Mapping[str, object]) -> None: ...


class JsonlRoutingAuditLog:
    """호출마다 한 줄을 append한다. 저장 실패는 숨기지 않는다.

    새 파일은 owner-only(0600)로 생성한다. 기존 파일을 지우거나 권한을 바꾸지 않는다.
    prepare()로 Run/계정 준비 전에 경로를 확인할 수 있다. 단일 프로세스 실행용이다.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        return os.fdopen(descriptor, "a", encoding="utf-8")

    def prepare(self) -> None:
        with self._open():
            pass

    def append(self, record: Mapping[str, object]) -> None:
        line = json.dumps(record, ensure_ascii=False, allow_nan=False, sort_keys=True)
        with self._open() as stream:
            stream.write(line + "\n")


class AuditedVulnerabilityRouter:
    """규칙형/Hybrid에 동일한 감사 스키마를 적용한다.

    예외 메시지, 원문 URL·query·본문·프롬프트·응답·자격증명은 기록하지 않는다.
    LLM 근거는 짧은 비신뢰 텍스트로 취급해 URL 및 흔한 인증 표현을 추가 제거한다.
    이 정규화는 임의의 자연어 비밀을 모두 식별하는 DLP가 아니다.
    """

    def __init__(
        self, router: VulnerabilityRouter, *, mode: str, audit_log: RoutingAuditSink,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        self.router = router
        self._mode = mode
        self._audit = audit_log
        # 실험 설정만 허용한다. 호출자가 임의 credential 필드를 추가하지 못한다.
        self._metadata = {
            key: _text(value) for key, value in (metadata or {}).items()
            if key in {
                "analysis_profile", "llm_provider", "llm_model", "vulnerability_types",
                "recon_mode", "router_review",
            }
        }

    def route(
        self, run: Run, surfaces: Sequence[Surface], evidence: Sequence[Evidence],
    ) -> tuple[RouteDecision, ...]:
        started = time.monotonic()
        decisions: tuple[RouteDecision, ...] = ()
        error_type = None
        try:
            decisions = self.router.route(run, surfaces, evidence)
            return decisions
        except Exception as error:
            error_type = type(error).__name__
            raise
        finally:
            elapsed_ms = (time.monotonic() - started) * 1000
            surface_keys = {surface.surface_id: surface_key(surface) for surface in surfaces}
            routing_identities = routing_surface_identities(surfaces, evidence)
            routed = (
                self.router
                if isinstance(self.router, RuleBasedVulnerabilityRouter)
                else None
            )
            advisor = getattr(routed, "_advisor", None) if routed else None
            advisor_trace = getattr(advisor, "last_trace", None)
            router_advisor_status = (
                routed.last_advisor_status if routed else "not_configured"
            )
            advisor_failed = router_advisor_status.startswith("advisor_failed:")
            baseline = routed.last_rule_decisions if routed else decisions
            original = {item.candidate.candidate_id: item for item in baseline}
            outcomes = dict(routed.last_advisor_outcomes) if routed else {}
            final_by_key = {
                (item.candidate.surface_id, item.candidate.vulnerability_type): item
                for item in decisions
            }
            proposals = []
            if routed:
                for index, item in enumerate(routed.last_advisor_suggestions):
                    final = final_by_key.get((item.surface_id, item.vulnerability_type))
                    proposals.append({
                        "index": index, "index_scope": "validated_items",
                        "surface_id": item.surface_id,
                        "vulnerability_type": item.vulnerability_type,
                        "agent_type": item.agent_type,
                        "priority": _priority(
                            final.priority if final is not None else ADVISOR_PRIORITY
                        ),
                        "reason": _text(item.reason),
                        "outcome": outcomes.get(index, "not_merged"),
                    })
            self._audit.append({
                "schema_version": 1, "event": "routing_decision",
                "routing_id": f"routing-{uuid4()}", "run_id": run.run_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "router_mode": self._mode, "configuration": self._metadata,
                "status": "failed" if error_type else "completed",
                "error_type": error_type,
                "elapsed_ms": elapsed_ms,
                "surface_count": len(surfaces),
                # strict 지문은 Recon 원문 관측의 변화를, routing 지문은 실제 Router가
                # 읽는 정규화 구조의 변화를 나타낸다. 동적 HTML 때문에 두 의미를
                # 혼동하지 않도록 둘 다 기록한다.
                "input_fingerprint": input_fingerprint(run, surfaces, evidence),
                "routing_input_fingerprint": routing_input_fingerprint(
                    run, surfaces, evidence
                ),
                "routing_input_manifest": routing_input_manifest(surfaces, evidence),
                "surface_reviews": [
                    {
                        "surface_id": surface.surface_id,
                        "reason": (
                            "advisor_review"
                            if advisor_trace
                            and surface.surface_id in advisor_trace.offered_surface_ids
                            else "heuristic_mode" if advisor is None else "not_offered"
                        ),
                        "selected": bool(
                            advisor_trace
                            and surface.surface_id in advisor_trace.offered_surface_ids
                        ),
                    }
                    for surface in surfaces
                ],
                "rule_decisions": [
                    _decision(item, "rule", surface_keys, routing_identities)
                    for item in baseline
                ],
                "llm": {
                    "source": (
                        "deterministic_fallback"
                        if advisor_failed
                        else advisor_trace.source
                        if advisor_trace
                        else "error" if error_type else "skipped"
                    ),
                    "status": (
                        router_advisor_status
                        if advisor_failed
                        else advisor_trace.status
                        if advisor_trace
                        else error_type or "heuristic_mode"
                    ),
                    # 예외로 응답을 못 받으면 호출/usage를 0으로 단정하지 않는다.
                    "calls": (
                        None
                        if advisor_failed
                        else advisor_trace.llm_calls if advisor_trace else 0
                    ),
                    "usage": (
                        asdict(advisor_trace.usage)
                        if advisor_trace and advisor_trace.usage_available
                        else None
                    ),
                    "model": _text(advisor_trace.model) if advisor_trace else "",
                    "elapsed_ms": advisor_trace.elapsed_ms if advisor_trace else None,
                    "rejected_items": [
                        {"index": index, "index_scope": "raw_items", "reason": reason}
                        for index, reason in (
                            advisor_trace.rejected_items if advisor_trace else ()
                        )
                    ],
                    "proposals": proposals,
                },
                "final_decisions": [
                    _decision(
                        item, _source(item, original), surface_keys, routing_identities
                    )
                    for item in decisions
                ],
            })


def _source(item: RouteDecision, original: Mapping[str, RouteDecision]) -> str:
    baseline = original.get(item.candidate.candidate_id)
    if baseline is None:
        return "llm"
    return "rule+llm" if item.priority > baseline.priority else "rule"


def _decision(
    item: RouteDecision,
    source: str,
    surface_keys: Mapping[str, str],
    routing_identities: Mapping[str, tuple[str, int]],
) -> dict[str, object]:
    candidate = item.candidate
    routing_key, occurrence = routing_identities.get(candidate.surface_id, (None, None))
    return {
        "candidate_id": candidate.candidate_id, "surface_id": candidate.surface_id,
        "surface_key": surface_keys.get(candidate.surface_id),
        "routing_surface_key": routing_key,
        "routing_surface_occurrence": occurrence,
        "vulnerability_type": candidate.vulnerability_type,
        "agent_type": candidate.assigned_agent, "priority": _priority(item.priority),
        "source": source, "reason": _text(candidate.hypothesis),
        "evidence_ids": list(candidate.evidence_ids),
        "exploration_parameters": list(candidate.exploration_parameters),
    }


def surface_key(surface: Surface) -> str:
    """Run마다 바뀌는 ID를 제외한 입력 지문. URL/값 자체를 로그에 저장하지 않는다."""
    data = asdict(surface)
    data.pop("run_id")
    data.pop("surface_id")
    return _fingerprint(data)


def routing_surface_key(surface: Surface, evidence: Sequence[Evidence]) -> str:
    """동적 URL·관측값이 아닌 Router가 읽는 Surface 의미 구조의 지문."""

    summary = surface_routing_summary(surface, evidence)
    return _fingerprint(
        {key: value for key, value in summary.items() if key != "surface_id"}
    )


def routing_surface_identities(
    surfaces: Sequence[Surface], evidence: Sequence[Evidence]
) -> dict[str, tuple[str, int]]:
    """동일 의미 Surface도 잃지 않도록 정규화 지문과 순번을 함께 부여한다."""

    counts: dict[str, int] = {}
    identities: dict[str, tuple[str, int]] = {}
    for surface in surfaces:
        key = routing_surface_key(surface, evidence)
        occurrence = counts.get(key, 0)
        counts[key] = occurrence + 1
        identities[surface.surface_id] = (key, occurrence)
    return identities


def input_fingerprint(run: Run, surfaces: Sequence[Surface], evidence: Sequence[Evidence]) -> str:
    keys = {surface.surface_id: surface_key(surface) for surface in surfaces}
    return _fingerprint({
        "surfaces": [keys[surface.surface_id] for surface in surfaces],
        "evidence": [
            {"surface": keys.get(item.surface_id), "type": item.evidence_type,
             "observation": dict(item.observation)} for item in evidence
        ],
        "policy_profile": run.policy_profile, "request_budget": run.request_budget,
        "timeout_seconds": run.timeout_seconds,
    })


def routing_input_manifest(
    surfaces: Sequence[Surface], evidence: Sequence[Evidence]
) -> dict[str, object]:
    """원문 응답·query 값 없이 Router가 실제 사용하는 입력을 사람이 읽게 만든다."""

    keys = {surface.surface_id: surface_key(surface) for surface in surfaces}
    summaries = {
        surface.surface_id: surface_routing_summary(surface, evidence)
        for surface in surfaces
    }
    routing_identities = routing_surface_identities(surfaces, evidence)
    return {
        "surfaces": [
            {
                "position": index,
                "surface_key": keys[surface.surface_id],
                "routing_surface_key": routing_identities[surface.surface_id][0],
                "routing_surface_occurrence": routing_identities[surface.surface_id][1],
                **summaries[surface.surface_id],
            }
            for index, surface in enumerate(surfaces)
        ],
        "evidence": [
            {
                "position": index,
                "surface_key": keys.get(item.surface_id),
                "routing_surface_key": (
                    routing_identities[item.surface_id][0]
                    if item.surface_id in routing_identities else None
                ),
                "routing_surface_occurrence": (
                    routing_identities[item.surface_id][1]
                    if item.surface_id in routing_identities else None
                ),
                "evidence_type": item.evidence_type,
                "observation_type": (
                    value if isinstance((value := item.observation.get("type")), str)
                    else None
                ),
                # strict 입력이 달라졌을 때 어느 관측이 원인인지 원문 없이 찾는다.
                "observation_fingerprint": _fingerprint(dict(item.observation)),
            }
            for index, item in enumerate(evidence)
        ],
    }


def routing_input_fingerprint(
    run: Run, surfaces: Sequence[Surface], evidence: Sequence[Evidence]
) -> str:
    """Rule/Advisor가 실제 읽는 정규화 입력의 결정적 지문."""

    manifest = routing_input_manifest(surfaces, evidence)
    # observation_fingerprint는 raw 응답 차이를 진단할 뿐 Router 입력은 아니다.
    normalized_surfaces = [
        {key: value for key, value in item.items()
         if key not in {"surface_key", "surface_id"}}
        for item in manifest["surfaces"]
    ]
    normalized_evidence = [
        {key: value for key, value in item.items()
         if key not in {"surface_key", "observation_fingerprint"}}
        for item in manifest["evidence"]
    ]
    return _fingerprint({
        "surfaces": normalized_surfaces,
        "evidence": normalized_evidence,
        "policy_profile": run.policy_profile,
        "request_budget": run.request_budget,
        "timeout_seconds": run.timeout_seconds,
    })


def _fingerprint(value: object) -> str:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _priority(value: object) -> int | float | None:
    return value if type(value) in (int, float) and math.isfinite(value) else None


def _text(value: object) -> str:
    text = str(value)
    text = re.sub(r"https?://\S+", "<redacted-url>", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\b(?:authorization|cookie|set-cookie)\s*[:=].*", "<redacted-header>",
        text, flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:bearer\s+\S+|(?:password|token|api[_-]?key|secret)\s*[:=]\s*\S+)",
        "<redacted-secret>", text, flags=re.IGNORECASE,
    )
    return "".join(char if char.isprintable() else "?" for char in text)[:500]
