"""대상별 실행기가 공유하는 Router 실험 옵션. Analysis profile과 독립적으로 선택한다."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Collection, Mapping

from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog, surface_key
from hacklipse.adapters.validation_review_contract import valid_review_claim_observation
from hacklipse.application.orchestrator import VALIDATION_ROUNDS_EXHAUSTED_REASON
from hacklipse.bootstrap import standard_router
from hacklipse.domain import RunExecutionProfile
from hacklipse.ports import LlmClient, VulnerabilityRouter

# render_report_v2가 v2 사실 블록에 적는 줄. 64자리 hex라 형식이 바뀌면 조용히
# 틀린 값을 집어오지 않고 아예 찾지 못한다.
_FACTS_HASH_LINE = re.compile(r"^- Facts SHA-256: `([0-9a-f]{64})`$", re.MULTILINE)
_COMPARABLE_HASH_LINE = re.compile(
    r"^- Facts SHA-256 \(생성 ID 제외\): `([0-9a-f]{64})`$", re.MULTILINE
)


@dataclass(frozen=True, slots=True)
class NoLlmUsage:
    """LLM을 아예 구성하지 않은 Run의 사용량.

    모르는 것이 아니라 0이다. 실행기는 client를 만들었는지 아닌지를 알고 있으므로,
    만들지 않았다면 그 Run의 LLM 호출은 0회가 확실하다. 이것을 "정보 없음"으로
    두면 요약을 껐을 때와 켰을 때의 사실이 사용량 때문에 달라져, 두 Run을 비교하는
    축이 성립하지 않는다.
    """

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def add_routing_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--recon", choices=("heuristic", "hybrid"), default="heuristic",
        help="Recon planner mode, independent of --profile and --router",
    )
    parser.add_argument(
        "--surface-collection",
        choices=("adaptive", "deterministic"),
        default="adaptive",
        help=(
            "adaptive applies Recon Planner ordering; deterministic keeps a stable "
            "bounded crawl frontier for regression and non-Recon comparisons"
        ),
    )
    parser.add_argument(
        "--router", choices=("heuristic", "hybrid"), default="heuristic",
        help="routing mode, independent of --profile (default: heuristic)",
    )
    parser.add_argument(
        "--report", choices=("heuristic", "llm"), default="heuristic",
        help="deterministic v2 report or v2 with a bounded LLM narrative",
    )
    parser.add_argument(
        "--report-out",
        help="생성된 Markdown 보고서를 저장할 경로 (기본: 저장하지 않음)",
    )
    parser.add_argument(
        "--routing-log", default="artifacts/routing-decisions.jsonl",
        help="append-only routing decision JSONL (default: artifacts/routing-decisions.jsonl)",
    )
    parser.add_argument(
        "--router-review", choices=("weak", "ambiguous"), default="weak",
        help="weak: include single weak candidates; ambiguous: legacy multiple/unmatched policy",
    )
    parser.add_argument(
        "--compare-routers", action="store_true",
        help="run both routers on the exact same Recon input; analyze only --router output (uses LLM)",
    )
    parser.add_argument(
        "--llm-rpm-limit",
        type=_positive_int,
        help=(
            "shared rolling 60-second LLM request limit; "
            "default: 14 for Gemini (one slot below a 15 RPM quota), "
            "unlimited for other providers"
        ),
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def needs_llm(args: argparse.Namespace) -> bool:
    return (
        args.profile == "llm" or args.router == "hybrid"
        or args.recon == "hybrid" or args.compare_routers
        or getattr(args, "orchestrator", "heuristic") == "hybrid"
        or getattr(args, "budget_allocation", "off") == "hybrid"
        or getattr(args, "validation_review", False)
        or getattr(args, "report", "heuristic") == "llm"
    )


def execution_profile_from_args(
    args: argparse.Namespace,
    *,
    selected_model: str = "",
    llm_rpm_limit: int | None = None,
) -> RunExecutionProfile:
    """실제로 선택·적용된 CLI 실행 조건을 Run 계약으로 변환한다."""

    return RunExecutionProfile(
        analysis_profile=getattr(args, "profile", "heuristic"),
        recon_mode=getattr(args, "recon", "heuristic"),
        surface_collection_mode=getattr(args, "surface_collection", "adaptive"),
        router_mode=getattr(args, "router", "heuristic"),
        router_review=getattr(args, "router_review", "weak"),
        compare_routers=getattr(args, "compare_routers", False),
        orchestrator_mode=getattr(args, "orchestrator", "heuristic"),
        budget_allocation_mode=getattr(args, "budget_allocation", "off"),
        validation_mode=(
            "llm" if getattr(args, "validation_review", False) else "heuristic"
        ),
        report_mode=getattr(args, "report", "heuristic"),
        llm_provider=getattr(args, "llm_provider", "") if selected_model else "",
        llm_model=selected_model,
        llm_rpm_limit=llm_rpm_limit,
    )


def build_run_router(
    args: argparse.Namespace, *, vulnerability_types: Collection[str] | None,
    llm_client: LlmClient | None, selected_model: str,
) -> VulnerabilityRouter:
    log = JsonlRoutingAuditLog(args.routing_log)
    router = standard_router(
        vulnerability_types, mode=args.router, llm_client=llm_client, audit_log=log,
        review_policy=args.router_review, compare=args.compare_routers,
        audit_metadata={
            "analysis_profile": args.profile,
            "llm_provider": args.llm_provider if llm_client is not None else "",
            "llm_model": selected_model,
            "recon_mode": args.recon,
            "surface_collection_mode": getattr(
                args, "surface_collection", "adaptive"
            ),
        },
    )
    # 계정 생성/로그인/HTTP 실행 전에 쓰기 실패를 확인한다. 기존 로그는 보존한다.
    log.prepare()
    return router


def append_run_result(args, app, run) -> None:
    """실제 Analysis/Validation 결과를 같은 Run ID로 연결한다. 증적 원문은 저장하지 않는다."""
    candidates = app.stores.candidates.list_by_run(run.run_id)
    profile = run.execution_profile
    review = _validation_review_summary(app, run, candidates)
    report_narrative = _report_narrative_summary(app, run)
    keys = {
        surface.surface_id: surface_key(surface)
        for surface in app.stores.surfaces.list_by_run(run.run_id)
    }
    JsonlRoutingAuditLog(args.routing_log).append({
        "schema_version": 4, "event": "run_result", "run_id": run.run_id,
        "report_facts_hash": _report_facts_hash(app, run, _FACTS_HASH_LINE),
        # 서로 다른 Run의 사실을 비교하는 축. 생성 ID가 빠져 있다.
        "report_facts_comparable_hash": _report_facts_hash(app, run, _COMPARABLE_HASH_LINE),
        "execution_profile_recorded": profile.recorded,
        "router_mode": profile.router_mode,
        "router_review": profile.router_review,
        "compare_routers": profile.compare_routers,
        "analysis_profile": profile.analysis_profile,
        "recon_mode": profile.recon_mode,
        "surface_collection_mode": profile.surface_collection_mode,
        "orchestrator_mode": profile.orchestrator_mode,
        "extra_recon_rounds": run.extra_recon_rounds,
        "budget_allocation_mode": profile.budget_allocation_mode,
        "validation_mode": profile.validation_mode,
        "report_mode": profile.report_mode,
        "llm_provider": profile.llm_provider,
        "llm_model": profile.llm_model,
        "llm_rpm_limit": profile.llm_rpm_limit,
        "budget_validation_reserve": run.budget_validation_reserve,
        "budget_allocation_source": run.budget_allocation_source,
        "budget_candidate_order": list(run.budget_candidate_order),
        "budget_candidate_weights": list(run.budget_candidate_weights),
        "phase": run.phase.value,
        "candidate_status_counts": dict(Counter(c.status.value for c in candidates)),
        "validation_review": review,
        "report_narrative": report_narrative,
        "finding_count": len(app.stores.findings.list_by_run(run.run_id)),
        "request_budget": run.request_budget,
        "requests_used": run.request_budget - app.budget_manager.remaining(run.run_id),
        "candidates": [{
            "candidate_id": c.candidate_id, "surface_key": keys.get(c.surface_id),
            "vulnerability_type": c.vulnerability_type, "agent_type": c.assigned_agent,
            "status": c.status.value, "evidence_count": len(c.evidence_ids),
            "exploration_parameters": list(c.exploration_parameters),
        } for c in candidates],
    })


def _report_facts_hash(app, run, pattern=None) -> str | None:
    """보고서가 실제로 쓴 사실 해시. 다시 계산하지 않고 산출물에서 읽는다.

    여기에서 다시 모으면 안 된다. 사실에는 Run의 LLM 사용량이 들어 있고, 그 값은
    Report 시점 이후로도 늘어난다 - 최소한 Narrator 자신의 호출이 그 사이에 끼어든다.
    다시 계산한 해시를 적으면 보고서가 쓴 사실과 다른 값이 기록되고, narrator off/on
    비교가 "사실이 다르다"고 잘못 말하게 된다.

    형식을 찾지 못하거나 Report가 아직 없으면 None이다. 0이나 빈 문자열로 적으면
    비교에서 서로 "같다"로 읽힌다. 틀린 값보다 모른다고 적는 편이 낫다.
    """

    try:
        reports = tuple(app.stores.reports.list_by_run(run.run_id))
    except Exception:  # noqa: BLE001 - 계측 실패가 실행 기록 전체를 막으면 안 된다
        return None
    for report in reversed(reports):
        found = (pattern or _FACTS_HASH_LINE).search(getattr(report, "content", "") or "")
        if found is not None:
            return found.group(1)
    return None


def _report_narrative_summary(app, run) -> dict[str, object]:
    """Persist bounded Narrator measurements without generated prose or offered IDs."""

    attached_ids = set(run.evidence_ids)
    statuses: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    claim_count = invalid_count = llm_calls = rejected_count = 0
    input_tokens = output_tokens = usage_available = usage_unavailable = 0
    elapsed_count = 0
    elapsed_ms = 0.0
    for item in app.stores.evidence.list_by_run(run.run_id):
        if item.created_by != "llm_report_narrator" or item.evidence_type != "claim":
            continue
        obs = item.observation
        usage = obs.get("usage") if isinstance(obs, Mapping) else None
        valid = (
            item.evidence_id in attached_ids
            and item.surface_id is None
            and isinstance(obs, Mapping)
            and obs.get("type") == "llm_report_narrative"
            and obs.get("selection_source") in {"llm", "deterministic_fallback"}
            and isinstance(obs.get("status"), str)
            and type(obs.get("llm_calls")) is int
            and obs["llm_calls"] >= 0
            and isinstance(obs.get("usage_available"), bool)
            and isinstance(usage, Mapping)
            and all(
                type(usage.get(key)) is int and usage[key] >= 0
                for key in ("input_tokens", "output_tokens")
            )
            and (
                obs.get("elapsed_ms") is None
                or (
                    type(obs["elapsed_ms"]) in (int, float)
                    and obs["elapsed_ms"] >= 0
                )
            )
            and isinstance(obs.get("rejected"), list)
        )
        if not valid:
            invalid_count += 1
            continue
        claim_count += 1
        statuses[obs["status"]] += 1
        sources[obs["selection_source"]] += 1
        llm_calls += obs["llm_calls"]
        rejected_count += len(obs["rejected"])
        if obs["usage_available"]:
            usage_available += 1
            input_tokens += usage["input_tokens"]
            output_tokens += usage["output_tokens"]
        elif obs["llm_calls"]:
            usage_unavailable += 1
        if obs["elapsed_ms"] is not None:
            elapsed_count += 1
            elapsed_ms += obs["elapsed_ms"]
    return {
        "schema_version": 1,
        "enabled": run.execution_profile.report_mode == "llm",
        "claim_count": claim_count,
        "invalid_claim_count": invalid_count,
        "selection_source_counts": dict(sources),
        "status_counts": dict(statuses),
        "rejected_sentence_count": rejected_count,
        "llm_calls": llm_calls,
        "input_tokens_observed": input_tokens,
        "output_tokens_observed": output_tokens,
        "usage_available_count": usage_available,
        "usage_unavailable_count": usage_unavailable,
        "elapsed_available_count": elapsed_count,
        "elapsed_ms_observed": round(elapsed_ms, 3),
    }


def _validation_review_summary(app, run, candidates) -> dict[str, object]:
    """Persist bounded review measurements without reasons, URLs, or raw evidence."""

    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    attached_ids = set(run.evidence_ids)
    outcomes: Counter[str] = Counter()
    fallbacks: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    reviewed_candidates: set[str] = set()
    claim_records: list[dict[str, object]] = []
    claim_count = invalid_count = llm_calls = input_tokens = output_tokens = 0
    usage_available = usage_unavailable = elapsed_count = 0
    elapsed_ms = 0.0
    for item in app.stores.evidence.list_by_run(run.run_id):
        if item.created_by != "llm_validation_reviewer" or item.evidence_type != "claim":
            continue
        obs = item.observation
        if item.validation_id is None or not valid_review_claim_observation(
            obs, identifiers=(run.run_id, item.validation_id or ""),
        ):
            invalid_count += 1
            continue
        candidate = by_id.get(obs["candidate_id"])
        if (
            item.evidence_id not in attached_ids
            or candidate is None
            or item.surface_id != candidate.surface_id
            or candidate.status.value != obs.get("verdict")
            or not valid_review_claim_observation(
                obs, identifiers=(run.run_id, candidate.candidate_id, item.validation_id),
            )
        ):
            invalid_count += 1
            continue
        claim_count += 1
        reviewed_candidates.add(candidate.candidate_id)
        outcomes[obs["outcome_class"]] += 1
        sources[obs["selection_source"]] += 1
        if obs["selection_source"] == "deterministic_fallback":
            fallbacks[obs["status"]] += 1
        llm_calls += obs["llm_calls"]
        if obs["usage_available"]:
            usage_available += 1
            input_tokens += obs["usage"]["input_tokens"]
            output_tokens += obs["usage"]["output_tokens"]
        elif obs["llm_calls"] or obs["status"] == "internal_error":
            usage_unavailable += 1
        if obs["elapsed_ms"] is not None:
            elapsed_count += 1
            elapsed_ms += obs["elapsed_ms"]
        claim_records.append({
            "candidate_id": candidate.candidate_id,
            "validation_id": item.validation_id,
            "verdict": obs["verdict"],
            "reason_code": obs["reason_code"],
            "outcome_class": obs["outcome_class"],
            "selection_source": obs["selection_source"],
            "status": obs["status"],
            "llm_calls": obs["llm_calls"],
            "llm_call_count_known": obs["status"] != "internal_error",
            "usage_available": obs["usage_available"],
            "input_tokens": (
                obs["usage"]["input_tokens"] if obs["usage_available"] else None
            ),
            "output_tokens": (
                obs["usage"]["output_tokens"] if obs["usage_available"] else None
            ),
            "elapsed_ms": (
                round(obs["elapsed_ms"], 3) if obs["elapsed_ms"] is not None else None
            ),
        })

    status_counts = Counter(candidate.status.value for candidate in candidates)
    rounds_exhausted_ids = {
        candidate.candidate_id for candidate in candidates
        if candidate.status.value == "suspected"
        and candidate.last_error == VALIDATION_ROUNDS_EXHAUSTED_REASON
    }
    eligible_ids = {
        candidate.candidate_id for candidate in candidates
        if candidate.status.value in {"rejected", "blocked"}
        or (
            candidate.status.value == "suspected"
            and candidate.candidate_id not in rounds_exhausted_ids
        )
    }
    return {
        "schema_version": 1,
        "enabled": run.execution_profile.validation_mode == "llm",
        "eligible_candidate_count": len(eligible_ids),
        "reviewed_candidate_count": len(reviewed_candidates),
        "missing_review_candidate_count": (
            len(eligible_ids - reviewed_candidates)
            if run.execution_profile.validation_mode == "llm" else 0
        ),
        "claim_count": claim_count,
        "claims": claim_records,
        "invalid_claim_count": invalid_count,
        "outcome_class_counts": dict(outcomes),
        "selection_source_counts": dict(sources),
        "fallback_status_counts": dict(fallbacks),
        "llm_calls": llm_calls,
        "unknown_llm_call_count": fallbacks["internal_error"],
        "input_tokens_observed": input_tokens,
        "output_tokens_observed": output_tokens,
        "usage_available_count": usage_available,
        "usage_unavailable_count": usage_unavailable,
        "elapsed_ms_observed": round(elapsed_ms, 3),
        "elapsed_available_count": elapsed_count,
        "validation_rounds_exhausted_count": len(rounds_exhausted_ids),
        "skipped_budget_candidate_count": status_counts["skipped_budget"],
        "failed_candidate_count": status_counts["failed"],
    }


def write_report_artifact(app, run, path: str | None) -> str | None:
    """생성된 Markdown 보고서를 파일로 남긴다. 없으면 조용히 넘어간다.

    Report Agent는 산출물을 ReportStore에만 넣는데 실행기는 메모리 Store를 쓰므로,
    적어두지 않으면 방금 만든 보고서를 아무도 읽을 수 없다.
    """

    if not path:
        return None
    reports = [
        item for item in app.stores.reports.list_by_run(run.run_id)
        if item.format == "markdown"
    ]
    if not reports:
        print("보고서가 생성되지 않아 저장하지 않았습니다.")
        return None
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(reports[-1].content, encoding="utf-8")
    except OSError as error:
        # 보고서를 못 적는 것이 완료된 Run을 실패로 만들면 안 된다.
        print(f"보고서를 저장하지 못했습니다: {type(error).__name__}")
        return None
    print(f"보고서를 저장했습니다: {target}")
    return str(target)
