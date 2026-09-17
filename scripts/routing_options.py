"""대상별 실행기가 공유하는 Router 실험 옵션. Analysis profile과 독립적으로 선택한다."""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Collection

from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog, surface_key
from hacklipse.bootstrap import standard_router
from hacklipse.domain import RunExecutionProfile
from hacklipse.ports import LlmClient, VulnerabilityRouter


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
    keys = {
        surface.surface_id: surface_key(surface)
        for surface in app.stores.surfaces.list_by_run(run.run_id)
    }
    JsonlRoutingAuditLog(args.routing_log).append({
        "schema_version": 1, "event": "run_result", "run_id": run.run_id,
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
