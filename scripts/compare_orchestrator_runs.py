"""P-1/P-2 조건으로 기록한 Orchestrator 반복 Run을 비교한다.

대상에 요청하지 않는다. 전용 --routing-log 파일에서 heuristic/hybrid Run을
각각 실행 순서대로 짝짓거나 --pair로 Run ID를 명시한다.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from statistics import mean


_FIXED_CONDITIONS = (
    "analysis_profile",
    "recon_mode",
    "surface_collection_mode",
    "router_mode",
    "router_review",
    "compare_routers",
    "budget_allocation_mode",
    "validation_mode",
    "report_mode",
    "request_budget",
)
_LLM_CONDITIONS = ("llm_provider", "llm_model", "llm_rpm_limit")


def load_runs(path: Path) -> dict[str, dict[str, object]]:
    runs: dict[str, dict[str, object]] = defaultdict(lambda: {"routes": [], "result": None})
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSONL line {line_number}") from error
            if not isinstance(record, dict) or not isinstance(record.get("run_id"), str):
                continue
            entry = runs[record["run_id"]]
            if record.get("event") == "routing_decision":
                entry["routes"].append(record)
            elif record.get("event") == "run_result":
                entry["result"] = record
    return dict(runs)


def _surface_manifest(route: dict[str, object]) -> Counter[str]:
    manifest = route.get("routing_input_manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("surfaces"), list):
        raise ValueError("routing record has no Surface manifest")
    keys = [item.get("comparison_surface_key", item.get("surface_key")) for item in manifest["surfaces"]]
    if any(not isinstance(key, str) for key in keys):
        raise ValueError("Surface manifest contains an invalid key")
    return Counter(keys)


def _candidate_manifest(route: dict[str, object]) -> Counter[tuple[str, int, str]]:
    decisions = route.get("final_decisions")
    if not isinstance(decisions, list):
        raise ValueError("routing record has no candidate decisions")
    keys = [
        (
            item.get("routing_surface_key", item.get("surface_key")),
            item.get("routing_surface_occurrence", 0),
            item.get("vulnerability_type"),
        )
        for item in decisions
    ]
    if any(not isinstance(surface, str) or type(occurrence) is not int or not isinstance(vuln, str)
           for surface, occurrence, vuln in keys):
        raise ValueError("routing candidate has an invalid identity")
    return Counter(keys)


def _stored_candidate_manifest(route: dict[str, object]) -> Counter[tuple[str, str]]:
    """같은 Run의 final result와 연결할 때만 strict Surface 지문을 쓴다."""

    decisions = route["final_decisions"]
    return Counter(
        (item["surface_key"], item["vulnerability_type"]) for item in decisions
    )


def _run_metrics(run: dict[str, object]) -> dict[str, object]:
    routes = run["routes"]
    result = run["result"]
    if not routes or not isinstance(result, dict):
        raise ValueError("Run needs a routing record and a final result")
    first, last = routes[0], routes[-1]
    initial_surfaces = _surface_manifest(first)
    final_surfaces = _surface_manifest(last)
    initial_candidates = _stored_candidate_manifest(first)
    candidates = result.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("Run result has no candidates")
    newly_routed = Counter(initial_candidates)
    new_candidate_count = 0
    new_confirmed_count = 0
    for candidate in candidates:
        key = (candidate.get("surface_key"), candidate.get("vulnerability_type"))
        if newly_routed[key]:
            newly_routed[key] -= 1
        else:
            new_candidate_count += 1
            new_confirmed_count += candidate.get("status") == "confirmed"
    return {
        "run_id": result["run_id"],
        "phase": result.get("phase"),
        "initial_surface_count": sum(initial_surfaces.values()),
        "new_surface_count": sum((final_surfaces - initial_surfaces).values()),
        "initial_candidate_count": sum(initial_candidates.values()),
        "new_candidate_count": new_candidate_count,
        "new_confirmed_candidate_count": new_confirmed_count,
        "candidate_count": len(candidates),
        "candidate_status_counts": result.get("candidate_status_counts"),
        "finding_count": result.get("finding_count"),
        "requests_used": result.get("requests_used"),
        "extra_recon_rounds": result.get("extra_recon_rounds"),
        "routing_rounds": len(routes),
    }


def compare_pair(
    baseline: dict[str, object], hybrid: dict[str, object]
) -> dict[str, object]:
    left, right = baseline["result"], hybrid["result"]
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise ValueError("both paired Runs need a final result")
    if not baseline["routes"] or not hybrid["routes"]:
        raise ValueError("both paired Runs need a routing record")
    left_route, right_route = baseline["routes"][0], hybrid["routes"][0]
    left_manifest, right_manifest = _surface_manifest(left_route), _surface_manifest(right_route)
    left_candidates, right_candidates = _candidate_manifest(left_route), _candidate_manifest(right_route)
    fixed_differences = [key for key in _FIXED_CONDITIONS if left.get(key) != right.get(key)]
    shared_llm = (
        left.get("analysis_profile") == "llm"
        or left.get("recon_mode") == "hybrid"
        or left.get("router_mode") == "hybrid"
        or left.get("compare_routers") is True
        or left.get("budget_allocation_mode") == "hybrid"
        or left.get("validation_mode") == "llm"
        or left.get("report_mode") == "llm"
    )
    if shared_llm:
        fixed_differences.extend(key for key in _LLM_CONDITIONS if left.get(key) != right.get(key))
    reasons = []
    if left.get("orchestrator_mode") != "heuristic" or right.get("orchestrator_mode") != "hybrid":
        reasons.append("orchestrator_modes_not_heuristic_vs_hybrid")
    if left.get("execution_profile_recorded") is not True or right.get("execution_profile_recorded") is not True:
        reasons.append("unrecorded_execution_profile")
    if left.get("surface_collection_mode") != "deterministic" or right.get("surface_collection_mode") != "deterministic":
        reasons.append("surface_collection_not_deterministic")
    if left.get("phase") != "done" or right.get("phase") != "done":
        reasons.append("run_not_done")
    if left_route.get("status") != "completed" or right_route.get("status") != "completed":
        reasons.append("initial_routing_not_completed")
    if any(key not in left or key not in right for key in _FIXED_CONDITIONS):
        reasons.append("missing_recorded_condition")
    if fixed_differences:
        reasons.append("different_fixed_conditions")
    if left_route.get("configuration", {}).get("vulnerability_types") != right_route.get("configuration", {}).get("vulnerability_types"):
        reasons.append("different_vulnerability_scope")
    if left_manifest != right_manifest:
        reasons.append("different_initial_surface_manifest")
    if (
        not left_route.get("routing_input_fingerprint")
        or left_route.get("routing_input_fingerprint") != right_route.get("routing_input_fingerprint")
    ):
        reasons.append("different_normalized_router_input")
    if left_candidates != right_candidates:
        reasons.append("different_initial_candidates")
    left_metrics, right_metrics = _run_metrics(baseline), _run_metrics(hybrid)
    numeric = (
        "finding_count", "requests_used", "candidate_count", "extra_recon_rounds",
        "new_surface_count", "new_candidate_count", "new_confirmed_candidate_count",
    )
    delta = {
        key: right_metrics[key] - left_metrics[key]
        for key in numeric
        if type(left_metrics[key]) is int and type(right_metrics[key]) is int
    }
    return {
        "eligible": not reasons,
        "reasons": reasons,
        "different_fixed_condition_names": fixed_differences,
        "same_initial_surface_manifest": left_manifest == right_manifest,
        "same_normalized_router_input": (
            left_route.get("routing_input_fingerprint") == right_route.get("routing_input_fingerprint")
        ),
        "same_raw_recon_input": left_route.get("input_fingerprint") == right_route.get("input_fingerprint"),
        "initial_surface_delta": {
            "baseline_only": sum((left_manifest - right_manifest).values()),
            "hybrid_only": sum((right_manifest - left_manifest).values()),
        },
        "baseline": left_metrics,
        "hybrid": right_metrics,
        "delta_hybrid_minus_baseline": delta,
    }


def summarize(pairs: list[dict[str, object]]) -> dict[str, object]:
    eligible = [pair for pair in pairs if pair["eligible"]]
    fields = ("finding_count", "requests_used", "new_surface_count", "new_candidate_count", "new_confirmed_candidate_count")
    return {
        "pair_count": len(pairs),
        "eligible_pair_count": len(eligible),
        "extra_recon_activated_count": sum(pair["hybrid"]["extra_recon_rounds"] > 0 for pair in eligible),
        "extra_recon_effect_observed": any(pair["hybrid"]["extra_recon_rounds"] > 0 for pair in eligible),
        "mean_delta_hybrid_minus_baseline": {
            key: mean(pair["delta_hybrid_minus_baseline"][key] for pair in eligible)
            for key in fields if eligible and all(key in pair["delta_hybrid_minus_baseline"] for pair in eligible)
        },
    }


def repeatability(runs: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """각 arm의 초기 입력과 P-2 조건이 반복 간에도 같았는지 확인한다."""

    result = {}
    for mode in ("heuristic", "hybrid"):
        entries = [entry for entry in runs if entry["result"].get("orchestrator_mode") == mode]
        valid = [entry for entry in entries if entry["routes"]]
        if not valid:
            result[mode] = {"run_count": len(entries), "assessable": False}
            continue
        first_route = valid[0]["routes"][0]
        first_result = valid[0]["result"]
        conditions = (*_FIXED_CONDITIONS, *_LLM_CONDITIONS, "orchestrator_mode")
        result[mode] = {
            "run_count": len(entries),
            "assessable": len(valid) == len(entries),
            "same_initial_surface_manifest": all(
                _surface_manifest(entry["routes"][0]) == _surface_manifest(first_route)
                for entry in valid
            ),
            "same_normalized_router_input": bool(first_route.get("routing_input_fingerprint")) and all(
                entry["routes"][0].get("routing_input_fingerprint")
                == first_route["routing_input_fingerprint"]
                for entry in valid
            ),
            "same_recorded_conditions": all(
                entry["result"].get("execution_profile_recorded") is True
                and all(entry["result"].get(key) == first_result.get(key) for key in conditions)
                for entry in valid
            ),
            "finding_counts": [entry["result"].get("finding_count") for entry in valid],
            "request_counts": [entry["result"].get("requests_used") for entry in valid],
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routing_log", type=Path, help="전용 A/B JSONL 실행 기록")
    parser.add_argument("--pair", action="append", nargs=2, metavar=("BASELINE_RUN_ID", "HYBRID_RUN_ID"),
                        help="명시적 Run 쌍; 여러 번 지정 가능. 생략하면 각 모드의 n번째 Run을 짝지음")
    parser.add_argument("--output", type=Path, help="비교 JSON 저장 경로")
    args = parser.parse_args(argv)
    try:
        runs = load_runs(args.routing_log)
        available = [entry for entry in runs.values() if isinstance(entry["result"], dict)]
        unpaired = {"heuristic": 0, "hybrid": 0}
        if args.pair:
            selected = [(runs[left], runs[right]) for left, right in args.pair]
        else:
            arms = {
                mode: [entry for entry in available if entry["result"].get("orchestrator_mode") == mode]
                for mode in ("heuristic", "hybrid")
            }
            selected = list(zip(arms["heuristic"], arms["hybrid"]))
            unpaired = {mode: len(entries) - len(selected) for mode, entries in arms.items()}
        pairs = [compare_pair(left, right) for left, right in selected]
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.error(str(error))
    report = {
        "schema_version": 1,
        "event": "orchestrator_ab_comparison",
        "pairing": "explicit" if args.pair else "run_order_by_mode",
        "available_runs": [
            {"run_id": entry["result"]["run_id"], "orchestrator_mode": entry["result"].get("orchestrator_mode")}
            for entry in available
        ],
        "unpaired_run_counts": unpaired,
        "repeatability": repeatability(available),
        "summary": summarize(pairs),
        "pairs": pairs,
        "interpretation": (
            "Eligible pairs control recorded execution conditions, initial Surface manifest, "
            "and normalized Router input. Raw target responses may still differ; this is "
            "a repeated target experiment, not a fixed-input LLM replay. "
            "Knowledge mode and target state are not recorded in the Run profile; "
            "keep them fixed in the invocation protocol."
        ),
        "effect_note": (
            "No hybrid Run performed extra Recon. Finding and request deltas, if any, "
            "cannot measure the benefit of extra Recon."
            if pairs and not any(pair["hybrid"]["extra_recon_rounds"] > 0 for pair in pairs)
            else "At least one hybrid Run performed extra Recon; inspect pair-level yield and variance."
            if pairs else "No A/B pairs are available."
        ),
    }
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    consistent = all(
        arm.get("assessable")
        and arm.get("same_initial_surface_manifest")
        and arm.get("same_normalized_router_input")
        and arm.get("same_recorded_conditions")
        for arm in report["repeatability"].values()
        if arm["run_count"]
    )
    return 0 if pairs and all(pair["eligible"] for pair in pairs) and not any(unpaired.values()) and consistent else 1


if __name__ == "__main__":
    raise SystemExit(main())
