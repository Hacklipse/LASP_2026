"""동일한 고정 입력의 Router 재생 또는 두 실제 Run 로그를 비교한다. 대상 HTTP 실행은 하지 않는다."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog  # noqa: E402
from hacklipse.bootstrap import (  # noqa: E402
    DEFAULT_ANTHROPIC_LLM_MODEL, DEFAULT_GEMINI_LLM_MODEL,
    build_gemini_llm_client_from_env, build_llm_client_from_env, standard_router,
)
from hacklipse.domain import Evidence, Run, RunScope, Surface  # noqa: E402
from hacklipse.ports.errors import LlmCredentialsMissing, LlmTimeout  # noqa: E402
from hacklipse.ports.llm import LlmResponse  # noqa: E402


class _FixtureLlm:
    def __init__(self, payload, failure):
        self.payload = payload
        self.failure = failure

    def complete(self, request):
        if self.failure == "timeout":
            raise LlmTimeout("fixture timeout")
        return LlmResponse(payload=self.payload, model="fixture-not-a-real-model")


class _Capture:
    def __init__(self, log):
        self.records = []
        self.log = log

    def append(self, record):
        self.log.append(record)
        self.records.append(record)


def compare_records(baseline, hybrid, baseline_result=None, hybrid_result=None):
    def candidates(record):
        indexed = {}
        for item in record["final_decisions"]:
            routing_key = item.get("routing_surface_key")
            if not isinstance(routing_key, str):
                # 이전 감사 로그에는 정규화 키가 없으므로 strict 키로 호환한다.
                routing_key = item["surface_key"]
            occurrence = item.get("routing_surface_occurrence", 0)
            if not isinstance(occurrence, int):
                occurrence = 0
            indexed[(routing_key, occurrence, item["vulnerability_type"])] = item
        return indexed

    left, right = candidates(baseline), candidates(hybrid)
    left_manifest = baseline.get("routing_input_manifest")
    right_manifest = hybrid.get("routing_input_manifest")
    if isinstance(left_manifest, dict) and isinstance(right_manifest, dict):
        # Manifest가 있으면 과거 버전이 생성 surface_id를 지문에 포함했더라도 현재
        # 의미 규칙으로 다시 계산한다. 불투명 ID는 Router 입력 내용이 아니다.
        same_input = _normalized_manifest(left_manifest) == _normalized_manifest(right_manifest)
    else:
        left_routing_fingerprint = baseline.get(
            "routing_input_fingerprint", baseline["input_fingerprint"]
        )
        right_routing_fingerprint = hybrid.get(
            "routing_input_fingerprint", hybrid["input_fingerprint"]
        )
        same_input = left_routing_fingerprint == right_routing_fingerprint
    same_raw_input = baseline["input_fingerprint"] == hybrid["input_fingerprint"]
    same_profile = baseline["configuration"].get("analysis_profile") == hybrid["configuration"].get("analysis_profile")
    same_scope = baseline["configuration"].get("vulnerability_types") == hybrid["configuration"].get("vulnerability_types")
    same_recon = baseline["configuration"].get("recon_mode") == hybrid["configuration"].get("recon_mode")
    same_review = baseline["configuration"].get("router_review") == hybrid["configuration"].get("router_review")
    paired = baseline["run_id"] == hybrid["run_id"]
    return {
        "schema_version": 1, "event": "router_comparison",
        "baseline_run_id": baseline["run_id"], "hybrid_run_id": hybrid["run_id"],
        "same_router_input": same_input, "same_analysis_profile": same_profile,
        "same_raw_recon_input": same_raw_input,
        "same_vulnerability_scope": same_scope,
        "same_recon_mode": same_recon, "same_review_policy": same_review,
        "paired_run": paired,
        "routing_completed": baseline["status"] == hybrid["status"] == "completed",
        "input_manifest_delta": _manifest_delta(
            baseline.get("routing_input_manifest"),
            hybrid.get("routing_input_manifest"),
        ),
        "candidate_counts": {"heuristic": len(left), "hybrid": len(right)},
        "added": [right[key] for key in sorted(right.keys() - left.keys())],
        "removed": [left[key] for key in sorted(left.keys() - right.keys())],
        "changed": [{
            "routing_surface_key": key[0],
            "routing_surface_occurrence": key[1],
            "vulnerability_type": key[2],
            "heuristic_priority": left[key]["priority"], "hybrid_priority": right[key]["priority"],
            "heuristic_agent": left[key]["agent_type"], "hybrid_agent": right[key]["agent_type"],
        } for key in sorted(left.keys() & right.keys()) if (
            left[key]["priority"], left[key]["agent_type"]
        ) != (right[key]["priority"], right[key]["agent_type"])],
        "router_cost": {
            "heuristic": {"elapsed_ms": baseline["elapsed_ms"], "llm": baseline["llm"]},
            "hybrid": {"elapsed_ms": hybrid["elapsed_ms"], "llm": hybrid["llm"]},
            "monetary_cost": None,
            "note": "Router token/time telemetry only, not total Recon/Analysis cost. Missing usage is unknown; fixture responses are not real billing.",
        },
        "analysis_results": {"heuristic": baseline_result, "hybrid": hybrid_result},
        "analysis_comparison_available": bool(baseline_result and hybrid_result),
        "analysis_delta": {
            "finding_count": hybrid_result["finding_count"] - baseline_result["finding_count"],
            "requests_used": hybrid_result["requests_used"] - baseline_result["requests_used"],
            "candidate_status_counts": {
                status: hybrid_result["candidate_status_counts"].get(status, 0)
                - baseline_result["candidate_status_counts"].get(status, 0)
                for status in sorted(set(baseline_result["candidate_status_counts"])
                                     | set(hybrid_result["candidate_status_counts"]))
            },
        } if baseline_result and hybrid_result else None,
        "comparison_warning": (
            "Inputs/profiles differ; differences are not a controlled Router ablation."
            if not all((same_input, same_profile, same_scope, same_recon, same_review)) else
            "Paired Router comparison uses one Recon input. Only the selected Router's candidates execute analyzers; this is not a two-branch analysis comparison."
            if paired else
            "Normalized Router inputs match. Analyzer results came from separate target runs; inspect same_raw_recon_input before causal interpretation."
            if baseline_result and hybrid_result else
            "Replay does not execute analyzers."
        ),
    }


def _manifest_delta(left, right):
    """정규화 구조와 raw 관측 지문 차이를 원문 없이 요약한다."""

    if not isinstance(left, dict) or not isinstance(right, dict):
        return None

    left_surfaces, right_surfaces = left.get("surfaces", []), right.get("surfaces", [])
    left_evidence, right_evidence = left.get("evidence", []), right.get("evidence", [])
    changed_observations = [
        index for index, (first, second) in enumerate(zip(left_evidence, right_evidence))
        if first.get("observation_fingerprint") != second.get("observation_fingerprint")
    ]
    if len(left_evidence) != len(right_evidence):
        changed_observations.extend(
            range(min(len(left_evidence), len(right_evidence)),
                  max(len(left_evidence), len(right_evidence)))
        )
    changed_surfaces = [
        index for index, (first, second) in enumerate(zip(left_surfaces, right_surfaces))
        if first.get("surface_key") != second.get("surface_key")
    ]
    if len(left_surfaces) != len(right_surfaces):
        changed_surfaces.extend(
            range(min(len(left_surfaces), len(right_surfaces)),
                  max(len(left_surfaces), len(right_surfaces)))
        )
    return {
        "surface_structure_equal": (
            _normalized_manifest(left)["surfaces"]
            == _normalized_manifest(right)["surfaces"]
        ),
        "evidence_structure_equal": (
            _normalized_manifest(left)["evidence"]
            == _normalized_manifest(right)["evidence"]
        ),
        "raw_observation_equal": not changed_observations,
        "raw_surface_equal": not changed_surfaces,
        "changed_raw_surface_positions": changed_surfaces,
        "changed_raw_observation_positions": changed_observations,
        "surface_counts": {"heuristic": len(left_surfaces), "hybrid": len(right_surfaces)},
        "evidence_counts": {"heuristic": len(left_evidence), "hybrid": len(right_evidence)},
    }


def _normalized_manifest(manifest):
    """생성 ID·strict hash·원문 관측 hash를 제외한 실제 Router 의미 입력."""

    surfaces = manifest.get("surfaces", [])
    # Evidence가 어느 Surface에 연결됐는지는 보존하되, Run별 surface_id/hash 대신
    # 정규화 Surface 구조 자체로 연결한다.
    normalized_surfaces = [
        {key: value for key, value in item.items()
         if key not in {"surface_id", "surface_key", "routing_surface_key"}}
        for item in surfaces
    ]
    by_strict_key = {
        item.get("surface_key"): normalized_surfaces[index]
        for index, item in enumerate(surfaces)
        if item.get("surface_key") is not None
    }
    evidence = []
    for item in manifest.get("evidence", []):
        normalized = {
            key: value for key, value in item.items()
            if key not in {
                "surface_key", "routing_surface_key", "observation_fingerprint"
            }
        }
        normalized["surface"] = by_strict_key.get(item.get("surface_key"))
        evidence.append(normalized)
    return {"surfaces": normalized_surfaces, "evidence": evidence}


def latest_run(path, mode):
    records = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    routes = [r for r in records if r.get("event") == "routing_decision" and r.get("router_mode") == mode]
    if not routes:
        raise ValueError(f"no {mode} routing record")
    route = routes[-1]
    results = [r for r in records if r.get("event") == "run_result" and r.get("run_id") == route["run_id"] and r.get("router_mode") == mode]
    return route, results[-1] if results else None


def replay(args):
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    if args.provider == "fixture":
        client = _FixtureLlm(fixture["llm_response"], args.failure)
        model = "fixture-not-a-real-model"
    else:
        if args.failure != "none":
            raise ValueError("failure injection is only supported by fixture provider")
        if args.provider == "gemini":
            model = args.model or DEFAULT_GEMINI_LLM_MODEL
            client = build_gemini_llm_client_from_env(model=model)
        else:
            model = args.model or DEFAULT_ANTHROPIC_LLM_MODEL
            client = build_llm_client_from_env(model=model)
    log = JsonlRoutingAuditLog(args.routing_log)
    log.prepare()
    capture = _Capture(log)
    shared_id = f"comparison-{uuid4()}"
    for mode in ("heuristic", "hybrid"):
        run = Run(
            run_id=f"{shared_id}-{mode}", target_url="http://localhost/",
            scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            policy_profile="safe", request_budget=20,
        )
        surfaces = tuple(Surface(
            run_id=run.run_id, **dict(item, parameters=tuple(item.get("parameters", ()))),
        ) for item in fixture["surfaces"])
        evidence = tuple(Evidence(
            run_id=run.run_id, created_by="comparison_fixture", evidence_type="observation", **item,
        ) for item in fixture.get("evidence", ()))
        router = standard_router(
            fixture.get("vulnerability_types"), mode=mode, llm_client=client, audit_log=capture,
            review_policy=getattr(args, "router_review", "weak"),
            audit_metadata={"analysis_profile": "not_executed", "llm_provider": args.provider, "llm_model": model},
        )
        router.route(run, surfaces, evidence)
    return compare_records(*capture.records)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    replay_parser = commands.add_parser("replay", help="fixed input replay; no target requests")
    replay_parser.add_argument("--fixture", default=str(ROOT / "tests/fixtures/router_comparison.json"))
    replay_parser.add_argument("--provider", choices=("fixture", "gemini", "anthropic"), default="fixture")
    replay_parser.add_argument("--model")
    replay_parser.add_argument("--router-review", choices=("weak", "ambiguous"), default="weak")
    replay_parser.add_argument("--failure", choices=("none", "timeout"), default="none")
    replay_parser.add_argument("--routing-log", default="artifacts/routing-replay.jsonl")
    logs_parser = commands.add_parser("logs", help="compare latest runs in recorded JSONL files")
    logs_parser.add_argument("--baseline-log", required=True)
    logs_parser.add_argument("--hybrid-log", required=True)
    for command in (replay_parser, logs_parser):
        command.add_argument("--output", default="artifacts/routing-comparisons.jsonl", help="append comparison JSONL")
    args = parser.parse_args(argv)
    try:
        output = JsonlRoutingAuditLog(args.output)
        output.prepare()
        if args.command == "replay":
            comparison = replay(args)
        else:
            baseline, baseline_result = latest_run(args.baseline_log, "heuristic")
            hybrid, hybrid_result = latest_run(args.hybrid_log, "hybrid")
            comparison = compare_records(baseline, hybrid, baseline_result, hybrid_result)
        output.append(comparison)
    except (OSError, ValueError, KeyError, TypeError, LlmCredentialsMissing) as error:
        print(f"Comparison failed: {type(error).__name__}; check input files and LLM configuration.")
        return 2
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
