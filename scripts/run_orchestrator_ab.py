"""로컬 Juice Shop XSS에서 P-1/P-2 Orchestrator 반복 A/B를 실행한다.

한 번 승인받은 뒤 기존 Juice Shop 실행기를 조건별로 호출한다. 각 Run의 상세
출력과 JSONL은 전용 디렉터리에 보존하며, 실패하거나 짝이 빠진 결과는 성공한
비교로 표시하지 않는다. 임시 계정이 필요 없는 XSS 경로만 사용한다.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlsplit

from compare_orchestrator_runs import load_runs, main as compare_main


_RUNNER = Path(__file__).with_name("run_juice_shop_baseline.py")
_CREDENTIAL_VARIABLES = {
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _schedule(repeats: int) -> list[str]:
    order = []
    for index in range(repeats):
        order.extend(("heuristic", "hybrid") if index % 2 == 0 else ("hybrid", "heuristic"))
    return order


def _initial_fetch_failed(routing_log: Path) -> bool:
    """샌드박스 연결 거부처럼 홈페이지 GET 자체가 실패하면 즉시 중단한다."""

    runs = load_runs(routing_log)
    if not runs:
        return True
    first = next(iter(runs.values()))
    if not first["routes"]:
        return True
    route = first["routes"][0]
    evidence = route.get("routing_input_manifest", {}).get("evidence", [])
    return (
        route.get("surface_count") == 1
        and bool(evidence)
        and evidence[0].get("observation_type") == "http_error"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="local Juice Shop URL")
    parser.add_argument("output_dir", type=Path, help="new directory for this experiment")
    parser.add_argument("--repeats", type=_positive_int, default=3, help="number of A/B pairs (default: 3)")
    parser.add_argument("--llm-provider", choices=tuple(_CREDENTIAL_VARIABLES), default="gemini")
    parser.add_argument("--llm-model", help="model ID passed to the existing runner")
    parser.add_argument("--llm-rpm-limit", type=_positive_int, default=14)
    parser.add_argument("--request-budget", type=_positive_int, default=80)
    args = parser.parse_args(argv)

    parsed = urlsplit(args.base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1"} or parsed.username or parsed.password:
        parser.error("target must be an unauthenticated local Juice Shop URL")
    if args.output_dir.exists():
        parser.error("output directory already exists; use a fresh directory for each experiment")
    credential_variable = _CREDENTIAL_VARIABLES[args.llm_provider]
    if not os.environ.get(credential_variable, "").strip():
        parser.error(f"{credential_variable} must be configured before the experiment")

    order = _schedule(args.repeats)
    print(
        f"Local XSS A/B: {args.repeats} pairs, deterministic Surface collection, "
        "heuristic Analysis/Recon/Router/Allocation/Validation/Report, "
        "Knowledge disabled. Each condition uses the same 80-request ceiling "
        "unless --request-budget overrides it."
    )
    if input("이 조건으로 반복 실행할까요? [y/N] ").strip().casefold() != "y":
        print("취소했습니다.")
        return 2

    args.output_dir.mkdir(parents=True)
    routing_log = args.output_dir / "routing.jsonl"
    protocol = {
        "schema_version": 1,
        "target": args.base_url,
        "vulnerability": "xss",
        "analysis_profile": "heuristic",
        "recon_mode": "heuristic",
        "surface_collection_mode": "deterministic",
        "router_mode": "heuristic",
        "orchestrator_schedule": order,
        "budget_allocation_mode": "heuristic",
        "validation_mode": "heuristic",
        "report_mode": "heuristic",
        "knowledge_enabled": False,
        "request_budget": args.request_budget,
        "hybrid_llm_provider": args.llm_provider,
        "hybrid_llm_model": args.llm_model or "runner_default",
        "hybrid_llm_rpm_limit": args.llm_rpm_limit,
        "runs": [],
    }
    protocol_path = args.output_dir / "protocol.json"
    protocol_path.write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for number, mode in enumerate(order, 1):
        command = [
            sys.executable, str(_RUNNER), args.base_url,
            "--vuln", "xss", "--profile", "heuristic",
            "--recon", "heuristic", "--router", "heuristic",
            "--orchestrator", mode, "--budget-allocation", "heuristic",
            "--surface-collection", "deterministic",
            "--request-budget", str(args.request_budget),
            "--routing-log", str(routing_log),
        ]
        if mode == "hybrid":
            command.extend(("--llm-provider", args.llm_provider,
                            "--llm-rpm-limit", str(args.llm_rpm_limit)))
            if args.llm_model:
                command.extend(("--llm-model", args.llm_model))
        log_path = args.output_dir / f"run-{number:02d}-{mode}.log"
        print(f"[{number}/{len(order)}] {mode} 실행 중")
        started = time.monotonic()
        with log_path.open("w", encoding="utf-8") as output:
            try:
                process = subprocess.run(
                    command, input="y\n", text=True, stdout=output,
                    stderr=subprocess.STDOUT, timeout=600, check=False,
                )
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                return_code = 124
        protocol["runs"].append({
            "sequence": number, "orchestrator_mode": mode,
            "exit_code": return_code,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "log_file": log_path.name,
        })
        protocol_path.write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if return_code != 0:
            print(f"실행 중단: {log_path.name}의 종료 코드 {return_code}을 확인하세요.")
            return 1
        if number == 1 and _initial_fetch_failed(routing_log):
            protocol["invalid_reason"] = "initial_target_fetch_failed"
            protocol_path.write_text(json.dumps(protocol, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print("실행 중단: 첫 홈페이지 수집이 http_error였습니다. 네트워크 권한을 확인하세요.")
            return 1
        print(f"[{number}/{len(order)}] 완료")

    comparison_path = args.output_dir / "comparison.json"
    with contextlib.redirect_stdout(io.StringIO()) as comparison_output:
        comparison_code = compare_main([str(routing_log), "--output", str(comparison_path)])
    comparison = json.loads(comparison_output.getvalue())
    summary = comparison["summary"]
    print(
        f"비교 완료: 유효한 쌍 {summary['eligible_pair_count']}/{summary['pair_count']}, "
        f"추가 Recon {summary['extra_recon_activated_count']}회"
    )
    if not summary["extra_recon_effect_observed"]:
        print("추가 Recon이 없어 이번 반복으로는 추가 탐색의 탐지 기여를 측정할 수 없습니다.")
    print(f"결과: {comparison_path}")
    return comparison_code


if __name__ == "__main__":
    raise SystemExit(main())
