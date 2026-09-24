"""같은 사실 위에서 Report narrator를 껐을 때와 켰을 때를 비교한다. 대상 HTTP 실행은 하지 않는다.

replay는 고정 fixture로 두 보고서를 offline 생성해 사실 보존·인용 정합성·비용을 재는다.
logs는 이미 기록된 run_result JSONL에서 P-2 실행 조건이 같은 완료 Run만 비교하고,
같은 조건·모델의 여러 Run에 걸친 fallback 비율과 rejected 비율을 집계한다.

지시서 §7이 요구하는 "사람 blind 평가"는 여기에서 다루지 않는다. 이 도구가 재는 것은
기계적으로 확인 가능한 축뿐이고, 문장의 의미적 정확성은 ID 검증만으로 증명되지 않는다.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hacklipse.adapters import InMemoryBudgetManager, MemoryStoreBundle  # noqa: E402
from hacklipse.adapters.llm_report_narrative import LlmReportNarrator  # noqa: E402
from hacklipse.adapters.report_contract import (  # noqa: E402
    NarratorFingerprintConfig, finding_fact_id, report_facts_hash,
)
from hacklipse.adapters.reporting import MarkdownReportAgent  # noqa: E402
from hacklipse.adapters.routing_audit import JsonlRoutingAuditLog  # noqa: E402
from hacklipse.domain import (  # noqa: E402
    Candidate, CandidateStatus, Evidence, Finding, Run, RunScope, Surface, TaskEnvelope,
    ValidationProofType,
)
from hacklipse.ports.errors import (  # noqa: E402
    LlmCredentialsMissing, LlmRateLimited, LlmRefused, LlmResponseFormatError, LlmTimeout,
    LlmTransportError,
)
from hacklipse.ports.llm import LlmResponse, LlmUsage  # noqa: E402


FIXTURE_MODEL = "fixture-not-a-real-model"
CONFIG = NarratorFingerprintConfig(model=FIXTURE_MODEL, prompt_version="llm-report-narrative-v1")
_COMPARISON_FIELDS = (
    "analysis_profile", "recon_mode", "surface_collection_mode",
    "router_mode", "router_review", "compare_routers",
    "orchestrator_mode", "budget_allocation_mode", "validation_mode",
    "request_budget",
)
_LLM_FIELDS = ("llm_provider", "llm_model", "llm_rpm_limit")
_FAILURES = {
    "timeout": LlmTimeout,
    "transport_error": LlmTransportError,
    "rate_limited": LlmRateLimited,
    "refused": LlmRefused,
    "invalid_response": LlmResponseFormatError,
}


class _FixtureLlm:
    """정해둔 payload나 실패만 돌려준다. 대상에도 provider에도 나가지 않는다."""

    def __init__(self, payload, failure="none"):
        self.payload = payload
        self.failure = failure

    def complete(self, request):
        error = _FAILURES.get(self.failure)
        if error is not None:
            raise error(f"fixture {self.failure}")
        return LlmResponse(
            payload=self.payload, model=FIXTURE_MODEL,
            usage=LlmUsage(input_tokens=1200, output_tokens=180),
        )


def _strip_comments(value):
    """fixture의 _comment 키를 지운다. Narrator schema는 추가 키를 통째로 거부한다."""

    if isinstance(value, dict):
        return {k: _strip_comments(v) for k, v in value.items() if k != "_comment"}
    if isinstance(value, list):
        return [_strip_comments(item) for item in value]
    return value


def _resolve_payload(payload):
    """fixture가 쓰는 @self / @finding:<id>를 실제 fact_id로 바꾼다.

    fact_id는 finding_id의 SHA-256이라 fixture에 손으로 적을 수 없다. 적어 두면
    Finding 이름을 바꾸는 순간 조용히 unknown_fact로 떨어져 비교가 무의미해진다.
    """

    resolved = dict(payload)
    findings = []
    for item in payload.get("findings", ()):
        if not isinstance(item, dict) or "finding_id" not in item:
            findings.append(item)
            continue
        entry = dict(item)
        entry["fact_ids"] = [
            finding_fact_id(item["finding_id"]) if reference == "@self"
            else finding_fact_id(reference[len("@finding:"):])
            if isinstance(reference, str) and reference.startswith("@finding:")
            else reference
            for reference in item.get("fact_ids", ())
        ]
        findings.append(entry)
    resolved["findings"] = findings
    return resolved


def _seed(fixture):
    """fixture를 메모리 Store에 심는다. 같은 run_id를 써야 facts가 비교 가능하다."""

    spec = fixture["run"]
    run_id = spec["run_id"]
    stores = MemoryStoreBundle()
    budget = InMemoryBudgetManager()
    stores.runs.add(Run(
        run_id=run_id, target_url=spec["target_url"],
        scope=RunScope(allowed_hosts=frozenset(spec.get("allowed_hosts", ()))),
        policy_profile="safe", request_budget=spec["request_budget"],
    ))
    budget.open_run(run_id, spec["request_budget"])
    if spec.get("requests_consumed"):
        budget.consume(run_id, spec["requests_consumed"])
    for item in fixture.get("surfaces", ()):
        stores.surfaces.add(Surface(
            run_id=run_id, **dict(item, parameters=tuple(item.get("parameters", ()))),
        ))
    for item in fixture.get("evidence", ()):
        stores.evidence.append(Evidence(
            run_id=run_id, created_by="comparison_fixture", evidence_type="observation", **item,
        ))
    for item in fixture.get("findings", ()):
        proof = item.get("proof_type")
        stores.findings.add(Finding(
            run_id=run_id, **dict(
                item,
                evidence_ids=tuple(item.get("evidence_ids", ())),
                proof_type=ValidationProofType(proof) if proof else None,
            ),
        ))
    # Candidate 상태는 개수만 fixture로 받는다. 사실 표의 집계 대상이지 본문 출처가 아니다.
    counts = fixture.get("candidate_counts", {})
    for status in CandidateStatus:
        for index in range(counts.get(status.value, 0)):
            stores.candidates.add(Candidate(
                candidate_id=f"candidate-{status.value}-{index}", run_id=run_id,
                surface_id=fixture["surfaces"][0]["surface_id"],
                vulnerability_type="XSS", hypothesis="fixture", assigned_agent="xss_analyzer",
                evidence_ids=(), status=status,
            ))
    task = TaskEnvelope(
        task_id=f"{run_id}-compare", run_id=run_id, agent_type="report",
        finding_ids=tuple(item["finding_id"] for item in fixture.get("findings", ())),
    )
    return stores, budget, task


def _render(fixture, *, narrator=None):
    """Store를 새로 심고 보고서를 한 번 만든다. 두 쪽이 서로의 상태를 보지 않게 한다."""

    stores, budget, task = _seed(fixture)
    # 계측기는 fixture 값을 그대로 읽는 대역이다. narrate 이전에 읽히므로 요약을
    # 켜든 끄든 같은 값이 facts에 들어간다.
    usage = fixture["run"].get("llm_usage")
    reporter = MarkdownReportAgent(
        finding_store=stores.findings, evidence_store=stores.evidence,
        candidate_store=stores.candidates, surface_store=stores.surfaces,
        run_store=stores.runs, budget_manager=budget, format_version="v2",
        llm_usage=SimpleNamespace(**usage) if usage else None,
        narrator=narrator, narrator_config=CONFIG if narrator is not None else None,
    )
    facts = reporter.collect_facts(task)
    result = reporter.handle(task)
    claims = [
        item.observation for item in stores.evidence.list_by_run(task.run_id)
        if item.created_by == "llm_report_narrator" and item.evidence_type == "claim"
    ]
    return {
        "run_id": task.run_id,
        "facts": facts,
        "facts_hash": report_facts_hash(facts),
        "content": result.reports[0].content,
        "new_evidence_ids": list(result.new_evidence_ids),
        "claim": claims[-1] if claims else None,
    }


def _narrative_metrics(claim):
    """Claim trace에서 비용과 거부 수만 꺼낸다. 생성된 문장은 여기에 없다."""

    if not isinstance(claim, dict):
        return {
            "present": False, "status": None, "selection_source": None, "llm_calls": 0,
            "accepted_fact_count": 0, "rejected_sentence_count": 0,
            "input_tokens": 0, "output_tokens": 0, "usage_available": False,
            "elapsed_ms": None,
        }
    usage = claim.get("usage") if isinstance(claim.get("usage"), dict) else {}
    return {
        "present": True,
        "status": claim.get("status"),
        "selection_source": claim.get("selection_source"),
        "llm_calls": claim.get("llm_calls", 0),
        "accepted_fact_count": len(claim.get("accepted_fact_ids", ())),
        "rejected_sentence_count": len(claim.get("rejected", ())),
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "usage_available": bool(claim.get("usage_available")),
        "elapsed_ms": claim.get("elapsed_ms"),
    }


def _citation_containment(claim, facts):
    """인용한 fact_id가 제공한 집합 안에 있는지 센다. §7의 사실 정합성 축이다."""

    offered = set(facts.fact_ids)
    cited = list(claim.get("accepted_fact_ids", ())) if isinstance(claim, dict) else []
    outside = sorted(set(cited) - offered)
    return {
        "offered_fact_count": len(offered),
        "cited_fact_count": len(cited),
        "outside_offered_set": outside,
        # 인용이 없으면 비율은 정의되지 않는다. 1.0으로 적으면 "완벽하다"로 읽힌다.
        "containment_rate": None if not cited else round(1 - len(outside) / len(cited), 6),
    }


def _status_representation(facts, content):
    """confirmed=0을 "취약점 없음"으로 읽지 못하게 하는 표현이 실제로 있는지 본다."""

    counts = dict(facts.candidate_counts)
    unconfirmed = sum(
        count for status, count in counts.items() if status is not CandidateStatus.CONFIRMED
    )
    skipped = counts[CandidateStatus.SKIPPED_BUDGET]
    return {
        "confirmed_finding_count": len(facts.findings),
        "unconfirmed_candidate_count": unconfirmed,
        "skipped_budget_count": skipped,
        "budget_shortfall_stated": (not skipped) or "예산 부족으로" in content,
        "unconfirmed_distinguished": (not unconfirmed) or any(
            phrase in content for phrase in ("미확정", "검증에서 기각", "검사 실패", "예산 부족으로")
        ),
    }


def compare_reports(off, on):
    """narrator off/on 두 보고서를 하나의 비교 레코드로 만든다."""

    same_facts = off["facts_hash"] == on["facts_hash"]
    deterministic_prefix = on["content"].startswith(off["content"].rstrip() + "\n")
    metrics = _narrative_metrics(on["claim"])
    return {
        "schema_version": 1, "event": "report_comparison",
        "off_run_id": off["run_id"], "on_run_id": on["run_id"],
        "paired_run": off["run_id"] == on["run_id"],
        # §7 결정적 사실 보존
        "same_report_facts": same_facts,
        "report_facts_hash": {"off": off["facts_hash"], "on": on["facts_hash"]},
        "deterministic_block_preserved": deterministic_prefix,
        "finding_counts": {
            "off": len(off["facts"].findings), "on": len(on["facts"].findings),
        },
        "candidate_status_counts": {
            mode: {status.value: count for status, count in side["facts"].candidate_counts}
            for mode, side in (("off", off), ("on", on))
        },
        # §7 사실 정합성
        "fact_citation": _citation_containment(on["claim"], on["facts"]),
        # §7 상태 표현 정확성
        "status_representation": {
            "off": _status_representation(off["facts"], off["content"]),
            "on": _status_representation(on["facts"], on["content"]),
        },
        # §7 비용
        "narrative": metrics,
        "cost_delta": {
            "llm_calls": metrics["llm_calls"],
            "input_tokens": metrics["input_tokens"],
            "output_tokens": metrics["output_tokens"],
            "elapsed_ms": metrics["elapsed_ms"],
            "note": (
                "Report narrator telemetry only, not total run cost. "
                "Fixture responses are not real billing."
            ),
        },
        "narrative_trace_stored": bool(on["new_evidence_ids"]),
        "comparison_warning": (
            "Report facts differ between the two renders; this is not a narrator ablation."
            if not same_facts else
            "Narrator output replaced part of the deterministic block."
            if not deterministic_prefix else
            "Narrator fell back; the report carries no model sentences."
            if metrics["selection_source"] != "llm" else
            "Fact IDs are contained in the offered set. ID containment is not semantic accuracy; "
            "§7 also requires fixed-fixture human blind review, which this tool does not perform."
        ),
    }


def replay(args):
    fixture = _strip_comments(json.loads(Path(args.fixture).read_text(encoding="utf-8")))
    client = _FixtureLlm(_resolve_payload(fixture["llm_response"]), args.failure)
    return compare_reports(
        _render(fixture),
        _render(fixture, narrator=LlmReportNarrator(llm_client=client, config=CONFIG)),
    )


def _run_results(paths):
    """두 축이 한 파일에 같이 적혀 있어도 Run을 두 번 세지 않는다.

    분모가 부풀면 fallback 비율이 실제보다 흔하거나 드물게 보인다. 같은 경로를 두 번
    받는 경우와 같은 run_id가 여러 번 적힌 경우를 모두 접는다. 마지막에 적힌 레코드가
    그 Run의 최종 상태다.
    """

    records = []
    for path in dict.fromkeys(str(Path(item).resolve()) for item in paths):
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("event") == "run_result":
                records.append(record)
    latest = {}
    for record in records:
        # 다시 넣어 순서를 뒤로 옮긴다. latest_run이 마지막 기록을 고르기 때문이다.
        latest.pop(record.get("run_id"), None)
        latest[record.get("run_id")] = record
    return list(latest.values())


def latest_run(records, mode):
    matching = [record for record in records if record.get("report_mode") == mode]
    if not matching:
        raise ValueError(f"no run_result record with report_mode={mode}")
    return matching[-1]


def _check_execution_conditions(off, on):
    """Report 모드만 다른 완료 Run인지 P-2 기록으로 확인한다."""

    required = (*_COMPARISON_FIELDS, "execution_profile_recorded", "phase", *_LLM_FIELDS)
    missing = [field for field in required if field not in off or field not in on]
    if missing:
        raise ValueError(f"missing execution conditions: {', '.join(missing)}")
    if off["execution_profile_recorded"] is not True or on["execution_profile_recorded"] is not True:
        raise ValueError("unrecorded execution conditions cannot be compared")
    if off["phase"] != "done" or on["phase"] != "done":
        raise ValueError("report comparison requires completed runs")
    different = [field for field in _COMPARISON_FIELDS if off[field] != on[field]]
    if different:
        raise ValueError(f"different execution conditions: {', '.join(different)}")
    if not on["llm_provider"] or not on["llm_model"]:
        raise ValueError("LLM report run is missing its provider or model")
    # Report가 유일한 LLM 축이면 off Run에는 provider/model이 없는 것이 정상이다.
    # 다른 축에서도 LLM을 썼다면 두 Run의 모델과 rate limit까지 같아야 한다.
    other_llm = (
        off["analysis_profile"] == "llm" or off["recon_mode"] == "hybrid"
        or off["router_mode"] == "hybrid" or off["compare_routers"]
        or off["orchestrator_mode"] == "hybrid"
        or off["budget_allocation_mode"] == "hybrid"
        or off["validation_mode"] == "llm"
    )
    if other_llm and (
        not off["llm_provider"] or not off["llm_model"]
        or any(off[field] != on[field] for field in _LLM_FIELDS)
    ):
        raise ValueError("different non-report LLM configuration")
    if not other_llm and (off["llm_provider"] or off["llm_model"]
                          or off["llm_rpm_limit"] is not None):
        raise ValueError("baseline has an unexpected LLM configuration")


def _same_run_conditions(record, reference):
    """비율 집계에 넣을 같은 모드·조건의 완료 Run만 고른다."""

    fields = (*_COMPARISON_FIELDS, *_LLM_FIELDS, "report_mode")
    return (
        record.get("execution_profile_recorded") is True
        and record.get("phase") == "done"
        and all(field in record and record[field] == reference[field] for field in fields)
    )


def _side_from_record(record):
    """기록된 run_result를 replay와 같은 축으로 읽는다. 사실 원문은 로그에 없다."""

    narrative = record.get("report_narrative")
    narrative = narrative if isinstance(narrative, dict) else {}
    statuses = narrative.get("status_counts", {})
    sources = narrative.get("selection_source_counts", {})
    return {
        "run_id": record.get("run_id"),
        "report_facts_hash": record.get("report_facts_hash"),
        "comparable_hash": record.get("report_facts_comparable_hash"),
        "finding_count": record.get("finding_count"),
        "candidate_status_counts": record.get("candidate_status_counts", {}),
        "requests_used": record.get("requests_used"),
        "llm_calls": narrative.get("llm_calls", 0),
        "input_tokens": narrative.get("input_tokens_observed", 0),
        "output_tokens": narrative.get("output_tokens_observed", 0),
        "elapsed_ms": narrative.get("elapsed_ms_observed", 0),
        "rejected_sentence_count": narrative.get("rejected_sentence_count", 0),
        "claim_count": narrative.get("claim_count", 0),
        "invalid_claim_count": narrative.get("invalid_claim_count", 0),
        "status_counts": statuses if isinstance(statuses, dict) else {},
        "selection_source_counts": sources if isinstance(sources, dict) else {},
    }


def aggregate_rates(records, mode):
    """여러 Run에 걸친 fallback 비율과 rejected 비율. 한 Run만으로는 비율이 아니다."""

    claims = rejected = llm_calls = runs = 0
    statuses: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    for record in records:
        if record.get("report_mode") != mode:
            continue
        runs += 1
        side = _side_from_record(record)
        claims += side["claim_count"]
        rejected += side["rejected_sentence_count"]
        llm_calls += side["llm_calls"]
        statuses.update({k: v for k, v in side["status_counts"].items() if isinstance(v, int)})
        sources.update({k: v for k, v in side["selection_source_counts"].items() if isinstance(v, int)})
    fallbacks = sources.get("deterministic_fallback", 0)
    return {
        "run_count": runs,
        "claim_count": claims,
        "llm_calls": llm_calls,
        "status_counts": dict(statuses),
        "selection_source_counts": dict(sources),
        "rejected_sentence_count": rejected,
        # 분모가 0이면 비율을 만들지 않는다. 0.0으로 적으면 "fallback이 없었다"로 읽힌다.
        "fallback_rate": None if not claims else round(fallbacks / claims, 6),
        "rejected_per_claim": None if not claims else round(rejected / claims, 6),
    }


def compare_logs(args):
    records = _run_results([args.baseline_log, args.narrative_log])
    off, on = latest_run(records, "heuristic"), latest_run(records, "llm")
    _check_execution_conditions(off, on)
    left, right = _side_from_record(off), _side_from_record(on)
    # 서로 다른 Run이므로 run-scoped 해시는 절대 같아지지 않는다. 생성 ID를 뺀
    # 해시로 비교해야 "같은 사실 위에서 돌았는가"를 물을 수 있다.
    hashes_known = bool(left["comparable_hash"] and right["comparable_hash"])
    same_facts = hashes_known and left["comparable_hash"] == right["comparable_hash"]
    return {
        "schema_version": 1, "event": "report_comparison", "source": "logs",
        "off_run_id": left["run_id"], "on_run_id": right["run_id"],
        "paired_run": left["run_id"] == right["run_id"],
        "report_facts_hash_available": hashes_known,
        "same_report_facts": same_facts if hashes_known else None,
        "report_facts_hash": {
            "off": left["report_facts_hash"], "on": right["report_facts_hash"],
        },
        "comparable_facts_hash": {
            "off": left["comparable_hash"], "on": right["comparable_hash"],
        },
        "finding_counts": {"off": left["finding_count"], "on": right["finding_count"]},
        "candidate_status_counts": {
            "off": left["candidate_status_counts"], "on": right["candidate_status_counts"],
        },
        "requests_used": {"off": left["requests_used"], "on": right["requests_used"]},
        "cost_delta": {
            "llm_calls": right["llm_calls"] - left["llm_calls"],
            "input_tokens": right["input_tokens"] - left["input_tokens"],
            "output_tokens": right["output_tokens"] - left["output_tokens"],
            "elapsed_ms": round(right["elapsed_ms"] - left["elapsed_ms"], 3),
            "note": "Report narrator telemetry only, not total run cost.",
        },
        "rates": {
            "off": aggregate_rates(
                [record for record in records if _same_run_conditions(record, off)],
                "heuristic",
            ),
            "on": aggregate_rates(
                [record for record in records if _same_run_conditions(record, on)],
                "llm",
            ),
        },
        "comparison_warning": (
            "Older records carry no report_facts_comparable_hash; fact preservation is unverified."
            if not hashes_known else
            "Report facts differ between the two runs; differences are not a narrator ablation."
            if not same_facts else
            "Separate target runs. Matching comparable hashes mean the same facts apart "
            "from per-run identifiers, not that the narrator caused any remaining difference."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    replay_parser = commands.add_parser(
        "replay", help="fixed fixture replay; no target requests and no provider calls",
    )
    replay_parser.add_argument(
        "--fixture", default=str(ROOT / "tests/fixtures/report_comparison.json"),
    )
    replay_parser.add_argument(
        "--failure", choices=("none", *sorted(_FAILURES)), default="none",
        help="inject a narrator failure to measure the fallback path",
    )
    logs_parser = commands.add_parser(
        "logs", help="compare the latest recorded runs and aggregate rates across all of them",
    )
    logs_parser.add_argument("--baseline-log", required=True, help="JSONL holding --report heuristic runs")
    logs_parser.add_argument("--narrative-log", required=True, help="JSONL holding --report llm runs")
    for command in (replay_parser, logs_parser):
        command.add_argument(
            "--output", default="artifacts/report-comparisons.jsonl",
            help="append comparison JSONL",
        )
    args = parser.parse_args(argv)
    try:
        output = JsonlRoutingAuditLog(args.output)
        output.prepare()
        comparison = replay(args) if args.command == "replay" else compare_logs(args)
        output.append(comparison)
    except (OSError, ValueError, KeyError, TypeError, LlmCredentialsMissing) as error:
        print(f"Comparison failed: {type(error).__name__}; check input files and fixture shape.")
        return 2
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
