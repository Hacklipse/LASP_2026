"""narrator off/on 비교 도구가 사실 보존·인용 정합성·비용·비율을 제대로 재는지 검증한다."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from compare_reports import (  # noqa: E402
    _FAILURES, _render, _resolve_payload, _seed, _strip_comments, aggregate_rates,
    compare_logs, compare_reports, latest_run, main, replay,
)
from routing_options import _report_facts_hash  # noqa: E402
from hacklipse.adapters import MemoryStoreBundle  # noqa: E402
from hacklipse.adapters.llm_report_narrative import LlmReportNarrator  # noqa: E402
from hacklipse.adapters.report_contract import finding_fact_id  # noqa: E402

import compare_reports as tool  # noqa: E402


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "report_comparison.json"


def load_fixture():
    return _strip_comments(json.loads(FIXTURE.read_text(encoding="utf-8")))


def replay_args(failure="none", output="artifacts/unused.jsonl"):
    return argparse.Namespace(fixture=str(FIXTURE), failure=failure, output=output)


def run_result(run_id, mode, *, facts_hash, findings=2, narrative=None, requests_used=100):
    """실행기가 남기는 run_result 레코드의 비교 관련 필드만 재현한다."""

    return {
        "schema_version": 4, "event": "run_result", "run_id": run_id,
        "report_mode": mode, "report_facts_hash": facts_hash,
        "finding_count": findings, "requests_used": requests_used,
        "candidate_status_counts": {"confirmed": findings, "skipped_budget": 3},
        "report_narrative": narrative if narrative is not None else {
            "schema_version": 1, "enabled": mode == "llm", "claim_count": 0,
            "invalid_claim_count": 0, "selection_source_counts": {}, "status_counts": {},
            "rejected_sentence_count": 0, "llm_calls": 0, "input_tokens_observed": 0,
            "output_tokens_observed": 0, "usage_available_count": 0,
            "usage_unavailable_count": 0, "elapsed_available_count": 0,
            "elapsed_ms_observed": 0,
        },
    }


def write_log(directory, name, records):
    path = Path(directory) / name
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )
    return str(path)


class FixtureShapeTests(unittest.TestCase):
    def test_comments_are_stripped_before_the_schema_sees_them(self):
        # Narrator schema는 추가 키를 통째로 거부한다. 주석이 남으면 전부 invalid_shape다.
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertIn("_comment", raw["llm_response"])
        stripped = _strip_comments(raw)
        self.assertNotIn("_comment", stripped["llm_response"])
        self.assertTrue(all("_comment" not in item for item in stripped["llm_response"]["findings"]))
        self.assertTrue(all("_comment" not in item for item in stripped["findings"]))

    def test_fact_references_are_resolved_to_real_ids(self):
        payload = _resolve_payload(load_fixture()["llm_response"])
        by_id = {item["finding_id"]: item["fact_ids"] for item in payload["findings"]}
        self.assertEqual(by_id["finding-xss"], [finding_fact_id("finding-xss")])
        # @finding:<id>는 남의 fact를 가리킨다. 이 fixture는 거부 경로를 일부러 밟는다.
        self.assertEqual(by_id["finding-legacy"], [finding_fact_id("finding-xss")])

    def test_run_level_fact_ids_stay_literal(self):
        payload = _resolve_payload(load_fixture()["llm_response"])
        self.assertIn("run:scope", payload["run_summary"]["fact_ids"])

    def test_seeded_stores_carry_every_candidate_status(self):
        fixture = load_fixture()
        stores, _, task = _seed(fixture)
        counts = {}
        for candidate in stores.candidates.list_by_run(task.run_id):
            counts[candidate.status.value] = counts.get(candidate.status.value, 0) + 1
        expected = {k: v for k, v in fixture["candidate_counts"].items() if v}
        self.assertEqual(counts, expected)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.comparison = replay(replay_args())

    def test_narrator_off_and_on_share_one_facts_hash(self):
        # §7 결정적 사실 보존. 이게 깨지면 아래 어떤 축도 ablation이 아니다.
        self.assertTrue(self.comparison["same_report_facts"])
        self.assertEqual(
            self.comparison["report_facts_hash"]["off"],
            self.comparison["report_facts_hash"]["on"],
        )
        self.assertTrue(self.comparison["paired_run"])

    def test_narrative_only_appends_to_the_deterministic_block(self):
        self.assertTrue(self.comparison["deterministic_block_preserved"])

    def test_findings_and_candidate_counts_do_not_move(self):
        self.assertEqual(
            self.comparison["finding_counts"]["off"], self.comparison["finding_counts"]["on"],
        )
        self.assertEqual(
            self.comparison["candidate_status_counts"]["off"],
            self.comparison["candidate_status_counts"]["on"],
        )

    def test_every_cited_fact_is_in_the_offered_set(self):
        citation = self.comparison["fact_citation"]
        self.assertEqual(citation["outside_offered_set"], [])
        self.assertEqual(citation["containment_rate"], 1.0)
        self.assertLessEqual(citation["cited_fact_count"], citation["offered_fact_count"])

    def test_foreign_fact_citation_is_counted_as_rejected(self):
        # fixture의 finding-legacy는 남의 fact를 인용한다. 통째로 버려져야 한다.
        self.assertEqual(self.comparison["narrative"]["rejected_sentence_count"], 1)
        self.assertEqual(self.comparison["narrative"]["status"], "completed")

    def test_status_representation_distinguishes_unconfirmed_from_absence(self):
        for side in ("off", "on"):
            representation = self.comparison["status_representation"][side]
            self.assertTrue(representation["budget_shortfall_stated"])
            self.assertTrue(representation["unconfirmed_distinguished"])
            self.assertGreater(representation["skipped_budget_count"], 0)

    def test_cost_is_reported_and_marked_as_narrator_only(self):
        cost = self.comparison["cost_delta"]
        self.assertEqual(cost["llm_calls"], 1)
        self.assertGreater(cost["input_tokens"], 0)
        self.assertGreater(cost["output_tokens"], 0)
        self.assertIn("not total run cost", cost["note"])

    def test_trace_is_stored_without_prose(self):
        self.assertTrue(self.comparison["narrative_trace_stored"])

    def test_warning_does_not_claim_semantic_accuracy(self):
        self.assertIn("not semantic accuracy", self.comparison["comparison_warning"])

    def test_replay_makes_no_provider_or_target_call(self):
        # fixture provider 외의 경로가 없다는 것을 모델 이름으로 확인한다.
        self.assertEqual(tool.FIXTURE_MODEL, "fixture-not-a-real-model")
        self.assertEqual(tool.CONFIG.model, tool.FIXTURE_MODEL)


class ReplayFailureTests(unittest.TestCase):
    def test_every_failure_keeps_the_facts_and_drops_the_sentences(self):
        for failure in sorted(_FAILURES):
            with self.subTest(failure=failure):
                with self.assertLogs("hacklipse.adapters.llm_report_narrative", level="WARNING"):
                    comparison = replay(replay_args(failure))
                self.assertTrue(comparison["same_report_facts"])
                self.assertTrue(comparison["deterministic_block_preserved"])
                self.assertEqual(comparison["narrative"]["status"], failure)
                self.assertEqual(
                    comparison["narrative"]["selection_source"], "deterministic_fallback",
                )
                self.assertEqual(comparison["narrative"]["accepted_fact_count"], 0)
                self.assertIn("fell back", comparison["comparison_warning"])

    def test_fallback_leaves_the_citation_rate_undefined_not_perfect(self):
        # 인용이 0건인데 1.0으로 적으면 "완벽하게 인용했다"로 읽힌다.
        with self.assertLogs("hacklipse.adapters.llm_report_narrative", level="WARNING"):
            comparison = replay(replay_args("timeout"))
        self.assertIsNone(comparison["fact_citation"]["containment_rate"])
        self.assertEqual(comparison["fact_citation"]["cited_fact_count"], 0)


class DifferingFactsTests(unittest.TestCase):
    def test_different_facts_are_reported_as_not_an_ablation(self):
        fixture = load_fixture()
        off = _render(fixture)
        changed = dict(fixture, candidate_counts=dict(fixture["candidate_counts"], rejected=99))
        on = _render(changed)
        comparison = compare_reports(off, on)
        self.assertFalse(comparison["same_report_facts"])
        self.assertIn("not a narrator ablation", comparison["comparison_warning"])

    def test_a_replaced_deterministic_block_is_flagged(self):
        fixture = load_fixture()
        off = _render(fixture)
        client = tool._FixtureLlm(_resolve_payload(fixture["llm_response"]))
        on = _render(fixture, narrator=LlmReportNarrator(llm_client=client, config=tool.CONFIG))
        # 요약이 사실 블록 위를 덮어쓴 상황을 만들어 검사 자체가 작동하는지 본다.
        on = dict(on, content="덮어쓴 보고서\n")
        comparison = compare_reports(off, on)
        self.assertFalse(comparison["deterministic_block_preserved"])
        self.assertIn("replaced part of the deterministic block", comparison["comparison_warning"])


class LogsTests(unittest.TestCase):
    def logs(self, records, *, second=None):
        with tempfile.TemporaryDirectory() as directory:
            baseline = write_log(directory, "baseline.jsonl", records)
            narrative = (
                write_log(directory, "narrative.jsonl", second) if second is not None else baseline
            )
            return compare_logs(argparse.Namespace(
                baseline_log=baseline, narrative_log=narrative,
                output=str(Path(directory) / "out.jsonl"),
            ))

    def test_matching_hashes_are_reported_as_the_same_report_input(self):
        comparison = self.logs([
            run_result("run-off", "heuristic", facts_hash="a" * 64),
            run_result("run-on", "llm", facts_hash="a" * 64),
        ])
        self.assertTrue(comparison["report_facts_hash_available"])
        self.assertTrue(comparison["same_report_facts"])
        self.assertFalse(comparison["paired_run"])
        self.assertIn("not that the narrator caused", comparison["comparison_warning"])

    def test_differing_hashes_are_not_an_ablation(self):
        comparison = self.logs([
            run_result("run-off", "heuristic", facts_hash="a" * 64),
            run_result("run-on", "llm", facts_hash="b" * 64),
        ])
        self.assertFalse(comparison["same_report_facts"])
        self.assertIn("not a narrator ablation", comparison["comparison_warning"])

    def test_records_without_a_hash_are_unverified_not_equal(self):
        # 구버전 로그를 "사실이 같다"로 읽으면 없는 근거를 만들어 내는 것이다.
        comparison = self.logs([
            run_result("run-off", "heuristic", facts_hash=None),
            run_result("run-on", "llm", facts_hash=None),
        ])
        self.assertFalse(comparison["report_facts_hash_available"])
        self.assertIsNone(comparison["same_report_facts"])
        self.assertIn("unverified", comparison["comparison_warning"])

    def test_latest_record_per_mode_wins(self):
        comparison = self.logs([
            run_result("run-old", "llm", facts_hash="a" * 64),
            run_result("run-off", "heuristic", facts_hash="a" * 64),
            run_result("run-new", "llm", facts_hash="a" * 64),
        ])
        self.assertEqual(comparison["on_run_id"], "run-new")

    def test_a_missing_mode_is_refused(self):
        with self.assertRaises(ValueError):
            self.logs([run_result("run-off", "heuristic", facts_hash="a" * 64)])

    def test_two_separate_files_are_read_together(self):
        comparison = self.logs(
            [run_result("run-off", "heuristic", facts_hash="a" * 64)],
            second=[run_result("run-on", "llm", facts_hash="a" * 64)],
        )
        self.assertEqual(comparison["off_run_id"], "run-off")
        self.assertEqual(comparison["on_run_id"], "run-on")

    def test_one_file_given_twice_is_not_counted_twice(self):
        # 두 축이 한 파일에 같이 적히는 것이 기본이다. 분모가 배로 뛰면 비율이 거짓이 된다.
        comparison = self.logs([
            run_result("run-off", "heuristic", facts_hash="a" * 64),
            run_result("run-on", "llm", facts_hash="a" * 64),
        ])
        self.assertEqual(comparison["rates"]["off"]["run_count"], 1)
        self.assertEqual(comparison["rates"]["on"]["run_count"], 1)

    def test_a_rewritten_run_is_counted_once_at_its_latest_state(self):
        comparison = self.logs([
            run_result("run-off", "heuristic", facts_hash="a" * 64),
            run_result("run-on", "llm", facts_hash="b" * 64, findings=1),
            run_result("run-on", "llm", facts_hash="a" * 64, findings=9),
        ])
        self.assertEqual(comparison["rates"]["on"]["run_count"], 1)
        self.assertEqual(comparison["finding_counts"]["on"], 9)
        self.assertTrue(comparison["same_report_facts"])

    def test_cost_delta_subtracts_the_baseline(self):
        narrative = dict(
            run_result("x", "llm", facts_hash="a" * 64)["report_narrative"],
            llm_calls=3, input_tokens_observed=900, output_tokens_observed=120,
            elapsed_ms_observed=450.5,
        )
        comparison = self.logs([
            run_result("run-off", "heuristic", facts_hash="a" * 64),
            run_result("run-on", "llm", facts_hash="a" * 64, narrative=narrative),
        ])
        self.assertEqual(comparison["cost_delta"]["llm_calls"], 3)
        self.assertEqual(comparison["cost_delta"]["input_tokens"], 900)
        self.assertEqual(comparison["cost_delta"]["elapsed_ms"], 450.5)


class RateTests(unittest.TestCase):
    def narrative(self, **changes):
        base = {
            "schema_version": 1, "enabled": True, "claim_count": 1, "invalid_claim_count": 0,
            "selection_source_counts": {"llm": 1}, "status_counts": {"completed": 1},
            "rejected_sentence_count": 0, "llm_calls": 1, "input_tokens_observed": 100,
            "output_tokens_observed": 20, "usage_available_count": 1,
            "usage_unavailable_count": 0, "elapsed_available_count": 1,
            "elapsed_ms_observed": 10,
        }
        base.update(changes)
        return base

    def test_rates_span_every_run_not_just_the_latest(self):
        records = [
            run_result("r1", "llm", facts_hash="a" * 64, narrative=self.narrative()),
            run_result("r2", "llm", facts_hash="a" * 64, narrative=self.narrative(
                selection_source_counts={"deterministic_fallback": 1},
                status_counts={"timeout": 1},
            )),
            run_result("r3", "llm", facts_hash="a" * 64, narrative=self.narrative(
                rejected_sentence_count=2,
            )),
        ]
        rates = aggregate_rates(records, "llm")
        self.assertEqual(rates["run_count"], 3)
        self.assertEqual(rates["claim_count"], 3)
        self.assertEqual(rates["fallback_rate"], round(1 / 3, 6))
        self.assertEqual(rates["rejected_per_claim"], round(2 / 3, 6))
        self.assertEqual(rates["status_counts"], {"completed": 2, "timeout": 1})

    def test_no_claims_leaves_rates_undefined_not_zero(self):
        # 0.0으로 적으면 "fallback이 한 번도 없었다"로 읽힌다. 분모가 없는 것과 다르다.
        rates = aggregate_rates([run_result("r1", "heuristic", facts_hash="a" * 64)], "heuristic")
        self.assertEqual(rates["run_count"], 1)
        self.assertIsNone(rates["fallback_rate"])
        self.assertIsNone(rates["rejected_per_claim"])

    def test_other_modes_are_excluded(self):
        records = [
            run_result("r1", "llm", facts_hash="a" * 64, narrative=self.narrative()),
            run_result("r2", "heuristic", facts_hash="a" * 64),
        ]
        self.assertEqual(aggregate_rates(records, "llm")["run_count"], 1)
        self.assertEqual(aggregate_rates(records, "heuristic")["claim_count"], 0)


class RunResultHashTests(unittest.TestCase):
    """logs 비교의 사실 보존 검사는 run_result에 적힌 이 해시 하나에 걸려 있다."""

    def app(self, stores):
        return SimpleNamespace(stores=stores)

    def stored(self, fixture, *, narrator=None):
        """보고서를 실제로 만들어 Store에 넣는다. 실행기와 같은 상태를 재현한다."""

        stores, budget, task = _seed(fixture)
        usage = fixture["run"].get("llm_usage")
        reporter = tool.MarkdownReportAgent(
            finding_store=stores.findings, evidence_store=stores.evidence,
            candidate_store=stores.candidates, surface_store=stores.surfaces,
            run_store=stores.runs, budget_manager=budget, format_version="v2",
            llm_usage=SimpleNamespace(**usage) if usage else None,
            narrator=narrator, narrator_config=tool.CONFIG if narrator is not None else None,
        )
        expected = tool.report_facts_hash(reporter.collect_facts(task))
        for report in reporter.handle(task).reports:
            stores.reports.add(report)
        run = stores.runs.get(task.run_id).with_updates(finding_ids=task.finding_ids)
        return stores, run, expected

    def test_recorded_hash_is_the_one_the_report_actually_used(self):
        fixture = load_fixture()
        stores, run, expected = self.stored(fixture)
        self.assertEqual(_report_facts_hash(self.app(stores), run), expected)
        self.assertEqual(_report_facts_hash(self.app(stores), run), _render(fixture)["facts_hash"])

    def test_usage_that_grew_after_the_report_does_not_change_the_record(self):
        """사실에는 LLM 사용량이 들어 있고 그 값은 Report 이후에도 늘어난다.

        여기에서 사실을 다시 모으면 보고서가 쓴 것과 다른 해시가 기록되고, off/on
        비교가 "사실이 다르다"고 잘못 말한다.
        """

        fixture = load_fixture()
        meter = SimpleNamespace(**fixture["run"]["llm_usage"])
        stores, budget, task = _seed(fixture)
        reporter = tool.MarkdownReportAgent(
            finding_store=stores.findings, evidence_store=stores.evidence,
            candidate_store=stores.candidates, surface_store=stores.surfaces,
            run_store=stores.runs, budget_manager=budget, format_version="v2",
            llm_usage=meter,
        )
        expected = tool.report_facts_hash(reporter.collect_facts(task))
        for report in reporter.handle(task).reports:
            stores.reports.add(report)
        # Narrator 호출과 이후 작업으로 계측기가 더 올라간 상태를 만든다.
        meter.calls += 3
        meter.input_tokens += 2500
        run = stores.runs.get(task.run_id).with_updates(finding_ids=task.finding_ids)
        self.assertEqual(_report_facts_hash(self.app(stores), run), expected)

    def test_a_run_without_a_report_is_unknown_not_empty(self):
        # None이어야 logs 비교가 "확인하지 못함"으로 읽는다. ""는 서로 같아 보인다.
        _, _, task = _seed(load_fixture())
        run = SimpleNamespace(run_id=task.run_id, finding_ids=task.finding_ids)
        self.assertIsNone(_report_facts_hash(self.app(MemoryStoreBundle()), run))

    def test_a_v1_report_carries_no_facts_hash(self):
        stores, _, task = _seed(load_fixture())
        reporter = tool.MarkdownReportAgent(
            finding_store=stores.findings, evidence_store=stores.evidence,
        )
        for report in reporter.handle(task).reports:
            stores.reports.add(report)
        run = stores.runs.get(task.run_id).with_updates(finding_ids=task.finding_ids)
        self.assertIsNone(_report_facts_hash(self.app(stores), run))

    def test_an_unreadable_report_store_is_unknown(self):
        class Exploding:
            def list_by_run(self, run_id):
                raise RuntimeError("store blew up")

        run = SimpleNamespace(run_id="run-1", finding_ids=())
        app = SimpleNamespace(stores=SimpleNamespace(reports=Exploding()))
        self.assertIsNone(_report_facts_hash(app, run))


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(argv)
        return code, stdout.getvalue()

    def test_replay_writes_one_comparison_line(self):
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "comparisons.jsonl")
            code, printed = self.run_cli(["replay", "--fixture", str(FIXTURE), "--output", output])
            self.assertEqual(code, 0)
            lines = Path(output).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["event"], "report_comparison")
            self.assertTrue(json.loads(printed)["same_report_facts"])

    def test_a_broken_fixture_fails_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "broken.json"
            broken.write_text('{"run": {}}', encoding="utf-8")
            code, printed = self.run_cli([
                "replay", "--fixture", str(broken),
                "--output", str(Path(directory) / "out.jsonl"),
            ])
            self.assertEqual(code, 2)
            self.assertIn("Comparison failed", printed)

    def test_logs_requires_both_sides(self):
        with tempfile.TemporaryDirectory() as directory:
            log = write_log(directory, "one.jsonl", [
                run_result("run-off", "heuristic", facts_hash="a" * 64),
            ])
            code, printed = self.run_cli([
                "logs", "--baseline-log", log, "--narrative-log", log,
                "--output", str(Path(directory) / "out.jsonl"),
            ])
            self.assertEqual(code, 2)
            self.assertIn("Comparison failed", printed)

    def test_latest_run_rejects_an_unknown_mode(self):
        with self.assertRaises(ValueError):
            latest_run([run_result("r", "heuristic", facts_hash="a" * 64)], "llm")


if __name__ == "__main__":
    unittest.main()
