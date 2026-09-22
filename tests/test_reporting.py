"""v1 bytes 보존과 v2의 Store 기반 사실/민감정보 경계를 검증한다."""

from dataclasses import replace
from types import SimpleNamespace
import unittest

from hacklipse.adapters import InMemoryBudgetManager, MemoryStoreBundle
from hacklipse.adapters.report_contract import serialize_report_facts
from hacklipse.adapters.reporting import FindingReportReferences, MarkdownReportAgent, render_report_v2
from hacklipse.domain import (
    Candidate, CandidateStatus, Evidence, Finding, Run, RunScope, Surface,
    TaskEnvelope, ValidationProofType,
)
from hacklipse.ports.errors import RecordNotFound


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.stores = MemoryStoreBundle()
        self.budget = InMemoryBudgetManager()
        self.stores.runs.add(Run(
            run_id="run-1", target_url="https://local.test/?token=target-secret",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=20, credential_ref="credential-secret",
        ))
        self.budget.open_run("run-1", 20)
        self.budget.consume("run-1", 3)
        self.stores.surfaces.add(Surface(
            surface_id="surface-1", run_id="run-1",
            url="https://local.test/users/123?token=query-secret#marker-secret",
            method="GET", parameters=("q", "q"), observed_query=(("token", "observed-secret"),),
        ))
        self.stores.evidence.append(Evidence(
            evidence_id="evi-1", run_id="run-1", surface_id="surface-1",
            created_by="fixture", evidence_type="http_response",
            observation={"body": "body-secret", "Cookie": "cookie-secret", "marker": "probe-secret"},
        ))
        self.finding = Finding(
            finding_id="finding-1", run_id="run-1", candidate_id="candidate-confirmed",
            validation_id="validation-1", vulnerability_type="XSS", surface_id="surface-1",
            evidence_ids=("evi-1",), proof_type=ValidationProofType.XSS_EXECUTION, reproduction_count=2,
        )
        self.stores.findings.add(self.finding)
        for status in CandidateStatus:
            self.stores.candidates.add(Candidate(
                candidate_id=f"candidate-{status.value}", run_id="run-1", surface_id="surface-1",
                vulnerability_type="XSS", hypothesis="hypothesis-secret", assigned_agent="xss_analyzer",
                evidence_ids=(), status=status, last_error="exception-secret",
            ))
        self.task = TaskEnvelope(task_id="task-report", run_id="run-1", agent_type="report", finding_ids=("finding-1",))

    def reporter(self, version="v2", **changes):
        kwargs = dict(
            finding_store=self.stores.findings, evidence_store=self.stores.evidence,
            candidate_store=self.stores.candidates, surface_store=self.stores.surfaces,
            run_store=self.stores.runs, budget_manager=self.budget, format_version=version,
        )
        kwargs.update(changes)
        return MarkdownReportAgent(**kwargs)

    def test_v1_preserves_exact_existing_output_and_default(self):
        expected = (
            "# Security assessment report\n\nRun: `run-1`\n\n## XSS (unrated)\n\n"
            "- Finding: `finding-1`\n- Surface: `surface-1`\n"
            "- Validation: `validation-1`\n- Evidence: `evi-1`\n"
        )
        default = MarkdownReportAgent(finding_store=self.stores.findings, evidence_store=self.stores.evidence)
        for reporter in (default, self.reporter("v1")):
            self.assertEqual(reporter.handle(self.task).reports[0].content.encode(), expected.encode())
            empty = reporter.handle(replace(self.task, finding_ids=())).reports[0].content
            self.assertEqual(empty, "# Security assessment report\n\nRun: `run-1`\n\nNo confirmed findings were produced.\n")

    def test_v2_collects_real_stores_and_ignores_report_task_budget(self):
        reporter = self.reporter()
        facts = reporter.collect_facts(self.task)
        self.assertEqual(facts.request_budget_total, 20)
        self.assertEqual(facts.request_budget_used, 3)
        self.assertEqual(self.task.request_budget, 0)
        self.assertEqual(facts.surface_count, 1)
        self.assertEqual(facts.parameter_count, 1)
        self.assertEqual(dict(facts.candidate_counts), {s: 1 for s in CandidateStatus})
        self.assertEqual(facts.findings[0].surface_path_hint, "/users/{value}")
        report = reporter.handle(self.task).reports[0]
        self.assertEqual(report.format, "markdown")
        self.assertIn("# Security assessment report (v2)", report.content)
        self.assertIn("재현 횟수: 2", report.content)
        self.assertIn("Proof type: `xss_execution`", report.content)
        self.assertIn("Evidence: `evi-1`", report.content)
        for status in CandidateStatus:
            self.assertIn(f"| {status.value} | 1 |", report.content)
        self.assertEqual(self.stores.findings.get("run-1", "finding-1"), self.finding)

    def test_same_v2_input_has_identical_content_despite_new_artifact_id(self):
        reporter = self.reporter()
        first = reporter.handle(self.task).reports[0]
        second = reporter.handle(self.task).reports[0]
        self.assertNotEqual(first.report_id, second.report_id)
        self.assertEqual(first.content.encode(), second.content.encode())
        facts = reporter.collect_facts(self.task)
        references = (FindingReportReferences("finding-1", "surface-1", "validation-1", ("evi-1",)),)
        execution = self.stores.runs.get("run-1").execution_profile
        self.assertEqual(first.content.encode(), render_report_v2(
            facts, references=references, execution=execution,
        ).encode())

    def test_legacy_finding_has_no_invented_reproduction(self):
        self.stores.findings.add(replace(self.finding, finding_id="legacy", proof_type=None, reproduction_count=0))
        task = replace(self.task, finding_ids=("legacy",))
        report = self.reporter().handle(task).reports[0].content
        self.assertIn("검증 상세를 사용할 수 없음", report)
        self.assertIn("재현 횟수: 정보 없음", report)
        self.assertNotIn("실행 신호 확인", report)
        self.assertNotIn("Proof type:", report)

    def test_all_proof_types_have_fixed_descriptions(self):
        for index, proof_type in enumerate(ValidationProofType):
            finding = replace(self.finding, finding_id=f"proof-{index}", proof_type=proof_type)
            self.stores.findings.add(finding)
            content = self.reporter().handle(replace(self.task, finding_ids=(finding.finding_id,))).reports[0].content
            self.assertIn(f"Proof type: `{proof_type.value}`", content)
            self.assertIn("재현 횟수: 2", content)

    def test_skips_failures_and_suspicions_remain_visible_without_findings(self):
        content = self.reporter().handle(replace(self.task, finding_ids=())).reports[0].content
        for phrase in ("확정 Finding이 없습니다", "예산 부족", "의심 상태이며 미확정", "검증 차단", "검사 실패"):
            self.assertIn(phrase, content)
        self.assertNotIn("취약점이 없습니다", content)
        self.assertNotIn("No confirmed findings were produced.", content)

    def test_missing_budget_measurement_is_unknown_not_zero(self):
        for manager in (None, InMemoryBudgetManager()):
            reporter = self.reporter(budget_manager=manager)
            self.assertIsNone(reporter.collect_facts(self.task).request_budget_used)
            self.assertIn("사용 요청 예산: 정보 없음", reporter.handle(self.task).reports[0].content)

    def execution(self, **changes):
        """Run에 영속된 실행 조건을 바꾼 뒤 보고서를 다시 만든다."""

        run = self.stores.runs.get("run-1")
        self.stores.runs.save(run.with_updates(
            execution_profile=replace(run.execution_profile, **changes),
        ))
        return self.reporter().handle(self.task).reports[0].content

    def test_recorded_execution_conditions_are_shown(self):
        # 보고서만 보고 이 실행이 어떤 모드·모델로 돌았는지 알 수 있어야 한다.
        content = self.execution(
            analysis_profile="llm", recon_mode="hybrid", router_mode="hybrid",
            router_review="ambiguous", orchestrator_mode="hybrid",
            budget_allocation_mode="heuristic", validation_mode="llm", report_mode="llm",
            llm_provider="gemini", llm_model="gemini-3.5-flash-lite", llm_rpm_limit=14,
        )
        self.assertIn("## 실행 조건", content)
        for line in (
            "- Analysis: `llm`", "- Recon: `hybrid` · Surface 수집 `adaptive`",
            "- Router: `hybrid` · review `ambiguous`",
            "- Orchestrator: `hybrid` · 예산 배분 `heuristic`",
            "- Validation: `llm`", "- Report: `llm`",
            "- LLM: `gemini` / `gemini-3.5-flash-lite`",
            "- LLM 분당 호출 제한: 14",
        ):
            self.assertIn(line, content)
        # §2.2 순서 - 식별자와 구성이 검사 범위보다 먼저다.
        self.assertLess(content.index("## 실행 조건"), content.index("## 검사 범위"))

    def test_a_run_without_llm_says_so_instead_of_naming_a_model(self):
        content = self.execution(llm_provider="", llm_model="")
        self.assertIn("- LLM: 사용 안 함", content)
        self.assertNotIn("LLM 분당 호출 제한", content)

    def test_unrecorded_conditions_are_withheld_not_guessed(self):
        # 구버전 DB의 기본값을 적으면 측정하지 않은 조건을 사실로 말하게 된다.
        content = self.execution(
            recorded=False, analysis_profile="llm",
            llm_provider="gemini", llm_model="x-1",
        )
        self.assertIn("## 실행 조건", content)
        self.assertIn("실제\n실행 조건으로 해석할 수 없어 표시하지 않습니다", content)
        self.assertNotIn("- Analysis:", content)
        self.assertNotIn("x-1", content)

    def test_execution_conditions_never_enter_the_narrator_facts(self):
        # §3.2의 허용 입력 목록은 닫혀 있고 실행 프로파일은 거기에 없다.
        self.execution(
            report_mode="llm", llm_provider="gemini", llm_model="secret-model-name",
        )
        serialized = serialize_report_facts(self.reporter().collect_facts(self.task))
        self.assertNotIn("secret-model-name", serialized)
        self.assertNotIn("analysis_profile", serialized)

    def test_an_unreadable_run_drops_the_section_instead_of_guessing(self):
        class Exploding:
            def get(self, run_id):
                raise RuntimeError("run store blew up")

            def list_by_run(self, run_id):
                return ()

        reporter = self.reporter()
        facts = reporter.collect_facts(self.task)
        reporter._runs = Exploding()
        with self.assertLogs("hacklipse.adapters.reporting", level="WARNING") as logs:
            content = render_report_v2(facts, execution=reporter._execution_profile(self.task))
        self.assertNotIn("## 실행 조건", content)
        self.assertNotIn("run store blew up", "\n".join(logs.output))

    def test_llm_usage_is_read_when_the_report_is_made_not_when_wired(self):
        # 조립 시점의 계측기는 0이다. 그때 읽으면 모든 보고서가 "LLM 0회"가 된다.
        meter = SimpleNamespace(calls=0, input_tokens=0, output_tokens=0)
        reporter = self.reporter(llm_usage=meter)
        meter.calls, meter.input_tokens, meter.output_tokens = 7, 4200, 610
        facts = reporter.collect_facts(self.task)
        self.assertEqual(
            (facts.llm_calls, facts.llm_input_tokens, facts.llm_output_tokens),
            (7, 4200, 610),
        )
        content = reporter.handle(self.task).reports[0].content
        for line in ("- LLM 호출: 7", "- LLM 입력 token: 4,200".replace(",", ""),
                     "- LLM 출력 token: 610"):
            self.assertIn(line, content)
        self.assertIn("보고서를 만들기 직전까지의 Run 누적값", content)

    def test_missing_usage_meter_is_unknown_not_zero(self):
        # LLM을 껐을 때와 계측을 안 붙였을 때를 0으로 합치면 없는 사실을 말하게 된다.
        reporter = self.reporter()
        facts = reporter.collect_facts(self.task)
        self.assertEqual(
            (facts.llm_calls, facts.llm_input_tokens, facts.llm_output_tokens),
            (None, None, None),
        )
        self.assertIn("- LLM 호출: 정보 없음", reporter.handle(self.task).reports[0].content)

    def test_an_unusable_meter_is_unknown_and_never_blocks_the_report(self):
        class Exploding:
            @property
            def calls(self):
                raise RuntimeError("meter blew up")
            input_tokens = 0
            output_tokens = 0

        for meter in (Exploding(), SimpleNamespace(calls=-1, input_tokens=0, output_tokens=0),
                      SimpleNamespace(calls=True, input_tokens=0, output_tokens=0),
                      SimpleNamespace(calls="7", input_tokens=0, output_tokens=0)):
            with self.subTest(meter=type(meter).__name__):
                reporter = self.reporter(llm_usage=meter)
                with self.assertLogs("hacklipse.adapters.reporting", level="WARNING") as logs:
                    facts = reporter.collect_facts(self.task)
                self.assertIsNone(facts.llm_calls)
                self.assertNotIn("meter blew up", "\n".join(logs.output))
                self.assertIn("LLM 호출: 정보 없음", reporter.handle(self.task).reports[0].content)

    def test_a_silent_llm_run_is_zero_not_unknown(self):
        reporter = self.reporter(
            llm_usage=SimpleNamespace(calls=0, input_tokens=0, output_tokens=0),
        )
        self.assertEqual(reporter.collect_facts(self.task).llm_calls, 0)
        self.assertIn("- LLM 호출: 0", reporter.handle(self.task).reports[0].content)

    def test_secrets_never_enter_facts_or_report(self):
        reporter = self.reporter()
        serialized = serialize_report_facts(reporter.collect_facts(self.task))
        content = reporter.handle(self.task).reports[0].content
        for secret in ("target-secret", "credential-secret", "query-secret", "marker-secret", "observed-secret",
                       "body-secret", "cookie-secret", "probe-secret", "hypothesis-secret", "exception-secret"):
            self.assertNotIn(secret, serialized + content)
        self.assertNotIn("evi-1", serialized)
        self.assertNotIn("validation-1", serialized)
        self.assertNotIn("https://", serialized + content)

    def test_missing_and_foreign_evidence_are_rejected_in_both_versions(self):
        self.stores.evidence.append(Evidence(evidence_id="foreign-evi", run_id="other-run", surface_id=None, created_by="fixture", evidence_type="http_response"))
        for index, evidence_id in enumerate(("missing-evi", "foreign-evi")):
            finding = replace(self.finding, finding_id=f"invalid-{index}", evidence_ids=(evidence_id,))
            self.stores.findings.add(finding)
            for version in ("v1", "v2"):
                with self.assertRaises(RecordNotFound):
                    self.reporter(version).handle(replace(self.task, finding_ids=(finding.finding_id,)))

    def test_foreign_findings_and_surfaces_are_rejected(self):
        self.stores.findings.add(replace(self.finding, finding_id="foreign", run_id="other-run"))
        with self.assertRaises(RecordNotFound):
            self.reporter().handle(replace(self.task, finding_ids=("foreign",)))
        self.stores.surfaces.add(Surface(surface_id="foreign-surface", run_id="other-run", url="https://elsewhere.test/", method="GET"))
        self.stores.findings.add(replace(self.finding, finding_id="wrong-surface", surface_id="foreign-surface"))
        with self.assertRaises(RecordNotFound):
            self.reporter().handle(replace(self.task, finding_ids=("wrong-surface",)))

    def test_zero_statuses_are_rendered_and_other_runs_excluded(self):
        for candidate in self.stores.candidates.list_by_run("run-1"):
            self.stores.candidates.save(replace(candidate, status=CandidateStatus.REJECTED))
        self.stores.candidates.add(replace(candidate, candidate_id="foreign-candidate", run_id="foreign", status=CandidateStatus.CONFIRMED))
        self.stores.surfaces.add(Surface(surface_id="foreign-surface", run_id="foreign", url="https://other.test/", method="GET"))
        reporter = self.reporter()
        task = replace(self.task, finding_ids=())
        facts = reporter.collect_facts(task)
        self.assertEqual(facts.surface_count, 1)
        self.assertEqual(sum(dict(facts.candidate_counts).values()), len(CandidateStatus))
        content = reporter.handle(task).reports[0].content
        self.assertIn("| rejected | 8 |", content)
        self.assertIn("| skipped_budget | 0 |", content)
        self.assertIn("| confirmed | 0 |", content)
        self.assertNotIn("예산 부족으로", content)

    def test_unknown_version_or_incomplete_v2_wiring_fails_early(self):
        for version, changes in (("v3", {}), ("v2", {"candidate_store": None}),
                                 ("v2", {"surface_store": None}), ("v2", {"run_store": None})):
            with self.assertRaises(ValueError):
                self.reporter(version, **changes)


if __name__ == "__main__":
    unittest.main()
