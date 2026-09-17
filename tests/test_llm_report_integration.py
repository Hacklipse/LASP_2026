"""Narrator를 붙여도 결정적 v2 사실이 그대로인지, 실패가 Run을 깨지 않는지 검증한다."""

import unittest

from hacklipse.adapters.llm_report_narrative import (
    LlmReportNarrator, ReportNarrative, deterministic_fallback,
)
from hacklipse.adapters.report_contract import (
    NarratorFingerprintConfig, RunReportFacts, report_facts_hash,
)
from hacklipse.adapters.reporting import FindingReportReferences, render_report_v2
from hacklipse.ports.errors import LlmCredentialsMissing

from .test_llm_report_narrative import CONFIG, FakeLlm, example_facts, payload
from .test_reporting import ReportingTests


def references(facts: RunReportFacts) -> tuple[FindingReportReferences, ...]:
    return tuple(
        FindingReportReferences(
            finding_id=fact.finding_id, surface_id=f"surface-{index}",
            validation_id=f"validation-{index}", evidence_ids=(f"evidence-{index}",),
        )
        for index, fact in enumerate(facts.findings)
    )


class DeterministicBlockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.facts = example_facts()
        self.refs = references(self.facts)
        self.baseline = render_report_v2(self.facts, references=self.refs)

    def narrate(self, client: FakeLlm) -> ReportNarrative:
        return LlmReportNarrator(llm_client=client, config=CONFIG).narrate(self.facts)

    def test_narrator_output_is_appended_and_never_edits_the_facts(self):
        narrative = self.narrate(FakeLlm(payload(self.facts)))
        report = render_report_v2(self.facts, references=self.refs, narrative=narrative)
        self.assertTrue(report.startswith(self.baseline.rstrip() + "\n"))
        self.assertIn("## 요약 (비권위적)", report)
        self.assertLess(report.index("## 확정 Finding"), report.index("## 요약 (비권위적)"))

    def test_facts_hash_is_identical_with_and_without_the_narrator(self):
        narrative = self.narrate(FakeLlm(payload(self.facts)))
        render_report_v2(self.facts, references=self.refs, narrative=narrative)
        self.assertEqual(report_facts_hash(self.facts), report_facts_hash(example_facts()))

    def test_every_llm_failure_still_produces_the_deterministic_block(self):
        for status in ("timeout", "rate_limited", "transport_error", "refused",
                       "invalid_response", "internal_error", "all_rejected"):
            with self.subTest(status=status):
                report = render_report_v2(
                    self.facts, references=self.refs,
                    narrative=deterministic_fallback(status),
                )
                self.assertTrue(report.startswith(self.baseline.rstrip() + "\n"))
                self.assertIn(f"- 생성 상태: `{status}`", report)
                self.assertIn("확정 Finding", report)

    def test_fallback_block_carries_no_model_sentences(self):
        report = render_report_v2(
            self.facts, references=self.refs, narrative=deterministic_fallback("timeout"),
        )
        self.assertIn("- 출처: `deterministic_fallback`", report)
        self.assertNotIn("### reflected xss — 요약", report)

    def test_rejected_sentences_are_counted_in_the_report(self):
        broken = payload(self.facts)
        broken["findings"] = [{**broken["findings"][0], "summary": "위험도 높음."}]
        narrative = self.narrate(FakeLlm(broken))
        report = render_report_v2(self.facts, references=self.refs, narrative=narrative)
        self.assertIn("검증을 통과하지 못해 제외한 문장: 1개.", report)
        self.assertNotIn("위험도", report.split("## 요약 (비권위적)")[1])

    def test_narrative_does_not_change_finding_count_or_proof(self):
        narrative = self.narrate(FakeLlm(payload(self.facts)))
        report = render_report_v2(self.facts, references=self.refs, narrative=narrative)
        for fact in self.facts.findings:
            self.assertIn(fact.finding_id, report)
            self.assertIn(fact.proof_description, report)
        self.assertEqual(report.count("- Proof type:"), len(self.facts.findings))

    def test_missing_credentials_are_not_absorbed_by_the_report(self):
        client = FakeLlm(error=LlmCredentialsMissing("no key"))
        with self.assertRaises(LlmCredentialsMissing):
            self.narrate(client)


class ReportAgentTest(unittest.TestCase):
    """팀원 fixture의 setUp/reporter만 빌려온다. 상속하면 A의 테스트가 재실행된다."""

    setUp = ReportingTests.setUp
    reporter = ReportingTests.reporter

    def report(self, **changes) -> str:
        return self.reporter(**changes).handle(self.task).reports[0].content

    def test_narrator_none_is_byte_for_byte_identical(self):
        self.assertEqual(self.report(), self.report(narrator=None))

    def test_attaching_a_narrator_only_appends(self):
        facts = self.reporter().collect_facts(self.task)
        narrator = LlmReportNarrator(llm_client=FakeLlm(payload(facts)), config=CONFIG)
        with_narrator = self.report(narrator=narrator)
        self.assertTrue(with_narrator.startswith(self.report().rstrip() + "\n"))

    def test_a_broken_narrator_still_produces_the_report(self):
        class Exploding:
            def narrate(self, facts, *, timeout_seconds=60.0):
                raise RuntimeError("narrator blew up")

        content = self.report(narrator=Exploding())
        self.assertTrue(content.startswith(self.report().rstrip() + "\n"))
        self.assertIn("- 생성 상태: `internal_error`", content)

    def test_narrator_requires_format_v2(self):
        with self.assertRaises(ValueError):
            self.reporter(version="v1", narrator=LlmReportNarrator(
                llm_client=FakeLlm({}), config=CONFIG))

    def test_narrator_sees_no_secret_from_the_run(self):
        facts = self.reporter().collect_facts(self.task)
        client = FakeLlm(payload(facts))
        LlmReportNarrator(llm_client=client, config=CONFIG).narrate(facts)
        prompt = client.requests[0].messages[0].content
        for secret in ("target-secret", "query-secret", "observed-secret", "marker-secret",
                       "body-secret", "cookie-secret", "probe-secret", "credential-secret",
                       "hypothesis-secret", "exception-secret"):
            self.assertNotIn(secret, prompt)


class NarratorConfigTest(unittest.TestCase):
    def test_narrator_limits_flow_from_the_shared_config(self):
        self.assertEqual(CONFIG.run_summary_max_chars, 800)
        self.assertEqual(CONFIG.finding_summary_max_chars, 400)
        self.assertIsInstance(CONFIG, NarratorFingerprintConfig)


if __name__ == "__main__":
    unittest.main()
