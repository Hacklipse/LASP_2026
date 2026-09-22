"""Store/실제 LLM 없이 Narrator 출력 검증과 fallback만 확인한다."""

from dataclasses import replace
import unittest

from hacklipse.adapters.llm_report_narrative import (
    FALLBACK_RUN_SUMMARY, NARRATIVE_STATUSES, REJECTION_REASONS, RUN_SUMMARY_INDEX,
    LlmReportNarrator, ReportNarrative, build_narrative_prompt, deterministic_fallback,
    verify_narrative,
)
from hacklipse.adapters.report_contract import (
    FindingReportFact, NarratorFingerprintConfig, RunReportFacts, finding_fact_id,
)
from hacklipse.domain import CandidateStatus, ValidationProofType
from hacklipse.ports.errors import (
    LlmCredentialsMissing, LlmRateLimited, LlmRefused, LlmResponseFormatError,
    LlmTimeout, LlmTransportError,
)
from hacklipse.ports.llm import LlmResponse, LlmUsage


CONFIG = NarratorFingerprintConfig(model="fake-model", prompt_version="report-narrative-v1")


def example_facts() -> RunReportFacts:
    return RunReportFacts(
        run_id="run-1", format_version="v2",
        candidate_counts=tuple(
            (status, 2 if status is CandidateStatus.SKIPPED_BUDGET else 1)
            for status in CandidateStatus
        ),
        findings=(
            FindingReportFact(
                fact_id=finding_fact_id("finding-a"), finding_id="finding-a",
                vulnerability_type="reflected xss", surface_path_hint="/search",
                proof_type=ValidationProofType.XSS_EXECUTION, reproduction_count=3,
            ),
            FindingReportFact(
                fact_id=finding_fact_id("finding-b"), finding_id="finding-b",
                vulnerability_type="sqli", surface_path_hint="/login",
                proof_type=ValidationProofType.SQLI_EFFECT, reproduction_count=2,
            ),
        ),
        request_budget_total=500, request_budget_used=487,
        surface_count=12, parameter_count=34,
    )


def payload(facts: RunReportFacts, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "run_summary": {
            "fact_ids": ["run:scope", "run:request-budget"],
            "text": "Candidate 9개 중 1개를 확정했고 2개는 요청 예산이 부족해 검사를 완료하지 못했습니다.",
        },
        "findings": [
            {
                "finding_id": "finding-a", "fact_ids": [finding_fact_id("finding-a")],
                "summary": "독립 browser control/probe 비교에서 probe 실행 신호가 3회 재현됐습니다.",
            },
        ],
    }
    base.update(overrides)
    return base


class FakeLlm:
    """정해둔 응답이나 예외만 돌려주는 대역. 실제 호출은 하지 않는다."""

    def __init__(self, payload: object = None, *, error: Exception | None = None,
                 usage: LlmUsage | None = None, model: str = "") -> None:
        self.payload = payload
        self.error = error
        self.usage = usage or LlmUsage()
        self.model = model
        self.requests: list[object] = []

    def complete(self, request: object) -> LlmResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return LlmResponse(payload=self.payload, usage=self.usage, model=self.model)


class VerifyNarrativeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.facts = example_facts()

    def test_valid_payload_keeps_only_cited_facts(self):
        narrative = verify_narrative(payload(self.facts), self.facts, config=CONFIG)
        self.assertEqual(narrative.status, "completed")
        self.assertEqual(narrative.source, "llm")
        self.assertEqual(narrative.rejected, ())
        self.assertEqual([item[0] for item in narrative.finding_summaries], ["finding-a"])
        self.assertEqual(
            narrative.accepted_fact_ids,
            ("run:scope", "run:request-budget", finding_fact_id("finding-a")),
        )

    def test_run_summary_cannot_cite_an_unoffered_fact(self):
        broken = payload(self.facts)
        broken["run_summary"] = {**broken["run_summary"], "fact_ids": ["run:invented"]}
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertEqual(narrative.run_summary, "")
        self.assertIn((RUN_SUMMARY_INDEX, "unknown_fact"), narrative.rejected)
        self.assertEqual(narrative.status, "completed")

    def test_finding_cannot_cite_another_finding_fact(self):
        broken = payload(self.facts)
        broken["findings"] = [
            {**broken["findings"][0], "fact_ids": [finding_fact_id("finding-b")]},
        ]
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertEqual(narrative.finding_summaries, ())
        self.assertIn((0, "foreign_fact"), narrative.rejected)

    def test_finding_cannot_cite_a_run_level_fact(self):
        broken = payload(self.facts)
        broken["findings"] = [
            {**broken["findings"][0],
             "fact_ids": [finding_fact_id("finding-a"), "run:request-budget"]},
        ]
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertEqual(narrative.finding_summaries, ())
        self.assertIn((0, "foreign_fact"), narrative.rejected)

    def test_unknown_finding_is_rejected(self):
        broken = payload(self.facts)
        broken["findings"] = [{**broken["findings"][0], "finding_id": "finding-z"}]
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertIn((0, "unknown_finding"), narrative.rejected)

    def test_duplicate_finding_keeps_the_first_entry(self):
        first = payload(self.facts)["findings"][0]
        narrative = verify_narrative(
            payload(self.facts, findings=[first, {**first, "summary": "두 번째 요약입니다."}]),
            self.facts, config=CONFIG,
        )
        self.assertEqual(len(narrative.finding_summaries), 1)
        self.assertIn("독립", narrative.finding_summaries[0][1])
        self.assertIn((1, "duplicate_finding"), narrative.rejected)

    def test_severity_language_drops_the_whole_summary(self):
        for text in ("위험도 높음으로 판단됩니다.", "CVSS 9.1 상당입니다.", "This is a high risk."):
            with self.subTest(text=text):
                broken = payload(self.facts)
                broken["findings"] = [{**broken["findings"][0], "summary": text}]
                narrative = verify_narrative(broken, self.facts, config=CONFIG)
                self.assertEqual(narrative.finding_summaries, ())
                self.assertIn((0, "severity_language"), narrative.rejected)

    def test_url_and_control_characters_are_rejected(self):
        for text in ("자세한 내용은 http://target.example 참고.", "재현됐습니다.\t추가 설명."):
            with self.subTest(text=text):
                broken = payload(self.facts)
                broken["findings"] = [{**broken["findings"][0], "summary": text}]
                narrative = verify_narrative(broken, self.facts, config=CONFIG)
                self.assertIn((0, "unsafe_text"), narrative.rejected)

    def test_invented_identifier_is_rejected(self):
        broken = payload(self.facts)
        broken["findings"] = [
            {**broken["findings"][0], "summary": "evidence-8c41f0aa 에서 확인했습니다."},
        ]
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertIn((0, "unsafe_text"), narrative.rejected)

    def test_offered_identifier_may_appear_in_text(self):
        allowed = payload(self.facts)
        allowed["findings"] = [
            {**allowed["findings"][0],
             "summary": f"{finding_fact_id('finding-a')} 사실에서 3회 재현이 확인됐습니다."},
        ]
        narrative = verify_narrative(allowed, self.facts, config=CONFIG)
        self.assertEqual(len(narrative.finding_summaries), 1)

    def test_length_limits_come_from_the_narrator_config(self):
        tight = replace(CONFIG, run_summary_max_chars=10, finding_summary_max_chars=10)
        narrative = verify_narrative(payload(self.facts), self.facts, config=tight)
        self.assertEqual(narrative.status, "all_rejected")
        self.assertEqual(narrative.source, "deterministic_fallback")
        self.assertEqual(narrative.run_summary, FALLBACK_RUN_SUMMARY)

    def test_empty_and_malformed_entries_are_rejected(self):
        broken = payload(self.facts, findings=[{"finding_id": "finding-a"}, "text"])
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertIn((0, "invalid_shape"), narrative.rejected)
        self.assertIn((1, "invalid_shape"), narrative.rejected)

    def test_unexpected_top_level_shape_falls_back(self):
        for broken in ({"run_summary": {}}, {"run_summary": {}, "findings": [], "extra": 1}, [], "x"):
            with self.subTest(broken=broken):
                narrative = verify_narrative(broken, self.facts, config=CONFIG)
                self.assertEqual(narrative.status, "invalid_response")
                self.assertEqual(narrative.source, "deterministic_fallback")

    def test_partial_acceptance_keeps_the_run_summary(self):
        broken = payload(self.facts)
        broken["findings"] = [{**broken["findings"][0], "finding_id": "finding-z"}]
        narrative = verify_narrative(broken, self.facts, config=CONFIG)
        self.assertTrue(narrative.run_summary)
        self.assertEqual(narrative.finding_summaries, ())
        self.assertEqual(narrative.status, "completed")

    def test_measurements_are_carried_through(self):
        narrative = verify_narrative(
            payload(self.facts), self.facts, config=CONFIG,
            llm_calls=1, model="fake-model", elapsed_ms=12.5, usage_available=True,
        )
        self.assertEqual((narrative.llm_calls, narrative.model), (1, "fake-model"))
        self.assertEqual(narrative.elapsed_ms, 12.5)
        self.assertTrue(narrative.usage_available)


class FallbackTest(unittest.TestCase):
    def test_every_failure_status_produces_an_empty_narrative(self):
        for status in sorted(NARRATIVE_STATUSES - {"completed"}):
            with self.subTest(status=status):
                narrative = deterministic_fallback(status)
                self.assertEqual(narrative.status, status)
                self.assertEqual(narrative.finding_summaries, ())
                self.assertEqual(narrative.accepted_fact_ids, ())
                self.assertEqual(narrative.run_summary, FALLBACK_RUN_SUMMARY)

    def test_fallback_text_does_not_claim_absence_of_vulnerabilities(self):
        self.assertNotIn("취약점이 없", FALLBACK_RUN_SUMMARY)
        self.assertIn("안전하다는 의미는 아닙니다", FALLBACK_RUN_SUMMARY)

    def test_fallback_cannot_carry_llm_content(self):
        with self.assertRaises(ValueError):
            ReportNarrative(
                run_summary="x", finding_summaries=(("finding-a", "y"),),
                accepted_fact_ids=(), rejected=(), source="deterministic_fallback",
                status="timeout",
            )

    def test_unknown_status_and_reason_are_rejected(self):
        with self.assertRaises(ValueError):
            deterministic_fallback("exploded")
        with self.assertRaises(ValueError):
            ReportNarrative(
                run_summary="", finding_summaries=(), accepted_fact_ids=(),
                rejected=((0, "because"),), source="llm", status="completed",
            )

    def test_rejection_reasons_are_a_closed_set(self):
        self.assertNotIn("", REJECTION_REASONS)
        self.assertTrue(REJECTION_REASONS.isdisjoint(NARRATIVE_STATUSES))


class NarratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.facts = example_facts()

    def test_facts_are_sent_and_the_narrative_comes_back_verified(self):
        client = FakeLlm(payload(self.facts), usage=LlmUsage(input_tokens=120, output_tokens=40))
        narrative = LlmReportNarrator(llm_client=client, config=CONFIG).narrate(self.facts)
        self.assertEqual(narrative.status, "completed")
        self.assertEqual(narrative.source, "llm")
        self.assertEqual(narrative.llm_calls, 1)
        self.assertTrue(narrative.usage_available)
        self.assertEqual(narrative.usage.input_tokens, 120)
        self.assertIsNotNone(narrative.elapsed_ms)

    def test_request_carries_only_facts_and_the_narrative_schema(self):
        client = FakeLlm(payload(self.facts))
        LlmReportNarrator(llm_client=client, config=CONFIG).narrate(self.facts)
        request = client.requests[0]
        self.assertEqual(len(request.messages), 1)
        self.assertEqual(request.messages[0].content, build_narrative_prompt(self.facts))
        self.assertEqual(request.max_output_tokens, CONFIG.max_output_tokens)
        self.assertIn("run_summary", request.response_schema["properties"])
        self.assertFalse(request.response_schema["additionalProperties"])

    def test_every_llm_failure_becomes_a_deterministic_report(self):
        cases = {
            "timeout": LlmTimeout("slow"),
            "rate_limited": LlmRateLimited("429"),
            "transport_error": LlmTransportError("socket"),
            "refused": LlmRefused("no"),
            "invalid_response": LlmResponseFormatError("bad json"),
            "internal_error": RuntimeError("unexpected"),
        }
        for status, error in cases.items():
            with self.subTest(status=status):
                client = FakeLlm(error=error)
                narrative = LlmReportNarrator(llm_client=client, config=CONFIG).narrate(self.facts)
                self.assertEqual(narrative.status, status)
                self.assertEqual(narrative.source, "deterministic_fallback")
                self.assertEqual(narrative.finding_summaries, ())
                self.assertEqual(narrative.model, CONFIG.model)

    def test_missing_credentials_are_not_hidden_as_a_fallback(self):
        client = FakeLlm(error=LlmCredentialsMissing("no key"))
        with self.assertRaises(LlmCredentialsMissing):
            LlmReportNarrator(llm_client=client, config=CONFIG).narrate(self.facts)

    def test_internal_exception_text_is_not_logged(self):
        client = FakeLlm(error=RuntimeError("target-secret-error"))
        with self.assertLogs(
            "hacklipse.adapters.llm_report_narrative", level="WARNING",
        ) as captured:
            narrative = LlmReportNarrator(
                llm_client=client, config=CONFIG,
            ).narrate(self.facts)
        self.assertEqual(narrative.status, "internal_error")
        self.assertNotIn("target-secret-error", "\n".join(captured.output))

    def test_unverifiable_payload_still_returns_a_report(self):
        # 상단 형식은 맞지만 내용이 전부 탈락한 경우와, 형식 자체가 깨진 경우를 구분한다.
        rejected = FakeLlm({"run_summary": {}, "findings": []})
        narrative = LlmReportNarrator(llm_client=rejected, config=CONFIG).narrate(self.facts)
        self.assertEqual(narrative.status, "all_rejected")
        self.assertEqual(narrative.run_summary, FALLBACK_RUN_SUMMARY)

        malformed = FakeLlm({"unexpected": 1})
        narrative = LlmReportNarrator(llm_client=malformed, config=CONFIG).narrate(self.facts)
        self.assertEqual(narrative.status, "invalid_response")

    def test_missing_usage_is_reported_as_unavailable(self):
        client = FakeLlm(payload(self.facts))
        narrative = LlmReportNarrator(llm_client=client, config=CONFIG).narrate(self.facts)
        self.assertFalse(narrative.usage_available)


class PromptTest(unittest.TestCase):
    def test_prompt_offers_every_fact_id_and_nothing_else(self):
        facts = example_facts()
        prompt = build_narrative_prompt(facts)
        for fact_id in facts.fact_ids:
            self.assertIn(fact_id, prompt)
        self.assertNotIn("?", prompt)
        for secret in ("cookie", "authorization", "password", "credential", "api_key"):
            self.assertNotIn(secret, prompt.lower())

    def test_the_word_token_appears_only_as_a_usage_count(self):
        """사용량 필드 이름 말고 "token"이 더 나오면 값이 실려 온 것이다."""

        facts = replace(
            example_facts(), llm_calls=4, llm_input_tokens=1200, llm_output_tokens=180,
        )
        prompt = build_narrative_prompt(facts)
        self.assertIn('"llm_input_tokens":1200', prompt)
        self.assertIn('"llm_output_tokens":180', prompt)
        self.assertEqual(prompt.lower().count("token"), 2)


if __name__ == "__main__":
    unittest.main()
