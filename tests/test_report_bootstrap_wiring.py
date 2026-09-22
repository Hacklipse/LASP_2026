"""Report Narrator가 표준 조립 경로로 실제 Run에 도달하는지 검증한다.

Report Agent만 register_standard_agents가 아니라 build_local_application 안에서
기본 fallback으로 등록된다. dispatcher가 재등록을 거부하므로 다른 LLM 옵션처럼
뒤에서 갈아끼울 수 없고, 그래서 옵션도 등록 지점인 이 함수로 받는다.
"""

import unittest

from hacklipse.adapters import MemoryStoreBundle
from hacklipse.bootstrap import build_local_application
from hacklipse.ports.errors import LlmCredentialsMissing

from test_llm_report_narrative import FakeLlm, payload


class ReportWiringTests(unittest.TestCase):
    def build(self, **changes):
        return build_local_application({}, stores=MemoryStoreBundle(), **changes)

    def reporter(self, app):
        return app.dispatcher._agents["report"]

    def test_default_assembly_is_unchanged(self):
        # 기존 호출자는 한 줄도 바뀌지 않아야 한다.
        reporter = self.reporter(self.build())
        self.assertEqual(reporter._format_version, "v1")
        self.assertIsNone(reporter._narrator)
        self.assertIsNone(reporter._narrator_config)

    def test_v2_can_be_enabled_without_an_llm(self):
        reporter = self.reporter(self.build(report_format_version="v2"))
        self.assertEqual(reporter._format_version, "v2")
        self.assertIsNone(reporter._narrator)

    def test_v2_receives_the_stores_its_facts_need(self):
        reporter = self.reporter(self.build(report_format_version="v2"))
        for store in (reporter._candidates, reporter._surfaces, reporter._runs, reporter._budget):
            self.assertIsNotNone(store)

    def test_narrator_reaches_the_registered_report_agent(self):
        client = FakeLlm(payload)
        reporter = self.reporter(self.build(
            report_format_version="v2", report_mode="llm",
            report_llm_client=client, report_llm_model="gemini-3.5-flash-lite",
        ))
        self.assertIsNotNone(reporter._narrator)
        self.assertIs(reporter._narrator._llm, client)

    def test_narrator_and_its_fingerprint_config_are_the_same_settings(self):
        # Claim의 input_fingerprint는 이 config로 만든다. 둘이 다르면 재개 비교가 깨진다.
        reporter = self.reporter(self.build(
            report_format_version="v2", report_mode="llm",
            report_llm_client=FakeLlm(payload), report_llm_model="gemini-3.5-flash-lite",
        ))
        self.assertIs(reporter._narrator._config, reporter._narrator_config)
        self.assertEqual(reporter._narrator_config.model, "gemini-3.5-flash-lite")
        self.assertEqual(
            reporter._narrator_config.prompt_version, "llm-report-narrative-v1",
        )

    def test_narrative_without_a_client_fails_at_wiring_time(self):
        # 실행 중 fallback으로 숨기면 LLM 요약을 켠 줄 알고 결정적 보고서를 받는다.
        with self.assertRaises(LlmCredentialsMissing):
            self.build(
                report_format_version="v2", report_mode="llm",
                report_llm_model="gemini-3.5-flash-lite",
            )

    def test_narrative_without_a_model_fails_at_wiring_time(self):
        with self.assertRaises(ValueError):
            self.build(
                report_format_version="v2", report_mode="llm",
                report_llm_client=FakeLlm(payload),
            )

    def test_narrative_on_v1_is_refused(self):
        with self.assertRaises(ValueError):
            self.build(
                report_format_version="v1", report_mode="llm",
                report_llm_client=FakeLlm(payload), report_llm_model="gemini-3.5-flash-lite",
            )

    def test_heuristic_mode_ignores_an_available_client(self):
        # 호출자가 다른 Agent용으로 만든 client를 그대로 넘겨도 요약은 켜지지 않는다.
        reporter = self.reporter(self.build(
            report_format_version="v2", report_llm_client=FakeLlm(payload),
            report_llm_model="gemini-3.5-flash-lite",
        ))
        self.assertIsNone(reporter._narrator)
        self.assertIsNone(reporter._narrator_config)

    def test_unknown_report_mode_is_refused(self):
        with self.assertRaises(ValueError):
            self.build(report_format_version="v2", report_mode="hybrid")

    def test_explicit_report_agent_still_wins(self):
        class Custom:
            def handle(self, task):
                raise AssertionError("not called")

        custom = Custom()
        app = build_local_application(
            {"report": custom}, stores=MemoryStoreBundle(), report_format_version="v2",
        )
        self.assertIs(self.reporter(app), custom)


if __name__ == "__main__":
    unittest.main()
