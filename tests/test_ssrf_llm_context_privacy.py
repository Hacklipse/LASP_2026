"""SSRF LLM tool context never exposes sensitive Surface path values."""

from __future__ import annotations

import json
import unittest

from hacklipse.adapters.llm_ssrf_analysis import LlmSsrfAnalyzer
from hacklipse.adapters.ssrf_analysis import (
    SSRF_ANALYZER,
    SSRF_CALLBACK_CAPABILITY,
)
from hacklipse.application.task_factory import TaskFactory
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import Candidate, Run, RunScope, Surface
from hacklipse.ports.llm import LlmResponse


class _ContextThenStopLlm:
    def __init__(self) -> None:
        self.requests = []

    def complete(self, request):
        self.requests.append(request)
        action = {"tool": "get_surface_context"} if len(self.requests) == 1 else {
            "tool": "stop"
        }
        return LlmResponse(payload=action, model="fixture")


class SsrfLlmContextPrivacyTests(unittest.TestCase):
    def test_sensitive_surface_path_is_redacted_before_llm_tool_context(self):
        app = build_local_application({})
        run = Run(
            run_id="run-private-path",
            target_url="https://target.example/",
            scope=RunScope(allowed_hosts=frozenset({"target.example"})),
            policy_profile="safe",
            request_budget=10,
        )
        surface = Surface(
            surface_id="surface-private-path",
            run_id=run.run_id,
            url=(
                "https://target.example/private/token/shortsecret"
                "?url=old"
            ),
            method="GET",
            parameters=("url",),
        )
        candidate = Candidate(
            candidate_id="candidate-private-path",
            run_id=run.run_id,
            surface_id=surface.surface_id,
            vulnerability_type="SSRF",
            hypothesis="observed URL input may trigger a server request",
            assigned_agent=SSRF_ANALYZER,
            evidence_ids=(),
            exploration_parameters=("url",),
            routing_capability_id=SSRF_CALLBACK_CAPABILITY,
            analysis_strategy_id="observed_url_callback_probe",
        )
        app.stores.runs.add(run)
        app.stores.surfaces.add(surface)
        app.stores.candidates.add(candidate)
        llm = _ContextThenStopLlm()
        analyzer = LlmSsrfAnalyzer(
            llm_client=llm,
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
            collector=app.collector,
        )

        analyzer.handle(TaskFactory().analysis(
            run,
            candidate,
            target_url=surface.url,
            request_budget=4,
        ))

        context = json.loads(llm.requests[1].messages[0].content)["tool_result"]
        self.assertEqual(context["path"], "/private/token/{redacted}")
        self.assertNotIn("shortsecret", str(context))


if __name__ == "__main__":
    unittest.main()
