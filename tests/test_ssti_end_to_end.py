"""SSTI Surface부터 독립 Proof와 Finding까지 수직 경로를 검증한다."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs

from hacklipse.adapters import StaticApprovalGate
from hacklipse.adapters.ssti_analysis import (
    SSTI_APPROVAL_REF,
    SSTI_EXPECTED_RESULT,
    SSTI_SAFE_EXPRESSION,
)
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import ExecutionRequest, ExecutionResult, RunPhase, RunRequest, RunScope
from hacklipse.ports.llm import LlmRequest, LlmResponse

_TARGET = "http://local.test/profile"


class _JuiceProfileRuntime:
    def __init__(self, *, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.username = "initial-user"
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        if request.method.upper() == "POST":
            self.username = parse_qs(request.body or "").get("username", [""])[0]
            return ExecutionResult(
                execution_id=request.execution_id,
                evidence_type="http_redirect",
                observation={"type": "http_redirect", "status": 302, "body": ""},
            )
        rendered = (
            SSTI_EXPECTED_RESULT
            if self.vulnerable and self.username == SSTI_SAFE_EXPRESSION
            else self.username
        )
        body = (
            "<html><p>" + rendered + "</p>"
            '<form action="./profile" method="post">'
            '<input name="email" disabled>'
            '<input name="role" disabled>'
            f'<input name="username" value="{self.username}">'
            "</form></html>"
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200, "body": body},
        )


class _FakeLlmClient:
    def __init__(self) -> None:
        self.requests: list[LlmRequest] = []

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)
        return LlmResponse(
            payload={
                "parameters": ["username"],
                "reason": "username is rendered on the server profile page",
            },
            model="fake",
        )


def _run(*, vulnerable: bool = True, llm: bool = False):
    runtime = _JuiceProfileRuntime(vulnerable=vulnerable)
    client = _FakeLlmClient() if llm else None
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(vulnerability_types=("SSTI",)),
        approval_gate=StaticApprovalGate((SSTI_APPROVAL_REF,)),
    )
    register_standard_agents(app, llm_client=client, recon_max_pages=1)
    run = app.orchestrator.start(
        RunRequest(
            target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=20,
        )
    )
    return app, run, runtime, client


class SstiEndToEndTests(unittest.TestCase):
    def test_heuristic_reaches_independent_proof_and_finding(self) -> None:
        app, run, runtime, _ = _run()

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [candidate.vulnerability_type for candidate in app.stores.candidates.list_by_run(run.run_id)],
            ["SSTI"],
        )
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "SSTI")
        # Analysis 5회 + 독립 Validation 5회. Recon GET은 별도다.
        self.assertEqual(
            len([request for request in runtime.requests if request.tool == "ssti_probe"]),
            10,
        )

    def test_fake_llm_uses_same_proof_path(self) -> None:
        app, run, _, client = _run(llm=True)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
        assert client is not None
        self.assertEqual(len(client.requests), 1)
        sent = repr(client.requests[0])
        self.assertIn("username", sent)
        self.assertNotIn(SSTI_SAFE_EXPRESSION, sent)

    def test_literal_template_does_not_create_finding(self) -> None:
        app, run, _, _ = _run(vulnerable=False)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())


if __name__ == "__main__":
    unittest.main()
