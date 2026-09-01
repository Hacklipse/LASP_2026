"""Juice Shop `/rest/basket/:id` 형태의 Access Control 수직 흐름을 검증한다."""

from __future__ import annotations

import json
import unittest
from urllib.parse import urlsplit

from hacklipse.adapters import InMemoryCredentialResolver
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import ExecutionRequest, ExecutionResult, RunPhase, RunRequest, RunScope
from hacklipse.ports import LlmResponse, ResolvedHttpCredential

_ACTOR_REF = "juice-actor"
_OWNER_REF = "juice-owner"


class _JuiceBasketRuntime:
    """두 token 세션과 basket 소유권 검사 여부를 흉내 내는 로컬 Runtime 대역."""

    def __init__(self, *, enforce_ownership: bool) -> None:
        self.enforce_ownership = enforce_ownership
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        requested_id = urlsplit(request.resolved_url).path.rstrip("/").rsplit("/", 1)[-1]
        session_basket = {_ACTOR_REF: "2", _OWNER_REF: "1"}.get(
            request.credential_ref or ""
        )
        if session_basket is None:
            status, body = 401, json.dumps({"error": "unauthorized"})
        elif self.enforce_ownership and requested_id != session_basket:
            status, body = 403, json.dumps({"error": "access denied"})
        else:
            status, body = 200, json.dumps(
                {"status": "success", "data": {"id": int(requested_id), "Products": []}}
            )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": status,
                "body": body,
                "requested_url": request.resolved_url,
            },
        )


class _FakeAccessLlm:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request):
        self.calls += 1
        return LlmResponse(
            payload={
                "parameters": ["path:basket_id"],
                "reason": "basket path segment identifies the requested object",
            },
            model="fake-access",
        )


def _run(*, enforce_ownership: bool, llm=None):
    runtime = _JuiceBasketRuntime(enforce_ownership=enforce_ownership)
    resolver = InMemoryCredentialResolver(
        {
            _ACTOR_REF: ResolvedHttpCredential(cookies=(("token", "actor-token"),)),
            _OWNER_REF: ResolvedHttpCredential(cookies=(("token", "owner-token"),)),
        }
    )
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(vulnerability_types=("Access Control",)),
        credential_resolver=resolver,
    )
    register_standard_agents(
        app,
        llm_client=llm,
        recon_max_pages=1,
        actor_object_id="2",
        owner_object_id="1",
    )
    run = app.orchestrator.start(
        RunRequest(
            target_url="http://local.test/rest/basket/2",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=20,
            credential_ref=_ACTOR_REF,
            principal_credentials=(("actor", _ACTOR_REF), ("owner", _OWNER_REF)),
        )
    )
    return app, runtime, run


class AccessControlEndToEndTests(unittest.TestCase):
    def test_vulnerable_basket_path_is_promoted_to_a_finding(self) -> None:
        app, runtime, run = _run(enforce_ownership=False)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [item.vulnerability_type for item in app.stores.findings.list_by_run(run.run_id)],
            ["Access Control"],
        )
        observations = [
            item.observation for item in app.stores.evidence.list_by_run(run.run_id)
        ]
        self.assertTrue(
            any(
                item.get("type") == "object_id_auth"
                and item.get("identifier_location") == "path"
                and item.get("identifier_parameter") == "basket_id"
                for item in observations
            )
        )
        # Analysis 세 요청과 Validation 세 요청이 각각 독립 실행돼야 한다.
        probes = [item for item in runtime.requests if item.tool == "access_control_probe"]
        self.assertEqual(len(probes), 6)

    def test_owner_enforcement_is_not_promoted(self) -> None:
        app, _, run = _run(enforce_ownership=True)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())

    def test_llm_selects_only_the_path_coordinate_and_reuses_the_python_proof(self) -> None:
        llm = _FakeAccessLlm()
        app, _, run = _run(enforce_ownership=False, llm=llm)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(llm.calls, 1)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
        plan = next(
            item
            for item in app.stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == "llm_access_control_plan"
        )
        self.assertEqual(plan.observation.get("selected_identifier"), "path:basket_id")


if __name__ == "__main__":
    unittest.main()
