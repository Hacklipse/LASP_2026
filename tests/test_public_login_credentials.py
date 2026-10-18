"""Public login literals require observed shape, approval, and a real session."""

from __future__ import annotations

import unittest

from hacklipse.adapters.public_login_credentials import (
    observed_login_target, replay_public_login,
)
from hacklipse.adapters.security import StaticApprovalGate
from hacklipse.application.task_factory import TaskFactory
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    Candidate, Evidence, ExecutionResult, Run, RunScope, Surface, TaskEnvelope,
)


_BASE = "http://local.test"
_SCRIPT = _BASE + "/static/login.js"
_LOGIN = _BASE + "/api/auth/login"
_EMAIL = "person@local.test"
_PASSWORD = "s3cr3tX9"


class _LoginRuntime:
    def __init__(self, *, accepted: bool):
        self.accepted = accepted
        self.posts = 0

    def execute(self, request):
        if request.resolved_url == _SCRIPT:
            return ExecutionResult(
                execution_id=request.execution_id, evidence_type="http_response",
                observation={
                    "type": "http_response", "status": 200,
                    "content_type": "application/javascript",
                    "requested_url": request.resolved_url,
                    "body": f'const accounts=[{{email:"{_EMAIL}",password:"{_PASSWORD}"}}];',
                },
            )
        self.posts += 1
        success = self.accepted and _EMAIL in (request.body or "") and _PASSWORD in (request.body or "")
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200 if success else 401,
                "content_type": "application/json",
                "requested_url": request.resolved_url,
                "headers": [["set-cookie", "sid=session-value; HttpOnly"]] if success else [],
                "body": '{"role":"user"}' if success else '{"error":"invalid"}',
            },
        )


def _app(*, accepted: bool, approved: bool):
    runtime = _LoginRuntime(accepted=accepted)
    app = build_local_application(
        {}, runtime=runtime,
        approval_gate=StaticApprovalGate(["approved"]) if approved else None,
        default_approval_ref="approved" if approved else None,
    )
    run = Run(
        run_id="run-1", target_url=_BASE + "/",
        scope=RunScope(allowed_hosts=frozenset({"local.test"})),
        policy_profile="safe", request_budget=20,
    )
    app.stores.runs.add(run)
    app.budget_manager.open_run(run.run_id, 20)
    app.stores.surfaces.add(Surface(
        surface_id="script", run_id=run.run_id, url=_SCRIPT,
        method="GET", parameters=(),
    ))
    app.stores.surfaces.add(Surface(
        surface_id="login", run_id=run.run_id, url=_LOGIN,
        method="POST", parameters=("email", "password"),
    ))
    app.stores.evidence.append(Evidence(
        evidence_id="shape", run_id=run.run_id, surface_id="login",
        created_by="recon", evidence_type="observation",
        observation={
            "type": "browser_request_structure", "source": "playwright_network",
            "method": "POST", "content_type": "application/json",
            "body_parameter_names": ["email", "password"],
            "query_parameter_names": [],
        },
    ))
    return app, runtime, run


class PublicLoginTests(unittest.TestCase):
    def test_observed_shape_and_task_tools(self):
        app, _, run = _app(accepted=True, approved=True)
        target = observed_login_target(run.run_id, _SCRIPT, app.stores.surfaces, app.stores.evidence)
        self.assertEqual(target, ("login", _LOGIN, "application/json"))
        candidate = Candidate(
            candidate_id="candidate", run_id=run.run_id, surface_id="script",
            vulnerability_type="Exposed Working Credentials", hypothesis="public login literals",
            assigned_agent="public_login_credentials_analyzer", evidence_ids=("shape",),
        )
        analysis = TaskFactory().analysis(
            run, candidate, target_url=_SCRIPT, request_budget=10,
        )
        validation = TaskFactory().validation(
            run, candidate, validation_id="validation-1",
            agent_type="validation", request_budget=10,
        )
        self.assertEqual(analysis.allowed_tools, ("http_get", "http_post"))
        self.assertEqual(validation.allowed_tools, ("http_get", "http_post"))

    def test_approved_valid_pair_replays_twice_without_persisting_values(self):
        app, runtime, run = _app(accepted=True, approved=True)
        target = observed_login_target(run.run_id, _SCRIPT, app.stores.surfaces, app.stores.evidence)
        assert target is not None
        for validation_id in (None, "validation-1"):
            task = TaskEnvelope(
                task_id=f"task-{validation_id}", run_id=run.run_id,
                agent_type="validation", surface_id="script",
                allowed_tools=("http_get", "http_post"), request_budget=10,
                validation_id=validation_id,
            )
            verified, ids, reason = replay_public_login(
                app.collector, task, _SCRIPT, target, validation_id=validation_id,
            )
            self.assertTrue(verified)
            self.assertEqual(reason, "verified")
            self.assertEqual(len(ids), 2)
        self.assertEqual(runtime.posts, 2)
        stored = str(app.stores.evidence.list_by_run(run.run_id))
        self.assertNotIn(_EMAIL, stored)
        self.assertNotIn(_PASSWORD, stored)
        self.assertNotIn("session-value", stored)

    def test_invalid_pair_and_missing_approval_never_confirm(self):
        for accepted, approved, expected_posts in ((False, True, 1), (True, False, 0)):
            with self.subTest(accepted=accepted, approved=approved):
                app, runtime, run = _app(accepted=accepted, approved=approved)
                target = observed_login_target(run.run_id, _SCRIPT, app.stores.surfaces, app.stores.evidence)
                assert target is not None
                task = TaskEnvelope(
                    task_id="task", run_id=run.run_id, agent_type="validation",
                    surface_id="script", allowed_tools=("http_get", "http_post"),
                    request_budget=10,
                )
                verified, _, reason = replay_public_login(app.collector, task, _SCRIPT, target)
                self.assertFalse(verified)
                self.assertEqual(runtime.posts, expected_posts)
                self.assertEqual(reason, "login_not_accepted" if approved else "approval_or_policy_blocked")


if __name__ == "__main__":
    unittest.main()
