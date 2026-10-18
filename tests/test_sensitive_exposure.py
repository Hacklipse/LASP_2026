"""Passive credential exposure requires independent analysis and validation fetches."""

from __future__ import annotations

import base64
import json
import unittest

from hacklipse.adapters.sensitive_exposure import (
    TRUSTED_LOGIN_PAIR_COUNT, client_login_pairs,
    credential_config_route_candidate, exposed_json_field_paths,
)
from hacklipse.adapters.security import SensitiveDataSanitizer
from hacklipse.bootstrap import build_local_application, register_standard_agents, standard_router
from hacklipse.domain import (
    ExecutionRequest, ExecutionResult, RunPhase, RunRequest, RunScope,
    ValidationProofType,
)


def _html(exposed: bool) -> str:
    config = (
        '{"locale":"en","smtp":{"pass":"unreported-value"},'
        '"internalAdminToken":"another-unreported-value"}'
        if exposed else '{"locale":"en","publicApiBase":"/api"}'
    )
    return '<html><body><script type="application/json">' + config + '</script></body></html>'


class _Runtime:
    def __init__(self, exposed: bool):
        self.exposed = exposed
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": _html(self.exposed),
                         "requested_url": request.resolved_url},
        )


class _ScriptRuntime:
    def __init__(self, exposed: bool):
        self.exposed = exposed
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        script = request.resolved_url.endswith("/bundle.js")
        body = (
            'const settings={clientSecret:"aB3dE5fG7hJ9kL2mN4pQ6rS8t"};'
            if self.exposed else
            'const settings={clientSecret:"placeholder-example-value-12345"};'
        ) if script else '<html><script src="/bundle.js"></script></html>'
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "application/javascript" if script else "text/html",
                         "body": body, "requested_url": request.resolved_url},
        )


class _RepeatedHtmlRuntime:
    def execute(self, request):
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html",
                         "body": _html(True) + '<a href="/signup">signup</a>',
                         "requested_url": request.resolved_url},
        )


class _BasicScriptRuntime:
    def __init__(self, exposed: bool):
        self.exposed = exposed
        self.calls = 0
        self.methods = []
        self.header = "Basic " + base64.b64encode(b"serviceuser:longsecretpass").decode()

    def execute(self, request):
        self.calls += 1
        self.methods.append(request.method)
        script = request.resolved_url.endswith("/bundle.js")
        body = (
            f'fetch("/api/sync",{{method:"POST",headers:{{authorization:"{self.header}"}}}});'
            if self.exposed else
            f'const documentation="{self.header}";'
        ) if script else '<html><script src="/bundle.js"></script></html>'
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "application/javascript" if script else "text/html",
                         "body": body, "requested_url": request.resolved_url},
        )


class _JsonRuntime:
    def __init__(self, exposed: bool):
        self.exposed = exposed
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        body = (
            '{"settings":{"signingSecret":"private-server-signing-value"}}'
            if self.exposed else
            '{"settings":{"publicApiBase":"/api","signingSecret":"redacted"}}'
        ) if request.resolved_url.endswith("/config") else '<a href="/config">config</a>'
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200,
                "content_type": (
                    "application/json" if request.resolved_url.endswith("/config")
                    else "text/html"
                ),
                "body": body, "requested_url": request.resolved_url,
            },
        )


class _ObservedConfigRuntime:
    def __init__(self, exposed: bool, path: str = "/api/chat/config"):
        self.exposed = exposed
        self.path = path
        self.paths = []

    def execute(self, request):
        from urllib.parse import urlsplit
        path = urlsplit(request.resolved_url).path
        self.paths.append(path)
        if path == "/":
            status, media, body = 200, "text/html", f'<a href="{self.path}">settings</a>'
        elif path == self.path and self.exposed:
            status, media = 200, "application/json"
            body = '{"llm_api_key":"qvnmtrslabcdjkpwxyzfghru",' \
                   '"service_credential":"qvnmtrslabc"}'
        else:
            status, media, body = 404, "application/json", '{"detail":"not found"}'
        return ExecutionResult(
            execution_id=request.execution_id, evidence_type="http_response",
            observation={"type": "http_response", "status": status,
                         "content_type": media, "body": body,
                         "requested_url": request.resolved_url},
        )


class SensitiveExposureTests(unittest.TestCase):
    def test_server_signing_key_in_html_config_requires_nontrivial_value(self):
        def observed(value: str) -> dict:
            return {
                "status": 200, "content_type": "text/html",
                "requested_url": "http://local.test/",
                "body": '<script type="application/json">'
                + json.dumps({"secret_key_base": value}) + "</script>",
            }

        strong = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
        self.assertEqual(exposed_json_field_paths(observed(strong)), ("secret_key_base",))
        self.assertEqual(exposed_json_field_paths(observed("not-a-secret-development")), ())

    def test_public_login_literals_are_redacted_without_claiming_validity(self):
        url = "http://local.test/login.js"
        body = ('let accounts=[{email:"person@local.test",password:"s3cr3tX9",note:"demo"}];'
                'fetch("/api/auth/login",{method:"POST",body:JSON.stringify(accounts[0])});')
        observation = {
            "type": "http_response", "status": 200,
            "content_type": "application/javascript", "requested_url": url,
            "body": body, TRUSTED_LOGIN_PAIR_COUNT: 999,
        }
        self.assertEqual(len(client_login_pairs(observation)), 1)
        request = ExecutionRequest(
            execution_id="exec-1", run_id="run-1", task_id="task-1",
            tool="http_get", target_url=url, surface_id="surface-1",
            purpose="public script fetch",
        )
        result = SensitiveDataSanitizer().sanitize(request, ExecutionResult(
            execution_id="exec-1", evidence_type="http_response",
            observation=observation,
        ))
        self.assertEqual(result.observation[TRUSTED_LOGIN_PAIR_COUNT], 1)
        self.assertNotIn("person@local.test", str(result.observation))
        self.assertNotIn("s3cr3tX9", str(result.observation))
        self.assertIn("/api/auth/login", str(result.observation))
        self.assertEqual(client_login_pairs({**observation, "status": 404}), ())
        self.assertEqual(client_login_pairs({**observation, "content_type": "text/html"}), ())

    def test_observed_config_route_requires_independent_credential_fetch(self):
        self.assertTrue(credential_config_route_candidate("http://local.test/api/chat/config"))
        self.assertTrue(credential_config_route_candidate("http://local.test/api/_debug/traces"))
        self.assertFalse(credential_config_route_candidate("http://local.test/static/config.js"))
        self.assertEqual(exposed_json_field_paths({
            "status": 200, "content_type": "application/json",
            "body": '{"public_api_key":"abcdefghijklmnopqrstuvwxy",'
                    '"llm_api_key":"qvnmtrslabcdjkpwxyzfghru"}',
        }), ("llm_api_key",))
        self.assertEqual(exposed_json_field_paths({
            "status": 200, "content_type": "application/json",
            "body": '{"database_url":"postgresql://app:fixturelongpass@db.local/app",'
                    '"redis_url":"redis://cache.local/0"}',
        }), ("database_url",))
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _ObservedConfigRuntime(exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=1)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertGreaterEqual(runtime.paths.count("/api/chat/config"), 2)
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.SENSITIVE_DATA_EXPOSURE)
                    self.assertNotIn("qvnmtrslabcdjkpwxyzfghru",
                                     str(app.stores.evidence.list_by_run(run.run_id)))

    def test_observed_diagnostic_route_requires_independent_credential_fetch(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _ObservedConfigRuntime(exposed, "/api/_debug/traces")
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=1)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), int(exposed))
                if exposed:
                    self.assertGreaterEqual(runtime.paths.count("/api/_debug/traces"), 2)

    def test_collector_signal_preserves_field_paths_without_storing_values(self):
        request = ExecutionRequest(
            execution_id="exec-1", run_id="run-1", task_id="task-1",
            tool="http_get", target_url="http://local.test/", surface_id="surface-1",
            purpose="read client page",
        )
        result = ExecutionResult(
            execution_id="exec-1", evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": _html(True)},
        )
        sanitized = SensitiveDataSanitizer().sanitize(request, result)
        stored = sanitized.observation
        self.assertEqual(exposed_json_field_paths(stored),
                         ("internalAdminToken", "smtp.pass"))
        self.assertNotIn("unreported-value", str(stored))
        self.assertNotIn("another-unreported-value", str(stored))
        self.assertEqual(stored["verified_sensitive_field_paths"],
                         ["internalAdminToken", "smtp.pass"])

        forged = ExecutionResult(
            execution_id="exec-1", evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "text/html", "body": "<html>public</html>",
                         "verified_sensitive_field_paths": ["adminToken"]},
        )
        self.assertNotIn("verified_sensitive_field_paths",
                         SensitiveDataSanitizer().sanitize(request, forged).observation)

    def test_database_url_password_is_redacted_before_evidence_storage(self):
        request = ExecutionRequest(
            execution_id="exec-db", run_id="run-db", task_id="task-db",
            tool="http_get", target_url="http://local.test/config",
            surface_id="surface-db", purpose="read configuration",
        )
        connection = "postgresql://app:fixturelongpass@db.local/app"
        result = ExecutionResult(
            execution_id="exec-db", evidence_type="http_response",
            observation={"type": "http_response", "status": 200,
                         "content_type": "application/json",
                         "body": json.dumps({"database_url": connection})},
        )
        stored = SensitiveDataSanitizer().sanitize(request, result).observation
        self.assertEqual(stored["verified_sensitive_field_paths"], ["database_url"])
        self.assertNotIn(connection, str(stored))
        self.assertNotIn("fixturelongpass", str(stored))

    def test_parser_retains_only_credential_field_paths(self):
        fields = exposed_json_field_paths({"status": 200, "content_type": "text/html", "body": _html(True)})
        self.assertEqual(fields, ("internalAdminToken", "smtp.pass"))
        self.assertEqual(exposed_json_field_paths({"status": 200, "content_type": "text/html", "body": _html(False)}), ())
        documentation = '<script type="application/json">{"form":{"password":"example-only-value"}}</script>'
        self.assertEqual(exposed_json_field_paths({"status": 200, "content_type": "text/html", "body": documentation}), ())

    def test_javascript_parser_ignores_placeholder_values_and_retains_names_only(self):
        observed = exposed_json_field_paths({
            "status": 200, "content_type": "application/javascript",
            "body": 'const config={clientSecret:"aB3dE5fG7hJ9kL2mN4pQ6rS8t"};',
        })
        self.assertEqual(observed, ("clientSecret",))
        self.assertEqual(exposed_json_field_paths({
            "status": 200, "content_type": "application/javascript",
            "body": 'const config={clientSecret:"placeholder-example-value-12345"};',
        }), ())

    def test_public_bundle_basic_header_requires_fetch_use_and_independent_fetch(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _BasicScriptRuntime(exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=3)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                self.assertNotIn(runtime.header, str(app.stores.evidence.list_by_run(run.run_id)))
                self.assertTrue(runtime.methods)
                self.assertEqual(set(runtime.methods), {"GET"})

    def test_json_response_exposure_requires_independent_validation(self):
        self.assertEqual(exposed_json_field_paths({
            "status": 200, "content_type": "application/problem+json",
            "body": '{"settings":{"signingSecret":"private-server-signing-value"}}',
        }), ("settings.signingSecret",))
        self.assertEqual(exposed_json_field_paths({
            "status": 200, "content_type": "application/json",
            "body": '{"openapi":"3.0.0","paths":{},'
                    '"example":{"signingSecret":"private-server-signing-value"}}',
        }), ())
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _JsonRuntime(exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=2)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertGreaterEqual(runtime.calls, 4)
                observations = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                                if item.evidence_type == "observation"]
                self.assertNotIn("private-server-signing-value", str(observations))

    def test_pipeline_confirms_only_reproduced_public_exposure(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _Runtime(exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=1)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertEqual(findings[0].proof_type, ValidationProofType.SENSITIVE_DATA_EXPOSURE)
                    self.assertGreaterEqual(runtime.calls, 3)
                observations = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                                if item.evidence_type == "observation"]
                self.assertNotIn("unreported-value", str(observations))

    def test_javascript_exposure_requires_independent_validation(self):
        for exposed in (True, False):
            with self.subTest(exposed=exposed):
                runtime = _ScriptRuntime(exposed)
                app = build_local_application(
                    {}, runtime=runtime,
                    router=standard_router(("Sensitive Data Exposure",)),
                )
                register_standard_agents(app, recon_max_pages=3)
                run = app.orchestrator.start(RunRequest(
                    target_url="http://local.test/",
                    scope=RunScope(allowed_hosts=frozenset({"local.test"})),
                    request_budget=20,
                ))
                self.assertEqual(run.phase, RunPhase.DONE)
                findings = app.stores.findings.list_by_run(run.run_id)
                self.assertEqual(len(findings), int(exposed))
                if exposed:
                    self.assertEqual(findings[0].proof_type,
                                     ValidationProofType.SENSITIVE_DATA_EXPOSURE)
                    self.assertGreaterEqual(runtime.calls, 4)
                observations = [item.observation for item in app.stores.evidence.list_by_run(run.run_id)
                                if item.evidence_type == "observation"]
                self.assertNotIn("aB3dE5fG7hJ9kL2mN4pQ6rS8t", str(observations))

    def test_repeated_config_on_linked_pages_is_one_run_level_finding(self):
        app = build_local_application(
            {}, runtime=_RepeatedHtmlRuntime(),
            router=standard_router(("Sensitive Data Exposure",)),
        )
        register_standard_agents(app, recon_max_pages=3)
        run = app.orchestrator.start(RunRequest(
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=20,
        ))
        self.assertEqual(run.phase, RunPhase.DONE)
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
