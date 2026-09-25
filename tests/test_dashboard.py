"""웹 대시보드의 요청 경계와 CLI 동등성을 검증한다.

여기서 확인하는 것은 세 가지다.

    ① 화면에서 고른 값이 실제 배선과 RunExecutionProfile 기록에 그대로 간다
    ② 다른 출처가 /api/run 으로 Run 을 시작할 수 없다
    ③ 비밀(계정 비밀번호·token)이 화면 상태 어디에도 남지 않는다

실제 Juice Shop 5종 통합 실행은 대상이 떠 있어야 하므로 기본적으로 건너뛴다.
돌리려면 npm start 로 Juice Shop 을 띄우고 아래 두 환경변수를 준다.

    HACKLIPSE_JUICE_SHOP_URL=http://127.0.0.1:3001/
    HACKLIPSE_JUICE_SHOP_DB=/path/to/juice-shop/data/juiceshop.sqlite
    HACKLIPSE_JUICE_ACTOR=email:password
    HACKLIPSE_JUICE_OWNER=email:password
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))

import serve_dashboard as sd  # noqa: E402
from dashboard_core import (  # noqa: E402
    MODE_GENERIC,
    MODE_JUICE_SHOP,
    AccessAccounts,
    DashboardState,
    RunOptions,
    RunSecrets,
    RunSupervisor,
)
from routing_options import execution_profile_from_args  # noqa: E402


def _defaults() -> RunOptions:
    return RunOptions(target="http://127.0.0.1:3000/")


class DashboardMarkupTests(unittest.TestCase):
    """접기 UI의 정적 계약이 HTML과 JavaScript 양쪽에서 유지된다."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (_ROOT / "web" / "index.html").read_text(encoding="utf-8")
        cls.javascript = (_ROOT / "web" / "app.js").read_text(encoding="utf-8")

    def test_run_conditions_have_two_controls_for_the_same_collapsible_body(self) -> None:
        self.assertIn('id="setup-body" hidden', self.html)
        self.assertEqual(self.html.count('aria-controls="setup-body"'), 2)
        self.assertIn('id="setup-panel-toggle"', self.html)
        self.assertIn("function setSetupExpanded(expanded)", self.javascript)

    def test_findings_use_per_type_accordions_instead_of_one_flat_body(self) -> None:
        self.assertIn('id="findings-groups"', self.html)
        self.assertNotIn('id="findings-body"', self.html)
        self.assertIn('class="finding-group-toggle"', self.javascript)
        self.assertIn('aria-expanded="${expanded}"', self.javascript)
        self.assertIn("const expandedFindingGroups = new Set();", self.javascript)


class PayloadValidationTests(unittest.TestCase):
    """계약을 벗어난 입력은 Run 으로 넘어가기 전에 막힌다."""

    def _parse(self, **overrides):
        payload = {"target": "http://127.0.0.1:3000/", **overrides}
        return sd.parse_run_payload(payload, _defaults())

    def test_accepts_a_minimal_payload(self) -> None:
        options, secrets = self._parse()
        self.assertEqual(options.mode, MODE_GENERIC)
        self.assertEqual(options.profile, "heuristic")
        self.assertEqual(secrets.ssti_token, "")

    def test_rejects_unknown_enum_values(self) -> None:
        for field, value in (
            ("mode", "nope"),
            ("vuln", "zzz"),
            ("router", "evil"),
            ("report", "banana"),
            ("surface_collection", "random"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(**{field: value})

    def test_rejects_wrong_types(self) -> None:
        for field, value in (
            ("target", 123),
            ("validation_review", "yes"),
            ("budget", "40"),
            ("llm_rpm_limit", 0),
            ("access_accounts", "actor"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(**{field: value})

    def test_rejects_out_of_range_budget(self) -> None:
        for value in (-1, 0.5, sd.MAX_BUDGET + 1):
            with self.subTest(value=value):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(budget=value)

    def test_absent_budget_means_the_per_type_default(self) -> None:
        options, _ = self._parse(mode=MODE_JUICE_SHOP, vuln="sqli")
        self.assertEqual(options.budget, 0)
        self.assertGreater(options.resolved_budget(), 0)

    def test_rejects_overlong_strings(self) -> None:
        with self.assertRaises(sd.RequestRejected):
            self._parse(target="http://127.0.0.1/" + "a" * 400)

    def test_rejects_an_engine_without_its_key(self) -> None:
        for engine in ("llm:anthropic", "llm:gemini"):
            env = sd.ENGINE_BY_ID[engine]["key_env"]
            with self.subTest(engine=engine), _without_env(env):
                with self.assertRaises(sd.RequestRejected):
                    self._parse(engine=engine)


class ExecutionProfileFidelityTests(unittest.TestCase):
    """화면 선택이 그대로 기록된다. 선택지만 보이고 실행은 고정값이면 안 된다."""

    def test_every_choice_reaches_the_recorded_profile(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/",
            profile="llm",
            recon="hybrid",
            surface_collection="deterministic",
            router="hybrid",
            router_review="ambiguous",
            orchestrator="hybrid",
            budget_allocation="hybrid",
            validation_review=True,
            report="llm",
            llm_provider="gemini",
            llm_rpm_limit=9,
        )
        profile = execution_profile_from_args(
            options.to_namespace(),
            selected_model=options.resolved_model(),
            llm_rpm_limit=options.llm_rpm_limit,
        )
        self.assertEqual(profile.analysis_profile, "llm")
        self.assertEqual(profile.recon_mode, "hybrid")
        self.assertEqual(profile.surface_collection_mode, "deterministic")
        self.assertEqual(profile.router_mode, "hybrid")
        self.assertEqual(profile.router_review, "ambiguous")
        self.assertEqual(profile.orchestrator_mode, "hybrid")
        self.assertEqual(profile.budget_allocation_mode, "hybrid")
        self.assertEqual(profile.validation_mode, "llm")
        self.assertEqual(profile.report_mode, "llm")
        self.assertEqual(profile.llm_provider, "gemini")
        self.assertEqual(profile.llm_rpm_limit, 9)
        self.assertTrue(profile.llm_model)

    def test_a_deterministic_run_records_no_llm(self) -> None:
        options = RunOptions(target="http://127.0.0.1:3000/")
        profile = execution_profile_from_args(
            options.to_namespace(), selected_model=options.resolved_model()
        )
        self.assertEqual(profile.analysis_profile, "heuristic")
        self.assertEqual(profile.llm_provider, "")
        self.assertEqual(profile.llm_model, "")


class ModeGatingTests(unittest.TestCase):
    """범용 대상에는 Juice Shop 전용 준비를 적용하지 않는다."""

    def test_generic_mode_asks_for_no_accounts_or_browser(self) -> None:
        options = RunOptions(target="http://127.0.0.1:8000/", mode=MODE_GENERIC)
        self.assertFalse(options.needs_access_accounts)
        self.assertFalse(options.needs_path_account)
        self.assertFalse(options.needs_ssti_token)
        self.assertFalse(options.needs_browser)

    def test_juice_shop_all_requires_accounts_and_a_browser(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP, vuln="all"
        )
        self.assertTrue(options.needs_access_accounts)
        self.assertTrue(options.needs_path_account)
        self.assertTrue(options.needs_browser)

    def test_validation_review_needs_the_llm_profile(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(
            target="http://127.0.0.1:3000/", validation_review=True, profile="heuristic"
        )
        self.assertIsNotNone(supervisor.validate(options, RunSecrets()))

    def test_access_control_without_accounts_is_refused(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP, vuln="access_control"
        )
        self.assertIn("ACTOR", supervisor.validate(options, RunSecrets()) or "")

    def test_targets_outside_the_allowlist_are_refused(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(target="http://example.com/")
        self.assertIn("허용 대상이 아니다", supervisor.validate(options, RunSecrets()) or "")


class SecretContainmentTests(unittest.TestCase):
    """비밀은 화면 상태에 애초에 들어가지 않는다."""

    def test_run_options_carry_no_secret_field(self) -> None:
        fields = set(RunOptions.__dataclass_fields__)
        for forbidden in ("password", "token", "email", "cookie"):
            self.assertFalse(
                any(forbidden in name for name in fields),
                f"RunOptions 에 비밀처럼 보이는 필드가 있다: {forbidden}",
            )

    def test_state_serialisation_never_contains_the_inputs(self) -> None:
        options = RunOptions(
            target="http://127.0.0.1:3000/", mode=MODE_JUICE_SHOP, vuln="all"
        )
        state = DashboardState(budget=40, target=options.target)
        state.begin(options, engine_label="Heuristic")
        state.note("ACTOR/OWNER 테스트 계정 로그인 중")
        rendered = json.dumps(state.read(0), ensure_ascii=False)
        for secret in ("super-secret-pw", "actor@example.test", "token-value"):
            self.assertNotIn(secret, rendered)

    def test_access_accounts_hide_values_in_repr(self) -> None:
        accounts = AccessAccounts(
            actor_email="actor@example.test",
            actor_password="super-secret-pw",
            owner_email="owner@example.test",
            owner_password="another-secret",
        )
        self.assertNotIn("super-secret-pw", repr(accounts))
        self.assertNotIn("actor@example.test", repr(accounts))

    def test_identical_accounts_are_refused(self) -> None:
        accounts = AccessAccounts(
            actor_email="same@example.test",
            actor_password="a",
            owner_email="SAME@example.test",
            owner_password="b",
        )
        with self.assertRaises(ValueError):
            accounts.to_cli_inputs()


class HttpBoundaryTests(unittest.TestCase):
    """다른 출처가 이 API 로 Run 을 시작할 수 없다."""

    @classmethod
    def setUpClass(cls) -> None:
        import socket
        from http.server import ThreadingHTTPServer

        cls.supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        cls.token = "test-csrf-token"
        # 핸들러는 만들 때의 포트로 같은 출처를 판단한다. 포트를 먼저 정하고 한 번만 만든다.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        options = sd.parse_args(["--port", str(cls.port)])
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", cls.port), sd.make_handler(cls.supervisor, options, cls.token)
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _post(self, *, token=None, origin=None, content_type="application/json", body=None):
        request = urllib.request.Request(
            f"{self.base}/api/run",
            data=json.dumps(body or {"target": "http://127.0.0.1:3000/"}).encode(),
            method="POST",
        )
        request.add_header("Content-Type", content_type)
        if token is not None:
            request.add_header(sd.CSRF_HEADER, token)
        if origin is not None:
            request.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_config_exposes_no_key_values(self) -> None:
        with urllib.request.urlopen(f"{self.base}/api/config", timeout=5) as response:
            config = json.loads(response.read())
        rendered = json.dumps(config)
        self.assertIn("csrf_token", config)
        for engine in config["engines"]:
            self.assertIn("available", engine)
        for variable in (sd.ANTHROPIC_API_KEY_ENV, sd.GEMINI_API_KEY_ENV):
            value = os.environ.get(variable, "").strip()
            if value:
                self.assertNotIn(value, rendered)

    def test_missing_csrf_token_is_refused(self) -> None:
        status, body = self._post()
        self.assertEqual(status, 403)
        self.assertIn(sd.CSRF_HEADER, body["error"])

    def test_wrong_csrf_token_is_refused(self) -> None:
        status, _ = self._post(token="not-the-token")
        self.assertEqual(status, 403)

    def test_foreign_origin_is_refused(self) -> None:
        status, body = self._post(token=self.token, origin="http://evil.example")
        self.assertEqual(status, 403)
        self.assertIn("Origin", body["error"])

    def test_form_content_type_is_refused(self) -> None:
        status, body = self._post(
            token=self.token, content_type="application/x-www-form-urlencoded"
        )
        self.assertEqual(status, 403)
        self.assertIn("application/json", body["error"])

    def test_no_cors_headers_are_offered(self) -> None:
        with urllib.request.urlopen(f"{self.base}/api/config", timeout=5) as response:
            self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
            self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")

    def test_invalid_payload_is_refused_before_the_run_starts(self) -> None:
        status, body = self._post(
            token=self.token,
            origin=self.base,
            body={"target": "http://127.0.0.1:3000/", "router": "evil"},
        )
        self.assertEqual(status, 400)
        self.assertIn("router", body["error"])
        self.assertFalse(self.supervisor.state.running)

    def test_unknown_routes_are_not_served(self) -> None:
        request = urllib.request.Request(f"{self.base}/api/secret", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 404)


class FailureCleanupTests(unittest.TestCase):
    """실패해도 credential 참조와 세션은 반드시 정리된다."""

    def test_a_failing_run_still_clears_credentials(self) -> None:
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        # 아무것도 듣고 있지 않은 포트. Recon 이 실패하고 Run 이 끝난다.
        options = RunOptions(target="http://127.0.0.1:9/", budget=3)
        supervisor.start(options, RunSecrets())
        deadline = time.monotonic() + 40
        while supervisor.state.running and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(supervisor.state.running, "Run 이 끝나지 않았다")
        view = supervisor.state.read(0)
        self.assertIn(view["status"], {"done", "failed"})
        notes = [
            item["detail"]
            for item in view["events"]
            if item["kind"] == "dashboard_note"
        ]
        self.assertIn("세션 credential 메모리 참조 폐기 완료", notes)


@unittest.skipUnless(
    os.environ.get("HACKLIPSE_JUICE_SHOP_URL"),
    "HACKLIPSE_JUICE_SHOP_URL 이 없으면 건너뛴다 (npm start 로 Juice Shop 을 띄운다)",
)
class JuiceShopIntegrationTests(unittest.TestCase):
    """웹에서 시작한 한 Run 이 5종을 Candidate→Analysis→Validation→Report 까지 끌고 간다."""

    def test_all_five_types_reach_a_verdict(self) -> None:
        actor = os.environ["HACKLIPSE_JUICE_ACTOR"].split(":", 1)
        owner = os.environ["HACKLIPSE_JUICE_OWNER"].split(":", 1)
        supervisor = RunSupervisor(
            allowed_hosts=frozenset({"127.0.0.1"}), defaults=_defaults()
        )
        options = RunOptions(
            target=os.environ["HACKLIPSE_JUICE_SHOP_URL"],
            mode=MODE_JUICE_SHOP,
            vuln="all",
            budget=120,
            juice_shop_db=os.environ["HACKLIPSE_JUICE_SHOP_DB"],
        )
        secrets = RunSecrets(
            access=AccessAccounts(
                actor_email=actor[0],
                actor_password=actor[1],
                owner_email=owner[0],
                owner_password=owner[1],
            )
        )
        self.assertIsNone(supervisor.validate(options, secrets))
        supervisor.start(options, secrets)
        deadline = time.monotonic() + 600
        while supervisor.state.running and time.monotonic() < deadline:
            time.sleep(1)
        view = supervisor.state.read(0)
        self.assertEqual(view["status"], "done", view["error"])

        types = {
            item["vulnerability_type"]
            for item in view["candidates"]
            if item["status"] in {"confirmed", "suspected", "rejected", "blocked"}
        }
        self.assertEqual(
            types,
            {"SQLi", "XSS", "Access Control", "Path Traversal", "SSTI"},
            "다섯 유형이 모두 판정까지 가지 않았다",
        )
        self.assertTrue(view["report"], "보고서가 없다")
        # 비밀은 결과 어디에도 없다.
        rendered = json.dumps(view, ensure_ascii=False)
        for secret in (actor[1], owner[1], actor[0], owner[0]):
            self.assertNotIn(secret, rendered)


class _without_env:
    """환경변수를 잠시 지운다. 키 유무에 따른 분기를 시험할 때 쓴다."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._previous: str | None = None

    def __enter__(self):
        self._previous = os.environ.pop(self._name, None)
        return self

    def __exit__(self, *_exc) -> None:
        if self._previous is not None:
            os.environ[self._name] = self._previous


if __name__ == "__main__":
    unittest.main()
