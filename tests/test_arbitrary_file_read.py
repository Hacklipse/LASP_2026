"""경로를 그대로 여는 표면에서 고정 절대 경로 파일 읽기를 증명하는지 검증한다."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, unquote, urlsplit

from hacklipse.adapters.arbitrary_file_read import (
    ARBITRARY_FILE_READ_OBSERVATION,
    ARBITRARY_FILE_READ_PROBE_PATH,
    ARBITRARY_FILE_READ_PROOF_FILE,
    ARBITRARY_FILE_READ_PROOF_MARKERS,
    ARBITRARY_FILE_READ_TOOL,
    arbitrary_file_read_signal,
    build_arbitrary_file_read_requests,
    looks_like_file_parameter,
    validate_arbitrary_file_read_request,
)
from hacklipse.adapters.http_runtime import HttpExecutionRuntime
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    ARBITRARY_FILE_READ_SAFE_PROBE_PATH,
    CandidateStatus,
    ValidationReasonCode,
    CONTROL_MARKER,
    DomainInvariantError,
    HttpRequestSpec,
    ARBITRARY_FILE_READ_SAFE_PROBE_VALUES,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    ValidationProofType,
)


def _surface(url: str = "http://localhost/view", parameters=("file",)) -> Surface:
    return Surface(
        surface_id="surface-1", run_id="run-1", url=url,
        method="GET", parameters=parameters,
    )


def _response(evidence_id: str, body: str, status: int = 200) -> Evidence:
    return Evidence(
        evidence_id=evidence_id, run_id="run-1", surface_id="surface-1",
        created_by="execution_runtime:arbitrary_file_read_probe",
        evidence_type="http_response",
        observation={"status": status, "method": "GET", "body": body},
    )


def _request(**overrides) -> ExecutionRequest:
    fields = dict(
        execution_id="exec-1", run_id="run-1", task_id="task-1",
        tool=ARBITRARY_FILE_READ_TOOL, target_url="http://localhost/view",
        surface_id="surface-1", purpose="probe", method="GET",
        request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
        query_parameters=(("file", ARBITRARY_FILE_READ_PROBE_PATH),),
    )
    fields.update(overrides)
    return ExecutionRequest(**fields)


class ProbeShapeTests(unittest.TestCase):
    def test_probe_sends_every_form_of_the_one_fixed_file(self) -> None:
        control, *probes = build_arbitrary_file_read_requests(
            _surface(), ("file",), ("file",), purpose="probe"
        )
        self.assertIs(control.http_request.request_kind, HttpRequestKind.CONTROL)
        # 표기는 여럿이지만 가리키는 파일은 하나다. 그게 안전 성질이다.
        self.assertEqual(
            [dict(item.http_request.query_parameters)["file"] for item in probes],
            list(ARBITRARY_FILE_READ_SAFE_PROBE_VALUES),
        )
        for item in probes:
            self.assertIs(
                item.http_request.request_kind,
                HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
            )

    def test_each_form_gets_its_own_fingerprint(self) -> None:
        """표기가 같은 지문을 받으면 두 번째 표기의 증적이 첫 번째로 오인된다."""

        _, *probes = build_arbitrary_file_read_requests(
            _surface(), ("file",), ("file",), purpose="probe"
        )
        prints = [item.request_fingerprint("http://localhost/view") for item in probes]
        self.assertEqual(len(set(prints)), len(prints))

    def test_only_the_selected_parameter_carries_the_probe(self) -> None:
        """한 요청에서 바뀌는 자리가 둘이면 무엇이 신호를 만들었는지 말할 수 없다."""

        _, *probes = build_arbitrary_file_read_requests(
            _surface(parameters=("file", "lang")), ("file", "lang"), ("file",),
            purpose="probe",
        )
        for item in probes:
            values = dict(item.http_request.query_parameters)
            self.assertIn(values["file"], ARBITRARY_FILE_READ_SAFE_PROBE_VALUES)
            self.assertNotIn(values["lang"], ARBITRARY_FILE_READ_SAFE_PROBE_VALUES)


class FileParameterNameTests(unittest.TestCase):
    """라우팅 관측이 파일 이름과 URL 이름을 한데 묶으므로 분석기가 좁힌다."""

    def test_file_like_names_are_accepted(self) -> None:
        for name in ("file", "filepath", "page", "template", "download", "doc"):
            with self.subTest(name=name):
                self.assertTrue(looks_like_file_parameter(name))

    def test_url_like_names_are_rejected(self) -> None:
        """URL 자리에 절대 경로를 보내도 파일이 나오지 않는다. 요청 낭비다."""

        for name in ("url", "redirect", "dest", "target", "src", "link", "uri"):
            with self.subTest(name=name):
                self.assertFalse(looks_like_file_parameter(name))

    def test_mixed_names_are_treated_as_url(self) -> None:
        self.assertFalse(looks_like_file_parameter("file_url"))
        self.assertFalse(looks_like_file_parameter("doc_src"))

    def test_unrelated_names_are_rejected(self) -> None:
        for name in ("q", "lang", "sort", "id"):
            with self.subTest(name=name):
                self.assertFalse(looks_like_file_parameter(name))


class ValidatorTests(unittest.TestCase):
    def test_fixed_absolute_path_is_accepted(self) -> None:
        validate_arbitrary_file_read_request(_request())

    def test_other_files_are_rejected(self) -> None:
        for value in ("/etc/passwd", "/etc/shadow", "../../../../../etc/os-release"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_arbitrary_file_read_request(
                        _request(query_parameters=(("file", value),))
                    )

    def test_exactly_one_parameter_may_carry_the_probe(self) -> None:
        with self.assertRaises(ValueError):
            validate_arbitrary_file_read_request(
                _request(query_parameters=(
                    ("file", ARBITRARY_FILE_READ_PROBE_PATH),
                    ("other", ARBITRARY_FILE_READ_PROBE_PATH),
                ))
            )

    def test_the_dedicated_tool_is_required(self) -> None:
        with self.assertRaises(ValueError):
            validate_arbitrary_file_read_request(_request(tool="http_get"))

    def test_body_and_headers_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_arbitrary_file_read_request(_request(method="POST", body="x=1"))


class SignalTests(unittest.TestCase):
    _PROOF = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nVERSION_ID=\"12\"\n"

    def test_markers_only_in_the_probe_are_a_signal(self) -> None:
        self.assertTrue(
            arbitrary_file_read_signal(
                _response("evi-control", "<html>home</html>"),
                _response("evi-probe", self._PROOF),
            )
        )

    def test_markers_already_in_the_control_are_not_a_signal(self) -> None:
        """대조 응답에도 있으면 그 표식은 파일을 읽어서 생긴 것이 아니다."""

        self.assertFalse(
            arbitrary_file_read_signal(
                _response("evi-control", self._PROOF),
                _response("evi-probe", self._PROOF),
            )
        )

    def test_error_status_is_not_a_signal(self) -> None:
        self.assertFalse(
            arbitrary_file_read_signal(
                _response("evi-control", "<html>home</html>"),
                _response("evi-probe", self._PROOF, status=500),
            )
        )

    def test_partial_markers_are_not_a_signal(self) -> None:
        self.assertFalse(
            arbitrary_file_read_signal(
                _response("evi-control", "<html>home</html>"),
                _response("evi-probe", 'PRETTY_NAME="Debian"'),
            )
        )

    def test_proof_markers_identify_the_fixed_file(self) -> None:
        self.assertEqual(
            ARBITRARY_FILE_READ_PROOF_MARKERS, ("PRETTY_NAME=", "VERSION_ID=")
        )
        self.assertEqual(ARBITRARY_FILE_READ_OBSERVATION, "arbitrary_file_read")


class _QueryFileRuntime:
    """query 로 받은 경로를 그대로 여는 로컬 대역.

    ``blocked`` 는 절대 경로를 거부하는 서버다. 취약하지 않은 대상에서 확정이 나오지
    않는지도 같은 파이프라인으로 확인한다.
    """

    def __init__(self, *, blocked: bool = False) -> None:
        self.blocked = blocked
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        parsed = urlsplit(request.resolved_url)
        values = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.path in ("/", "/index.html"):
            body, status = '<a href="/view?page=readme.txt">doc</a>', 200
        elif values.get("page") == ARBITRARY_FILE_READ_PROBE_PATH:
            if self.blocked:
                body, status = '{"detail":"File not allowed"}', 403
            else:
                body, status = "\n".join(ARBITRARY_FILE_READ_PROOF_MARKERS), 200
        else:
            body, status = "a readme", 200
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": status, "body": body,
                "requested_url": request.resolved_url,
            },
        )


def _pipeline_run(runtime):
    """Recon 부터 독립 Validation 까지 실제 Orchestrator 로 한 Run 을 돌린다."""

    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(vulnerability_types=("Arbitrary File Read",)),
    )
    register_standard_agents(app, recon_max_pages=2)
    run = app.orchestrator.start(
        RunRequest(
            target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            request_budget=30,
        )
    )
    return app, run


class ArbitraryFileReadPipelineTests(unittest.TestCase):
    """query 좌표를 실제 Orchestrator 경로로 끝까지 통과시킨다.

    이 Agent 의 다른 테스트는 Evidence 를 직접 만들어 넣고 Runtime·Dispatcher·
    TaskFactory 를 거치지 않는다. 그래서 도구가 Runtime·Task·Dispatcher·proof type
    어디에도 등록되지 않아 실제 대상에서 한 건도 실행되지 못했는데 전부 통과했다.
    여기서는 그 관문들을 실제로 지나가게 한다.
    """

    def test_query_file_parameter_is_confirmed_end_to_end(self) -> None:
        runtime = _QueryFileRuntime()
        app, run = _pipeline_run(runtime)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [
                item.vulnerability_type
                for item in app.stores.findings.list_by_run(run.run_id)
            ],
            ["Arbitrary File Read"],
        )
        finding = app.stores.findings.list_by_run(run.run_id)[0]
        self.assertIs(finding.proof_type, ValidationProofType.ARBITRARY_FILE_READ)

    def test_probe_tool_actually_reaches_the_runtime(self) -> None:
        # TaskFactory 가 이 취약점 유형에 전용 도구를 주지 않으면 Dispatcher 가
        # AgentToolNotAllowed 로 Candidate 를 실패시키고 요청은 한 건도 나가지 않는다.
        runtime = _QueryFileRuntime()
        app, run = _pipeline_run(runtime)

        probes = [
            item for item in runtime.requests
            if item.tool == ARBITRARY_FILE_READ_TOOL
            and item.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE
        ]
        self.assertTrue(probes)
        for probe in probes:
            self.assertIn(
                dict(parse_qsl(urlsplit(probe.resolved_url).query))["page"],
                ARBITRARY_FILE_READ_SAFE_PROBE_VALUES,
            )
        candidates = app.stores.candidates.list_by_run(run.run_id)
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertIsNone(candidate.last_error)

    def test_validation_sends_its_own_requests(self) -> None:
        runtime = _QueryFileRuntime()
        app, run = _pipeline_run(runtime)

        finding = app.stores.findings.list_by_run(run.run_id)[0]
        replayed = [
            item for item in runtime.requests
            if item.validation_id == finding.validation_id
        ]
        # 독립 Validation 세션이 control 과 표기별 probe 를 직접 다시 보냈다.
        kinds = [item.request_kind.value for item in replayed]
        self.assertEqual(kinds.count("control"), 1)
        self.assertEqual(
            kinds.count("arbitrary_file_read_probe"),
            len(ARBITRARY_FILE_READ_SAFE_PROBE_VALUES),
        )
        by_id = {
            item.evidence_id: item
            for item in app.stores.evidence.list_by_run(run.run_id)
        }
        for evidence_id in finding.evidence_ids:
            self.assertEqual(by_id[evidence_id].validation_id, finding.validation_id)

    def test_blocked_absolute_path_is_not_confirmed(self) -> None:
        app, run = _pipeline_run(_QueryFileRuntime(blocked=True))

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())

    def test_budget_accounting_matches_the_requests_sent(self) -> None:
        runtime = _QueryFileRuntime()
        app, run = _pipeline_run(runtime)

        self.assertEqual(
            app.budget_manager.remaining(run.run_id), 30 - len(runtime.requests)
        )


class _SingleDecodeRuntime:
    """한 번만 디코딩하는 대상. 평문 절대 경로는 거부하고 이중 인코딩만 통과시킨다.

    필터가 내용이 아니라 형태로 막는 전형이다. 표기가 하나뿐이면 이 대상은 "읽을 수
    없다"로 보고되는데, 실제로는 읽힌다.
    """

    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        parsed = urlsplit(request.resolved_url)
        raw = dict(parse_qsl(parsed.query, keep_blank_values=True)).get("page", "")
        if parsed.path in ("/", "/index.html"):
            body, status = '<a href="/view?page=readme.txt">doc</a>', 200
        elif raw.startswith("/"):
            # 디코딩된 결과가 절대 경로면 형태로 거부한다.
            body, status = '{"detail":"absolute path rejected"}', 403
        elif raw == "%2fetc%2fos-release":
            # 한 번 더 디코딩해 파일을 연다.
            body, status = "\n".join(ARBITRARY_FILE_READ_PROOF_MARKERS), 200
        else:
            body, status = "a readme", 200
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": status, "body": body,
                "requested_url": request.resolved_url,
            },
        )


class ProbeFormCoverageTests(unittest.TestCase):
    """한 표기로는 못 찾는 대상을 다른 표기가 찾는지 확인한다."""

    def test_encoded_form_reaches_a_target_the_literal_form_cannot(self) -> None:
        runtime = _SingleDecodeRuntime()
        app, run = _pipeline_run(runtime)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [
                item.vulnerability_type
                for item in app.stores.findings.list_by_run(run.run_id)
            ],
            ["Arbitrary File Read"],
        )
        sent = [
            dict(parse_qsl(urlsplit(item.resolved_url).query)).get("page")
            for item in runtime.requests
            if item.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE
        ]
        # 평문은 403을 받았고, 그래도 이중 인코딩 표기까지 시도해 확정했다.
        self.assertIn(ARBITRARY_FILE_READ_SAFE_PROBE_PATH, sent)
        self.assertIn("%2fetc%2fos-release", sent)

    def test_one_coordinate_yields_one_finding_not_one_per_form(self) -> None:
        runtime = _QueryFileRuntime()
        app, run = _pipeline_run(runtime)

        # 같은 파일을 두 표기로 읽어도 발견은 하나다.
        self.assertEqual(len(app.stores.findings.list_by_run(run.run_id)), 1)
        observations = [
            item for item in app.stores.evidence.list_by_run(run.run_id)
            if item.observation.get("type") == ARBITRARY_FILE_READ_OBSERVATION
        ]
        self.assertEqual(len(observations), 1)


class _SegmentRuntime:
    """query 가 없고 마지막 세그먼트가 파일 이름인 라우트."""

    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        if path in ("/", "/index.html"):
            body, status = '<a href="/download/report.pdf">doc</a>', 200
        elif path.startswith("/download/"):
            value = unquote(path[len("/download/"):])
            if value.endswith("os-release"):
                body, status = "\n".join(ARBITRARY_FILE_READ_PROOF_MARKERS), 200
            else:
                body, status = "a report", 200
        else:
            body, status = '{"detail":"not found"}', 404
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": status, "body": body,
                "requested_url": request.resolved_url,
            },
        )


class PathSegmentCoordinateTests(unittest.TestCase):
    """query 가 없어 다른 두 좌표로는 닿지 못하는 라우트."""

    def test_parameterless_file_route_is_confirmed(self) -> None:
        runtime = _SegmentRuntime()
        app, run = _pipeline_run(runtime)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [
                item.vulnerability_type
                for item in app.stores.findings.list_by_run(run.run_id)
            ],
            ["Arbitrary File Read"],
        )
        observation = next(
            item for item in app.stores.evidence.list_by_run(run.run_id)
            if item.observation.get("location") == "path_segment"
        )
        self.assertEqual(observation.observation["parameter"], "report.pdf")

    def test_only_the_final_segment_changes(self) -> None:
        runtime = _SegmentRuntime()
        _pipeline_run(runtime)

        probes = [
            item for item in runtime.requests
            if item.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE
        ]
        self.assertTrue(probes)
        for probe in probes:
            # 앞 디렉터리는 관측된 그대로 남고 query 도 붙지 않는다.
            self.assertTrue(urlsplit(probe.resolved_url).path.startswith("/download/"))
            self.assertEqual(urlsplit(probe.resolved_url).query, "")
            self.assertIn(
                probe.file_read_path_value, ARBITRARY_FILE_READ_SAFE_PROBE_VALUES
            )

    def test_control_puts_the_fixed_marker_in_the_segment(self) -> None:
        runtime = _SegmentRuntime()
        _pipeline_run(runtime)

        controls = [
            item for item in runtime.requests
            if item.tool == ARBITRARY_FILE_READ_TOOL
            and item.request_kind is HttpRequestKind.CONTROL
        ]
        self.assertTrue(controls)
        for control in controls:
            # 정상 파일 응답을 증명으로 오인하지 않으려면 control 도 그 자리를 바꿔야 한다.
            self.assertEqual(control.file_read_path_value, CONTROL_MARKER)

    def test_segment_value_is_bounded_by_the_domain(self) -> None:
        for bad in ("/etc/passwd", "../../secret", "anything"):
            with self.subTest(value=bad), self.assertRaises(DomainInvariantError):
                HttpRequestSpec(
                    request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                    file_read_path_index=2, file_read_path_value=bad,
                )

    def test_routes_only_where_a_directory_cue_says_file_serving(self) -> None:
        from hacklipse.adapters.arbitrary_file_read import file_serving_segment_index
        from hacklipse.domain import Surface

        cases = {
            "http://t/download/report.pdf": 2,
            "http://t/assets/js/app.js": 3,
            "http://t/about/team.html": None,
            "http://t/report.pdf": None,
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                surface = Surface(
                    surface_id="s", run_id="r", url=url, method="GET",
                )
                self.assertEqual(file_serving_segment_index(surface), expected)


class _PublicProofFileRuntime:
    """증명 파일을 정적 핸들러로 이미 공개하는 앱.

    파라미터로도 읽히지만, 원래 공개된 자료라 읽기 취약점이 아니다. 이 대조군이
    없으면 그런 대상을 확정해 버린다.
    """

    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        parsed = urlsplit(request.resolved_url)
        values = dict(parse_qsl(parsed.query, keep_blank_values=True))
        markers = "\n".join(ARBITRARY_FILE_READ_PROOF_MARKERS)
        if parsed.path in ("/", "/index.html"):
            body = '<a href="/view?page=readme.txt">doc</a>'
        elif parsed.path == ARBITRARY_FILE_READ_PROOF_FILE:
            # 정적 핸들러가 그대로 내준다.
            body = markers
        elif values.get("page") in ARBITRARY_FILE_READ_SAFE_PROBE_VALUES:
            body = markers
        else:
            body = "a readme"
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": 200, "body": body,
                "requested_url": request.resolved_url,
            },
        )


class PublicProofFileTests(unittest.TestCase):
    """증명 파일이 원래 공개면 확정하지 않는다."""

    def test_public_proof_file_is_not_a_finding(self) -> None:
        runtime = _PublicProofFileRuntime()
        app, run = _pipeline_run(runtime)

        self.assertIs(run.phase, RunPhase.DONE)
        # 파라미터로 표식이 나왔지만 같은 파일이 정적 경로로도 공개돼 있다.
        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())
        candidate, = app.stores.candidates.list_by_run(run.run_id)
        self.assertIs(candidate.status, CandidateStatus.REJECTED)
        self.assertIs(
            candidate.validation_reason_code,
            ValidationReasonCode.CONTROL_SIGNAL_PRESENT,
        )

    def test_the_check_requests_the_proof_file_on_the_same_origin(self) -> None:
        runtime = _PublicProofFileRuntime()
        _pipeline_run(runtime)

        checks = [
            item for item in runtime.requests
            if item.request_kind is HttpRequestKind.FILE_READ_PUBLIC_CHECK
        ]
        self.assertTrue(checks)
        for check in checks:
            parsed = urlsplit(check.resolved_url)
            self.assertEqual(parsed.path, ARBITRARY_FILE_READ_PROOF_FILE)
            self.assertEqual(parsed.netloc, "local.test")
            # 좌표를 싣지 않는다 — 바꾸는 자리가 없는 평범한 GET 이다.
            self.assertEqual(parsed.query, "")

    def test_the_check_costs_nothing_when_no_signal_was_found(self) -> None:
        # 신호가 없으면 확정 직전에 도달하지 않으므로 요청을 쓰지 않는다.
        runtime = _QueryFileRuntime(blocked=True)
        _pipeline_run(runtime)

        self.assertEqual(
            [
                item for item in runtime.requests
                if item.request_kind is HttpRequestKind.FILE_READ_PUBLIC_CHECK
            ],
            [],
        )

    def test_override_is_reserved_for_the_public_check(self) -> None:
        from hacklipse.domain import EvidenceRequest

        # 다른 종류가 target_url_override 를 쓰면 Task 생성에서 막힌다.
        smuggled = EvidenceRequest(
            evidence_type="http_response", surface_id="s", reason="r",
            suggested_tool=ARBITRARY_FILE_READ_TOOL,
            target_url_override="http://elsewhere.invalid/etc/os-release",
            http_request=HttpRequestSpec(
                method="GET",
                request_kind=HttpRequestKind.ARBITRARY_FILE_READ_PROBE,
                query_parameters=(("page", ARBITRARY_FILE_READ_SAFE_PROBE_PATH),),
            ),
        )
        from hacklipse.application.task_factory import TaskFactory
        from hacklipse.domain import Candidate, Run, RunScope

        run = Run(
            run_id="r", target_url="http://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe", request_budget=10,
        )
        candidate = Candidate(
            candidate_id="c", run_id="r", surface_id="s",
            vulnerability_type="Arbitrary File Read", hypothesis="h",
            assigned_agent="arbitrary_file_read_analyzer", evidence_ids=(),
        )
        with self.assertRaises(ValueError):
            TaskFactory(id_factory=iter(("1",)).__next__).evidence_collection(
                run, candidate, smuggled, target_url="http://local.test/view",
                agent_type="evidence_collector", request_budget=5,
            )


class _AbsolutePathHandler(BaseHTTPRequestHandler):
    """query 로 받은 절대 경로를 여는 최소 서버. 요청 경로를 그대로 기록한다."""

    paths: list[str] = []

    def log_message(self, *args) -> None:  # 테스트 출력을 더럽히지 않는다.
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 규약
        type(self).paths.append(self.path)
        parsed = urlsplit(self.path)
        values = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.path in ("/", "/index.html"):
            body = b'<html><body><a href="/view?page=readme.txt">doc</a></body></html>'
            media = "text/html"
        elif values.get("page") == ARBITRARY_FILE_READ_PROBE_PATH:
            body = "\n".join(ARBITRARY_FILE_READ_PROOF_MARKERS).encode()
            media = "text/plain"
        else:
            body = b"a readme"
            media = "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ArbitraryFileReadWireTests(unittest.TestCase):
    """실제 HTTP Runtime 을 거쳐 전송된 요청을 확인한다.

    ``_HTTP_TOOLS`` 에 도구가 없으면 여기서만 드러난다 — 대역 Runtime 은 어떤 도구든
    받아 주므로 이 관문을 지나가지 않는다.
    """

    @classmethod
    def setUpClass(cls) -> None:
        _AbsolutePathHandler.paths = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _AbsolutePathHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_real_runtime_sends_the_encoded_absolute_path(self) -> None:
        port = self.server.server_address[1]
        app = build_local_application(
            {},
            runtime=HttpExecutionRuntime(),
            router=standard_router(vulnerability_types=("Arbitrary File Read",)),
        )
        register_standard_agents(app, recon_max_pages=2)
        run = app.orchestrator.start(
            RunRequest(
                target_url=f"http://127.0.0.1:{port}/",
                scope=RunScope(allowed_hosts=frozenset({"127.0.0.1"})),
                request_budget=30,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(
            [
                item.vulnerability_type
                for item in app.stores.findings.list_by_run(run.run_id)
            ],
            ["Arbitrary File Read"],
        )
        # 서버가 실제로 받은 요청 경로. 고정 절대 경로가 query 에 인코딩되어 실린다.
        probes = [
            path for path in _AbsolutePathHandler.paths
            if "page=%2Fetc%2Fos-release" in path
        ]
        # Analysis 1회 + 독립 Validation 1회.
        self.assertEqual(len(probes), 2)
        for path in probes:
            self.assertTrue(path.startswith("/view?"))


if __name__ == "__main__":
    unittest.main()
