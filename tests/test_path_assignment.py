"""경로에 `이름=값`으로 실린 입력 좌표의 관측·라우팅·실행·독립 검증을 검증한다.

핵심 회귀는 하나다 — `/file=web_assets/javascript/example.js`에서 만든 탐침이 경로
안의 값만 바꿔야 하고, `?file=`을 새로 덧붙이면 안 된다. 문자열 조립만 보면 그 차이를
놓칠 수 있어서, 실제 로컬 서버가 받은 요청 라인까지 확인한다.
"""

from __future__ import annotations

import socket
import threading
import unittest
from dataclasses import replace
from urllib.parse import urlsplit

from hacklipse.adapters import HeuristicPathTraversalAnalyzer
from hacklipse.adapters.analyzer_capabilities import (
    DEFAULT_ANALYZER_CAPABILITIES,
    capability_matches,
    capability_missing_requirements,
)
from hacklipse.adapters.http_runtime import HttpExecutionRuntime
from hacklipse.adapters.path_traversal_analysis import (
    FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION,
    PATH_ASSIGNMENT_CAPABILITY,
    PATH_ASSIGNMENT_OBSERVATION,
    PATH_ASSIGNMENT_SKIPPED_OBSERVATION,
    PATH_ASSIGNMENT_SOURCE,
    PATH_TRAVERSAL_OBSERVATION,
    PATH_TRAVERSAL_PROBE_PATH,
    PATH_TRAVERSAL_PROOF_MARKERS,
    PATH_TRAVERSAL_TOOL,
    build_path_assignment_requests,
)
from hacklipse.adapters.arbitrary_file_read import (
    ARBITRARY_FILE_READ_PATH_CAPABILITY,
    ARBITRARY_FILE_READ_PROBE_PATH,
    ARBITRARY_FILE_READ_PROOF_MARKERS,
    ARBITRARY_FILE_READ_TOOL,
    build_arbitrary_file_read_path_requests,
)
from hacklipse.adapters.policy import AllowlistPolicyGate
from hacklipse.adapters.recon import _path_assignment
from hacklipse.adapters.routing import RouteSuggestion, RuleBasedVulnerabilityRouter
from hacklipse.application.errors import AgentContractError
from hacklipse.adapters.sqlite_store import SQLiteStoreBundle
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    Candidate,
    DomainInvariantError,
    Evidence,
    EvidenceRequest,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    HttpRequestSpec,
    PathAssignment,
    CandidateStatus,
    Run,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationProofType,
)
from hacklipse.ports.errors import ApprovalRequired, PolicyViolation

_HOST = "local.test"
_ORIGIN = f"http://{_HOST}"
_FILE_PATH = "/file=web_assets/javascript/example.js"
_TARGET = f"{_ORIGIN}{_FILE_PATH}"
_OBSERVED_VALUE = "web_assets/javascript/example.js"
# `/file=` 뒤, 즉 값이 시작하는 자리. 경로 문자열에 대한 slice 범위다.
_VALUE_START = len("/file=")
_VALUE_END = _VALUE_START + len(_OBSERVED_VALUE)


def _assignment(**overrides) -> PathAssignment:
    fields = {
        "name": "file",
        "value_start": _VALUE_START,
        "value_end": _VALUE_END,
        "observed_value": _OBSERVED_VALUE,
        "source": PATH_ASSIGNMENT_SOURCE,
    }
    fields.update(overrides)
    return PathAssignment(**fields)


class PathAssignmentObservationTests(unittest.TestCase):
    """Recon이 경로 좌표를 보수적으로만 인정하는지 확인한다."""

    def test_file_assignment_keeps_the_value_to_the_end_of_the_path(self) -> None:
        found, skipped = _path_assignment(_TARGET, source=PATH_ASSIGNMENT_SOURCE)

        self.assertIsNone(skipped)
        assert found is not None
        self.assertEqual(found.name, "file")
        # 값에 `/`가 들어 있어도 다음 세그먼트에서 자르지 않는다.
        self.assertEqual(found.observed_value, _OBSERVED_VALUE)
        self.assertTrue(found.matches(_TARGET))

    def test_ambiguous_empty_and_encoded_paths_are_skipped_with_a_reason(self) -> None:
        cases = {
            f"{_ORIGIN}/file=a=b": "ambiguous_multiple_assignments",
            f"{_ORIGIN}/file=": "empty_value",
            f"{_ORIGIN}/=value": "empty_name",
            f"{_ORIGIN}/file=/nested": "value_starts_with_separator",
            f"{_ORIGIN}/x%2Ffile=a.js": "encoded_delimiter",
            f"{_ORIGIN}/file=web%2Fa.js": "encoded_delimiter",
            f"{_ORIGIN}/9lives=a.js": "name_not_identifier",
        }
        for url, reason in cases.items():
            with self.subTest(url=url):
                found, skipped = _path_assignment(url, source=PATH_ASSIGNMENT_SOURCE)
                self.assertIsNone(found)
                self.assertEqual(skipped, reason)

    def test_paths_without_an_assignment_are_not_reported_as_skipped(self) -> None:
        # `=`가 없으면 건너뛴 좌표가 아니라 애초에 좌표가 아니다. 사유를 남기면
        # 감사 로그가 평범한 경로로 가득 차 실제 모호 사례가 묻힌다.
        for url in (f"{_ORIGIN}/users/17", f"{_ORIGIN}/assets/app.js", _ORIGIN + "/"):
            with self.subTest(url=url):
                self.assertEqual(
                    _path_assignment(url, source=PATH_ASSIGNMENT_SOURCE), (None, None)
                )

    def test_base64_tail_is_not_mistaken_for_a_coordinate(self) -> None:
        found, _ = _path_assignment(
            f"{_ORIGIN}/token/aGVsbG8=/next", source=PATH_ASSIGNMENT_SOURCE
        )
        self.assertIsNone(found)


class PathAssignmentSurfaceContractTests(unittest.TestCase):
    """Surface가 좌표와 URL의 일치를 강제하는지 확인한다."""

    def test_surface_keeps_the_coordinate_out_of_query_parameters(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url=_TARGET, method="GET",
            path_assignment=_assignment(),
        )
        # 경로 좌표는 query parameters와 섞이지 않는다. 섞으면 Analyzer가 `?file=`을
        # 덧붙인, 대상이 제공한 적 없는 URL을 만든다.
        self.assertEqual(surface.parameters, ())
        assert surface.path_assignment is not None
        self.assertEqual(surface.path_assignment.name, "file")

    def test_span_that_does_not_select_the_value_is_rejected(self) -> None:
        with self.assertRaises(DomainInvariantError):
            Surface(
                surface_id="s", run_id="r", url=_TARGET, method="GET",
                path_assignment=_assignment(value_start=_VALUE_START + 1),
            )

    def test_name_also_present_in_the_query_is_rejected(self) -> None:
        with self.assertRaises(DomainInvariantError):
            Surface(
                surface_id="s", run_id="r", url=_TARGET, method="GET",
                parameters=("file",), path_assignment=_assignment(),
            )

    def test_empty_name_or_value_is_rejected(self) -> None:
        for overrides in (
            {"name": ""},
            {"observed_value": "", "value_end": _VALUE_START},
            {"name": "9lives"},
        ):
            with self.subTest(**overrides), self.assertRaises(DomainInvariantError):
                _assignment(**overrides)


class PathAssignmentRequestContractTests(unittest.TestCase):
    """실행 계약이 값 교체를 고정 증명 경로 하나로 묶어 두는지 확인한다."""

    def _probe(self, **overrides) -> HttpRequestSpec:
        fields = {
            "method": "GET",
            "request_kind": HttpRequestKind.PATH_TRAVERSAL_PROBE,
            "path_assignment_name": "file",
            "path_assignment_value_start": _VALUE_START,
            "path_assignment_value_end": _VALUE_END,
            "path_assignment_value": PATH_TRAVERSAL_PROBE_PATH,
        }
        fields.update(overrides)
        return HttpRequestSpec(**fields)

    def test_only_the_fixed_safe_path_may_be_placed_in_the_path(self) -> None:
        self.assertEqual(
            self._probe().path_assignment_value, PATH_TRAVERSAL_PROBE_PATH
        )
        for value in (
            "../../../etc/passwd",
            "/etc/os-release",
            "../../../../etc/os-release",
            "web_assets/other.js",
        ):
            with self.subTest(value=value), self.assertRaises(DomainInvariantError):
                self._probe(path_assignment_value=value)

    def test_partial_coordinates_are_rejected(self) -> None:
        for missing in (
            "path_assignment_name",
            "path_assignment_value_start",
            "path_assignment_value_end",
            "path_assignment_value",
        ):
            with self.subTest(missing=missing), self.assertRaises(DomainInvariantError):
                self._probe(**{missing: None})

    def test_control_kind_cannot_carry_a_path_replacement(self) -> None:
        # control은 관측된 원래 URL 그대로여야 한다. 값을 바꾸는 control은 비교 기준이
        # 아니다.
        with self.assertRaises(DomainInvariantError):
            self._probe(request_kind=HttpRequestKind.CONTROL)

    def test_replacement_cannot_be_combined_with_other_url_changes(self) -> None:
        for overrides in (
            {"query_parameters": (("file", PATH_TRAVERSAL_PROBE_PATH),)},
            {"path_suffix": "%2500.md"},
            {"headers": (("X-Test", "1"),)},
            {"method": "POST"},
        ):
            with self.subTest(**overrides), self.assertRaises(DomainInvariantError):
                self._probe(**overrides)

    def test_fingerprint_separates_the_coordinate_from_a_plain_request(self) -> None:
        base = {
            "evidence_type": "http_response",
            "surface_id": "s",
            "reason": "same purpose",
            "suggested_tool": PATH_TRAVERSAL_TOOL,
        }
        with_coordinate = EvidenceRequest(**base, http_request=self._probe())
        without = EvidenceRequest(
            **base,
            http_request=HttpRequestSpec(
                method="GET", request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE
            ),
        )
        self.assertNotEqual(
            with_coordinate.request_fingerprint(_TARGET),
            without.request_fingerprint(_TARGET),
        )
        # 같은 좌표는 같은 지문이어야 재개 후에도 증적이 다시 연결된다.
        self.assertEqual(
            with_coordinate.request_fingerprint(_TARGET),
            EvidenceRequest(**base, http_request=self._probe()).request_fingerprint(
                _TARGET
            ),
        )


class PathAssignmentResolvedUrlTests(unittest.TestCase):
    """직렬화 결과가 값 교체인지, query 추가가 아닌지 확인한다."""

    def _request(self, **overrides) -> ExecutionRequest:
        fields = {
            "execution_id": "exec-1",
            "run_id": "r",
            "task_id": "t",
            "tool": PATH_TRAVERSAL_TOOL,
            "target_url": _TARGET,
            "surface_id": "s",
            "purpose": "p",
            "request_kind": HttpRequestKind.PATH_TRAVERSAL_PROBE,
            "path_assignment_name": "file",
            "path_assignment_value_start": _VALUE_START,
            "path_assignment_value_end": _VALUE_END,
            "path_assignment_value": PATH_TRAVERSAL_PROBE_PATH,
        }
        fields.update(overrides)
        return ExecutionRequest(**fields)

    def test_probe_replaces_the_path_value_and_adds_no_query(self) -> None:
        resolved = self._request().resolved_url

        self.assertEqual(resolved, f"{_ORIGIN}/file={PATH_TRAVERSAL_PROBE_PATH}")
        parsed = urlsplit(resolved)
        self.assertEqual(parsed.query, "")
        self.assertNotIn("?", resolved)
        # 경로 구조(앞의 `/file=`)는 관측된 그대로 남는다.
        self.assertTrue(parsed.path.startswith("/file="))

    def test_existing_query_on_the_target_is_preserved_untouched(self) -> None:
        resolved = self._request(target_url=f"{_TARGET}?lang=en").resolved_url

        self.assertEqual(urlsplit(resolved).query, "lang=en")
        self.assertEqual(
            urlsplit(resolved).path, f"/file={PATH_TRAVERSAL_PROBE_PATH}"
        )

    def test_span_outside_the_target_path_is_refused(self) -> None:
        request = self._request(target_url=f"{_ORIGIN}/short")
        with self.assertRaises(DomainInvariantError):
            request.resolved_url

    def test_out_of_scope_host_is_still_blocked(self) -> None:
        gate = AllowlistPolicyGate()
        run = Run(
            run_id="r", target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            policy_profile="safe", request_budget=10,
        )
        outside = self._request(
            run_id="r", target_url="http://evil.invalid/file=a.js",
            path_assignment_value_end=_VALUE_START + len("a.js"),
        )
        with self.assertRaises(PolicyViolation):
            gate.validate_execution(run, outside)


class _LoopbackServer:
    """실제 요청 라인을 그대로 받아 적는 최소 HTTP 서버."""

    def __init__(self, body: str) -> None:
        self.body = body.encode("utf-8")
        self.request_lines: list[str] = []
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(8)
        self.port = self._socket.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self._socket.accept()
            except OSError:
                return
            with connection:
                received = connection.recv(8192).decode("latin-1")
                if not received:
                    continue
                self.request_lines.append(received.split("\r\n", 1)[0])
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(self.body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + self.body
                )

    def close(self) -> None:
        self._socket.close()


class PathAssignmentWireTests(unittest.TestCase):
    """문자열 조립이 아니라 서버가 실제로 받은 경로를 확인한다."""

    def setUp(self) -> None:
        self.server = _LoopbackServer("\n".join(PATH_TRAVERSAL_PROOF_MARKERS))
        self.addCleanup(self.server.close)
        self.origin = f"http://127.0.0.1:{self.server.port}"

    def test_real_request_carries_the_replaced_path_without_a_query(self) -> None:
        runtime = HttpExecutionRuntime()
        target = f"{self.origin}{_FILE_PATH}"
        runtime.execute(
            ExecutionRequest(
                execution_id="exec-wire", run_id="r", task_id="t",
                tool=PATH_TRAVERSAL_TOOL, target_url=target, surface_id="s",
                purpose="wire check",
                request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
                path_assignment_name="file",
                path_assignment_value_start=_VALUE_START,
                path_assignment_value_end=_VALUE_END,
                path_assignment_value=PATH_TRAVERSAL_PROBE_PATH,
            )
        )

        self.assertEqual(
            self.server.request_lines,
            [f"GET /file={PATH_TRAVERSAL_PROBE_PATH} HTTP/1.1"],
        )
        # 회귀의 핵심: query에 file이 붙지 않는다.
        self.assertNotIn("?", self.server.request_lines[0])
        self.assertNotIn("%2F", self.server.request_lines[0])

    def test_real_control_request_is_the_observed_url_unchanged(self) -> None:
        runtime = HttpExecutionRuntime()
        target = f"{self.origin}{_FILE_PATH}"
        runtime.execute(
            ExecutionRequest(
                execution_id="exec-control", run_id="r", task_id="t",
                tool=PATH_TRAVERSAL_TOOL, target_url=target, surface_id="s",
                purpose="control", request_kind=HttpRequestKind.CONTROL,
            )
        )

        self.assertEqual(
            self.server.request_lines, [f"GET {_FILE_PATH} HTTP/1.1"]
        )


class _PathAssignmentRuntime:
    """경로의 값 부분만 파일로 여는 로컬 대역."""

    def __init__(self, *, vulnerable: bool = True, server_error: bool = False) -> None:
        self.vulnerable = vulnerable
        self.server_error = server_error
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        value = path[len("/file="):] if path.startswith("/file=") else ""
        if path in ("/", "/index.html"):
            body, status = (
                f'<a href="{_FILE_PATH}">bundle</a>', 200,
            )
        elif self.server_error and value == PATH_TRAVERSAL_PROBE_PATH:
            body, status = "<h1>500 Internal Server Error</h1>", 500
        elif self.vulnerable and value == PATH_TRAVERSAL_PROBE_PATH:
            body, status = "\n".join(PATH_TRAVERSAL_PROOF_MARKERS), 200
        elif value == PATH_TRAVERSAL_PROBE_PATH:
            body, status = "<h1>400 Bad Request</h1>", 400
        else:
            body, status = "console.log('example');", 200
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


def _end_to_end(**runtime_options):
    runtime = _PathAssignmentRuntime(**runtime_options)
    app = build_local_application(
        {},
        runtime=runtime,
        router=standard_router(vulnerability_types=("Path Traversal",)),
    )
    register_standard_agents(app, recon_max_pages=2)
    run = app.orchestrator.start(
        RunRequest(
            target_url=f"{_ORIGIN}/",
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            request_budget=30,
        )
    )
    return app, runtime, run


class PathAssignmentEndToEndTests(unittest.TestCase):
    """관측 좌표가 Recon에서 독립 Validation까지 그대로 이어지는지 확인한다."""

    def test_observed_coordinate_survives_recon_router_analysis_validation(self) -> None:
        app, runtime, run = _end_to_end()

        self.assertIs(run.phase, RunPhase.DONE)
        surface = next(
            item
            for item in app.stores.surfaces.list_by_run(run.run_id)
            if item.path_assignment is not None
        )
        assert surface.path_assignment is not None
        self.assertEqual(surface.url, _TARGET)
        self.assertEqual(surface.path_assignment.name, "file")
        self.assertEqual(surface.path_assignment.observed_value, _OBSERVED_VALUE)
        # 경로 좌표가 query parameter로 새지 않았다.
        self.assertNotIn("file", surface.parameters)

        candidates = [
            item
            for item in app.stores.candidates.list_by_run(run.run_id)
            if item.surface_id == surface.surface_id
        ]
        self.assertEqual(
            [item.vulnerability_type for item in candidates], ["Path Traversal"]
        )
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual([item.vulnerability_type for item in findings], ["Path Traversal"])

        probes = [
            item for item in runtime.requests
            if item.request_kind is HttpRequestKind.PATH_TRAVERSAL_PROBE
        ]
        # Analysis 1회 + 독립 Validation 1회. 같은 좌표를 두 세션이 각각 보낸다.
        self.assertEqual(len(probes), 2)
        for probe in probes:
            self.assertEqual(probe.path_assignment_name, "file")
            self.assertEqual(
                probe.resolved_url, f"{_ORIGIN}/file={PATH_TRAVERSAL_PROBE_PATH}"
            )
            self.assertNotIn("?", probe.resolved_url)

    def test_controls_replay_the_observed_url_without_the_replacement(self) -> None:
        _, runtime, _ = _end_to_end()

        controls = [
            item for item in runtime.requests
            if item.tool == PATH_TRAVERSAL_TOOL
            and item.request_kind is HttpRequestKind.CONTROL
        ]
        self.assertTrue(controls)
        for control in controls:
            self.assertIsNone(control.path_assignment_name)
            self.assertEqual(control.resolved_url, _TARGET)

    def test_missing_marker_is_not_confirmed(self) -> None:
        app, _, run = _end_to_end(vulnerable=False)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())

    def test_server_error_alone_is_not_confirmed(self) -> None:
        app, _, run = _end_to_end(server_error=True)

        self.assertIs(run.phase, RunPhase.DONE)
        self.assertEqual(app.stores.findings.list_by_run(run.run_id), ())

    def test_analysis_evidence_is_not_reused_as_the_validation_proof(self) -> None:
        app, runtime, run = _end_to_end()

        finding = app.stores.findings.list_by_run(run.run_id)[0]
        by_id = {
            item.evidence_id: item
            for item in app.stores.evidence.list_by_run(run.run_id)
        }
        proof_evidence = [by_id[item] for item in finding.evidence_ids]
        self.assertTrue(proof_evidence)
        # proof 로 쓰인 증적은 전부 이 Validation 세션이 직접 보낸 요청의 결과여야 한다.
        for item in proof_evidence:
            self.assertEqual(item.validation_id, finding.validation_id)
        # Validation 세션이 control 과 probe 를 각각 새로 보냈다.
        validation_probes = [
            item for item in runtime.requests
            if item.validation_id == finding.validation_id
        ]
        self.assertEqual(
            sorted(item.request_kind.value for item in validation_probes),
            ["control", "path_traversal_probe"],
        )


class PathAssignmentRoutingTests(unittest.TestCase):
    """capability가 위치와 의미 가설을 모두 요구하는지 확인한다."""

    def _capability(self):
        return next(
            item for item in DEFAULT_ANALYZER_CAPABILITIES
            if item.capability_id == PATH_ASSIGNMENT_CAPABILITY
        )

    def _surface(self, **overrides) -> Surface:
        fields = {
            "surface_id": "s", "run_id": "r", "url": _TARGET, "method": "GET",
            "path_assignment": _assignment(),
        }
        fields.update(overrides)
        return Surface(**fields)

    def _observation(self, observation_type: str, name: str = "file") -> Evidence:
        return Evidence(
            evidence_id=f"evi-{observation_type}", run_id="r", surface_id="s",
            created_by="recon", evidence_type="observation",
            observation={
                "type": observation_type, "parameter": name,
                "source": PATH_ASSIGNMENT_SOURCE,
            },
        )

    def test_location_and_file_hypothesis_are_both_required(self) -> None:
        capability = self._capability()
        surface = self._surface()
        location = self._observation(PATH_ASSIGNMENT_OBSERVATION)
        file_like = self._observation(FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION)

        self.assertTrue(capability_matches(capability, surface, (location, file_like)))
        # 위치만 있으면 파일 탐침의 근거가 없다.
        self.assertIn(
            "required_observation",
            capability_missing_requirements(capability, surface, (location,)),
        )

    def test_surface_without_the_coordinate_cannot_match(self) -> None:
        capability = self._capability()
        surface = Surface(surface_id="s", run_id="r", url=_TARGET, method="GET")

        self.assertIn(
            "path_assignment",
            capability_missing_requirements(
                capability,
                surface,
                (
                    self._observation(PATH_ASSIGNMENT_OBSERVATION),
                    self._observation(FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION),
                ),
            ),
        )

    def test_query_capability_does_not_claim_a_path_only_surface(self) -> None:
        query_capability = next(
            item for item in DEFAULT_ANALYZER_CAPABILITIES
            if item.capability_id == "path_traversal.http.query"
        )
        # 경로 좌표만 있는 표면에는 query 탐침기가 붙지 않아야 한다. 붙으면 없던
        # `?file=`을 덧붙인 요청이 나간다.
        self.assertFalse(capability_matches(query_capability, self._surface(), ()))

    def test_remote_url_name_does_not_get_a_file_hypothesis(self) -> None:
        app = build_local_application({}, runtime=_PathAssignmentRuntime())
        redirect_url = f"{_ORIGIN}/redirect=https://example.invalid/next"
        found, _ = _path_assignment(redirect_url, source=PATH_ASSIGNMENT_SOURCE)
        self.assertIsNotNone(found)

        agent = app  # 사용하지 않지만 bootstrap 가능 여부를 함께 확인한다.
        self.assertIsNotNone(agent)
        from hacklipse.adapters.arbitrary_file_read import looks_like_file_parameter

        for name in ("url", "redirect", "src", "dest", "target", "link", "file_url"):
            with self.subTest(name=name):
                self.assertFalse(looks_like_file_parameter(name))
        for name in ("file", "page", "template", "download"):
            with self.subTest(name=name):
                self.assertTrue(looks_like_file_parameter(name))


class PathAssignmentBudgetAndResumeTests(unittest.TestCase):
    """예산 집계와 저장·재개에서 좌표가 유지되는지 확인한다."""

    def test_requests_are_two_per_analysis_session(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url=_TARGET, method="GET",
            path_assignment=_assignment(),
        )
        requests = build_path_assignment_requests(surface, purpose="budget check")

        self.assertEqual(len(requests), 2)
        self.assertEqual(
            [item.http_request.request_kind for item in requests],
            [HttpRequestKind.CONTROL, HttpRequestKind.PATH_TRAVERSAL_PROBE],
        )

    def test_budget_accounting_matches_the_requests_sent(self) -> None:
        app, runtime, run = _end_to_end()
        http_requests = [item for item in runtime.requests]

        self.assertEqual(
            app.budget_manager.remaining(run.run_id), 30 - len(http_requests)
        )

    def test_coordinate_survives_a_store_round_trip(self) -> None:
        bundle = SQLiteStoreBundle(":memory:")
        surface = Surface(
            surface_id="s", run_id="r", url=_TARGET, method="GET",
            path_assignment=_assignment(), discovery_types=("html_link",),
        )
        bundle.surfaces.add(surface)

        restored = bundle.surfaces.get("r", "s")
        self.assertEqual(restored, surface)
        assert restored.path_assignment is not None
        self.assertEqual(restored.path_assignment.value_start, _VALUE_START)
        self.assertTrue(restored.path_assignment.matches(restored.url))

    def test_stored_span_that_no_longer_matches_is_refused_on_load(self) -> None:
        bundle = SQLiteStoreBundle(":memory:")
        bundle.surfaces.add(
            Surface(
                surface_id="s", run_id="r", url=_TARGET, method="GET",
                path_assignment=_assignment(),
            )
        )
        connection = bundle._database.connection  # type: ignore[attr-defined]
        row = connection.execute(
            "SELECT data FROM surfaces WHERE surface_id = 's'"
        ).fetchone()
        tampered = row[0].replace(
            '"url":"' + _TARGET + '"', '"url":"' + _ORIGIN + '/other"'
        )
        connection.execute(
            "UPDATE surfaces SET data = ? WHERE surface_id = 's'", (tampered,)
        )
        connection.commit()
        with self.assertRaises(DomainInvariantError):
            bundle.surfaces.get("r", "s")


class PathAssignmentRegressionTests(unittest.TestCase):
    """기존 좌표와 라우팅이 그대로 동작하는지 확인한다."""

    def test_query_path_traversal_surface_keeps_the_query_flow(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r",
            url="http://local.test/vulnerabilities/fi/", method="GET",
            parameters=("page",),
        )
        capability = next(
            item for item in DEFAULT_ANALYZER_CAPABILITIES
            if item.capability_id == "path_traversal.http.query"
        )
        self.assertTrue(capability_matches(capability, surface, ()))
        path_capability = next(
            item for item in DEFAULT_ANALYZER_CAPABILITIES
            if item.capability_id == PATH_ASSIGNMENT_CAPABILITY
        )
        self.assertFalse(capability_matches(path_capability, surface, ()))

    def test_numeric_rest_identifier_surface_is_unchanged(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url="http://local.test/rest/basket/2",
            method="GET", path_identifier="basket_id", path_identifier_index=3,
            observed_path_identifier="2",
        )
        self.assertIsNone(surface.path_assignment)
        access_capability = next(
            item for item in DEFAULT_ANALYZER_CAPABILITIES
            if item.capability_id == "access_control.object_identifier"
        )
        self.assertTrue(capability_matches(access_capability, surface, ()))

    def test_unregistered_vulnerability_types_are_still_not_routed(self) -> None:
        # SSRF Analyzer는 이 저장소에 없다. 경로 좌표가 생겼다고 해서 미구현 유형이
        # 라우팅되기 시작하면 안 된다.
        routed = {
            capability.vulnerability_type
            for capability in DEFAULT_ANALYZER_CAPABILITIES
        }
        self.assertNotIn("SSRF", routed)

    def test_capability_ids_remain_unique(self) -> None:
        ids = [item.capability_id for item in DEFAULT_ANALYZER_CAPABILITIES]
        self.assertEqual(len(ids), len(set(ids)))


class PathAssignmentAnalyzerSelectionTests(unittest.TestCase):
    """같은 Surface에 두 좌표가 있을 때의 선택과 중복을 확인한다."""

    def _fixture(self, *, parameters: tuple[str, ...], capability_id: str = ""):
        runtime = _PathAssignmentRuntime()
        app = build_local_application({}, runtime=runtime)
        app.stores.runs.add(
            Run(
                run_id="r", target_url=_TARGET,
                scope=RunScope(allowed_hosts=frozenset({_HOST})),
                policy_profile="safe", request_budget=20,
            )
        )
        app.stores.surfaces.add(
            Surface(
                surface_id="s", run_id="r", url=_TARGET, method="GET",
                parameters=parameters, path_assignment=_assignment(),
            )
        )
        evidence_ids = []
        for observation_type, name in (
            (PATH_ASSIGNMENT_OBSERVATION, "file"),
            (FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION, "file"),
            *(("url_or_file_parameter", item) for item in parameters),
        ):
            evidence_id = f"evi-{observation_type}-{name}"
            app.stores.evidence.append(
                Evidence(
                    evidence_id=evidence_id, run_id="r", surface_id="s",
                    created_by="recon", evidence_type="observation",
                    observation={
                        "type": observation_type, "parameter": name,
                        "source": PATH_ASSIGNMENT_SOURCE,
                    },
                )
            )
            evidence_ids.append(evidence_id)
        app.stores.candidates.add(
            Candidate(
                candidate_id="c", run_id="r", surface_id="s",
                vulnerability_type="Path Traversal", hypothesis="h",
                assigned_agent="path_traversal_analyzer",
                evidence_ids=tuple(evidence_ids),
                routing_capability_id=capability_id,
            )
        )
        app.budget_manager.open_run("r", 20)
        agent = HeuristicPathTraversalAnalyzer(
            candidate_store=app.stores.candidates,
            surface_store=app.stores.surfaces,
            evidence_store=app.stores.evidence,
            id_factory=iter(str(index) for index in range(50)).__next__,
        )
        task = TaskEnvelope(
            task_id="task", run_id="r", agent_type="path_traversal_analyzer",
            target_url=_TARGET, surface_id="s", candidate_id="c",
            evidence_ids=tuple(evidence_ids),
            allowed_tools=(PATH_TRAVERSAL_TOOL,), request_budget=10,
        )
        return agent, task

    def test_path_only_surface_probes_the_path_coordinate(self) -> None:
        agent, task = self._fixture(parameters=())
        result = agent.handle(task)

        probe = result.evidence_requests[-1].http_request
        assert probe is not None
        self.assertEqual(probe.path_assignment_name, "file")
        self.assertEqual(probe.query_parameters, ())

    def test_rule_routed_surface_with_query_inputs_keeps_the_query_flow(self) -> None:
        # 규칙 Router는 (Surface, 취약점)당 Candidate 하나만 만든다. 기존 query 흐름이
        # 조용히 경로 흐름으로 바뀌면 기존 결과가 달라진다.
        agent, task = self._fixture(parameters=("page",))
        result = agent.handle(task)

        probe = result.evidence_requests[-1].http_request
        assert probe is not None
        self.assertIsNone(probe.path_assignment_name)
        self.assertEqual(
            dict(probe.query_parameters)["page"], PATH_TRAVERSAL_PROBE_PATH
        )

    def test_capability_routed_candidate_probes_only_its_own_coordinate(self) -> None:
        agent, task = self._fixture(
            parameters=("page",), capability_id=PATH_ASSIGNMENT_CAPABILITY
        )
        result = agent.handle(task)

        self.assertEqual(len(result.evidence_requests), 2)
        probe = result.evidence_requests[-1].http_request
        assert probe is not None
        self.assertEqual(probe.path_assignment_name, "file")
        # 경로 좌표 Candidate는 query를 건드리지 않는다. 그래야 두 Candidate가 같은
        # 자리를 두 번 탐침하지 않는다.
        self.assertEqual(probe.query_parameters, ())


class _StubAdvisor:
    def __init__(self, *suggestions: RouteSuggestion) -> None:
        self._suggestions = suggestions

    def advise(self, run, surfaces, evidence, routed):
        return self._suggestions


class PathAssignmentDuplicationTests(unittest.TestCase):
    """query와 path 좌표를 모두 가진 Surface의 Candidate·예산 중복을 확인한다."""

    def _both_coordinates(self) -> tuple[Surface, tuple[Evidence, ...]]:
        surface = Surface(
            surface_id="s", run_id="r", url=_TARGET, method="GET",
            parameters=("page",), path_assignment=_assignment(),
        )
        evidence = tuple(
            Evidence(
                evidence_id=f"evi-{index}", run_id="r", surface_id="s",
                created_by="recon", evidence_type="observation",
                observation={
                    "type": observation_type, "parameter": name,
                    "source": PATH_ASSIGNMENT_SOURCE,
                },
            )
            for index, (observation_type, name) in enumerate(
                (
                    ("url_or_file_parameter", "page"),
                    (PATH_ASSIGNMENT_OBSERVATION, "file"),
                    (FILE_LIKE_PATH_ASSIGNMENT_OBSERVATION, "file"),
                )
            )
        )
        return surface, evidence

    def _run(self) -> Run:
        return Run(
            run_id="r", target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            policy_profile="safe", request_budget=20,
        )

    def test_rule_router_makes_one_candidate_for_the_pair(self) -> None:
        surface, evidence = self._both_coordinates()
        router = standard_router(vulnerability_types=("Path Traversal",))

        decisions = router.route(self._run(), (surface,), evidence)

        # 규칙 Router는 (Surface, 취약점 유형)당 하나만 만든다. 좌표가 둘이어도
        # 예산은 한 Candidate 몫만 쓴다.
        self.assertEqual(
            [item.candidate.vulnerability_type for item in decisions],
            ["Path Traversal"],
        )

    def test_capability_router_separates_the_two_coordinates(self) -> None:
        surface, evidence = self._both_coordinates()
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="s", vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
                capability_id="path_traversal.http.query",
            ),
            RouteSuggestion(
                surface_id="s", vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
                capability_id=PATH_ASSIGNMENT_CAPABILITY,
            ),
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(str(index) for index in range(10)).__next__,
            advisor=advisor,
            advisor_mode="primary",
        )

        decisions = router.route(self._run(), (surface,), evidence)

        # capability Router는 좌표마다 Candidate를 따로 만든다 — 서로 다른 자리를
        # 탐침하므로 중복이 아니다. 대신 이 Surface의 예산은 두 Candidate 몫이 된다.
        self.assertEqual(
            sorted(item.candidate.routing_capability_id for item in decisions),
            [PATH_ASSIGNMENT_CAPABILITY, "path_traversal.http.query"],
        )
        # 두 Candidate가 같은 자리를 두 번 탐침하지는 않는다.
        self.assertEqual(
            [
                item.candidate.exploration_parameters
                for item in sorted(
                    decisions, key=lambda d: d.candidate.routing_capability_id
                )
            ],
            [(), ("page",)],
        )

    def test_advisor_cannot_invent_a_coordinate_the_surface_lacks(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url=f"{_ORIGIN}/plain", method="GET",
            parameters=("page",),
        )
        advisor = _StubAdvisor(
            RouteSuggestion(
                surface_id="s", vulnerability_type="Path Traversal",
                agent_type="path_traversal_analyzer",
                capability_id=PATH_ASSIGNMENT_CAPABILITY,
            )
        )
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(str(index) for index in range(10)).__next__,
            advisor=advisor,
            advisor_mode="primary",
        )

        decisions = router.route(self._run(), (surface,), ())

        # 관측된 좌표가 없는 표면에 경로 탐침 capability를 붙일 수 없다.
        self.assertNotIn(
            PATH_ASSIGNMENT_CAPABILITY,
            [item.candidate.routing_capability_id for item in decisions],
        )

    def test_analyzer_refuses_a_capability_without_the_stored_coordinate(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url=f"{_ORIGIN}/plain", method="GET",
            parameters=("page",),
        )
        with self.assertRaises(AgentContractError):
            build_path_assignment_requests(surface, purpose="invented")


class PathAssignmentApprovalTests(unittest.TestCase):
    """상태 변경 가능성이 있는 경로 좌표는 승인 없이 실행되지 않는다."""

    def test_state_changing_path_still_requires_approval(self) -> None:
        delete_path = "/delete=web_assets/app.js"
        value_start = len("/delete=")
        target = f"{_ORIGIN}{delete_path}"
        gate = AllowlistPolicyGate()
        run = Run(
            run_id="r", target_url=target,
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            policy_profile="safe", request_budget=10,
        )
        request = ExecutionRequest(
            execution_id="e", run_id="r", task_id="t", tool=PATH_TRAVERSAL_TOOL,
            target_url=target, surface_id="s", purpose="p",
            request_kind=HttpRequestKind.PATH_TRAVERSAL_PROBE,
            path_assignment_name="delete",
            path_assignment_value_start=value_start,
            path_assignment_value_end=value_start + len("web_assets/app.js"),
            path_assignment_value=PATH_TRAVERSAL_PROBE_PATH,
        )

        with self.assertRaises(ApprovalRequired):
            gate.validate_execution(run, request)


class _FilteringRuntime:
    """`..`를 거르지만 값을 그대로 join하는 서버. 절대 경로만 통과한다."""

    def __init__(self) -> None:
        self.requests: list[ExecutionRequest] = []

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self.requests.append(request)
        path = urlsplit(request.resolved_url).path
        value = path[len("/file="):] if path.startswith("/file=") else ""
        if path in ("/", "/index.html"):
            body, status = f'<a href="{_FILE_PATH}">js</a>', 200
        elif ".." in value:
            body, status = "403 blocked", 403
        elif value == ARBITRARY_FILE_READ_PROBE_PATH:
            body, status = "\n".join(ARBITRARY_FILE_READ_PROOF_MARKERS), 200
        else:
            body, status = "console.log('example');", 200
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response", "status": status, "body": body,
                "requested_url": request.resolved_url,
            },
        )


class ArbitraryFileReadPathAssignmentTests(unittest.TestCase):
    """`..`가 막힌 경로 좌표에서 절대 경로 읽기를 증명하는지 확인한다."""

    def _run(self):
        runtime = _FilteringRuntime()
        app = build_local_application(
            {},
            runtime=runtime,
            router=standard_router(
                vulnerability_types=("Path Traversal", "Arbitrary File Read")
            ),
        )
        register_standard_agents(app, recon_max_pages=2)
        run = app.orchestrator.start(
            RunRequest(
                target_url=f"{_ORIGIN}/",
                scope=RunScope(allowed_hosts=frozenset({_HOST})),
                request_budget=40,
            )
        )
        return app, runtime, run

    def test_blocked_traversal_still_yields_an_absolute_path_finding(self) -> None:
        app, runtime, run = self._run()

        self.assertIs(run.phase, RunPhase.DONE)
        statuses = {
            item.vulnerability_type: item.status
            for item in app.stores.candidates.list_by_run(run.run_id)
        }
        # 상대 탈출은 막혔고, 절대 경로는 통과했다. 같은 좌표에서 결과가 갈린다.
        self.assertEqual(statuses["Path Traversal"], CandidateStatus.REJECTED)
        self.assertEqual(
            [item.vulnerability_type for item in app.stores.findings.list_by_run(run.run_id)],
            ["Arbitrary File Read"],
        )

    def test_absolute_probe_replaces_the_path_value_without_a_query(self) -> None:
        _, runtime, _ = self._run()

        probes = [
            item for item in runtime.requests
            if item.request_kind is HttpRequestKind.ARBITRARY_FILE_READ_PROBE
        ]
        # Analysis 1회 + 독립 Validation 1회.
        self.assertEqual(len(probes), 2)
        for probe in probes:
            self.assertEqual(probe.path_assignment_name, "file")
            self.assertEqual(
                probe.resolved_url, f"{_ORIGIN}/file={ARBITRARY_FILE_READ_PROBE_PATH}"
            )
            self.assertNotIn("?", probe.resolved_url)

    def test_each_kind_is_bound_to_its_own_fixed_path(self) -> None:
        base = {
            "path_assignment_name": "file",
            "path_assignment_value_start": _VALUE_START,
            "path_assignment_value_end": _VALUE_END,
        }
        # 올바른 짝은 통과한다.
        for kind, value in (
            (HttpRequestKind.PATH_TRAVERSAL_PROBE, PATH_TRAVERSAL_PROBE_PATH),
            (HttpRequestKind.ARBITRARY_FILE_READ_PROBE, ARBITRARY_FILE_READ_PROBE_PATH),
        ):
            with self.subTest(kind=kind):
                spec = HttpRequestSpec(
                    request_kind=kind, path_assignment_value=value, **base
                )
                self.assertEqual(spec.path_assignment_value, value)
        # 값을 종류와 바꿔 실을 수는 없다. 이 제약이 없으면 이 필드가 허용 목록 중
        # 아무 값이나 경로에 넣는 통로가 된다.
        for kind, value in (
            (HttpRequestKind.PATH_TRAVERSAL_PROBE, ARBITRARY_FILE_READ_PROBE_PATH),
            (HttpRequestKind.ARBITRARY_FILE_READ_PROBE, PATH_TRAVERSAL_PROBE_PATH),
        ):
            with self.subTest(kind=kind, value=value), self.assertRaises(
                DomainInvariantError
            ):
                HttpRequestSpec(
                    request_kind=kind, path_assignment_value=value, **base
                )

    def test_other_probe_kinds_still_cannot_replace_a_path_value(self) -> None:
        for kind in (
            HttpRequestKind.CONTROL,
            HttpRequestKind.PROBE,
            HttpRequestKind.ACCESS_CONTROL_PROBE,
            HttpRequestKind.SSTI_PROBE,
            HttpRequestKind.OPEN_REDIRECT_PROBE,
        ):
            with self.subTest(kind=kind), self.assertRaises(DomainInvariantError):
                HttpRequestSpec(
                    request_kind=kind,
                    path_assignment_name="file",
                    path_assignment_value_start=_VALUE_START,
                    path_assignment_value_end=_VALUE_END,
                    path_assignment_value=ARBITRARY_FILE_READ_PROBE_PATH,
                )

    def test_two_capabilities_probe_the_same_coordinate_with_different_values(self) -> None:
        surface = Surface(
            surface_id="s", run_id="r", url=_TARGET, method="GET",
            path_assignment=_assignment(),
        )
        traversal = build_path_assignment_requests(surface, purpose="p")[1]
        absolute = build_arbitrary_file_read_path_requests(surface, purpose="p")[1]

        assert traversal.http_request is not None and absolute.http_request is not None
        self.assertEqual(
            traversal.http_request.path_assignment_value, PATH_TRAVERSAL_PROBE_PATH
        )
        self.assertEqual(
            absolute.http_request.path_assignment_value, ARBITRARY_FILE_READ_PROBE_PATH
        )
        # 좌표는 같고 값만 다르다. 서로 다른 지문이라 증적이 섞이지 않는다.
        self.assertEqual(
            traversal.http_request.path_assignment_value_start,
            absolute.http_request.path_assignment_value_start,
        )
        self.assertNotEqual(
            traversal.request_fingerprint(_TARGET),
            absolute.request_fingerprint(_TARGET),
        )


class ArbitraryFileReadWiringTests(unittest.TestCase):
    """Arbitrary File Read가 실제로 실행될 수 있도록 배선됐는지 확인한다.

    이 분석기는 구현돼 있었지만 도구가 Runtime·Task·Dispatcher 어디에도 등록되지 않아
    실제 대상에서 한 건도 실행되지 못했다. 각 관문을 개별적으로 고정한다.
    """

    def test_runtime_implements_the_probe_tool(self) -> None:
        from hacklipse.adapters.http_runtime import _HTTP_TOOLS

        self.assertIn(ARBITRARY_FILE_READ_TOOL, _HTTP_TOOLS)

    def test_task_factory_grants_the_probe_tool(self) -> None:
        from hacklipse.application.task_factory import TaskFactory

        run = Run(
            run_id="r", target_url=_TARGET,
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            policy_profile="safe", request_budget=10,
        )
        candidate = Candidate(
            candidate_id="c", run_id="r", surface_id="s",
            vulnerability_type="Arbitrary File Read", hypothesis="h",
            assigned_agent="arbitrary_file_read_analyzer", evidence_ids=(),
        )
        factory = TaskFactory(id_factory=iter(("1", "2")).__next__)
        analysis = factory.analysis(
            run, candidate, target_url=_TARGET, request_budget=5
        )
        validation = factory.validation(
            run, candidate, validation_id="v", agent_type="validation",
            request_budget=5,
        )
        self.assertEqual(analysis.allowed_tools, (ARBITRARY_FILE_READ_TOOL,))
        self.assertEqual(validation.allowed_tools, (ARBITRARY_FILE_READ_TOOL,))

    def test_confirmed_proof_type_is_accepted_by_the_orchestrator(self) -> None:
        from hacklipse.application.orchestrator import _PROOF_TYPE_BY_VULNERABILITY

        self.assertEqual(
            _PROOF_TYPE_BY_VULNERABILITY["Arbitrary File Read"],
            ValidationProofType.ARBITRARY_FILE_READ,
        )

    def test_one_observation_can_reach_both_file_analyzers(self) -> None:
        from hacklipse.adapters.routing import DEFAULT_RULES, RuleBasedVulnerabilityRouter

        # 규칙 표가 관측 타입당 하나만 남기면 나중에 선언된 쪽이 조용히 다른 쪽을
        # 지운다. 파일형 관측은 두 분석기 모두를 정당화한다.
        router = RuleBasedVulnerabilityRouter(
            id_factory=iter(str(index) for index in range(10)).__next__
        )
        surface = Surface(
            surface_id="s", run_id="r", url=f"{_ORIGIN}/view", method="GET",
            parameters=("page",),
        )
        evidence = (
            Evidence(
                evidence_id="evi-1", run_id="r", surface_id="s", created_by="recon",
                evidence_type="observation",
                observation={"type": "url_or_file_parameter", "parameter": "page"},
            ),
        )
        run = Run(
            run_id="r", target_url=f"{_ORIGIN}/view",
            scope=RunScope(allowed_hosts=frozenset({_HOST})),
            policy_profile="safe", request_budget=20,
        )
        decisions = router.route(run, (surface,), evidence)
        self.assertEqual(
            sorted(
                item.candidate.vulnerability_type
                for item in decisions
                if item.candidate.vulnerability_type
                in {"Path Traversal", "Arbitrary File Read"}
            ),
            ["Arbitrary File Read", "Path Traversal"],
        )


if __name__ == "__main__":
    unittest.main()
