"""ValidationAgent가 Evidence만으로 재현을 판정하고 증적 요청 루프를 도는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters.memory import (
    InMemoryCandidateStore,
    InMemoryEvidenceStore,
    InMemorySurfaceStore,
)
from hacklipse.adapters.recon import ReconAgent
from hacklipse.adapters.routing import RoutingRule, RuleBasedVulnerabilityRouter
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.application.errors import AgentContractError
from hacklipse.application import OrchestratorConfig
from hacklipse.bootstrap import (
    build_local_application,
    register_standard_agents,
    standard_router,
)
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    HttpRequestKind,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    TaskEnvelope,
    ValidationProofType,
    ValidationVerdict,
)

_RUN_ID = "run-1"
_SURFACE_ID = "surface-1"
_CANDIDATE_ID = "candidate-1"
_VALIDATION_ID = "validation-1"


def _make_candidate(
    vulnerability_type: str = "Path Traversal", *, evidence_ids: tuple[str, ...] = ("evi-seed",)
) -> Candidate:
    return Candidate(
        candidate_id=_CANDIDATE_ID,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        vulnerability_type=vulnerability_type,
        hypothesis=f"{vulnerability_type} candidate from recon",
        assigned_agent="path_traversal_analyzer",
        evidence_ids=evidence_ids,
    )


def _seed_evidence(evidence_id: str = "evi-seed") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="recon",
        evidence_type="observation",
        observation={"type": "url_or_file_parameter", "parameter": "page"},
    )


def _reproduction_evidence(
    evidence_id: str,
    *,
    status: int | None = 200,
    validation_id: str | None = _VALIDATION_ID,
    observation_type: str = "http_response",
) -> Evidence:
    observation: dict[str, object] = {"type": observation_type}
    if status is not None:
        observation["status"] = status
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="execution_runtime:http_get",
        evidence_type=observation_type,
        source_task_id="task-collect",
        validation_id=validation_id,
        observation=observation,
    )


def _sql_error_observation(evidence_id: str = "evi-sql-signal") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="heuristic_sqli_analyzer",
        evidence_type="observation",
        observation={
            "type": "sql_error",
            "parameter": "q",
            "signal": "error_message",
            "engine": "mysql",
        },
    )


def _reflection_observation(evidence_id: str = "evi-reflection") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="heuristic_xss_analyzer",
        evidence_type="observation",
        observation={"type": "reflection", "parameter": "q"},
    )


def _browser_collected_for_request(
    evidence_id: str,
    request,
    *,
    executed: bool,
    marker: str | None,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="execution_runtime:browser_xss",
        evidence_type="browser_execution",
        source_task_id=f"task-{evidence_id}",
        validation_id=_VALIDATION_ID,
        observation={
            "type": "browser_execution",
            "status": 200,
            "method": "GET",
            "request_kind": request.http_request.request_kind.value,
            "request_fingerprint": request.request_fingerprint(
                "http://localhost/search"
            ),
            "script_executed": executed,
            "execution_marker": marker,
        },
    )


def _collected_for_request(
    evidence_id: str,
    request,
    *,
    body: str,
    observation_type: str = "http_response",
    status: int | None = 200,
) -> Evidence:
    observation: dict[str, object] = {
        "type": observation_type,
        "method": "GET",
        "request_kind": request.http_request.request_kind.value,
        "request_fingerprint": request.request_fingerprint("http://localhost/search"),
        "body": body,
    }
    if status is not None:
        observation["status"] = status
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="execution_runtime:http_get",
        evidence_type=observation_type,
        source_task_id=f"task-{evidence_id}",
        validation_id=_VALIDATION_ID,
        observation=observation,
    )


def _task(evidence_ids: tuple[str, ...], *, candidate_id: str | None = _CANDIDATE_ID) -> TaskEnvelope:
    return TaskEnvelope(
        task_id="task-validate",
        run_id=_RUN_ID,
        agent_type="validation",
        surface_id=_SURFACE_ID,
        candidate_id=candidate_id,
        evidence_ids=evidence_ids,
        allowed_tools=("http_get",),
        request_budget=5,
        validation_id=_VALIDATION_ID,
    )


def _make_agent() -> tuple[
    ValidationAgent,
    InMemoryCandidateStore,
    InMemoryEvidenceStore,
    InMemorySurfaceStore,
]:
    candidates = InMemoryCandidateStore()
    evidence = InMemoryEvidenceStore()
    surfaces = InMemorySurfaceStore()
    surfaces.add(
        Surface(
            surface_id=_SURFACE_ID,
            run_id=_RUN_ID,
            url="http://localhost/search",
            method="GET",
            parameters=("q", "Submit"),
        )
    )
    return (
        ValidationAgent(
            candidate_store=candidates,
            evidence_store=evidence,
            surface_store=surfaces,
        ),
        candidates,
        evidence,
        surfaces,
    )


class ValidationAgentTests(unittest.TestCase):
    def test_xss_browser_execution_creates_structured_proof(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(
            _make_candidate("XSS", evidence_ids=("evi-reflection",))
        )
        evidence.append(_reflection_observation())
        task = TaskEnvelope(
            task_id="task-validate",
            run_id=_RUN_ID,
            agent_type="validation",
            surface_id=_SURFACE_ID,
            candidate_id=_CANDIDATE_ID,
            evidence_ids=("evi-reflection",),
            allowed_tools=("http_get", "browser_xss"),
            request_budget=5,
            validation_id=_VALIDATION_ID,
        )

        first = agent.handle(task)

        self.assertIs(first.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(first.evidence_requests), 2)
        control_request, probe_request = first.evidence_requests
        self.assertEqual(control_request.suggested_tool, "browser_xss")
        self.assertEqual(probe_request.suggested_tool, "browser_xss")
        assert probe_request.http_request is not None
        marker = dict(probe_request.http_request.query_parameters)["q"]
        control = _browser_collected_for_request(
            "evi-browser-control",
            control_request,
            executed=False,
            marker=None,
        )
        probe = _browser_collected_for_request(
            "evi-browser-probe",
            probe_request,
            executed=True,
            marker=marker,
        )
        evidence.append(control)
        evidence.append(probe)
        second = agent.handle(
            TaskEnvelope(
                task_id="task-validate-2",
                run_id=_RUN_ID,
                agent_type="validation",
                surface_id=_SURFACE_ID,
                candidate_id=_CANDIDATE_ID,
                evidence_ids=(
                    "evi-reflection",
                    "evi-browser-control",
                    "evi-browser-probe",
                ),
                allowed_tools=("http_get", "browser_xss"),
                request_budget=3,
                validation_id=_VALIDATION_ID,
            )
        )

        assert second.validation is not None
        self.assertIs(second.validation.verdict, ValidationVerdict.CONFIRMED)
        assert second.validation.proof is not None
        self.assertIs(
            second.validation.proof.proof_type,
            ValidationProofType.XSS_EXECUTION,
        )
        self.assertEqual(
            second.validation.proof.evidence_ids,
            ("evi-browser-control", "evi-browser-probe"),
        )

    def test_xss_reflection_without_browser_execution_is_rejected(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate("XSS", evidence_ids=("evi-reflection",)))
        evidence.append(_reflection_observation())
        task = TaskEnvelope(
            task_id="task-validate",
            run_id=_RUN_ID,
            agent_type="validation",
            surface_id=_SURFACE_ID,
            candidate_id=_CANDIDATE_ID,
            evidence_ids=("evi-reflection",),
            allowed_tools=("http_get", "browser_xss"),
            request_budget=5,
            validation_id=_VALIDATION_ID,
        )
        first = agent.handle(task)
        control_request, probe_request = first.evidence_requests
        evidence.append(
            _browser_collected_for_request(
                "evi-browser-control", control_request, executed=False, marker=None
            )
        )
        evidence.append(
            _browser_collected_for_request(
                "evi-browser-probe", probe_request, executed=False, marker=None
            )
        )

        result = agent.handle(
            TaskEnvelope(
                task_id="task-validate-2",
                run_id=_RUN_ID,
                agent_type="validation",
                surface_id=_SURFACE_ID,
                candidate_id=_CANDIDATE_ID,
                evidence_ids=(
                    "evi-reflection",
                    "evi-browser-control",
                    "evi-browser-probe",
                ),
                allowed_tools=("http_get", "browser_xss"),
                request_budget=3,
                validation_id=_VALIDATION_ID,
            )
        )

        assert result.validation is not None
        self.assertIs(result.validation.verdict, ValidationVerdict.REJECTED)
        self.assertIsNone(result.validation.proof)

    def test_requests_independent_reproduction_when_none_collected_yet(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-analysis-http")))
        evidence.append(_seed_evidence())
        # Analysis가 만든 일반 HTTP 응답은 Validation 재현 증적으로 인정하면 안 된다.
        evidence.append(
            _reproduction_evidence(
                "evi-analysis-http", status=200, validation_id=None
            )
        )

        result = agent.handle(_task(("evi-seed", "evi-analysis-http")))

        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertIsNone(result.validation)
        self.assertEqual(len(result.evidence_requests), 1)
        request = result.evidence_requests[0]
        self.assertEqual(request.surface_id, _SURFACE_ID)
        self.assertEqual(request.suggested_tool, "http_get")

    def test_successful_generic_reproduction_remains_suspected(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-repro")))
        evidence.append(_seed_evidence())
        evidence.append(_reproduction_evidence("evi-repro", status=200))

        result = agent.handle(_task(("evi-seed", "evi-repro")))

        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)
        self.assertEqual(result.validation.reproduction_count, 1)
        self.assertEqual(result.validation.evidence_ids, ("evi-repro",))
        self.assertIsNone(result.validation.proof)

    def test_http_status_alone_never_confirms_or_rejects(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-repro")))
        evidence.append(_seed_evidence())
        evidence.append(_reproduction_evidence("evi-repro", status=404))

        result = agent.handle(_task(("evi-seed", "evi-repro")))

        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)

    def test_network_error_marks_validation_blocked(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-error")))
        evidence.append(_seed_evidence())
        evidence.append(
            _reproduction_evidence(
                "evi-error", status=None, observation_type="http_error"
            )
        )

        result = agent.handle(_task(("evi-seed", "evi-error")))

        assert result.validation is not None
        self.assertEqual(result.validation.verdict, ValidationVerdict.BLOCKED)

    def test_evidence_from_another_validation_session_is_ignored(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-old")))
        evidence.append(_seed_evidence())
        evidence.append(
            _reproduction_evidence(
                "evi-old", status=200, validation_id="validation-old"
            )
        )

        result = agent.handle(_task(("evi-seed", "evi-old")))

        self.assertIs(result.status, AgentResultStatus.NEEDS_EVIDENCE)

    def test_missing_candidate_id_is_a_contract_error(self) -> None:
        agent, *_ = _make_agent()
        with self.assertRaises(AgentContractError):
            agent.handle(_task((), candidate_id=None))

    def test_unknown_vulnerability_type_is_a_contract_error(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(vulnerability_type="Unknown"))
        evidence.append(_seed_evidence())

        with self.assertRaises(AgentContractError):
            agent.handle(_task(("evi-seed",)))

    def test_sqli_requests_independent_control_and_quote_probe(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(
            _make_candidate(
                vulnerability_type="SQLi", evidence_ids=("evi-sql-signal",)
            )
        )
        evidence.append(_sql_error_observation())

        result = agent.handle(_task(("evi-sql-signal",)))

        self.assertIs(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertEqual(len(result.evidence_requests), 2)
        control, probe = result.evidence_requests
        assert control.http_request is not None
        assert probe.http_request is not None
        self.assertIs(control.http_request.request_kind, HttpRequestKind.CONTROL)
        self.assertIs(probe.http_request.request_kind, HttpRequestKind.PROBE)
        control_value = dict(control.http_request.query_parameters)["q"]
        probe_value = dict(probe.http_request.query_parameters)["q"]
        self.assertEqual(probe_value, control_value + "'")
        self.assertEqual(
            dict(probe.http_request.query_parameters)["Submit"], control_value
        )

    def test_sqli_independent_differential_creates_structured_proof(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(
            _make_candidate(
                vulnerability_type="SQLi", evidence_ids=("evi-sql-signal",)
            )
        )
        evidence.append(_sql_error_observation())
        first = agent.handle(_task(("evi-sql-signal",)))
        control_request, probe_request = first.evidence_requests
        control = _collected_for_request(
            "evi-validation-control", control_request, body="normal result"
        )
        probe = _collected_for_request(
            "evi-validation-probe",
            probe_request,
            body="You have an error in your SQL syntax",
        )
        evidence.append(control)
        evidence.append(probe)

        result = agent.handle(
            _task(
                (
                    "evi-sql-signal",
                    "evi-validation-control",
                    "evi-validation-probe",
                )
            )
        )

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertIs(result.validation.verdict, ValidationVerdict.CONFIRMED)
        self.assertEqual(result.validation.reproduction_count, 2)
        assert result.validation.proof is not None
        self.assertIs(
            result.validation.proof.proof_type, ValidationProofType.SQLI_EFFECT
        )
        self.assertEqual(
            result.validation.proof.evidence_ids,
            ("evi-validation-control", "evi-validation-probe"),
        )

    def test_sqli_identical_independent_responses_are_rejected(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(
            _make_candidate(
                vulnerability_type="SQLi", evidence_ids=("evi-sql-signal",)
            )
        )
        evidence.append(_sql_error_observation())
        first = agent.handle(_task(("evi-sql-signal",)))
        control_request, probe_request = first.evidence_requests
        control = _collected_for_request(
            "evi-validation-control", control_request, body="same response"
        )
        probe = _collected_for_request(
            "evi-validation-probe", probe_request, body="same response"
        )
        evidence.append(control)
        evidence.append(probe)

        result = agent.handle(
            _task(
                (
                    "evi-sql-signal",
                    "evi-validation-control",
                    "evi-validation-probe",
                )
            )
        )

        assert result.validation is not None
        self.assertIs(result.validation.verdict, ValidationVerdict.REJECTED)
        self.assertIsNone(result.validation.proof)

    def test_sqli_without_analysis_signal_is_rejected_without_requests(self) -> None:
        agent, candidates, evidence, _ = _make_agent()
        candidates.add(_make_candidate(vulnerability_type="SQLi", evidence_ids=()))

        result = agent.handle(_task(()))

        self.assertIs(result.status, AgentResultStatus.COMPLETED)
        self.assertEqual(result.evidence_requests, ())
        assert result.validation is not None
        self.assertIs(result.validation.verdict, ValidationVerdict.REJECTED)
        self.assertIsNone(result.validation.proof)


_SAMPLE_TARGET = "http://localhost/vulnerabilities/fi/?page=include.php"


class _RouteThenReproduceRuntime:
    """Recon의 최초 수집과 Validation의 독립 재현 요청을 구분해 응답하는 Runtime 대역."""

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if "initial recon fetch" in request.purpose:
            return ExecutionResult(
                execution_id=request.execution_id,
                evidence_type="http_response",
                observation={"type": "http_response", "status": 200, "body": None},
            )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={"type": "http_response", "status": 200},
        )


class _PassthroughAnalysisAgent:
    """Phase 6 이전까지 Router의 판단을 그대로 통과시키는 최소 Analysis 대역."""

    def handle(self, task: TaskEnvelope) -> AgentResult:
        return AgentResult(
            task_id=task.task_id,
            status=AgentResultStatus.COMPLETED,
            candidate_ids=(task.candidate_id,) if task.candidate_id else (),
        )


class ValidationDrivesEvidenceLoopTests(unittest.TestCase):
    """중앙 수집 Evidence가 현재 Validation 세션 provenance를 갖는지 검증한다."""

    def test_generic_reproduction_stays_suspected_and_reaches_report(self) -> None:
        # 취약점별 proof가 아직 없는 Access Control은 Finding을 만들지 않는다.
        app = build_local_application(
            agents={},
            runtime=_RouteThenReproduceRuntime(),
            router=RuleBasedVulnerabilityRouter(
                rules=(
                    RoutingRule(
                        "url_or_file_parameter",
                        "Access Control",
                        "access_control_analyzer",
                    ),
                ),
                surface_rules=(),
            ),
        )
        app.dispatcher.register(
            "recon",
            ReconAgent(
                collector=app.collector,
                evidence_store=app.stores.evidence,
                surface_store=app.stores.surfaces,
            ),
            allowed_tools=("http_get",),
        )
        # Access Control Task는 전용 도구로만 나간다. 대역도 같은 권한을 받아야
        # Dispatcher를 통과한다.
        app.dispatcher.register(
            "access_control_analyzer",
            _PassthroughAnalysisAgent(),
            allowed_tools=("access_control_probe",),
        )
        app.dispatcher.register(
            "validation",
            ValidationAgent(
                candidate_store=app.stores.candidates,
                evidence_store=app.stores.evidence,
                surface_store=app.stores.surfaces,
            ),
            allowed_tools=("http_get", "access_control_probe"),
        )

        run = app.orchestrator.start(
            RunRequest(
                target_url=_SAMPLE_TARGET,
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(findings, ())
        candidate = app.stores.candidates.list_by_run(run.run_id)[0]
        self.assertEqual(candidate.status, "suspected")
        validation_evidence = [
            item
            for item in app.stores.evidence.list_by_run(run.run_id)
            if item.validation_id is not None
        ]
        # Access Control은 무엇을 재현할지 알려주는 Analysis Observation이 없으면
        # 요청을 쓰지 않는다. 무엇과 비교할지 모르는 채로 한 번 더 받아오는 것은
        # 예산만 쓰고 판정에 기여하지 못한다.
        self.assertEqual(validation_evidence, [])
        tasks = app.stores.tasks.list_by_run(run.run_id)
        self.assertEqual(
            [item.envelope.agent_type for item in tasks],
            ["recon", "access_control_analyzer", "validation", "report"],
        )
        reports = app.stores.reports.list_by_run(run.run_id)
        self.assertEqual(len(reports), 1)


class _SqliDifferentialRuntime:
    """SQLi 페이지의 id 작은따옴표 probe에만 DB 오류를 반환하는 Runtime 대역."""

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        parameters = dict(request.query_parameters)
        body = "normal database result"
        if "Submit" in parameters and parameters.get("id", "").endswith("'"):
            body = "You have an error in your SQL syntax"
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": body,
                "method": request.method,
                "request_kind": request.request_kind.value,
                "requested_url": request.resolved_url,
            },
        )


class _XssBrowserExecutionRuntime:
    """HTTP 반사와 별개의 브라우저 실행 결과를 돌려주는 Runtime 대역."""

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        parameters = dict(request.query_parameters)
        if request.tool == "browser_xss":
            marker = next(
                (
                    value
                    for value in parameters.values()
                    if value.startswith("hacklipsexecution")
                ),
                None,
            )
            return ExecutionResult(
                execution_id=request.execution_id,
                evidence_type="browser_execution",
                observation={
                    "type": "browser_execution",
                    "status": 200,
                    "method": "GET",
                    "request_kind": request.request_kind.value,
                    "requested_url": request.resolved_url,
                    "script_executed": marker is not None,
                    "execution_marker": marker,
                },
            )

        body = " ".join(parameters.values()) or (
            '<form method="GET"><input name="name"></form>'
        )
        return ExecutionResult(
            execution_id=request.execution_id,
            evidence_type="http_response",
            observation={
                "type": "http_response",
                "status": 200,
                "body": body,
                "method": request.method,
                "request_kind": request.request_kind.value,
                "requested_url": request.resolved_url,
            },
        )


class SqliFindingEndToEndTests(unittest.TestCase):
    def test_independent_sqli_reproduction_promotes_one_finding(self) -> None:
        app = build_local_application(
            {}, runtime=_SqliDifferentialRuntime(), router=standard_router()
        )
        register_standard_agents(app, recon_max_pages=1)

        run = app.orchestrator.start(
            RunRequest(
                target_url=(
                    "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit"
                ),
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                request_budget=30,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, "SQLi")
        self.assertEqual(len(finding.evidence_ids), 2)
        proof_evidence = app.stores.evidence.get_many(
            run.run_id, finding.evidence_ids
        )
        self.assertTrue(
            all(item.validation_id == finding.validation_id for item in proof_evidence)
        )
        self.assertTrue(
            all(
                item.created_by.startswith("execution_runtime:")
                for item in proof_evidence
            )
        )


class XssFindingEndToEndTests(unittest.TestCase):
    def test_independent_browser_execution_promotes_one_finding(self) -> None:
        app = build_local_application(
            {},
            runtime=_XssBrowserExecutionRuntime(),
            router=standard_router(vulnerability_types=("XSS",)),
            config=OrchestratorConfig(browser_xss_validation=True),
        )
        register_standard_agents(app, recon_max_pages=1)

        run = app.orchestrator.start(
            RunRequest(
                target_url="http://localhost/vulnerabilities/xss_r/?name=seed",
                scope=RunScope(allowed_hosts=frozenset({"localhost"})),
                request_budget=30,
            )
        )

        self.assertIs(run.phase, RunPhase.DONE)
        findings = app.stores.findings.list_by_run(run.run_id)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.vulnerability_type, "XSS")
        proof_evidence = app.stores.evidence.get_many(
            run.run_id, finding.evidence_ids
        )
        self.assertEqual(
            [item.evidence_type for item in proof_evidence],
            ["browser_execution", "browser_execution"],
        )
        self.assertTrue(
            all(item.validation_id == finding.validation_id for item in proof_evidence)
        )


if __name__ == "__main__":
    unittest.main()
