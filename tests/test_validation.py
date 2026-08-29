"""ValidationAgent가 Evidence만으로 재현을 판정하고 증적 요청 루프를 도는지 검증."""

from __future__ import annotations

import unittest

from hacklipse.adapters.memory import InMemoryCandidateStore, InMemoryEvidenceStore
from hacklipse.adapters.recon import ReconAgent
from hacklipse.adapters.routing import RuleBasedVulnerabilityRouter
from hacklipse.adapters.validation import ValidationAgent
from hacklipse.application.errors import AgentContractError
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Candidate,
    Evidence,
    ExecutionRequest,
    ExecutionResult,
    RunPhase,
    RunRequest,
    RunScope,
    TaskEnvelope,
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


def _make_agent() -> tuple[ValidationAgent, InMemoryCandidateStore, InMemoryEvidenceStore]:
    candidates = InMemoryCandidateStore()
    evidence = InMemoryEvidenceStore()
    return (
        ValidationAgent(candidate_store=candidates, evidence_store=evidence),
        candidates,
        evidence,
    )


class ValidationAgentTests(unittest.TestCase):
    def test_requests_independent_reproduction_when_none_collected_yet(self) -> None:
        agent, candidates, evidence = _make_agent()
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
        agent, candidates, evidence = _make_agent()
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
        agent, candidates, evidence = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-repro")))
        evidence.append(_seed_evidence())
        evidence.append(_reproduction_evidence("evi-repro", status=404))

        result = agent.handle(_task(("evi-seed", "evi-repro")))

        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertEqual(result.validation.verdict, ValidationVerdict.SUSPECTED)

    def test_network_error_marks_validation_blocked(self) -> None:
        agent, candidates, evidence = _make_agent()
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
        agent, candidates, evidence = _make_agent()
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
        agent, candidates, evidence = _make_agent()
        candidates.add(_make_candidate(vulnerability_type="Unknown"))
        evidence.append(_seed_evidence())

        with self.assertRaises(AgentContractError):
            agent.handle(_task(("evi-seed",)))


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
        # 취약점별 proof가 없는 Path Traversal baseline은 Finding을 만들지 않는다.
        app = build_local_application(
            agents={},
            runtime=_RouteThenReproduceRuntime(),
            router=RuleBasedVulnerabilityRouter(surface_rules=()),
        )
        app.dispatcher.register(
            "recon",
            ReconAgent(
                collector=app.collector,
                evidence_store=app.stores.evidence,
                surface_store=app.stores.surfaces,
            ),
        )
        app.dispatcher.register("path_traversal_analyzer", _PassthroughAnalysisAgent())
        app.dispatcher.register(
            "validation",
            ValidationAgent(
                candidate_store=app.stores.candidates, evidence_store=app.stores.evidence
            ),
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
        self.assertEqual(len(validation_evidence), 1)
        self.assertIsNotNone(validation_evidence[0].source_task_id)
        tasks = app.stores.tasks.list_by_run(run.run_id)
        self.assertEqual(
            [item.envelope.agent_type for item in tasks],
            [
                "recon",
                "path_traversal_analyzer",
                "validation",
                "evidence_collector",
                "validation",
                "report",
            ],
        )
        reports = app.stores.reports.list_by_run(run.run_id)
        self.assertEqual(len(reports), 1)


if __name__ == "__main__":
    unittest.main()
