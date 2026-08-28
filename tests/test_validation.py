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


def _reproduction_evidence(evidence_id: str, *, status: int) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        surface_id=_SURFACE_ID,
        created_by="http_execution_runtime:http_get",
        evidence_type="http_response",
        observation={"type": "http_response", "status": status},
    )


def _task(evidence_ids: tuple[str, ...], *, candidate_id: str | None = _CANDIDATE_ID) -> TaskEnvelope:
    return TaskEnvelope(
        task_id="task-validate",
        run_id=_RUN_ID,
        agent_type="validation",
        surface_id=_SURFACE_ID,
        candidate_id=candidate_id,
        evidence_ids=evidence_ids,
        request_budget=5,
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
        candidates.add(_make_candidate())
        evidence.append(_seed_evidence())

        result = agent.handle(_task(("evi-seed",)))

        self.assertEqual(result.status, AgentResultStatus.NEEDS_EVIDENCE)
        self.assertIsNone(result.validation)
        self.assertEqual(len(result.evidence_requests), 1)
        request = result.evidence_requests[0]
        self.assertEqual(request.surface_id, _SURFACE_ID)
        self.assertEqual(request.suggested_tool, "http_get")

    def test_confirms_when_independent_reproduction_succeeds(self) -> None:
        agent, candidates, evidence = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-repro")))
        evidence.append(_seed_evidence())
        evidence.append(_reproduction_evidence("evi-repro", status=200))

        result = agent.handle(_task(("evi-seed", "evi-repro")))

        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertEqual(result.validation.verdict, ValidationVerdict.CONFIRMED)
        self.assertEqual(result.validation.reproduction_count, 1)
        self.assertEqual(result.validation.evidence_ids, ("evi-repro",))

    def test_rejects_when_independent_reproduction_fails(self) -> None:
        agent, candidates, evidence = _make_agent()
        candidates.add(_make_candidate(evidence_ids=("evi-seed", "evi-repro")))
        evidence.append(_seed_evidence())
        evidence.append(_reproduction_evidence("evi-repro", status=404))

        result = agent.handle(_task(("evi-seed", "evi-repro")))

        self.assertEqual(result.status, AgentResultStatus.COMPLETED)
        assert result.validation is not None
        self.assertEqual(result.validation.verdict, ValidationVerdict.REJECTED)

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
    """완료 기준: evidence_requests 루프가 실제 ValidationAgent로 Finding까지 완주한다."""

    def test_independent_reproduction_confirms_and_reaches_report(self) -> None:
        # 이 테스트는 Path Traversal Validation 루프 하나만 검증한다.
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
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "Path Traversal")
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
        self.assertIn(findings[0].finding_id, reports[0].content)


if __name__ == "__main__":
    unittest.main()
