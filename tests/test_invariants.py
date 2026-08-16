"""아키텍처의 핵심 안전 규칙과 도메인 불변식을 검증한다."""

from __future__ import annotations

import unittest

from hacklipse.adapters import AllowlistPolicyGate, DisabledExecutionRuntime, MemoryStoreBundle
from hacklipse.application import RunStateMachine
from hacklipse.bootstrap import build_local_application
from hacklipse.domain import (
    Candidate,
    DomainInvariantError,
    Evidence,
    ExecutionRequest,
    Finding,
    Run,
    RunPhase,
    RunRequest,
    RunScope,
    Surface,
    ValidationResult,
    ValidationVerdict,
)
from hacklipse.ports.errors import (
    DuplicateRecord,
    ExternalExecutionDisabled,
    PolicyViolation,
    RecordNotFound,
)


class ArchitectureInvariantTests(unittest.TestCase):
    """구현체가 바뀌어도 유지되어야 하는 규칙을 검사한다."""

    def test_unconfirmed_validation_cannot_create_finding(self) -> None:
        """suspected 판정은 Finding으로 승격할 수 없어야 한다."""

        candidate = Candidate(
            candidate_id="candidate-1",
            run_id="run-1",
            surface_id="surface-1",
            vulnerability_type="XSS",
            hypothesis="reflection",
            assigned_agent="xss_analyzer",
            evidence_ids=("evi-1",),
        )
        validation = ValidationResult(
            validation_id="validation-1",
            run_id="run-1",
            candidate_id="candidate-1",
            verdict=ValidationVerdict.SUSPECTED,
            evidence_ids=("evi-1",),
            reason="not enough evidence",
        )

        with self.assertRaises(DomainInvariantError):
            Finding.from_confirmed(
                finding_id="finding-1", candidate=candidate, validation=validation
            )

    def test_confirmed_finding_requires_supporting_evidence(self) -> None:
        """confirmed라도 근거 Evidence가 없으면 Finding 생성이 실패해야 한다."""

        candidate = Candidate(
            candidate_id="candidate-1",
            run_id="run-1",
            surface_id="surface-1",
            vulnerability_type="XSS",
            hypothesis="reflection",
            assigned_agent="xss_analyzer",
            evidence_ids=("evi-1",),
        )
        validation = ValidationResult(
            validation_id="validation-1",
            run_id="run-1",
            candidate_id="candidate-1",
            verdict=ValidationVerdict.CONFIRMED,
            evidence_ids=(),
            reason="invalid fixture",
        )

        with self.assertRaises(DomainInvariantError):
            Finding.from_confirmed(
                finding_id="finding-1", candidate=candidate, validation=validation
            )

    def test_evidence_is_append_only_and_run_scoped(self) -> None:
        """Evidence 덮어쓰기와 다른 Run을 통한 조회를 모두 차단한다."""

        stores = MemoryStoreBundle()
        evidence = Evidence(
            evidence_id="evi-1",
            run_id="run-1",
            surface_id="surface-1",
            created_by="fixture",
            evidence_type="observation",
        )
        stores.evidence.append(evidence)

        with self.assertRaises(DuplicateRecord):
            stores.evidence.append(evidence)
        with self.assertRaises(RecordNotFound):
            stores.evidence.get("run-2", "evi-1")

    def test_surface_is_run_scoped(self) -> None:
        """Run.surface_ids로는 조회되고 다른 Run 범위는 넘어갈 수 없어야 한다."""

        stores = MemoryStoreBundle()
        surface = Surface(
            surface_id="surface-1",
            run_id="run-1",
            url="https://local.test/login",
            method="GET",
        )
        stores.surfaces.add(surface)
        run = Run(
            run_id="run-1",
            target_url="https://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=1,
            surface_ids=("surface-1",),
        )

        # Recon이 반환한 surface_ids가 실제 구조체로 되돌아오는 경로를 고정한다.
        for surface_id in run.surface_ids:
            self.assertEqual(stores.surfaces.get(run.run_id, surface_id), surface)
        with self.assertRaises(RecordNotFound):
            stores.surfaces.get("run-2", "surface-1")

    def test_policy_rejects_target_outside_allowlist_before_run_creation(self) -> None:
        """허용되지 않은 호스트는 Run이나 Task 생성 전에 거부한다."""

        app = build_local_application({})
        request = RunRequest(
            target_url="https://outside.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
        )

        with self.assertRaises(PolicyViolation):
            app.orchestrator.start(request)
        with self.assertRaises(RecordNotFound):
            app.stores.runs.get("missing")

    def test_safe_policy_rejects_state_changing_execution(self) -> None:
        """safe 정책에서 상태 변경 가능성이 있는 POST 실행을 막는다."""

        scope = RunScope(allowed_hosts=frozenset({"local.test"}))
        run = Run(
            run_id="run-1",
            target_url="https://local.test/",
            scope=scope,
            policy_profile="safe",
            request_budget=1,
        )
        request = ExecutionRequest(
            execution_id="exec-1",
            run_id="run-1",
            task_id="task-1",
            tool="http_replay",
            target_url="https://local.test/",
            surface_id=None,
            purpose="fixture",
            method="POST",
        )

        with self.assertRaises(PolicyViolation):
            AllowlistPolicyGate().validate_execution(run, request)

    def test_default_runtime_is_explicitly_disabled(self) -> None:
        """Runtime 미설정 상태에서는 외부 도구가 절대 실행되지 않아야 한다."""

        request = ExecutionRequest(
            execution_id="exec-1",
            run_id="run-1",
            task_id="task-1",
            tool="browser_render",
            target_url="https://local.test/",
            surface_id=None,
            purpose="fixture",
        )
        with self.assertRaises(ExternalExecutionDisabled):
            DisabledExecutionRuntime().execute(request)

    def test_state_machine_owns_transition_rules(self) -> None:
        """INIT에서 DONE으로 건너뛰는 잘못된 상태 전이를 차단한다."""

        run = Run(
            run_id="run-1",
            target_url="https://local.test/",
            scope=RunScope(allowed_hosts=frozenset({"local.test"})),
            policy_profile="safe",
            request_budget=1,
        )
        with self.assertRaises(DomainInvariantError):
            RunStateMachine().transition(run, RunPhase.DONE)


if __name__ == "__main__":
    unittest.main()
