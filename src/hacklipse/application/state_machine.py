"""Run 상태 전이 규칙을 워크플로 실행 코드와 분리한다."""

from __future__ import annotations

from hacklipse.domain import DomainInvariantError, Run, RunPhase


class RunStateMachine:
    """상태 전이 규칙만 담당하며 Agent 호출이나 저장은 수행하지 않는다."""

    # 정상 단계는 앞 방향으로만 진행하며, 모든 활성 단계에서 FAILED로 종료할 수 있다.
    _allowed: dict[RunPhase, frozenset[RunPhase]] = {
        RunPhase.INIT: frozenset({RunPhase.RECON, RunPhase.FAILED}),
        RunPhase.RECON: frozenset({RunPhase.ROUTE, RunPhase.FAILED}),
        RunPhase.ROUTE: frozenset({RunPhase.ANALYZE, RunPhase.REPORT, RunPhase.FAILED}),
        RunPhase.ANALYZE: frozenset({RunPhase.VALIDATE, RunPhase.FAILED}),
        RunPhase.VALIDATE: frozenset({RunPhase.REPORT, RunPhase.FAILED}),
        RunPhase.REPORT: frozenset({RunPhase.DONE, RunPhase.FAILED}),
        RunPhase.DONE: frozenset(),
        RunPhase.FAILED: frozenset(),
    }

    def transition(self, run: Run, target: RunPhase) -> Run:
        """허용된 전이인지 검사한 뒤 새로운 Run 상태를 반환한다."""

        if target not in self._allowed[run.phase]:
            raise DomainInvariantError(
                f"invalid run transition: {run.phase.value} -> {target.value}"
            )
        return run.with_updates(phase=target, last_error=None)

    def fail(self, run: Run, error: Exception) -> Run:
        """활성 Run을 FAILED로 전환하고 원인을 보존한다."""

        # 이미 종료된 Run은 다시 상태를 바꾸지 않는다.
        if run.phase in {RunPhase.DONE, RunPhase.FAILED}:
            return run
        failed = self.transition(run, RunPhase.FAILED)
        return failed.with_updates(last_error=str(error))
