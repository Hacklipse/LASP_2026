"""Application 계층에서 발생하는 워크플로·Agent 계약 예외."""


class WorkflowExecutionError(RuntimeError):
    """Run 처리 중 특정 워크플로 단계가 실패했음을 외부에 전달한다."""

    def __init__(self, run_id: str, phase: str, message: str) -> None:
        # 호출자가 실패한 Run과 단계를 구조적으로 확인할 수 있도록 별도 필드로 보존한다.
        super().__init__(f"run {run_id} failed in phase {phase}: {message}")
        self.run_id = run_id
        self.phase = phase


class AgentContractError(RuntimeError):
    """Agent, Router, Runtime이 선언된 계약 밖의 데이터를 반환할 때 발생한다."""
