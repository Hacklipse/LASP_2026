"""Application 계층에서 발생하는 워크플로·Agent 계약 예외."""


def safe_error_reason(error: BaseException) -> str:
    """저장·표시에 사용할 비민감 오류 식별자를 반환한다.

    외부 Runtime과 Agent의 예외 메시지에는 응답 본문, 토큰, Cookie 같은 값이 섞일 수
    있다. 오류 종류만으로도 재시도·분류가 가능하므로 영속 저장소와 사용자 출력에는
    원문을 복사하지 않는다. 자세한 원인은 예외 체인으로만 보존한다.
    """

    return type(error).__name__


class WorkflowExecutionError(RuntimeError):
    """Run 처리 중 특정 워크플로 단계가 실패했음을 외부에 전달한다."""

    def __init__(self, run_id: str, phase: str, reason: str) -> None:
        # 호출자가 실패한 Run과 단계를 구조적으로 확인할 수 있도록 별도 필드로 보존한다.
        super().__init__(f"run {run_id} failed in phase {phase}: {reason}")
        self.run_id = run_id
        self.phase = phase
        self.reason = reason


class AgentContractError(RuntimeError):
    """Agent, Router, Runtime이 선언된 계약 밖의 데이터를 반환할 때 발생한다."""
