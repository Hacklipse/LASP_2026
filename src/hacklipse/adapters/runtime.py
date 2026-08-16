"""외부 실행 Port의 안전한 기본 구현."""

from hacklipse.domain import ExecutionRequest, ExecutionResult
from hacklipse.ports.errors import ExternalExecutionDisabled


class DisabledExecutionRuntime:
    """Runtime이 명시적으로 주입되기 전에는 모든 외부 실행을 거부한다."""

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """어떠한 네트워크·도구 실행도 하지 않고 명시적 예외를 발생시킨다."""

        raise ExternalExecutionDisabled(
            f"external execution is disabled (tool={request.tool}, run={request.run_id})"
        )
