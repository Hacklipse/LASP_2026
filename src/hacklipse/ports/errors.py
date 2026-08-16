"""Port와 Adapter 사이에서 공통으로 사용하는 계약 예외."""


class ArchitectureError(RuntimeError):
    """컴포넌트 계약 실패를 나타내는 공통 예외."""


class RecordNotFound(ArchitectureError):
    """요청한 범위에 참조 대상 레코드가 없을 때 발생한다."""


class DuplicateRecord(ArchitectureError):
    """생성·추가 작업이 이미 존재하는 식별자를 재사용할 때 발생한다."""


class AgentUnavailable(ArchitectureError):
    """요청된 Agent 유형에 등록된 Worker가 없을 때 발생한다."""


class PolicyViolation(ArchitectureError):
    """Run 또는 실행 요청이 승인된 정책·Scope를 벗어날 때 발생한다."""


class BudgetExceeded(ArchitectureError):
    """Run이 남은 실행 예산보다 많은 단위를 소비하려 할 때 발생한다."""


class ExternalExecutionDisabled(ArchitectureError):
    """안전한 기본 Runtime이 외부 실행을 거부했음을 나타낸다."""
