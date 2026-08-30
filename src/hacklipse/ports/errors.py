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


class CredentialNotFound(ArchitectureError):
    """credential_ref를 안전한 저장소에서 해석할 수 없다."""


class AuthenticationFailed(ArchitectureError):
    """중앙 인증 Worker가 세션을 확립하지 못했다."""


class ApprovalRequired(PolicyViolation):
    """상태 변경 가능 요청에 명시적 승인 참조가 없거나 승인되지 않았다."""


class AgentToolNotAllowed(PolicyViolation):
    """Task가 Agent 등록 시 고정된 도구 권한을 벗어났다."""


class TaskTimeout(ArchitectureError):
    """Task가 Orchestrator가 부여한 실행시간 제한을 초과했다."""


class LlmError(ArchitectureError):
    """LLM 호출 경계에서 발생하는 오류의 공통 상위 타입."""


class LlmTimeout(LlmError):
    """요청이 계약된 제한시간 안에 끝나지 않았다."""


class LlmTransportError(LlmError):
    """전송 실패 또는 성공이 아닌 응답 상태를 받았다."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class LlmRateLimited(LlmTransportError):
    """호출량 제한에 걸렸다. retry_after_seconds가 있으면 그만큼 기다린 뒤 재시도한다."""

    def __init__(
        self, message: str, *, status_code: int | None = None, retry_after_seconds: float | None = None
    ) -> None:
        super().__init__(message, status_code=status_code)
        self.retry_after_seconds = retry_after_seconds


class LlmResponseFormatError(LlmError):
    """응답이 약속된 구조화 형식이 아니다(JSON 파싱 실패, 객체 아님, 본문 없음)."""


class LlmRefused(LlmError):
    """모델이 안전 정책상 응답을 거부했다.

    형식 오류와 구분한다: 거부는 본문이 비어 파싱이 실패하지만 원인이 전혀 다르고,
    프롬프트를 고쳐 재시도할 대상인지 판단하려면 이 사실이 그대로 올라와야 한다.
    """

    def __init__(self, message: str, *, category: str | None = None) -> None:
        super().__init__(message)
        self.category = category


class LlmCredentialsMissing(LlmError):
    """LLM 자격증명이 주입되지 않았다.

    조용히 LLM 없이 진행하지 않고 명시적으로 실패한다. "키가 없어서 휴리스틱으로
    돌았는데 LLM 결과인 줄 알았다"가 실험에서 가장 위험한 오독이다.
    """
