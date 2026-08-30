"""Agent가 특정 LLM 벤더를 알지 않고 구조화 판단을 요청하는 계약.

이 Port의 요청·응답 타입을 domain이 아니라 여기 두는 것은 의도적이다. domain은
"이 시스템의 워크플로 어휘"이고, 토큰·메시지·모델명은 그 어휘가 아니다. domain에
넣으면 LLM을 쓰지 않는 결정적 대조군 Agent(HeuristicXssAnalyzer 등)까지 LLM
어휘를 보게 되어 마일스톤 A/B의 경계가 흐려진다.

핵심 계약: LlmResponse.payload는 이미 파싱된 매핑이다. 자유 서술 텍스트는 이 Port를
넘어오지 못한다. 다만 "파싱됐다"는 것과 "믿을 수 있다"는 것은 다르다 — Enum 값,
Evidence ID 실재 여부, Surface 소유 관계 검증은 이 계층이 아니라 이를 도메인 객체로
바꾸는 Agent와 Orchestrator의 책임이다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence


@dataclass(frozen=True, slots=True)
class LlmMessage:
    """대화 한 턴. role은 벤더 중립적으로 user/assistant만 사용한다."""

    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"user", "assistant"}:
            raise ValueError("llm message role must be user or assistant")
        if not self.content.strip():
            raise ValueError("llm message content cannot be empty")


@dataclass(frozen=True, slots=True)
class LlmRequest:
    """모델에 보낼 요청. 벤더별 파라미터는 Adapter 설정으로 분리한다.

    response_schema가 있으면 응답은 그 스키마를 따르는 JSON 객체여야 한다.
    없으면 응답 본문 전체가 JSON 객체이기만 하면 된다.
    """

    messages: Sequence[LlmMessage]
    system: str | None = None
    max_output_tokens: int = 4096
    response_schema: Mapping[str, object] | None = None
    # 취소 가능성은 Port 계약에 남긴다: 호출자가 상한을 정하고 초과 시 LlmTimeout이 난다.
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("llm request requires at least one message")
        if self.max_output_tokens <= 0:
            raise ValueError("llm max output tokens must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("llm timeout must be positive")


@dataclass(frozen=True, slots=True)
class LlmUsage:
    """비용 산정에 필요한 원시 사용량. 요금 계산은 이 계층에서 하지 않는다."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


@dataclass(frozen=True, slots=True)
class LlmResponse:
    """구조화 응답 본체와 사용량. payload는 파싱을 마친 JSON 객체다."""

    payload: Mapping[str, object]
    usage: LlmUsage = field(default_factory=LlmUsage)
    model: str = ""
    stop_reason: str = ""


class LlmClient(Protocol):
    """LLM 공급자를 교체해도 Agent 코드가 바뀌지 않게 하는 경계."""

    def complete(self, request: LlmRequest) -> LlmResponse: ...
