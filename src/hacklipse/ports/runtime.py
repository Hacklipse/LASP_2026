"""HTTP·브라우저·도구 실행을 캡슐화하는 외부 실행 계약."""

from __future__ import annotations

from typing import Protocol

from hacklipse.domain import ExecutionRequest, ExecutionResult


class ExecutionRuntime(Protocol):
    """외부 실행 경계. 이 Port가 호출되기 전에 정책 검사가 완료되어야 한다."""

    def execute(self, request: ExecutionRequest) -> ExecutionResult: ...
