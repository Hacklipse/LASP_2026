"""자동 probe에 적합하지 않은 상태 변경성 GET 입력을 보수적으로 식별한다."""

from __future__ import annotations

import re
from collections.abc import Sequence


_STATE_CHANGE_TOKENS = frozenset(
    {
        "change",
        "create",
        "delete",
        "disable",
        "enable",
        "logout",
        "passwd",
        "password",
        "remove",
        "reset",
        "transfer",
        "update",
        "upload",
    }
)


def has_state_changing_parameters(parameters: Sequence[str]) -> bool:
    """필드명만으로 상태 변경 가능성이 높은 Surface인지 판정한다.

    GET은 메서드 자체로 안전하지 않다. 비밀번호 변경·삭제처럼 잘못 구현된 GET 폼은
    자동 control/probe만으로 상태를 바꿀 수 있으므로 Router와 최종 Policy가 같은
    결정적 규칙을 사용한다.
    """

    for parameter in parameters:
        expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", parameter)
        tokens = {
            token
            for token in re.split(r"[^a-z0-9]+", expanded.casefold())
            if token
        }
        if tokens & _STATE_CHANGE_TOKENS:
            return True
    return False
