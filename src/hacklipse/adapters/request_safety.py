"""자동 probe에 적합하지 않은 상태 변경성 GET 입력을 보수적으로 식별한다."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import parse_qsl, unquote, urlsplit


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
_ACTION_PARAMETER_NAMES = frozenset(
    {"action", "button", "cmd", "command", "mode", "op", "operation", "submit", "task"}
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


def has_state_changing_get(url: str, parameters: Sequence[str] = ()) -> bool:
    """GET의 경로·기존/추가 query를 함께 검사한다.

    검색어에 'delete'가 등장한 것만으로는 차단하지 않지만, action=delete처럼
    동작 선택 필드의 값이 상태 변경을 지시하면 승인 없는 자동 실행을 막는다.
    """

    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if has_state_changing_parameters((
        unquote(unquote(parsed.path)), *(name for name, _ in query), *parameters
    )):
        return True
    return any(
        name.casefold() in _ACTION_PARAMETER_NAMES
        and has_state_changing_parameters((unquote(value),))
        for name, value in query
    )


# 객체 식별자로 볼 수 있는 파라미터 이름. Access Control은 "다른 사람의 객체를 가리키는
# 입력"이 있어야 성립하므로, 파라미터가 있다는 이유만으로 Candidate를 만들지 않는다.
_IDENTIFIER_NAMES = frozenset({"id", "uid", "no", "num", "seq", "idx"})
_IDENTIFIER_SUFFIXES = ("_id", "_no", "_uid", "_seq")

# 식별자처럼 보이지만 객체를 가리키지 않는 것들. 세션·CSRF 값을 바꿔가며 찔러보는 것은
# 객체 권한 검사가 아니라 인증 우회 시도이므로 자동 탐침 대상에서 제외한다.
_NON_OBJECT_NAMES = frozenset(
    {
        "action",
        "submit",
        "token",
        "csrf",
        "csrf_token",
        "user_token",
        "session",
        "session_id",
        "sessionid",
        "sid",
        "nonce",
        "state",
        "security",
    }
)


def is_object_identifier_parameter(name: str) -> bool:
    """파라미터 이름이 객체 식별자를 가리키는지 판정한다."""

    lowered = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).casefold()
    if lowered in _NON_OBJECT_NAMES:
        return False
    if lowered in _IDENTIFIER_NAMES:
        return True
    return any(lowered.endswith(suffix) for suffix in _IDENTIFIER_SUFFIXES)


def object_identifier_parameters(parameters: Sequence[str]) -> tuple[str, ...]:
    """Surface에서 객체 식별자로 볼 수 있는 파라미터만 순서대로 고른다."""

    return tuple(name for name in parameters if is_object_identifier_parameter(name))
