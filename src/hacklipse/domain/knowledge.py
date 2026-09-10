"""Knowledge 발행과 검색이 공유하는 Surface 일반화 규칙."""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import unquote, urlsplit


_SAFE_PARAMETER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_INTEGER_SEGMENT = re.compile(r"^[0-9]{1,20}$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def generalize_parameter_names(parameters: Sequence[str]) -> tuple[str, ...]:
    """안전한 이름만 유지하고 값처럼 보이는 이름은 자리표시자로 바꾼다."""

    return tuple(
        dict.fromkeys(
            name if _SAFE_PARAMETER.fullmatch(name) is not None else "{parameter}"
            for name in parameters
        )
    )


def generalize_surface_path(url: str) -> str:
    """호스트·query·사용자 식별자를 제외한 재사용 가능한 경로 모양을 만든다."""

    path = unquote(urlsplit(url).path or "/")
    segments = path.split("/")
    generalized: list[str] = []
    for segment in segments:
        if not segment:
            generalized.append("")
        elif _INTEGER_SEGMENT.fullmatch(segment) or _UUID_SEGMENT.fullmatch(segment):
            generalized.append("{id}")
        elif segment.startswith("{") and segment.endswith("}"):
            generalized.append("{id}")
        elif _SAFE_PATH_SEGMENT.fullmatch(segment):
            generalized.append(segment.casefold())
        else:
            generalized.append("{value}")
    value = "/".join(generalized)
    return value if value.startswith("/") else f"/{value}"
