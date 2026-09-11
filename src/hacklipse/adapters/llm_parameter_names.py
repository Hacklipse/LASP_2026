"""대상이 통제하는 파라미터명을 LLM에 안전한 별칭으로 전달한다."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass


_SAFE_PARAMETER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")


@dataclass(frozen=True, slots=True)
class ParameterNameAliases:
    """LLM 표시 이름과 실제 Surface 이름 사이의 Run-local 대응표.

    안전한 이름은 의미 판단을 위해 그대로 유지한다. 줄바꿈·괄호 등 프롬프트 문법을
    바꿀 수 있는 이름은 ``parameter_N``으로 치환하며, 대응표 자체는 LLM에 보내지 않는다.
    """

    prompt_names: tuple[str, ...]
    original_by_prompt: tuple[tuple[str, str], ...]

    def decode_selection(self, raw: object) -> object:
        """LLM 선택의 별칭만 실제 이름으로 복원하고 나머지 형식은 검증기에 맡긴다."""

        if not isinstance(raw, list):
            return raw
        mapping = dict(self.original_by_prompt)
        return [mapping.get(item, item) if isinstance(item, str) else item for item in raw]

    def prompt_name(self, original: str) -> str:
        """실제 이름 하나를 이 목록에서 사용한 prompt 이름으로 바꾼다."""

        mapping = {
            original_name: prompt
            for prompt, original_name in self.original_by_prompt
        }
        return mapping.get(original, original)

    def decode_name(self, prompt_name: str) -> str:
        """LLM이 돌려준 prompt 이름 하나를 실제 이름으로 복원한다."""

        return dict(self.original_by_prompt).get(prompt_name, prompt_name)

    def redact_text(self, value: str) -> str:
        """자유 형식 문맥에 나타난 안전하지 않은 원문 이름도 별칭으로 치환한다."""

        replacements = sorted(
            (
                (original, prompt)
                for prompt, original in self.original_by_prompt
                if prompt != original
            ),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        for original, prompt in replacements:
            value = value.replace(original, prompt)
        return value

    def encode_names(self, names: Sequence[str]) -> tuple[str, ...]:
        """전체 목록의 일부를 동일한 prompt 별칭으로 표현한다."""

        return tuple(self.prompt_name(name) for name in names)


def alias_parameter_names(parameters: Sequence[str]) -> ParameterNameAliases:
    """순서를 보존하며 안전하지 않은 이름에 충돌 없는 결정적 별칭을 부여한다."""

    used = set(parameters)
    prompt_names: list[str] = []
    mapping: list[tuple[str, str]] = []
    next_alias = 1
    for name in parameters:
        if _SAFE_PARAMETER_NAME.fullmatch(name):
            prompt_name = name
        else:
            while (prompt_name := f"parameter_{next_alias}") in used:
                next_alias += 1
            next_alias += 1
            used.add(prompt_name)
        prompt_names.append(prompt_name)
        mapping.append((prompt_name, name))
    return ParameterNameAliases(tuple(prompt_names), tuple(mapping))
