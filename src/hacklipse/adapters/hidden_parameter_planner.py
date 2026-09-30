"""Bounded hypotheses for unobserved form-body file/render parameters."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from hacklipse.domain import Surface
from hacklipse.ports import LlmClient
from hacklipse.ports.errors import LlmError
from hacklipse.ports.llm import LlmMessage, LlmRequest


MAX_HYPOTHESES = 12
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,39}\Z")
_DANGEROUS_PARTS = (
    "password", "passwd", "delete", "confirm", "csrf", "token",
    "authorization", "cookie", "admin", "role",
)
_SEMANTICS = frozenset({
    "file_path", "template_selector", "render_layout", "resource_name",
})
# Generic vocabulary: never map an endpoint or product to one of these names.
_CORPUS = (
    ("file", "file_path"),
    ("path", "file_path"),
    ("template", "template_selector"),
    ("layout", "render_layout"),
    ("view", "template_selector"),
    ("resource", "resource_name"),
    ("filename", "file_path"),
    ("document", "resource_name"),
    ("page", "template_selector"),
    ("include", "file_path"),
    ("theme", "render_layout"),
    ("render", "render_layout"),
)
_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "semantic_role": {"type": "string"},
                    "confidence": {"type": "string"},
                    "reason_code": {"type": "string"},
                },
                "required": ["name", "semantic_role", "confidence", "reason_code"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["hypotheses"],
    "additionalProperties": False,
}


@dataclass(frozen=True, slots=True)
class ParameterHypothesis:
    name: str
    semantic_role: str
    source: str
    confidence: str

    def observation(self) -> dict[str, object]:
        return {
            "name": self.name,
            "semantic_role": self.semantic_role,
            "source": self.source,
            "observed": False,
            "confidence": self.confidence,
        }


def safe_hidden_name(name: str, observed: tuple[str, ...]) -> bool:
    """Reject unsafe, duplicate and already observed form-body coordinates."""

    if _NAME.fullmatch(name) is None:
        return False
    folded = name.casefold()
    return bool(
        folded != "email"
        and not any(part in folded for part in _DANGEROUS_PARTS)
        and folded not in {item.casefold() for item in observed}
    )


class HiddenParameterPlanner:
    """Suggest names only; neither the LLM nor this planner can send probes."""

    def __init__(self, llm_client: LlmClient | None) -> None:
        self._llm = llm_client

    def plan(
        self,
        surface: Surface,
        *,
        timeout_seconds: float,
    ) -> tuple[ParameterHypothesis, ...]:
        offered = tuple(surface.parameters)
        proposed: list[ParameterHypothesis] = []
        if self._llm is not None:
            path_tokens = re.findall(r"[A-Za-z]+", urlsplit(surface.url).path)
            context = {
                "method": surface.method.upper(),
                "path_tokens": path_tokens[:8],
                "content_type": "application/x-www-form-urlencoded",
                "observed_parameters": list(offered),
                "parameter_semantics": sorted(_SEMANTICS),
                "generic_name_corpus": [name for name, _ in _CORPUS],
                "max_hypotheses": MAX_HYPOTHESES,
            }
            try:
                payload = self._llm.complete(LlmRequest(
                    messages=(LlmMessage(role="user", content=json.dumps(context)),),
                    system=(
                        "Suggest or reorder generic names for unobserved form-body "
                        "file/render inputs on this authorized endpoint. These are "
                        "hypotheses, never observations. Return names and semantic "
                        "roles only; do not return URLs, headers, credentials, values, "
                        "payloads, or target-specific knowledge."
                    ),
                    response_schema=_SCHEMA,
                    timeout_seconds=timeout_seconds,
                )).payload
                entries = payload.get("hypotheses")
                if isinstance(entries, list):
                    # Reserve four slots for the generic corpus even when the
                    # model fills every hypothesis slot with other names.
                    for entry in entries[: MAX_HYPOTHESES - 4]:
                        if not isinstance(entry, dict):
                            continue
                        name = entry.get("name")
                        role = entry.get("semantic_role")
                        confidence = entry.get("confidence")
                        if (
                            isinstance(name, str)
                            and isinstance(role, str)
                            and role in _SEMANTICS
                            and confidence in {"low", "medium", "high"}
                        ):
                            proposed.append(ParameterHypothesis(
                                name, role, "llm_hypothesis", confidence
                            ))
            except LlmError:
                pass  # Generic corpus is the deterministic fallback.

        proposed.extend(
            ParameterHypothesis(name, role, "generic_corpus", "low")
            for name, role in _CORPUS
        )
        seen = {name.casefold() for name in offered}
        valid: list[ParameterHypothesis] = []
        for item in proposed:
            folded = item.name.casefold()
            if folded in seen or not safe_hidden_name(item.name, offered):
                continue
            seen.add(folded)
            valid.append(item)
            if len(valid) == MAX_HYPOTHESES:
                break
        return tuple(valid)
