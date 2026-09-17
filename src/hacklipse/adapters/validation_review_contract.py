"""Created 2026-09-15 18:47 KST.
Purpose: Vendor-neutral, immutable contract for non-confirmed Validation reviews.
Input: Deterministic Validation facts; output: a bounded review claim and fingerprint.
Dependencies: hacklipse.domain, hacklipse.ports.llm, Python standard library.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol

from hacklipse.domain import ValidationReasonCode, ValidationVerdict
from hacklipse.ports.llm import LlmUsage

from .security import contains_personal_data

CONTRACT_VERSION = "validation-review-v1"
_UNSAFE_REASON = re.compile(
    r"(?i)(?:https?://|www\.|\b(?:token|secret|cookie|authorization|password|apikey|api_key)\b|"
    r"\b(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9_=-]{48,})\b)"
)


def safe_review_reason(reason: object, identifiers: tuple[str, ...] = ()) -> bool:
    return (
        isinstance(reason, str)
        and 0 < len(reason.strip()) <= 300
        and all(character.isprintable() for character in reason)
        and not _UNSAFE_REASON.search(reason)
        and not contains_personal_data(reason)
        and all(identifier not in reason for identifier in identifiers if identifier)
    )


class ValidationOutcomeClass(str, Enum):
    REQUEST_REJECTED = "request_rejected"
    SIGNAL_NOT_OBSERVED = "signal_not_observed"
    PROBE_CONTRACT_MISMATCH = "probe_contract_mismatch"
    EVIDENCE_COLLECTION_INCOMPLETE = "evidence_collection_incomplete"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ValidationReviewContext:
    run_id: str
    candidate_id: str
    validation_id: str
    vulnerability_type: str
    verdict: ValidationVerdict
    reason_code: ValidationReasonCode
    surface_path_hint: str
    surface_method: str
    parameter_aliases: tuple[str, ...]
    reproduction_facts: tuple[tuple[str, str | int], ...]
    reproduction_count: int
    expected_proof_type: str
    validation_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict is ValidationVerdict.CONFIRMED:
            raise ValueError("confirmed validation cannot be reviewed")
        if not isinstance(self.verdict, ValidationVerdict) or not isinstance(
            self.reason_code, ValidationReasonCode
        ):
            raise ValueError("review context requires structured deterministic facts")
        if not all((self.run_id, self.candidate_id, self.validation_id)):
            raise ValueError("review context requires run, candidate, and session IDs")
        if self.reproduction_count < 0:
            raise ValueError("reproduction count cannot be negative")

    def fingerprint(self, *, reviewer_config_version: str) -> str:
        if not reviewer_config_version:
            raise ValueError("reviewer config version is required")
        facts = (
            CONTRACT_VERSION,
            reviewer_config_version,
            self.run_id,
            self.candidate_id,
            self.validation_id,
            self.verdict.value,
            self.reason_code.value,
            self.validation_evidence_ids,
        )
        return hashlib.sha256(
            json.dumps(facts, ensure_ascii=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class ValidationReview:
    outcome_class: ValidationOutcomeClass
    reason: str
    source: Literal["llm", "deterministic_fallback"]
    status: str
    llm_calls: int
    usage: LlmUsage = field(default_factory=LlmUsage)
    usage_available: bool = False
    model: str = ""
    elapsed_ms: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome_class, ValidationOutcomeClass):
            raise ValueError("review outcome must be one of the offered classes")
        if self.source not in {"llm", "deterministic_fallback"}:
            raise ValueError("review source must be llm or deterministic_fallback")
        if not safe_review_reason(self.reason):
            raise ValueError("review reason must be short, printable, and free of secret forms")
        if self.llm_calls < 0 or not isinstance(self.usage, LlmUsage):
            raise ValueError("review trace is invalid")


class ValidationReviewer(Protocol):
    def review(
        self, context: ValidationReviewContext, *, timeout_seconds: float
    ) -> ValidationReview: ...
