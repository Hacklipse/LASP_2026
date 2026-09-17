"""Created 2026-09-15 18:47 KST.
Purpose: Vendor-neutral, immutable contract for non-confirmed Validation reviews.
Input: Deterministic Validation facts; output: a bounded review claim and fingerprint.
Dependencies: hacklipse.domain, hacklipse.ports.llm, Python standard library.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Protocol

from hacklipse.domain import ValidationReasonCode, ValidationVerdict
from hacklipse.ports.llm import LlmUsage

from .security import contains_personal_data

CONTRACT_VERSION = "validation-review-v1"
REVIEW_STATUSES = frozenset({
    "completed", "timeout", "rate_limited", "refused", "invalid_response",
    "transport_error", "unsafe_response", "reason_code_unspecified", "internal_error",
})
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


def valid_review_claim_observation(
    observation: object, *, identifiers: tuple[str, ...] = (),
) -> bool:
    """Validate the stored v1 claim before reuse or aggregate measurement."""

    if not isinstance(observation, Mapping) or set(observation) != {
        "type", "contract_version", "candidate_id", "verdict", "reason_code",
        "outcome_class", "selection_source", "status", "input_fingerprint",
        "offered_classes", "llm_calls", "usage", "usage_available", "model",
        "elapsed_ms", "reason",
    }:
        return False
    source = observation["selection_source"]
    status = observation["status"]
    usage = observation["usage"]
    elapsed = observation["elapsed_ms"]
    if (
        observation["type"] != "llm_validation_review"
        or observation["contract_version"] != CONTRACT_VERSION
        or type(observation["candidate_id"]) is not str
        or not observation["candidate_id"]
        or type(observation["verdict"]) is not str
        or observation["verdict"] not in {
            ValidationVerdict.REJECTED.value, ValidationVerdict.BLOCKED.value
        }
        or type(observation["reason_code"]) is not str
        or observation["reason_code"] not in {code.value for code in ValidationReasonCode}
        or type(observation["outcome_class"]) is not str
        or observation["outcome_class"] not in {item.value for item in ValidationOutcomeClass}
        or type(source) is not str
        or source not in {"llm", "deterministic_fallback"}
        or type(status) is not str
        or status not in REVIEW_STATUSES
        or type(observation["input_fingerprint"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", observation["input_fingerprint"]) is None
        or observation["offered_classes"] != [item.value for item in ValidationOutcomeClass]
        or type(observation["llm_calls"]) is not int
        or observation["llm_calls"] not in {0, 1}
        or not isinstance(usage, Mapping)
        or set(usage) != {"input_tokens", "output_tokens"}
        or any(type(usage[key]) is not int or usage[key] < 0 for key in usage)
        or type(observation["usage_available"]) is not bool
        or (not observation["usage_available"] and any(usage.values()))
        or type(observation["model"]) is not str
        or len(observation["model"]) > 200
        or (observation["model"] and not observation["model"].isprintable())
        or (elapsed is not None and (
            type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0
        ))
        or (status != "reason_code_unspecified" and elapsed is None)
        or not safe_review_reason(observation["reason"], identifiers)
    ):
        return False
    if source == "llm":
        return status == "completed" and observation["llm_calls"] == 1
    return (
        status != "completed"
        and observation["outcome_class"] == ValidationOutcomeClass.UNKNOWN.value
        and not observation["usage_available"]
        and not observation["model"]
        and (observation["llm_calls"] == 0) == (
            status in {"reason_code_unspecified", "internal_error"}
        )
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
