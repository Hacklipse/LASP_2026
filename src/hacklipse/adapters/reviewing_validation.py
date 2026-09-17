"""Created 2026-09-15 18:47 KST.
Purpose: Add an isolated review claim after deterministic Validation completes.
Input: Validation TaskEnvelope; output: original AgentResult plus separate claim ID.
Dependencies: Validation Agent/Reviewer contracts, repository ports, standard library.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Mapping
from dataclasses import replace
from typing import Callable
from urllib.parse import urlsplit

from hacklipse.domain import (
    AgentResult,
    AgentResultStatus,
    Evidence,
    TaskEnvelope,
    ValidationProofType,
    ValidationReasonCode,
    ValidationVerdict,
)
from hacklipse.ports import CandidateStore, EvidenceStore, SurfaceStore
from hacklipse.ports.agents import Agent
from hacklipse.ports.errors import LlmCredentialsMissing
from hacklipse.ports.llm import LlmClient, LlmUsage

from .llm_parameter_names import alias_parameter_names
from .llm_validation_review import LlmValidationReviewer
from .validation import ValidationAgent
from .validation_review_contract import (
    CONTRACT_VERSION,
    ValidationOutcomeClass,
    ValidationReview,
    ValidationReviewContext,
    ValidationReviewer,
    safe_review_reason,
    valid_review_claim_observation,
)

_LOG = logging.getLogger(__name__)
_EXPECTED_PROOF = {
    "XSS": ValidationProofType.XSS_EXECUTION,
    "SQLi": ValidationProofType.SQLI_EFFECT,
    "Access Control": ValidationProofType.UNAUTHORIZED_OBJECT_ACCESS,
    "Path Traversal": ValidationProofType.PATH_TRAVERSAL_FILE_READ,
    "SSTI": ValidationProofType.SSTI_EXECUTION,
}


class ReviewingValidationAgent:
    def __init__(
        self,
        *,
        validator: Agent,
        reviewer: ValidationReviewer,
        candidate_store: CandidateStore,
        evidence_store: EvidenceStore,
        surface_store: SurfaceStore,
        reviewer_config_version: str = "llm-validation-review-v1",
        timeout_seconds: float = 15.0,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if timeout_seconds <= 0 or not reviewer_config_version:
            raise ValueError("review timeout and configuration version are required")
        self._validator = validator
        self._reviewer = reviewer
        self._candidates = candidate_store
        self._evidence = evidence_store
        self._surfaces = surface_store
        self._config_version = reviewer_config_version
        self._timeout = timeout_seconds
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)

    def handle(self, task: TaskEnvelope) -> AgentResult:
        result = self._validator.handle(task)
        validation = result.validation
        if (result.status is not AgentResultStatus.COMPLETED or validation is None
                or validation.verdict is ValidationVerdict.CONFIRMED):
            return result

        try:
            context, surface_id = self._context(task, result)
            fingerprint = context.fingerprint(reviewer_config_version=self._config_version)
            claim = self._find_claim(context, surface_id, fingerprint)
            if claim is not None:
                return replace(result, new_evidence_ids=result.new_evidence_ids + (claim.evidence_id,))
        except Exception as error:
            _LOG.warning("validation review context unavailable: %s", type(error).__name__)
            return result

        started = time.monotonic()
        if context.reason_code is ValidationReasonCode.UNSPECIFIED:
            review = self._fallback("reason_code_unspecified")
        else:
            try:
                review = self._reviewer.review(
                    context, timeout_seconds=min(self._timeout, task.timeout_seconds / 2)
                )
                if not isinstance(review, ValidationReview) or not safe_review_reason(
                    review.reason, (context.run_id, context.candidate_id, context.validation_id)
                ):
                    raise ValueError("reviewer returned an invalid or unsafe claim")
            except Exception as error:
                _LOG.warning("validation review internal fallback: %s", type(error).__name__)
                review = self._fallback(
                    "internal_error",
                    elapsed_ms=(time.monotonic() - started) * 1000,
                )

        try:
            observation = self._claim_observation(context, fingerprint, review)
            if not valid_review_claim_observation(
                observation,
                identifiers=(context.run_id, context.candidate_id, context.validation_id),
            ):
                raise ValueError("reviewer returned an inconsistent claim")
        except Exception as error:
            _LOG.warning("validation review contract fallback: %s", type(error).__name__)
            review = self._fallback(
                "internal_error",
                elapsed_ms=(time.monotonic() - started) * 1000,
            )
            observation = self._claim_observation(context, fingerprint, review)

        try:
            claim = Evidence(
                evidence_id=f"validation-review-{self._id_factory()}",
                run_id=task.run_id,
                surface_id=surface_id,
                source_task_id=task.task_id,
                validation_id=context.validation_id,
                created_by="llm_validation_reviewer",
                evidence_type="claim",
                observation=observation,
            )
            self._evidence.append(claim)
            return replace(result, new_evidence_ids=result.new_evidence_ids + (claim.evidence_id,))
        except Exception as error:
            # A broken Evidence store cannot record a claim; preserve the verdict.
            _LOG.warning("validation review claim storage failed: %s", type(error).__name__)
            return result

    @staticmethod
    def _claim_observation(
        context: ValidationReviewContext, fingerprint: str, review: ValidationReview,
    ) -> dict[str, object]:
        return {
            "type": "llm_validation_review",
            "contract_version": CONTRACT_VERSION,
            "candidate_id": context.candidate_id,
            "verdict": context.verdict.value,
            "reason_code": context.reason_code.value,
            "outcome_class": review.outcome_class.value,
            "selection_source": review.source,
            "status": review.status,
            "input_fingerprint": fingerprint,
            "offered_classes": [item.value for item in ValidationOutcomeClass],
            "llm_calls": review.llm_calls,
            "usage": {
                "input_tokens": review.usage.input_tokens,
                "output_tokens": review.usage.output_tokens,
            },
            "usage_available": review.usage_available,
            "model": review.model,
            "elapsed_ms": review.elapsed_ms,
            "reason": review.reason,
        }

    def _context(self, task: TaskEnvelope, result: AgentResult) -> tuple[ValidationReviewContext, str]:
        validation = result.validation
        assert validation is not None
        candidate = self._candidates.get(task.run_id, validation.candidate_id)
        surface = self._surfaces.get(task.run_id, candidate.surface_id)
        reproduction = self._evidence.get_many(task.run_id, validation.evidence_ids)
        facts: list[tuple[str, str | int]] = []
        for item in reproduction:
            kind = item.observation.get("type")
            status = item.observation.get("status")
            if isinstance(kind, str) and type(status) is int:
                facts.append((kind, status))
            elif isinstance(kind, str) and kind in {"http_error", "browser_error"}:
                facts.append((kind, "execution_error"))
        expected = _EXPECTED_PROOF.get(candidate.vulnerability_type)
        return ValidationReviewContext(
            run_id=task.run_id,
            candidate_id=candidate.candidate_id,
            validation_id=validation.validation_id,
            vulnerability_type=candidate.vulnerability_type,
            verdict=validation.verdict,
            reason_code=validation.reason_code,
            surface_path_hint=urlsplit(surface.url).path or "/",
            surface_method=surface.method,
            parameter_aliases=alias_parameter_names(surface.parameters).prompt_names,
            reproduction_facts=tuple(facts),
            reproduction_count=validation.reproduction_count,
            expected_proof_type=expected.value if expected else "unknown",
            validation_evidence_ids=validation.evidence_ids,
        ), candidate.surface_id

    def _find_claim(self, context: ValidationReviewContext, surface_id: str,
                    fingerprint: str) -> Evidence | None:
        # ponytail: Run-local linear scan is enough for current review volume;
        # add a fingerprint index only if measured resume latency warrants it.
        for item in self._evidence.list_by_run(context.run_id):
            obs = item.observation
            if not isinstance(obs, Mapping):
                continue
            if (item.run_id == context.run_id
                    and item.evidence_type == "claim" and item.created_by == "llm_validation_reviewer"
                    and item.validation_id == context.validation_id
                    and item.surface_id == surface_id
                    and obs.get("candidate_id") == context.candidate_id
                    and obs.get("input_fingerprint") == fingerprint
                    and obs.get("verdict") == context.verdict.value
                    and obs.get("reason_code") == context.reason_code.value
                    and valid_review_claim_observation(
                        obs,
                        identifiers=(context.run_id, context.candidate_id, context.validation_id),
                    )):
                return item
        return None

    @staticmethod
    def _fallback(
        status: str, *, llm_calls: int = 0, elapsed_ms: float | None = None,
    ) -> ValidationReview:
        return ValidationReview(
            outcome_class=ValidationOutcomeClass.UNKNOWN,
            reason="이번 Validation session의 제한된 facts만으로 결과를 분류할 수 없음",
            source="deterministic_fallback",
            status=status,
            llm_calls=llm_calls,
            usage=LlmUsage(),
            elapsed_ms=elapsed_ms,
        )


def build_llm_reviewing_validation_agent(
    *, llm_client: LlmClient, candidate_store: CandidateStore,
    evidence_store: EvidenceStore, surface_store: SurfaceStore,
    timeout_seconds: float = 15.0,
) -> ReviewingValidationAgent:
    """Opt-in assembly point; common bootstrap can register this Agent unchanged."""

    if llm_client is None:
        raise LlmCredentialsMissing("validation reviewer requires an explicit LlmClient")
    return ReviewingValidationAgent(
        validator=ValidationAgent(
            candidate_store=candidate_store,
            evidence_store=evidence_store,
            surface_store=surface_store,
        ),
        reviewer=LlmValidationReviewer(llm_client=llm_client),
        candidate_store=candidate_store,
        evidence_store=evidence_store,
        surface_store=surface_store,
        timeout_seconds=timeout_seconds,
    )
