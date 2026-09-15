"""Created 2026-09-15 18:47 KST.
Purpose: Assign deterministic reason codes without editing the baseline Validator.
Input: Existing ValidationAgent branch result; output: same result with reason_code.
Dependencies: validation.ValidationAgent, hacklipse.domain, standard library.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from hacklipse.domain import (
    AgentResult, Evidence, TaskEnvelope, ValidationProof,
    ValidationReasonCode as Code, ValidationVerdict,
)

from .validation import ValidationAgent

# ponytail: exact baseline messages avoid touching shared Validator code; move
# codes into its branches when the Validation team owns that file exclusively.
# Unknown branches remain UNSPECIFIED, so they cannot be mislabeled.
_REASONS = {
    "analysis produced no reflected parameter to execute": Code.ANALYSIS_SIGNAL_MISSING,
    "independent browser reproduction could not execute": Code.REPRODUCTION_EXECUTION_ERROR,
    "browser control unexpectedly contained an execution signal": Code.CONTROL_SIGNAL_PRESENT,
    "independent browser probe did not execute the XSS marker": Code.PROBE_SIGNAL_NOT_REPRODUCED,
    "analysis produced no SQL error signal to reproduce": Code.ANALYSIS_SIGNAL_MISSING,
    "independent SQLi reproduction could not obtain comparable responses": Code.COMPARABLE_RESPONSES_MISSING,
    "independent quote probe did not reproduce the SQL error differential": Code.PROBE_SIGNAL_NOT_REPRODUCED,
    "no object_id_auth observation to reproduce independently": Code.ACCESS_PLAN_MISSING,
    "independent access control reproduction exceeded the request budget": Code.ACCESS_BUDGET_EXHAUSTED,
    "access control reproduction did not belong to this validation session": Code.VALIDATION_SESSION_MISMATCH,
    "actor session did not expose the owner object": Code.ACCESS_NOT_EXPOSED,
    "analysis produced no safe-file read signal to reproduce": Code.ANALYSIS_SIGNAL_MISSING,
    "independent safe-file reproduction could not obtain comparable responses": Code.COMPARABLE_RESPONSES_MISSING,
    "independent probe did not reproduce the safe-file read": Code.PROBE_SIGNAL_NOT_REPRODUCED,
    "analysis produced no filter bypass signal to reproduce": Code.ANALYSIS_SIGNAL_MISSING,
    "independent bypass reproduction could not obtain comparable responses": Code.COMPARABLE_RESPONSES_MISSING,
    "independent probe did not reproduce the filter bypass read": Code.PROBE_SIGNAL_NOT_REPRODUCED,
    "analysis produced no fixed-arithmetic SSTI signal to reproduce": Code.ANALYSIS_SIGNAL_MISSING,
    "independent SSTI sequence encountered an HTTP execution error": Code.REPRODUCTION_EXECUTION_ERROR,
    "independent SSTI sequence could not restore the safe username": Code.CLEANUP_FAILED,
    "independent fixed arithmetic probe was not evaluated by the template": Code.PROBE_SIGNAL_NOT_REPRODUCED,
}


class ReasonCodedValidationAgent(ValidationAgent):
    @staticmethod
    def _validation_result(
        task: TaskEnvelope, *, verdict: ValidationVerdict,
        evidence: Sequence[Evidence], reason: str,
        proof: ValidationProof | None = None,
    ) -> AgentResult:
        result = ValidationAgent._validation_result(
            task, verdict=verdict, evidence=evidence, reason=reason, proof=proof,
        )
        assert result.validation is not None
        code = Code.CONFIRMED_PROOF if verdict is ValidationVerdict.CONFIRMED else _REASONS.get(
            reason, Code.UNSPECIFIED
        )
        return replace(result, validation=replace(result.validation, reason_code=code))

    def _decide(self, task: TaskEnvelope, reproduction: Sequence[Evidence]) -> AgentResult:
        result = super()._decide(task, reproduction)
        assert result.validation is not None
        code = (
            Code.REPRODUCTION_EXECUTION_ERROR
            if result.validation.verdict is ValidationVerdict.BLOCKED
            else Code.GENERIC_NO_PROOF
        )
        return replace(result, validation=replace(result.validation, reason_code=code))
