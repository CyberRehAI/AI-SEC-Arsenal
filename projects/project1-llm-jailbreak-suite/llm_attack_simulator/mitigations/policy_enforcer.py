"""
Policy enforcement layer that makes final decisions on response safety.

This module implements the final decision layer that rejects unsafe responses
and logs violations for metrics tracking.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from llm_attack_simulator.mitigations.output_filter import ValidationResult


@dataclass
class EnforcementResult:
    """Result of policy enforcement."""

    is_allowed: bool
    final_output: str
    rejection_reason: str | None = None
    violation_log: List[str] | None = None


class PolicyEnforcer:
    """
    Policy enforcer that makes final decisions on response safety.

    This enforcer:
    - Rejects unsafe responses based on validation results
    - Returns safe responses
    - Logs violations for metrics
    - Provides rejection reasons
    """

    REJECTION_MESSAGE = (
        "I cannot fulfill this request as it violates my safety guidelines. "
        "Please ask something else."
    )

    def __init__(self, violation_threshold: float = 0.3):
        """
        Initialize the policy enforcer.

        Args:
            violation_threshold: Threshold for violation score (0.0-1.0).
                                Responses above this threshold are rejected.
        """
        self.violation_threshold = violation_threshold

    def enforce(
        self, output: str, validation_result: ValidationResult
    ) -> EnforcementResult:
        """
        Enforce policy based on validation results.

        Args:
            output: The LLM output to evaluate
            validation_result: Result from output validation

        Returns:
            EnforcementResult with final decision
        """
        violation_log = []

        # Check if output is safe based on validation
        if not validation_result.is_safe:
            violation_log.extend(validation_result.detected_violations)
            violation_log.extend(validation_result.violation_flags)

            # Determine rejection reason
            if "harmful_content" in validation_result.detected_violations:
                rejection_reason = "Contains harmful or illegal content"
            elif "system_prompt_leak" in validation_result.detected_violations:
                rejection_reason = "Attempts to reveal system instructions"
            elif "policy_bypass" in validation_result.detected_violations:
                rejection_reason = "Attempts to bypass safety guidelines"
            else:
                rejection_reason = "Violates safety policy"

            return EnforcementResult(
                is_allowed=False,
                final_output=self.REJECTION_MESSAGE,
                rejection_reason=rejection_reason,
                violation_log=violation_log,
            )

        # Output is safe, allow it
        return EnforcementResult(
            is_allowed=True,
            final_output=output,
            rejection_reason=None,
            violation_log=None,
        )

    def enforce_with_custom_message(
        self,
        output: str,
        validation_result: ValidationResult,
        custom_rejection_message: str | None = None,
    ) -> EnforcementResult:
        """
        Enforce policy with optional custom rejection message.

        Args:
            output: The LLM output to evaluate
            validation_result: Result from output validation
            custom_rejection_message: Optional custom message for rejected responses

        Returns:
            EnforcementResult with final decision
        """
        result = self.enforce(output, validation_result)

        if not result.is_allowed and custom_rejection_message:
            result.final_output = custom_rejection_message

        return result
