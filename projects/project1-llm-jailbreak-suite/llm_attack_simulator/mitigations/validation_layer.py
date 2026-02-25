"""
Validation layer that orchestrates all mitigation layers.

This module implements the complete mitigation pipeline:
Input Filter → Prompt Guard → LLM → Output Validator → Policy Enforcer
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from llm_attack_simulator.mitigations.input_filter import FilterResult, InputFilter
from llm_attack_simulator.mitigations.output_filter import OutputFilter, ValidationResult
from llm_attack_simulator.mitigations.policy_enforcer import EnforcementResult, PolicyEnforcer
from llm_attack_simulator.mitigations.prompt_guard import PromptGuard
from llm_attack_simulator.utils.llm_interface import LLMInterface


@dataclass
class DefenseLog:
    """Log entry for defense layer activity."""

    layer_name: str
    action: str
    details: str | None = None


@dataclass
class MitigationResult:
    """Result of the complete mitigation pipeline."""

    final_output: str
    defense_logs: List[DefenseLog]
    input_filter_result: FilterResult | None = None
    validation_result: ValidationResult | None = None
    enforcement_result: EnforcementResult | None = None
    was_blocked: bool = False


class ValidationLayer:
    """
    Validation layer that orchestrates all mitigation components.

    This layer implements the complete defense pipeline:
    1. Input Filter - Detects suspicious patterns
    2. Prompt Guard - Wraps input in structured template
    3. LLM Interface - Generates response
    4. Output Validator - Checks for violations
    5. Policy Enforcer - Makes final decision
    """

    def __init__(
        self,
        llm: LLMInterface,
        input_filter: InputFilter | None = None,
        prompt_guard: PromptGuard | None = None,
        output_filter: OutputFilter | None = None,
        policy_enforcer: PolicyEnforcer | None = None,
        protected_secret: str | None = None,
    ):
        """
        Initialize the validation layer with mitigation components.

        Args:
            llm: LLM interface for generating responses
            input_filter: Optional input filter (creates default if None)
            prompt_guard: Optional prompt guard (creates default if None)
            output_filter: Optional output filter (creates default if None)
            policy_enforcer: Optional policy enforcer (creates default if None)
            protected_secret: Optional secret to protect; if output contains it, response is blocked
        """
        self.llm = llm
        self.input_filter = input_filter or InputFilter()
        self.prompt_guard = prompt_guard or PromptGuard()
        self.output_filter = (
            output_filter if output_filter is not None else OutputFilter(protected_secret=protected_secret)
        )
        self.policy_enforcer = policy_enforcer or PolicyEnforcer()

    def process(
        self, user_input: str, base_system_prompt: str = "", mitigation_enabled: bool = True
    ) -> MitigationResult:
        """
        Process user input through the complete mitigation pipeline.

        Args:
            user_input: The user's input to process
            base_system_prompt: Optional base system prompt
            mitigation_enabled: Whether to apply mitigations (False = direct LLM call)

        Returns:
            MitigationResult with final output and defense logs
        """
        defense_logs: List[DefenseLog] = []

        if not mitigation_enabled:
            # Bypass all mitigations, direct LLM call
            defense_logs.append(
                DefenseLog(
                    layer_name="ValidationLayer",
                    action="Mitigation disabled - direct LLM call",
                )
            )
            raw_output = self.llm.generate(user_input)
            return MitigationResult(
                final_output=raw_output,
                defense_logs=defense_logs,
                was_blocked=False,
            )

        # Step 1: Input Filter
        filter_result = self.input_filter.filter(user_input)
        defense_logs.append(
            DefenseLog(
                layer_name="InputFilter",
                action="Filtered input",
                details=f"Suspicious: {filter_result.is_suspicious}, Patterns: {filter_result.detected_patterns}",
            )
        )

        # Step 2: Prompt Guard
        guarded_prompt = self.prompt_guard.guard(user_input, base_system_prompt)
        defense_logs.append(
            DefenseLog(
                layer_name="PromptGuard",
                action="Wrapped input in guarded template",
            )
        )

        # Step 3: LLM Generation
        llm_output = self.llm.generate(guarded_prompt)
        defense_logs.append(
            DefenseLog(
                layer_name="LLMInterface",
                action="Generated response",
                details=f"Output length: {len(llm_output)} chars",
            )
        )

        # Step 4: Output Validation
        validation_result = self.output_filter.validate(llm_output)
        defense_logs.append(
            DefenseLog(
                layer_name="OutputFilter",
                action="Validated output",
                details=f"Safe: {validation_result.is_safe}, Score: {validation_result.violation_score:.2f}, Violations: {validation_result.detected_violations}",
            )
        )

        # Step 5: Policy Enforcement
        enforcement_result = self.policy_enforcer.enforce(llm_output, validation_result)
        defense_logs.append(
            DefenseLog(
                layer_name="PolicyEnforcer",
                action="Enforced policy",
                details=f"Allowed: {enforcement_result.is_allowed}, Reason: {enforcement_result.rejection_reason}",
            )
        )

        was_blocked = not enforcement_result.is_allowed

        return MitigationResult(
            final_output=enforcement_result.final_output,
            defense_logs=defense_logs,
            input_filter_result=filter_result,
            validation_result=validation_result,
            enforcement_result=enforcement_result,
            was_blocked=was_blocked,
        )
