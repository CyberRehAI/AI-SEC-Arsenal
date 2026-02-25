"""Evaluation helpers for running attacks and computing metrics."""

from llm_attack_simulator.evaluation.metrics import (
    AttackResult,
    calculate_post_mitigation_success_rate,
    calculate_reduction_percentage,
    calculate_security_score,
    calculate_success_rate,
    is_attack_successful,
    meets_target_threshold,
)
from llm_attack_simulator.evaluation.tester import (
    run_batch_tests,
    run_comparison_tests,
    run_single_attack,
)

__all__ = [
    "AttackResult",
    "is_attack_successful",
    "calculate_success_rate",
    "calculate_post_mitigation_success_rate",
    "calculate_reduction_percentage",
    "calculate_security_score",
    "meets_target_threshold",
    "run_single_attack",
    "run_batch_tests",
    "run_comparison_tests",
]