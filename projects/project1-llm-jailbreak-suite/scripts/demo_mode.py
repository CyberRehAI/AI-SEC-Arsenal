#!/usr/bin/env python3
"""
Demo mode script for reproducible demonstrations.

This script runs a predefined set of attacks with fixed inputs
to produce consistent results for demonstrations.

Usage:
    python scripts/demo_mode.py
"""

from llm_attack_simulator.attacks import get_registered_attacks
from llm_attack_simulator.evaluation import (
    calculate_post_mitigation_success_rate,
    calculate_reduction_percentage,
    calculate_security_score,
    calculate_success_rate,
    run_comparison_tests,
)
from llm_attack_simulator.mitigations import ValidationLayer
from llm_attack_simulator.utils.llm_interface import MockLLM


def main():
    """Run demo mode with predefined attacks."""
    print("=" * 60)
    print("LLM Attack Simulator - Demo Mode")
    print("=" * 60)
    print()

    # Initialize components
    llm = MockLLM()
    validation_layer = ValidationLayer(llm)
    attacks = list(get_registered_attacks().values())

    print(f"Running {len(attacks)} attacks...")
    print()

    # Run comparison tests
    results_without, results_with = run_comparison_tests(
        attack_classes=attacks,
        llm=llm,
        validation_layer=validation_layer,
    )

    # Calculate metrics
    before_rate = calculate_success_rate(results_without)
    after_rate = calculate_post_mitigation_success_rate(results_with)
    reduction = calculate_reduction_percentage(before_rate, after_rate)
    security_score = calculate_security_score(after_rate)
    meets_target = after_rate < 0.05

    # Display results
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Success Rate (Before Mitigation): {before_rate * 100:.1f}%")
    print(f"Success Rate (After Mitigation):  {after_rate * 100:.1f}%")
    print(f"Reduction:                        {reduction:.1f}%")
    print(f"Security Score:                   {security_score:.1f}%")
    print()

    if meets_target:
        print("✅ TARGET MET: Post-mitigation success rate is below 5%")
    else:
        print("⚠️  TARGET NOT MET: Post-mitigation success rate is above 5%")
    print()

    # Show individual attack results
    print("=" * 60)
    print("INDIVIDUAL ATTACK RESULTS")
    print("=" * 60)
    print(f"{'Attack Name':<30} {'Before':<10} {'After':<10}")
    print("-" * 60)

    for result_without, result_with in zip(results_without, results_with):
        before_status = "✅ Success" if result_without.success_before else "❌ Blocked"
        after_status = "✅ Success" if result_with.success_after else "❌ Blocked"
        print(f"{result_without.attack_name:<30} {before_status:<10} {after_status:<10}")

    print()
    print("=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
