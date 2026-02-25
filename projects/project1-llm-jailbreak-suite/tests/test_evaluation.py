"""
Unit tests for evaluation metrics and test runners.

Tests verify that metrics are calculated correctly and test runners work.
"""

import pytest

from llm_attack_simulator.evaluation.metrics import (
    AttackResult,
    calculate_post_mitigation_success_rate,
    calculate_reduction_percentage,
    calculate_security_score,
    calculate_success_rate,
    is_attack_successful,
    meets_target_threshold,
)
from llm_attack_simulator.evaluation.tester import run_single_attack
from llm_attack_simulator.attacks.dan import DANAttack
from llm_attack_simulator.mitigations import ValidationLayer
from llm_attack_simulator.utils.llm_interface import MockLLM


def test_is_attack_successful():
    """Test attack success detection."""
    unsafe_output = "Here's how to hack into a system..."
    assert is_attack_successful(unsafe_output)

    safe_output = "I cannot provide instructions for hacking."
    assert not is_attack_successful(safe_output)


def test_calculate_success_rate():
    """Test success rate calculation."""
    results = [
        AttackResult("test1", "input1", "output1", success_before=True),
        AttackResult("test2", "input2", "output2", success_before=False),
        AttackResult("test3", "input3", "output3", success_before=True),
    ]
    rate = calculate_success_rate(results)
    assert rate == pytest.approx(2 / 3)


def test_calculate_post_mitigation_success_rate():
    """Test post-mitigation success rate calculation."""
    results = [
        AttackResult("test1", "input1", "output1", mitigated_output="out1", success_after=True, mitigation_enabled=True),
        AttackResult("test2", "input2", "output2", mitigated_output="out2", success_after=False, mitigation_enabled=True),
        AttackResult("test3", "input3", "output3", mitigated_output="out3", success_after=False, mitigation_enabled=True),
    ]
    rate = calculate_post_mitigation_success_rate(results)
    assert rate == pytest.approx(1 / 3)


def test_calculate_reduction_percentage():
    """Test reduction percentage calculation."""
    reduction = calculate_reduction_percentage(0.8, 0.2)
    assert reduction == pytest.approx(75.0)


def test_calculate_security_score():
    """Test security score calculation."""
    score = calculate_security_score(0.05)
    assert score == pytest.approx(95.0)


def test_meets_target_threshold():
    """Test target threshold check."""
    assert meets_target_threshold(0.03)
    assert not meets_target_threshold(0.10)


def test_run_single_attack():
    """Test running a single attack."""
    llm = MockLLM()
    validation_layer = ValidationLayer(llm)
    
    result = run_single_attack(
        attack_class=DANAttack,
        user_input="test input",
        llm=llm,
        validation_layer=validation_layer,
        mitigation_enabled=True,
    )
    
    assert isinstance(result, AttackResult)
    assert result.attack_name == "DAN Jailbreak"
    assert result.user_input == "test input"
    assert result.raw_output is not None
    assert result.mitigated_output is not None
