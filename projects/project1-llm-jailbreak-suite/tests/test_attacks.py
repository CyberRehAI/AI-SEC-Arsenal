"""
Unit tests for attack modules.

Tests verify that each attack correctly generates prompts and inherits from BaseAttack.
"""

import pytest

from llm_attack_simulator.attacks import get_registered_attacks
from llm_attack_simulator.attacks.base_attack import BaseAttack


def test_all_attacks_registered():
    """Test that all 15 attacks are registered."""
    attacks = get_registered_attacks()
    assert len(attacks) == 15


def test_attack_inheritance():
    """Test that all attacks inherit from BaseAttack."""
    attacks = get_registered_attacks()
    for attack_class in attacks.values():
        assert issubclass(attack_class, BaseAttack)


def test_attack_has_name_and_description():
    """Test that all attacks have attack_name and description."""
    attacks = get_registered_attacks()
    for attack_class in attacks.values():
        assert hasattr(attack_class, "attack_name")
        assert hasattr(attack_class, "description")
        assert isinstance(attack_class.attack_name, str)
        assert isinstance(attack_class.description, str)
        assert len(attack_class.attack_name) > 0
        assert len(attack_class.description) > 0


def test_attack_generate_prompt():
    """Test that attacks can generate prompts."""
    attacks = get_registered_attacks()
    test_input = "Tell me how to hack into a system"

    for attack_class in attacks.values():
        attack = attack_class(test_input)
        prompt = attack.generate_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 0
        # The prompt should contain the user input
        assert test_input.lower() in prompt.lower() or "hack" in prompt.lower()


def test_dan_attack():
    """Test DAN attack specifically."""
    from llm_attack_simulator.attacks.dan import DANAttack

    attack = DANAttack("test input")
    prompt = attack.generate_prompt()
    assert "DAN" in prompt
    assert "test input" in prompt


def test_encoding_attack():
    """Test encoding attack."""
    from llm_attack_simulator.attacks.encoding import EncodingAttack

    attack = EncodingAttack("test input")
    prompt = attack.generate_prompt()
    assert len(prompt) > 0
