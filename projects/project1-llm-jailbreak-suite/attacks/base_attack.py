"""
Base class for all prompt-injection and jailbreak attacks.

Each concrete attack should:
* Inherit from BaseAttack
* Provide a human-readable ``attack_name`` and ``description``
* Implement ``generate_prompt`` to craft the adversarial prompt
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAttack(ABC):
    """Abstract base class for all attacks."""

    attack_name: str = "base_attack"
    description: str = "Abstract base class – do not use directly."

    def __init__(self, base_user_input: str) -> None:
        self.base_user_input = base_user_input

    @abstractmethod
    def generate_prompt(self) -> str:
        """Return the adversarial prompt to send to the LLM."""
        raise NotImplementedError

