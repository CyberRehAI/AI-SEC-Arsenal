"""
Attack package.

All attacks are consolidated in all_attacks.py for easier management.
The ``get_registered_attacks`` helper is used by the Streamlit UI and
the evaluation harness to dynamically discover attacks.
"""

from .base_attack import BaseAttack


def get_registered_attacks() -> dict[str, type[BaseAttack]]:
    """Return a mapping of attack_name -> attack class."""
    # Import all attacks from the consolidated file
    from .all_attacks import (
        AdversarialSuffixAttack,
        CoTManipulationAttack,
        ContextPoisoningAttack,
        DANAttack,
        DelimiterBreakAttack,
        EncodingAttack,
        InstructionOverrideAttack,
        JailbreakComboAttack,
        MultiTurnAttack,
        PayloadSplittingAttack,
        RecursiveReasoningAttack,
        RolePlayAttack,
        SystemPromptLeakAttack,
        TranslationAttack,
        UnicodeObfuscationAttack,
    )

    attacks: list[type[BaseAttack]] = [
        DANAttack,
        EncodingAttack,
        RolePlayAttack,
        InstructionOverrideAttack,
        ContextPoisoningAttack,
        MultiTurnAttack,
        CoTManipulationAttack,
        TranslationAttack,
        UnicodeObfuscationAttack,
        PayloadSplittingAttack,
        SystemPromptLeakAttack,
        RecursiveReasoningAttack,
        JailbreakComboAttack,
        DelimiterBreakAttack,
        AdversarialSuffixAttack,
    ]

    return {attack.attack_name: attack for attack in attacks}

