"""
Setup script for LLM Attack Simulator.

Install in development mode with: pip install -e .
"""

from setuptools import setup, find_packages

setup(
    name="llm_attack_simulator",
    version="1.0.0",
    description="Prompt Injection & Jailbreak Attack Simulator for LLM Security Research",
    packages=find_packages(),
    install_requires=[
        "streamlit>=1.28.0",
        "openai>=1.0.0",
        "plotly>=5.17.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "pytest>=7.4.0",
        "python-dotenv>=1.0.0",
    ],
    python_requires=">=3.8",
)
