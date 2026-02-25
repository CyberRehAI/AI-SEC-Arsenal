#!/usr/bin/env python3
"""
Script to run all tests for the LLM Attack Simulator.

Usage:
    python scripts/run_tests.py
    python scripts/run_tests.py -v  # verbose
    python scripts/run_tests.py tests/test_attacks.py  # specific test file
"""

import sys
import subprocess
from pathlib import Path


def main():
    """Run pytest with appropriate arguments."""
    project_root = Path(__file__).parent.parent
    test_dir = project_root / "tests"

    # Default pytest arguments
    pytest_args = [
        "pytest",
        str(test_dir),
        "-v",
        "--tb=short",
    ]

    # Add any command-line arguments
    if len(sys.argv) > 1:
        pytest_args.extend(sys.argv[1:])
    else:
        # Default: run all tests
        pytest_args.append(str(test_dir))

    print(f"Running tests from: {test_dir}")
    print(f"Command: {' '.join(pytest_args)}")
    print("-" * 60)

    result = subprocess.run(pytest_args, cwd=project_root)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
