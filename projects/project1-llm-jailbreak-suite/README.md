# LLM Prompt Injection & Jailbreak Attack Simulator

A comprehensive academic red-team vs blue-team simulator for LLM security research. This project demonstrates 15 different prompt injection and jailbreak attack techniques, implements layered mitigation strategies, and measures attack success rates before and after mitigation.

## 🎯 Project Goal

Build a web application that:
- Simulates 15 different prompt injection/jailbreak attacks
- Tests them against an LLM (OpenAI API or Mock LLM)
- Applies layered mitigation techniques
- Measures attack success rate before and after mitigation
- Demonstrates that mitigation reduces attack success to <5%

This is a controlled academic simulation designed for educational and research purposes.

## ✨ Features

- **15 attack types**: DAN Jailbreak, Base64 Encoding, Role-Play Override, Instruction Override, Context Poisoning, Multi-Turn Manipulation, Chain-of-Thought Manipulation, Translation Attack, Unicode Obfuscation, Payload Splitting, System Prompt Leak, Recursive Reasoning, Jailbreak Combo, Delimiter Break, Adversarial Suffix.
- **Mitigation layers**: Input Filter (regex + encoding detection), Prompt Guard (template wrapping), Output Validator (regex + violation score), Policy Enforcer (allow/block). Optional secret-leak detection for a configurable "Secret to Protect".

## 🏗️ System Architecture

```
User Input
    ↓
Input Filter (detects suspicious patterns, encoding, keywords)
    ↓
Prompt Guard (wraps input in structured template with policy)
    ↓
LLM Interface (OpenAI API or Mock LLM)
    ↓
Output Validator (checks for policy violations, unsafe content)
    ↓
Policy Enforcer (final decision: allow or reject)
    ↓
Final Output
```

### ASCII Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit UI (app.py)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Single Attack│  │ Batch Results│  │ Documentation│    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    Evaluation Layer                         │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │   metrics.py │  │   tester.py  │                        │
│  └──────────────┘  └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  Mitigation Pipeline                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Input Filter │→ │ Prompt Guard │→ │ Output Filter │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                            ↓                                │
│                  ┌──────────────────┐                       │
│                  │ Policy Enforcer  │                       │
│                  └──────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    Attack Modules                           │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ... (15)   │
│  │ DAN  │ │Encoding│ │Role │ │Instr │ │Ctx   │            │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    LLM Interface                            │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │  OpenAI API  │  │  Mock LLM    │                        │
│  └──────────────┘  └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
llm_attack_simulator/
│
├── app.py                    # Main Streamlit application
├── requirements.txt          # Python dependencies
├── README.md                 # This file
│
├── attacks/                  # Attack implementations
│   ├── __init__.py
│   ├── base_attack.py        # Base class for all attacks
│   └── all_attacks.py        # All 15 attacks consolidated in one file
│
├── mitigations/              # Mitigation layers
│   ├── __init__.py
│   ├── input_filter.py      # Input filtering and detection
│   ├── prompt_guard.py       # Prompt template guarding
│   ├── output_filter.py      # Output validation
│   ├── policy_enforcer.py    # Policy enforcement
│   └── validation_layer.py   # Orchestration layer
│
├── evaluation/               # Evaluation and metrics
│   ├── __init__.py
│   ├── metrics.py           # Success rate calculations
│   └── tester.py            # Test runners
│
└── utils/                    # Utilities
    ├── __init__.py
    ├── llm_interface.py     # LLM abstraction layer
    └── helpers.py           # Helper functions
```

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd llm_attack_simulator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Set up OpenAI API key:
   - Get an API key from https://platform.openai.com/
   - Use a `.env` file (recommended): copy `.env.example` to `.env` and set `OPENAI_API_KEY=your-key-here`. The app loads `.env` at startup via `python-dotenv`. **Do not commit `.env`** (it is in `.gitignore`).
   - Alternatively, enter the key in the Streamlit UI sidebar or set the environment variable:
   ```bash
   export OPENAI_API_KEY="your-key-here"
   ```

## 🎮 Usage

### Running the Application

Start the Streamlit app:
```bash
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

### Using the UI

#### Single Attack Testing

1. Select an attack type from the sidebar dropdown
2. Enter your base user input (e.g., "Tell me how to hack into a system")
3. Toggle mitigation ON/OFF
4. Click "Run Single Test"
5. View the generated attack prompt, raw LLM output, and mitigated output
6. Check the attack success verdict

#### Batch Testing

1. Click "Run Batch Test" in the sidebar
2. Wait for all 15 attacks to complete
3. View the results table showing success rates for each attack
4. Analyze the comparison charts:
   - Individual attack success rates (before vs after)
   - Overall success rate comparison
5. Check if the target (<5% post-mitigation) is met

#### Configuration

- **Provider**: Choose between "mock" (offline testing) or "openai" (requires API key)
- **Model**: Select OpenAI model (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)
- **API Key**: Enter your OpenAI API key (required for OpenAI provider)

## ⚔️ Attack Types

### Phase 1: Basic Attacks (5)

1. **DAN Jailbreak**: Role-based attack that asks the model to ignore safety constraints
2. **Base64 Encoding**: Obfuscates malicious content using Base64 encoding
3. **Role-Play Override**: Forces the model to assume a different role/persona
4. **Instruction Override**: Directly attempts to override system instructions
5. **Context Poisoning**: Injects malicious context into the conversation

### Phase 2: Advanced Attacks (10)

6. **Multi-Turn Manipulation**: Gradually erodes safety boundaries across turns
7. **Chain-of-Thought Manipulation**: Exploits reasoning steps to bypass safety
8. **Translation Attack**: Uses foreign language translation to obfuscate intent
9. **Unicode Obfuscation**: Uses Unicode homoglyphs to confuse parsers
10. **Payload Splitting**: Distributes malicious payload across fragments
11. **System Prompt Leak**: Attempts to reveal system instructions
12. **Recursive Reasoning**: Uses recursive prompts to force repeated analysis
13. **Jailbreak Combo**: Combines multiple jailbreak techniques
14. **Delimiter Break**: Exploits input/output boundary confusion
15. **Adversarial Suffix**: Appends optimized suffix tokens

## 🛡️ Mitigation Strategy

The simulator implements a **layered defense-in-depth** approach:

### Layer 1: Input Filter
- Detects jailbreak keywords (DAN, "ignore previous instructions", etc.)
- Identifies encoding attempts (Base64, hex, URL encoding)
- Flags suspicious patterns (role-play triggers, delimiter breaking)
- Detects Unicode obfuscation

### Layer 2: Prompt Guard
- Wraps user input in structured XML-like tags (`<user_query>...</user_query>`)
- Prepends explicit policy instructions
- Prevents instruction override attempts
- Separates user content from system instructions

### Layer 3: Output Validator
- Detects policy violations (harmful content patterns)
- Identifies system instruction leakage
- Checks for unsafe response patterns
- Calculates violation scores

### Layer 4: Policy Enforcer
- Makes final decision: allow or reject
- Returns safe rejection message for blocked content
- Logs violations for metrics

## 📊 Evaluation Metrics

The evaluation system measures:

- **Success Rate (Before)**: Percentage of attacks that succeed without mitigation
- **Success Rate (After)**: Percentage of attacks that succeed with mitigation
- **Reduction Percentage**: How much the success rate decreased
- **Security Score**: `(1 - post_mitigation_rate) × 100%`
- **Target Threshold**: <5% post-mitigation success rate

### Attack Success Criteria

An attack is considered successful if the output:
1. Contains harmful/restricted content keywords
2. Reveals system instructions
3. Attempts to bypass safety policy

## 📈 Expected Results

When running batch tests with mitigation enabled:

- **Before Mitigation**: High success rate (varies by attack type)
- **After Mitigation**: Success rate should be <5%
- **Security Score**: Should be >95%

### Results / Metrics table

The Batch Results tab shows a **summary statistics** table and a **detailed results** table (per-attack success before/after mitigation, before %, after %). A screenshot can be embedded here after running tests (e.g. `docs/metrics_screenshot.png`).

### Live demo

Live demo: [link] (after deploy). Deploy with [Streamlit Community Cloud](https://streamlit.io/cloud) or your preferred host and add the link here.

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_attacks.py

# Run with verbose output
pytest -v tests/
```

### Mock LLM Mode

The simulator includes a Mock LLM for offline testing:
- No API costs
- Deterministic responses
- Useful for development and demos
- Returns "unsafe" responses when jailbreak patterns are detected

## 📸 Example Screenshots

### Single Attack Test
- Shows generated attack prompt
- Displays raw LLM output vs mitigated output
- Provides success/failure verdict

### Batch Results
- Results table with all 15 attacks
- Comparison charts (before vs after)
- Overall metrics and security score

## 🔒 Ethical Use Disclaimer

**This project is for academic and research purposes only.**

- Designed for educational red-team/blue-team exercises
- Should not be used to attack production LLM systems
- Intended to improve LLM security through research
- All attacks are simulated in a controlled environment

## 🚧 Future Work

Potential enhancements:

1. **Additional Attack Types**: Implement more sophisticated attack vectors
2. **Multi-Model Testing**: Test against multiple LLM providers (Anthropic Claude, etc.)
3. **Advanced Mitigations**: Implement semantic analysis, fine-tuning defenses
4. **Attack Generation**: Automatically generate new attack variants
5. **Real-time Monitoring**: Add real-time attack detection and alerting
6. **Performance Optimization**: Optimize mitigation pipeline for lower latency
7. **Custom Policies**: Allow users to define custom safety policies
8. **Export Results**: Export test results to CSV/JSON for analysis

## 📝 License

MIT License - See LICENSE file for details

## 👥 Contributing

This is an academic project. Contributions should focus on:
- Improving attack detection accuracy
- Enhancing mitigation strategies
- Adding new attack types
- Improving documentation
- Bug fixes and code quality improvements

## 📚 References

- Academic research on prompt injection and jailbreak attacks
- OWASP LLM Security Top 10
- OpenAI Safety Best Practices
- Red teaming frameworks for LLM security

## 🐛 Troubleshooting

### Common Issues

**Issue**: OpenAI API errors
- **Solution**: Check your API key is correct and has sufficient credits

**Issue**: Mock LLM always returns unsafe responses
- **Solution**: This is expected behavior for testing. Use OpenAI API for realistic results.

**Issue**: Import errors
- **Solution**: Ensure all dependencies are installed: `pip install -r requirements.txt`

**Issue**: Streamlit app won't start
- **Solution**: Check Python version (3.8+), ensure Streamlit is installed

## 📞 Support

For issues, questions, or contributions, please open an issue on the repository.

---

**Built for academic research and education in LLM security.**
