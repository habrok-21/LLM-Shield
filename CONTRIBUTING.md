# Contributing to ShieldLLM

Thank you for considering contributing to ShieldLLM. This document outlines our standards, workflow, and expectations to keep the project maintainable and high-quality.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Commit Guidelines](#commit-guidelines)
- [Feature Requests & Bug Reports](#feature-requests--bug-reports)

## Code of Conduct

This project adheres to the [Apache 2.0 License](LICENSE) and expects all contributors to maintain a respectful, inclusive, and constructive environment. Harassment, personal attacks, or disruptive behavior are not tolerated.

## Getting Started

1. **Fork** the repository and **clone** your fork.
2. **Set up** your local environment (see [Development Setup](#development-setup)).
3. **Find an issue** to work on — look for [good first issue] or [help wanted] labels.
4. **Discuss** in the issue before writing code for significant changes.
5. **Submit** a pull request once your changes are ready.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/habrok-21/LLM-Shield.git
cd shieldllm

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies (linting, testing)
pip install pytest pytest-asyncio pyyaml ruff

# Verify everything works
python3 app.py &
curl http://localhost:8080/health
```

Optional ML guard dependencies:

```bash
# For ONNX backend
pip install onnxruntime tokenizers numpy

# For HuggingFace backend
pip install transformers torch
```

## Code Standards

### Language & Runtime

- **Python 3.9+** — all code must be compatible with Python 3.9.
- **Type annotations** — all function signatures must include type hints.
- **Async-first** — I/O operations (HTTP calls, file reads) must use `asyncio`.

### Style

We enforce [Ruff](https://docs.astral.sh/ruff/) with the following rules:

```bash
make lint   # runs ruff check
```

Rules we follow:

- **Line length**: 100 characters maximum.
- **Quotes**: double quotes for strings (`"`), single quotes only inside double-quoted strings.
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants.
- **Imports**: standard library → third-party → local, one blank line between groups.
- **Docstrings**: module-level docstrings required. Class and public method docstrings encouraged.
- **No comments in code** — prefer self-documenting code with clear names. If a comment is needed, write a docstring on the enclosing function.

### Module Patterns

Each module in `security/` follows a consistent pattern:

1. Module-level docstring describing the module's purpose.
2. Constants in `UPPER_CASE`.
3. Public functions with type annotations and docstrings.
4. Internal functions prefixed with `_`.

## Testing

**All new code must include tests.** We use `pytest` with `pytest-asyncio`.

```bash
# Run all tests
make test

# Run a specific test file
python3 -m pytest tests/test_ingress.py -v

# Run a specific test
python3 -m pytest tests/test_ingress.py::TestCheckIngress::test_banned_keyword -v
```

### Test conventions

- **File naming**: `tests/test_<module>.py`
- **Class naming**: `Test<Module>` (e.g., `TestCheckIngress`)
- **Method naming**: `test_<scenario>` (e.g., `test_banned_keyword_blocked`)
- **Coverage**: include positive (blocked) and negative (allowed) cases.
- **Mocking**: avoid mocking — tests should test real logic. Use synthetic inputs instead.
- **Fixtures**: prefer factory functions over `pytest.fixture` for simplicity.

## Pull Request Process

1. **Create a feature branch** from `main`:

   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** following the [Code Standards](#code-standards).
3. **Run tests** and ensure they all pass.
4. **Run the linter** and fix any warnings.
5. **Commit** your changes (see [Commit Guidelines](#commit-guidelines)).
6. **Push** to your fork and open a pull request against `main`.

### PR requirements

- **Title**: concise, prefixed with the type (e.g., `feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- **Description**: explain what the change does and why. Link related issues.
- **Checklist**:
  - [ ] Tests pass (`make test`)
  - [ ] Linter passes (`make lint`)
  - [ ] New code has tests
  - [ ] Type annotations added
  - [ ] Module docstring updated if applicable
  - [ ] No commented-out code

### Review process

- Maintainers will review within 3 business days.
- Address review feedback promptly.
- Once approved, a maintainer will merge your PR.

## Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`.

Examples:

```
feat(ingress): add leetspeak detection for common substitutions
fix(egress): handle empty response in PII scanner
docs: add API reference for config endpoint
test(cache): add TTL expiry edge case
```

## Feature Requests & Bug Reports

### Bug reports

Open an issue with:

- **Summary**: one-line description.
- **Steps to reproduce**: minimal code or curl example.
- **Expected vs actual behavior**.
- **Environment**: Python version, OS, dependency versions.

### Feature requests

Open an issue with:

- **Problem**: what problem are you solving?
- **Proposed solution**: how would you implement it?
- **Alternatives considered**: any other approaches you thought of.

## Project Structure

```
shieldllm/
├── app.py                  # FastAPI server, proxy pipeline, API endpoints
├── dashboard.html          # Self-contained SPA (no CDN deps)
├── config.yml              # YAML config with env var overrides
├── security/               # Core filtering modules
│   ├── ingress.py          # Input protection pipeline
│   ├── egress.py           # Output protection pipeline
│   ├── exfiltration.py     # Secret/key pattern detection
│   ├── safety.py           # Content safety & contradiction
│   ├── cyber.py            # SSRF, XSS, command injection
│   ├── rate_limiter.py     # Token budget rate limiter
│   ├── router.py           # Circuit breaker & provider routing
│   ├── cache.py            # Semantic response cache
│   ├── streaming.py        # SSE stream inspector
│   ├── encoders.py         # Encoded payload detection
│   ├── guard_model.py      # ML guard orchestrator
│   ├── guard_onnx.py       # ONNX backend
│   ├── guard_hf.py         # HuggingFace backend
│   ├── guardrails_plugin.py# Guardrails AI integration
│   ├── ip_filter.py        # IP allowlist/blocklist
│   ├── state.py            # Stats tracker
│   ├── dashboard.py        # SSE event bus
│   ├── audit.py            # JSON audit logging
│   └── config.py           # Config loader
└── tests/                  # Test suite
```

## Questions?

Open a [Discussion](https://github.com/habrok-21/LLM-Shield/discussions) or ask in the issue tracker. We're happy to help new contributors.
