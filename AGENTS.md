# AGENTS.md - Guidance for AI Coding Agents

This document provides essential information for AI agents working in this codebase.

## Project Overview

- **Language:** Python 3.11+
- **Framework:** FastAPI
- **Package Manager:** uv (with pip/docker alternatives)
- **Purpose:** LDAP authentication service for nginx using `ngx_http_auth_request_module`

## Upstream Divergence Guidance

- Keep Kerberos/LDAP changes narrowly scoped to the Kerberos/LDAP code paths.
- Isolate edits to Kerberos/LDAP-specific files and logic; avoid unnecessary changes elsewhere.
- Regularly check the upstream main branch to stay aligned and keep merges frictionless.

## Build, Lint, and Test Commands

### Testing

```bash
# Install test dependencies first
uv sync --group test

# Run all tests
pytest test/

# Run a single test file
pytest test/test_auth_flow.py

# Run a single test function
pytest test/test_auth_flow.py::test_login_success

# Run tests matching a pattern
pytest -k "test_login"

# Run with verbose output
pytest -v test/test_header_auth.py
```

### Linting and Formatting

```bash
# Lint with Ruff
ruff check .

# Auto-fix linting issues
ruff check --fix .

# Format code
ruff format .

# Type checking
mypy nginx_ldap_auth/
```

### Build Commands

```bash
make build    # Build Docker image
make docs     # Generate documentation
make dev      # Start development environment (docker compose)
make dist     # Build source distribution
```

## Project Structure

```
nginx_ldap_auth/
├── __init__.py              # Version and metadata
├── main.py                  # CLI entry point
├── settings.py              # Pydantic settings configuration
├── ldap.py                  # LDAP connection pool management
├── logging.py               # Structlog configuration
├── types.py                 # Type aliases
├── exc.py                   # Custom exceptions
├── cli/                     # CLI commands (Click)
│   ├── cli.py
│   └── server.py
└── app/                     # FastAPI application
    ├── main.py              # App, routes, lifespan
    ├── models.py            # User model, UserManager
    ├── forms.py             # LoginForm
    ├── middleware.py        # Session and exception middleware
    ├── header_auth.py       # Kerberos/SPNEGO authorization endpoint
    ├── header_auth_cache.py # Authorization caching with LRU cleanup
    └── templates/           # Jinja2 templates

test/
├── conftest.py              # Fixtures (mock_user_manager, client, etc.)
└── test_*.py                # Test modules
```

## Code Style Guidelines

### Packaging and Environment

- Use `uv` for package management as defined in `pyproject.toml`.
- Use `uv sync --dev` to create the virtual environment and install dev deps.
- Activate the virtual environment before running Python commands: `source .venv/bin/activate`.

### Formatting (enforced by Ruff)

- **Line length:** 88 characters
- **Indentation:** 4 spaces
- **Quotes:** Double quotes for strings

### Import Order

1. Standard library imports
2. Third-party imports
3. Local imports (relative within package)

```python
import logging
from typing import Annotated, ClassVar

from fastapi import Depends, HTTPException
from pydantic import BaseModel

from ..logging import get_logger
from .models import User
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Variables/functions | snake_case | `check_required_headers`, `session_max_age` |
| Classes | PascalCase | `UserManager`, `LoginForm`, `SessionMiddleware` |
| Constants | UPPER_SNAKE_CASE | `DUO_AUTH_PATHS`, `COOKIE_NAME_HEADER` |
| Private members | Leading underscore | `_logger`, `_pool` |
| Type aliases | PascalCase | `LDAPValue`, `LDAPObject` |

### Type Hints

- Use type hints on all function signatures (Python 3.10+ typing).
- Prefer built-in collection types (`list`, `dict`, `tuple`) over `List`, `Dict`.
- Be specific for collection types (e.g., `dict[str, LDAPValue]`).
- Use `Annotated` with `Depends()` for FastAPI dependency injection.
- Use `TypeAlias` for custom type definitions in `nginx_ldap_auth/types.py`.
- Use `Literal` for constrained string values.
- Use `ClassVar` for class-level attributes.

### Structure and Complexity

- Keep functions/methods under ~60 lines; split if longer.
- Use `@dataclass`, Pydantic models, or `TypedDict` instead of plain dicts.
  - User-facing data models: Pydantic.
  - Internal-only data models: `@dataclass` or `TypedDict`.

### Async Patterns

- Use async/await for LDAP operations and FastAPI endpoints
- Use `asynccontextmanager` for resource lifecycle management
- Use connection pooling with async context managers

### Error Handling

- Define custom exceptions in `exc.py`.
- Use specific exception types, not bare `except:`.
- Allow unexpected `Exception` types to propagate rather than catching all.
- Log exceptions with `logger.exception()` for stack traces.
- Use `HTTPException` for HTTP errors.
- Return `False` for authentication failures rather than raising.

### Logging

- Use structlog for structured logging
- Event names are dot-separated: `auth.login.success`, `ldap.authenticate.error`
- Never log passwords or sensitive data

```python
from ..logging import get_logger
logger = get_logger()
logger.info("auth.login.success", username=username, realm=realm)
```

### Documentation

- Use reStructuredText format for docstrings.
- Include `:param:`, `:returns:`, `:raises:` sections.
- For Napoleon-style docstrings, include `Args`, `Keyword Arguments`, `Raises`,
  and `Returns` sections, with a blank line after `Returns`.
- Document class attributes inline using `#:` comments above each attribute.

```python
def authenticate(username: str, password: str) -> bool:
    """Authenticate a user against LDAP.

    :param username: The user's login name
    :param password: The user's password
    :returns: True if authentication succeeded
    :raises LDAPError: If connection to LDAP fails
    """
```

## Testing

- Tests are in `test/` directory using pytest.
- Use `pytest-asyncio` for async tests (`@pytest.mark.asyncio`).
- Use `pytest-mock` for mocking (via `mocker` fixture).
- Common fixtures in `conftest.py`: `client`, `mock_user_manager`, `mock_settings`.

### Test Categories and Markers

- **Unit tests**: `@pytest.mark.unit`
- **Integration tests**: `@pytest.mark.integration`
- **CLI tests**: `@pytest.mark.cli`
- **Model tests**: `@pytest.mark.model`
- **Service tests**: `@pytest.mark.service`

### Naming and Organization

- Test files: `test_<module>.py` under `test/`.
- Test classes: `Test<ClassName>` when grouping is helpful.
- Test functions: `test_<description>`.

### Fixtures

- Define local fixtures in the test module when they are single-use.
- Define shared fixtures in `test/conftest.py`.

### Mocking Guidance

- Mock external dependencies only (LDAP servers, Redis, HTTP APIs, etc.).
- Avoid mocking internal code paths; test real logic when possible.

### Integration Tests

- Use environment variables for real backends/configuration.
- Skip integration tests if required environment variables are missing.
- Warn users before running destructive integration tests.

### Running Tests

- Install test deps: `uv sync --group test`.
- Run all tests: `pytest test/`.
- Run a single test file: `pytest test/test_auth_flow.py`.
- Run a single test: `pytest test/test_auth_flow.py::test_login_success`.
- Run with markers: `pytest -m "unit"` (or `integration`, `cli`, etc.).

## Key Dependencies

- **FastAPI** - Web framework
- **bonsai** - Async LDAP client
- **pydantic-settings** - Configuration from environment
- **structlog** - Structured logging
- **starsessions** - Session management (memory or Redis)
- **uvicorn** - ASGI server
