# Agent Guidelines for Gato-X

## Code Quality Requirements

### Formatting & Linting
- Format all Python code with `black` (line-length: 88)
- Run `ruff check --fix` before committing
- Use `isort` for import ordering (standard library → third-party → local)
- Follow PEP8 conventions with type hints

### Documentation
- Add docstrings to all public classes, methods, and functions
- Update `docs/` for any API changes or new features
- Update CLI help text when adding commands/options

## Testing

- Tests live in `unit_test/` mirroring source structure
- Run `pytest` - all tests must pass
- Coverage must stay above 70%
- Mock external dependencies (GitHub API, file I/O)
- Test both success and failure paths

## Feature-Specific Rules

### New Detections
- MUST include Fix/Mitigation documentation
- Add defensive recommendations and remediation steps

### New Enumeration Features
- MUST add corresponding MCP server tools in `gatox/mcp/mcp_server.py`
- Update MCP docs in `docs/user-guide/mcp-server/mcp.md`

### Attack Features
- Isolate from enumeration code
- Target single resources only (no mass exploits)
- Document all steps clearly for penetration testing

## Pre-Commit Checklist

```bash
pytest                    # All tests pass
black .                   # Format code
ruff check --fix          # Lint and fix
isort gatox/              # Sort imports
```

## Design Philosophy

- Operator-focused: prioritize usability for security practitioners
- Avoid false negatives: prefer comprehensive coverage over precision
- Performance: optimize for scanning thousands of repos efficiently
- Context: provide enough detail to assess findings quickly
