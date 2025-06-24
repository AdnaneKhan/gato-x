# Contributing to Gato-X

Contributions are welcome! This document provides guidelines and instructions for contributing to the Gato-X project.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- A GitHub account

### Setting Up the Development Environment

1. Fork the Gato-X repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/gato-x.git
   cd gato-x
   ```
3. Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install in development mode:
   ```bash
   pip install -e .
   ```

## Development Guidelines

### Code Style

Gato-X follows the Black code style. Before submitting a pull request, format your code:

```bash
pip install black
black .
```

### Adding New Features

When adding new features:

1. Create a new branch:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Implement your feature
3. Add tests for your feature
4. Update documentation
5. Submit a pull request

### Design Methodology

Before working on significant changes, please review the project's design methodology:

1. **Operator-Focused**: Gato-X is designed for security practitioners, prioritizing usability and effectiveness over perfect precision
2. **Avoid False Negatives**: The tool is tuned to catch all potential vulnerabilities, even if it means some false positives
3. **Provide Context**: For each finding, provide enough context for operators to quickly determine if it's a true positive
4. **Performance Matters**: The tool should be able to scan thousands of repositories efficiently

## Submitting Changes

### Pull Request Process

1. Ensure your code follows the project's style guidelines
2. Update documentation to reflect your changes
3. Add or update tests as necessary
4. Submit a pull request with a clear description of the changes

### Proposing Significant Changes

If you're proposing significant changes to the tool, please open an issue first to discuss the motivation for the changes.

## Reporting Issues

If you find a bug or have a feature request:

1. Check if the issue already exists in the GitHub issues
2. If not, create a new issue with:
   - A clear description of the problem
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Any relevant logs or screenshots

For more detailed information about contributing, see [Advanced Contributing Guide](advanced/contributing.md).
