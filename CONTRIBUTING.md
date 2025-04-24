# Contributing to WebShell Tester

[English](CONTRIBUTING.md) | [中文](CONTRIBUTING_CN.md)

Thank you for your interest in contributing to WebShell Tester! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Code Style Guide](#code-style-guide)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful and considerate of others.

## How to Contribute

### Reporting Issues

When reporting issues, please include:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, Docker version)
- Relevant logs or error messages

### Feature Requests

For feature requests:
- Describe the feature and its benefits
- Provide use cases
- Suggest implementation approaches if possible

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature/fix
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## Development Setup

### Prerequisites

- Python 3.8+
- Docker 20.10+
- Git
- Virtual environment (recommended)

### Setup Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/webshell_tester.git
cd webshell_tester

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development tools
```

## Code Style Guide

### Python Code

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints where appropriate
- Write docstrings for all public functions and classes
- Keep functions focused and small
- Use meaningful variable names

### Docker Configuration

- Use multi-stage builds when possible
- Minimize layer count
- Use specific version tags
- Document exposed ports and volumes

## Testing Guidelines

### Unit Tests

- Write tests for new features
- Maintain test coverage
- Use pytest for testing
- Mock external dependencies

### Integration Tests

- Test WebShell functionality
- Verify environment setup
- Test container interactions

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_environment.py

# Run with coverage
pytest --cov=core tests/
```

## Pull Request Process

1. Ensure your code passes all tests
2. Update documentation if needed
3. Provide clear commit messages
4. Reference related issues
5. Wait for review and address feedback

### Commit Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation changes
- style: Code style changes
- refactor: Code refactoring
- test: Test related changes
- chore: Maintenance tasks

## Documentation

### Code Documentation

- Use docstrings following Google style
- Document complex algorithms
- Explain non-obvious code

### User Documentation

- Update README.md for new features
- Add usage examples
- Document configuration options

## Getting Help

- Check existing issues
- Join our community chat
- Contact maintainers

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE). 