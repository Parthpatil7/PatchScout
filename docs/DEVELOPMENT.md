# Development Guide

## Setup Development Environment

### 1. Clone and Setup

```bash
git clone https://github.com/Parthpatil7/PatchScout.git
cd PatchScout

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file in the project root:

```env
# API Keys (if using LLM APIs)
OPENAI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

# Model Settings
MODEL_TYPE=transformer
MODEL_NAME=microsoft/codebert-base
DEVICE=cuda

# Paths
DATA_DIR=data
MODEL_DIR=models
OUTPUT_DIR=output
```

## Project Structure

```
src/
├── analyzers/          # Code analysis modules
│   ├── __init__.py
│   ├── code_analyzer.py
│   └── language_detector.py
├── detectors/          # Vulnerability detection
│   ├── __init__.py
│   ├── vulnerability_detector.py
│   ├── pattern_matcher.py
│   └── ml_detector.py
├── parsers/            # Language parsers
│   ├── __init__.py
│   ├── java_parser.py
│   ├── python_parser.py
│   ├── c_parser.py
│   └── php_parser.py
├── mitigation/         # Fix suggestions
│   ├── __init__.py
│   └── fix_generator.py
├── reporting/          # Report generation
│   ├── __init__.py
│   └── report_generator.py
├── utils/              # Utilities
│   ├── __init__.py
│   ├── config_loader.py
│   └── dataset_loader.py
└── main.py             # Entry point
```

## Development Workflow

### 1. Adding a New Language Parser

```python
# src/parsers/new_language_parser.py
from .base_parser import BaseParser

class NewLanguageParser(BaseParser):
    def __init__(self):
        super().__init__()
        self.language = "new_language"
    
    def parse(self, code: str):
        # Implement parsing logic
        pass
    
    def extract_features(self, ast):
        # Extract features for ML model
        pass
```

### 2. Adding a New Vulnerability Detector

```python
# src/detectors/custom_detector.py
from .base_detector import BaseDetector

class CustomVulnerabilityDetector(BaseDetector):
    def detect(self, code, ast):
        vulnerabilities = []
        # Implement detection logic
        return vulnerabilities
```

### 3. Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test
pytest tests/test_parsers.py::test_java_parser
```

## Code Style

We follow PEP 8 guidelines:

```bash
# Format code
black src/

# Check style
flake8 src/

# Type checking
mypy src/
```

## Commit Guidelines

Follow conventional commits:

```
feat: add Java parser
fix: resolve SQL injection detection bug
docs: update README with examples
test: add unit tests for vulnerability detector
```

## Building and Testing

### Run the tool locally

```bash
# Test on a single file
python src/main.py --file test_data/sample.java

# Test on directory
python src/main.py --directory test_data/projects/java_app

# Generate report
python src/main.py --directory test_data --output results.xlsx
```

## Debugging

Enable verbose logging:

```bash
python src/main.py --file sample.py --verbose
```

Check logs in `output/patchscout.log`

## Performance Profiling

```python
import cProfile
import pstats

cProfile.run('main()', 'profile_stats')
stats = pstats.Stats('profile_stats')
stats.sort_stats('cumulative')
stats.print_stats(20)
```

## CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - run: pip install -r requirements.txt
      - run: pytest tests/
```

## Resources

- [Tree-sitter Documentation](https://tree-sitter.github.io/tree-sitter/)
- [Transformers Library](https://huggingface.co/docs/transformers)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [NVD CVE Database](https://nvd.nist.gov/)
