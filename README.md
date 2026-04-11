# PatchScout

PatchScout is a Python CLI tool for source-code vulnerability scanning with normalized findings and competition-style reporting.

## Current Scope

Implemented and supported today:
- Language support: **Python, Java, C/C++, PHP**
- Detection: regex/rule-based plus parser-assisted checks
- Output formats: **Excel** (competition schema) and **JSON**
- Severity + CWE classification, conservative CVE attribution
- Directory scan summaries, size limits, optional parallel scan workers

Experimental / partial:
- Dataset loading utilities in `src/utils/dataset_loader.py`
- ML training pipeline and model artifacts

## Quick Start

### 1) Install runtime dependencies

```bash
pip install -r requirements.txt
```

### 2) Scan a file

```bash
python -m src.main -f test_samples/vulnerable.py -v
```

### 3) Scan a directory and generate report

```bash
python -m src.main -d test_samples -o output/GC_PS_01_TeamName.xlsx --team-name TeamName
```

### 4) JSON output

```bash
python -m src.main -d test_samples --format json -o output/results.json
```

## Testing

Install dev dependencies and run pytest:

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Dependency Sets

- `requirements.txt` → runtime dependencies
- `requirements-dev.txt` → test/lint/type tooling
- `requirements-ml.txt` → ML training stack (optional)

## CI

GitHub Actions workflow `.github/workflows/ci.yml` runs:
- dependency installation
- static checks (`compileall`, `flake8`)
- tests (`pytest`)
- artifact sanity checks

## Notes on CVE Mapping

PatchScout now uses a conservative CVE policy:
- Uses a CVE only when explicitly present and valid in evidence
- Otherwise returns `N/A` by default to avoid misleading attribution
- Optional reference mapping can be enabled via config for research usage
