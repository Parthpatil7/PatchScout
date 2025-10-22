# PatchScout - Quick Start Guide

## Installation

1. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

## Usage

### 1. Analyze a Single File

```bash
python -m src.main -f test_samples/vulnerable.py
```

### 2. Analyze a Directory

```bash
python -m src.main -d test_samples
```

### 3. Generate Report with Team Name

```bash
python -m src.main -d test_samples -o output/GC_PS_01_YourTeam.xlsx --team-name YourTeam
```

### 4. Verbose Output

```bash
python -m src.main -d test_samples -v
```

### 5. JSON + Excel Output

```bash
python -m src.main -d test_samples --format both
```

## Testing

Run the test suite:

```bash
python test_patchscout.py
```

## Expected Output

The tool will:
1. ✅ Detect vulnerabilities (SQL Injection, XSS, Buffer Overflow, etc.)
2. ✅ Map to CVE IDs (e.g., CVE-2023-28432)
3. ✅ Map to CWE IDs (e.g., CWE-89)
4. ✅ Assign severity (Critical, High, Medium, Low)
5. ✅ Generate Excel report in competition format
6. ✅ Support Python, Java, C/C++, PHP (Stage I languages)

## Competition Submission Format

Output file: `GC_PS_01_TeamName.xlsx`

Columns:
- S.No
- Primary Language of Benchmark
- Vulnerability
- CVE ID
- Severity
- CWE ID
- file name with path
- line number
- Code Snippet at the line

## Example Commands

### For Competition Dataset (Stage I)

```bash
# Download dataset on Oct 28, 2025
# Analyze it
python -m src.main -d path/to/dataset -o output/GC_PS_01_YourTeam.xlsx --team-name YourTeam -v

# Verify output format
python -c "import pandas as pd; df = pd.read_excel('output/GC_PS_01_YourTeam.xlsx'); print(df.head())"
```

## Performance

- Processing Speed: < 1 second per KB (target)
- Supported Languages: Java, Python, C, C++, PHP (Stage I)
- Detection: OWASP Top 10, CWE Top 25

## Architecture

```
PatchScout
├── Parsers (Language-specific AST parsing)
├── Detectors (Pattern matching + vulnerability detection)
├── Mappers (CVE/CWE mapping)
├── Analyzers (Orchestration)
└── Reporters (Excel/JSON generation)
```

## Key Features

✅ **Pattern-based detection** for common vulnerabilities
✅ **Language-specific parsers** for Python, Java, C, PHP
✅ **CVE/CWE mapping** with Top 25 CWEs
✅ **OWASP Top 10** coverage
✅ **Competition-ready Excel output**
✅ **Rich CLI** with progress bars and colored output

## Troubleshooting

If you get import errors:
```bash
# Run from project root
cd c:\Users\DELL\Desktop\Projects\PatchScout
python -m src.main -f test_samples/vulnerable.py
```

## Next Steps

1. Test on sample files ✅ (Done)
2. Download competition dataset (Oct 28, 2025)
3. Run analysis on dataset
4. Review and validate output
5. Submit before midnight Oct 31, 2025
