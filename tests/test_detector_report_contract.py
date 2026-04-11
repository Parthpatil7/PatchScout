from pathlib import Path

import pandas as pd

from src.detectors.vulnerability_detector import VulnerabilityDetector
from src.reporting.report_generator import ReportGenerator


def test_detector_returns_normalized_contract_fields():
    detector = VulnerabilityDetector(config={})
    code = """
user = input()
query = "SELECT * FROM users WHERE id = " + user
"""

    vulnerabilities = detector.detect(code, 'python', 'sample.py')
    assert vulnerabilities

    required = {
        'type',
        'severity',
        'cwe',
        'cve',
        'line_number',
        'code_snippet',
        'description',
        'file_path',
        'language',
        'source',
        'confidence',
    }

    for vulnerability in vulnerabilities:
        assert required.issubset(vulnerability.keys())
        assert 0.0 <= vulnerability['confidence'] <= 1.0


def test_report_generator_accepts_canonical_contract(tmp_path: Path):
    vulnerabilities = [
        {
            'type': 'SQL Injection',
            'severity': 'Critical',
            'cwe': 'CWE-89',
            'cve': 'N/A',
            'line_number': 10,
            'code_snippet': 'query = "SELECT" + user',
            'description': 'demo',
            'file_path': 'src/app.py',
            'language': 'python',
            'source': 'pattern',
            'confidence': 0.9,
        }
    ]

    output_file = tmp_path / 'report.xlsx'
    generator = ReportGenerator(config={})
    generated_path = generator.generate_excel_report(vulnerabilities, str(output_file), team_name='Team')

    assert Path(generated_path).exists()

    df = pd.read_excel(generated_path, sheet_name='Vulnerabilities', keep_default_na=False)
    assert list(df.columns) == generator.REQUIRED_COLUMNS
    assert df.iloc[0]['Vulnerability'] == 'SQL Injection'
    assert df.iloc[0]['CVE ID'] == 'N/A'
    assert df.iloc[0]['Common Weakness Enumeration (CWE) Id'] == 'CWE-89'
