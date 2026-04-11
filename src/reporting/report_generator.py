"""Report generator for PatchScout."""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

import pandas as pd


class ReportGenerator:
    """Generates vulnerability reports in various formats."""

    REQUIRED_COLUMNS = [
        'S.No',
        'Primary Language of Benchmark',
        'Vulnerability',
        'CVE ID',
        'Severity',
        'Common Weakness Enumeration (CWE) Id',
        'file name with path',
        'line number',
        'Code Snippet at the line',
    ]

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}

    @staticmethod
    def _pick(vuln: Dict[str, Any], *keys: str, default: Any = 'N/A') -> Any:
        for key in keys:
            value = vuln.get(key)
            if value not in (None, ''):
                return value
        return default

    def _normalize_row(self, vulnerability: Dict[str, Any], index: int) -> Dict[str, Any]:
        return {
            'S.No': index,
            'Primary Language of Benchmark': self._pick(vulnerability, 'language', default='Unknown'),
            'Vulnerability': self._pick(vulnerability, 'type', 'vulnerability_type', default='Unknown'),
            'CVE ID': self._pick(vulnerability, 'cve', 'cve_id', default='N/A'),
            'Severity': self._pick(vulnerability, 'severity', default='Unknown'),
            'Common Weakness Enumeration (CWE) Id': self._pick(vulnerability, 'cwe', 'cwe_id', default='N/A'),
            'file name with path': self._pick(vulnerability, 'file_path', 'file_name', default='Unknown'),
            'line number': self._pick(vulnerability, 'line_number', 'line', default='N/A'),
            'Code Snippet at the line': self._pick(vulnerability, 'code_snippet', default='N/A'),
        }

    def generate_excel_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        output_path: str,
        team_name: str = 'Team_Name',
    ):
        report_data = [
            self._normalize_row(vulnerability=vuln, index=idx)
            for idx, vuln in enumerate(vulnerabilities, start=1)
        ]

        df = pd.DataFrame(report_data, columns=self.REQUIRED_COLUMNS)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if output_file.suffix.lower() != '.xlsx':
            output_file = output_file.parent / f'GC_PS_01_{team_name}.xlsx'

        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
            summary_df = self._generate_summary(vulnerabilities)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)

        return str(output_file)

    def _generate_summary(self, vulnerabilities: List[Dict[str, Any]]) -> pd.DataFrame:
        total_vulns = len(vulnerabilities)

        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        language_counts: Dict[str, int] = {}
        cwe_counts: Dict[str, int] = {}

        for vuln in vulnerabilities:
            severity = self._pick(vuln, 'severity', default='Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1

            language = self._pick(vuln, 'language', default='Unknown')
            language_counts[language] = language_counts.get(language, 0) + 1

            cwe = self._pick(vuln, 'cwe', 'cwe_id', default='N/A')
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

        summary_data = [
            {'Metric': 'Total Vulnerabilities', 'Count': total_vulns},
            {'Metric': 'Critical Severity', 'Count': severity_counts['Critical']},
            {'Metric': 'High Severity', 'Count': severity_counts['High']},
            {'Metric': 'Medium Severity', 'Count': severity_counts['Medium']},
            {'Metric': 'Low Severity', 'Count': severity_counts['Low']},
            {'Metric': 'Languages Covered', 'Count': len(language_counts)},
            {'Metric': 'Distinct CWE IDs', 'Count': len(cwe_counts)},
            {'Metric': 'Report Generated', 'Count': datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
        ]

        return pd.DataFrame(summary_data)

    def generate_json_report(self, vulnerabilities: List[Dict[str, Any]], output_path: str):
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'tool': 'PatchScout v1.0.0',
            },
            'vulnerabilities': vulnerabilities,
        }

        with open(output_file, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)

        return str(output_file)
