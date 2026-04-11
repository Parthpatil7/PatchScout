"""CVE (Common Vulnerabilities and Exposures) Mapper."""

from typing import Dict, List, Any
import re


class CVEMapper:
    """Maps vulnerabilities to CVE IDs with conservative attribution."""

    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    def __init__(self, use_reference_cves: bool = False):
        """Initialize mapper; reference mappings are optional and disabled by default."""
        self.use_reference_cves = use_reference_cves
        self.cve_database = self._load_cve_database()

    def _load_cve_database(self) -> Dict[str, List[str]]:
        """Load reference CVE examples by vulnerability class (non-authoritative)."""
        return {
            'SQL Injection': ['CVE-2023-28432'],
            'Cross-Site Scripting (XSS)': ['CVE-2023-26360'],
            'Command Injection': ['CVE-2023-22952'],
            'Buffer Overflow': ['CVE-2023-23560'],
            'XML External Entity (XXE)': ['CVE-2023-1370'],
            'Insecure Deserialization': ['CVE-2023-21839'],
            'Path Traversal': ['CVE-2023-29017'],
            'Server-Side Request Forgery (SSRF)': ['CVE-2023-27524'],
            'Hardcoded Credentials': ['CVE-2023-28121'],
            'Weak Cryptography': ['CVE-2023-2650'],
            'File Inclusion': ['CVE-2023-38646'],
            'Code Injection': ['CVE-2023-33246'],
            'Format String Vulnerability': ['CVE-2023-4863'],
            'Integer Overflow': ['CVE-2023-4863'],
            'Use After Free': ['CVE-2023-5217'],
            'Weak Randomness': ['CVE-2023-20569'],
        }

    def _is_valid_cve(self, value: str) -> bool:
        return bool(value and self.CVE_PATTERN.fullmatch(value.strip().upper()))

    def map_vulnerability_to_cve(self, vulnerability: Dict[str, Any]) -> str:
        """Map vulnerability to CVE only when evidence exists; otherwise return N/A."""
        for key in ('cve', 'cve_id'):
            value = str(vulnerability.get(key, '')).strip().upper()
            if self._is_valid_cve(value):
                return value

        description = vulnerability.get('description', '') or ''
        code_snippet = vulnerability.get('code_snippet', '') or ''

        for text in (description, code_snippet):
            match = self.CVE_PATTERN.search(text)
            if match:
                return match.group(0).upper()

        if self.use_reference_cves:
            vuln_type = vulnerability.get('type', '')
            refs = self.cve_database.get(vuln_type, [])
            if refs:
                return refs[0]

        return 'N/A'

    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Get basic details for a valid CVE id."""
        normalized = (cve_id or '').strip().upper()
        if not self._is_valid_cve(normalized):
            return {
                'cve_id': 'N/A',
                'description': 'No validated CVE available',
                'severity': 'Unknown',
                'cvss_score': None,
                'published_date': None,
                'references': [],
            }

        return {
            'cve_id': normalized,
            'description': f'Reference details for {normalized}',
            'severity': 'Unknown',
            'cvss_score': None,
            'published_date': None,
            'references': [f'https://nvd.nist.gov/vuln/detail/{normalized}'],
        }

    def search_cve_by_pattern(self, code_pattern: str, language: str) -> List[str]:
        """Return non-authoritative reference CVEs related to a coarse code pattern."""
        relevant_cves = []

        if 'strcpy' in code_pattern or 'strcat' in code_pattern:
            relevant_cves.extend(self.cve_database.get('Buffer Overflow', []))
        if 'eval(' in code_pattern or 'exec(' in code_pattern:
            relevant_cves.extend(self.cve_database.get('Code Injection', []))
        if re.search(r'SELECT.*[+\.]', code_pattern):
            relevant_cves.extend(self.cve_database.get('SQL Injection', []))

        return list(dict.fromkeys(relevant_cves))[:5]
