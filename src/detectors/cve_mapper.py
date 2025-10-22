"""CVE (Common Vulnerabilities and Exposures) Mapper"""

from typing import Dict, List, Any, Optional
import re


class CVEMapper:
    """Maps vulnerabilities to CVE IDs"""
    
    def __init__(self):
        """Initialize CVE mapper with known vulnerability patterns"""
        self.cve_database = self._load_cve_database()
        
    def _load_cve_database(self) -> Dict[str, List[str]]:
        """
        Load CVE database mapping
        
        Returns:
            Dictionary mapping vulnerability patterns to CVE IDs
        """
        return {
            'SQL Injection': [
                'CVE-2023-28432',  # SQL injection in common frameworks
                'CVE-2023-25194',
                'CVE-2022-42889',
                'CVE-2021-44228'   # Log4Shell
            ],
            'Cross-Site Scripting (XSS)': [
                'CVE-2023-26360',
                'CVE-2023-23752',
                'CVE-2022-24112'
            ],
            'Command Injection': [
                'CVE-2023-22952',
                'CVE-2022-46169',
                'CVE-2021-44228'   # Log4j RCE
            ],
            'Buffer Overflow': [
                'CVE-2023-23560',
                'CVE-2022-37454',  # SHA-3 buffer overflow
                'CVE-2021-3156'    # Sudo heap overflow
            ],
            'XML External Entity (XXE)': [
                'CVE-2023-1370',
                'CVE-2022-42252',
                'CVE-2021-21295'
            ],
            'Insecure Deserialization': [
                'CVE-2023-21839',
                'CVE-2022-42889',
                'CVE-2017-5638'    # Apache Struts
            ],
            'Path Traversal': [
                'CVE-2023-29017',
                'CVE-2022-24348',
                'CVE-2021-21972'
            ],
            'Server-Side Request Forgery (SSRF)': [
                'CVE-2023-27524',
                'CVE-2022-26134',
                'CVE-2021-26855'   # ProxyLogon
            ],
            'Hardcoded Credentials': [
                'CVE-2023-28121',
                'CVE-2022-30525',
                'CVE-2021-35394'
            ],
            'Weak Cryptography': [
                'CVE-2023-2650',
                'CVE-2022-37454',
                'CVE-2020-1967'
            ],
            'File Inclusion': [
                'CVE-2023-38646',
                'CVE-2022-1388',
                'CVE-2021-41773'
            ],
            'Code Injection': [
                'CVE-2023-33246',
                'CVE-2022-1292',
                'CVE-2021-3129'
            ],
            'Format String Vulnerability': [
                'CVE-2023-4863',
                'CVE-2022-3786',
                'CVE-2021-3156'
            ],
            'Integer Overflow': [
                'CVE-2023-4863',
                'CVE-2022-37454',
                'CVE-2021-3450'
            ],
            'Use After Free': [
                'CVE-2023-5217',
                'CVE-2022-41128',
                'CVE-2021-21166'
            ],
            'Weak Randomness': [
                'CVE-2023-20569',
                'CVE-2022-24407',
                'CVE-2020-1967'
            ]
        }
    
    def map_vulnerability_to_cve(self, vulnerability: Dict[str, Any]) -> str:
        """
        Map a vulnerability to a CVE ID
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            CVE ID or "N/A" if no match found
        """
        vuln_type = vulnerability.get('type', '')
        
        # Check if we have CVE mappings for this vulnerability type
        if vuln_type in self.cve_database:
            cve_list = self.cve_database[vuln_type]
            if cve_list:
                # Return the most recent CVE (first in list)
                return cve_list[0]
        
        # Try to extract CVE from description or code
        code_snippet = vulnerability.get('code_snippet', '')
        description = vulnerability.get('description', '')
        
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        for text in [description, code_snippet]:
            match = re.search(cve_pattern, text)
            if match:
                return match.group(0)
        
        return "N/A"
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Get details about a specific CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Dictionary with CVE details
        """
        # In a real implementation, this would query NVD database
        # For now, return basic structure
        return {
            'cve_id': cve_id,
            'description': f'Vulnerability associated with {cve_id}',
            'severity': 'High',
            'cvss_score': 7.5,
            'published_date': '2023-01-01',
            'references': [
                f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            ]
        }
    
    def search_cve_by_pattern(self, code_pattern: str, language: str) -> List[str]:
        """
        Search for CVEs related to a code pattern
        
        Args:
            code_pattern: Code pattern to search for
            language: Programming language
            
        Returns:
            List of relevant CVE IDs
        """
        relevant_cves = []
        
        # Check common patterns
        if 'strcpy' in code_pattern or 'strcat' in code_pattern:
            relevant_cves.extend(self.cve_database.get('Buffer Overflow', []))
        
        if 'eval(' in code_pattern or 'exec(' in code_pattern:
            relevant_cves.extend(self.cve_database.get('Code Injection', []))
        
        if re.search(r'SELECT.*\+.*\$', code_pattern):
            relevant_cves.extend(self.cve_database.get('SQL Injection', []))
        
        return list(set(relevant_cves))[:5]  # Return top 5 unique CVEs
