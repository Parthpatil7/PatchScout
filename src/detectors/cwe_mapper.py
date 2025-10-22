"""CWE (Common Weakness Enumeration) Mapper"""

from typing import Dict, List, Any, Optional


class CWEMapper:
    """Maps vulnerabilities to CWE IDs"""
    
    def __init__(self):
        """Initialize CWE mapper"""
        self.cwe_database = self._load_cwe_database()
        
    def _load_cwe_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Load CWE database with Top 25 and OWASP mappings
        
        Returns:
            Dictionary mapping CWE IDs to details
        """
        return {
            'CWE-89': {
                'name': 'SQL Injection',
                'description': 'Improper Neutralization of Special Elements used in an SQL Command',
                'severity': 'Critical',
                'rank': 1,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-79': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Improper Neutralization of Input During Web Page Generation',
                'severity': 'High',
                'rank': 2,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-78': {
                'name': 'OS Command Injection',
                'description': 'Improper Neutralization of Special Elements used in an OS Command',
                'severity': 'Critical',
                'rank': 3,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-787': {
                'name': 'Out-of-bounds Write',
                'description': 'Software writes data past the end of intended buffer',
                'severity': 'Critical',
                'rank': 4,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-20': {
                'name': 'Improper Input Validation',
                'description': 'Product does not validate input properly',
                'severity': 'High',
                'rank': 5,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-125': {
                'name': 'Out-of-bounds Read',
                'description': 'Software reads data past the end of intended buffer',
                'severity': 'High',
                'rank': 6,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-416': {
                'name': 'Use After Free',
                'description': 'Referencing memory after it has been freed',
                'severity': 'Critical',
                'rank': 7,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-22': {
                'name': 'Path Traversal',
                'description': 'Improper Limitation of a Pathname to a Restricted Directory',
                'severity': 'High',
                'rank': 8,
                'owasp': 'A01:2021 - Broken Access Control'
            },
            'CWE-352': {
                'name': 'Cross-Site Request Forgery (CSRF)',
                'description': 'Application does not verify that request is from authenticated user',
                'severity': 'Medium',
                'rank': 9,
                'owasp': 'A01:2021 - Broken Access Control'
            },
            'CWE-434': {
                'name': 'Unrestricted Upload of Dangerous File Type',
                'description': 'Software allows upload of dangerous file types',
                'severity': 'High',
                'rank': 10,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-862': {
                'name': 'Missing Authorization',
                'description': 'Software does not perform authorization check',
                'severity': 'High',
                'rank': 11,
                'owasp': 'A01:2021 - Broken Access Control'
            },
            'CWE-476': {
                'name': 'NULL Pointer Dereference',
                'description': 'NULL pointer is dereferenced causing segfault',
                'severity': 'Medium',
                'rank': 12,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-287': {
                'name': 'Improper Authentication',
                'description': 'Authentication is not performed or can be bypassed',
                'severity': 'Critical',
                'rank': 13,
                'owasp': 'A07:2021 - Identification and Authentication Failures'
            },
            'CWE-190': {
                'name': 'Integer Overflow',
                'description': 'Integer computation can result in overflow',
                'severity': 'High',
                'rank': 14,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-502': {
                'name': 'Insecure Deserialization',
                'description': 'Deserialization of Untrusted Data',
                'severity': 'High',
                'rank': 15,
                'owasp': 'A08:2021 - Software and Data Integrity Failures'
            },
            'CWE-77': {
                'name': 'Command Injection',
                'description': 'Improper Neutralization of Special Elements in Command',
                'severity': 'Critical',
                'rank': 16,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-119': {
                'name': 'Buffer Errors',
                'description': 'Improper Restriction of Operations within Bounds of Memory Buffer',
                'severity': 'Critical',
                'rank': 17,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-798': {
                'name': 'Hardcoded Credentials',
                'description': 'Use of Hard-coded Credentials',
                'severity': 'High',
                'rank': 18,
                'owasp': 'A07:2021 - Identification and Authentication Failures'
            },
            'CWE-918': {
                'name': 'Server-Side Request Forgery (SSRF)',
                'description': 'Server performs request to untrusted URL',
                'severity': 'High',
                'rank': 19,
                'owasp': 'A10:2021 - Server-Side Request Forgery'
            },
            'CWE-306': {
                'name': 'Missing Authentication',
                'description': 'Missing Authentication for Critical Function',
                'severity': 'Critical',
                'rank': 20,
                'owasp': 'A07:2021 - Identification and Authentication Failures'
            },
            'CWE-362': {
                'name': 'Race Condition',
                'description': 'Concurrent Execution using Shared Resource',
                'severity': 'Medium',
                'rank': 21,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-269': {
                'name': 'Improper Privilege Management',
                'description': 'Improper Privilege Management',
                'severity': 'High',
                'rank': 22,
                'owasp': 'A01:2021 - Broken Access Control'
            },
            'CWE-94': {
                'name': 'Code Injection',
                'description': 'Improper Control of Generation of Code',
                'severity': 'Critical',
                'rank': 23,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-863': {
                'name': 'Incorrect Authorization',
                'description': 'Incorrect Authorization',
                'severity': 'High',
                'rank': 24,
                'owasp': 'A01:2021 - Broken Access Control'
            },
            'CWE-276': {
                'name': 'Incorrect Default Permissions',
                'description': 'Incorrect Default Permissions',
                'severity': 'Medium',
                'rank': 25,
                'owasp': 'A05:2021 - Security Misconfiguration'
            },
            'CWE-120': {
                'name': 'Buffer Overflow',
                'description': 'Buffer Copy without Checking Size of Input',
                'severity': 'Critical',
                'rank': 26,
                'owasp': 'A04:2021 - Insecure Design'
            },
            'CWE-611': {
                'name': 'XML External Entity (XXE)',
                'description': 'Improper Restriction of XML External Entity Reference',
                'severity': 'High',
                'rank': 27,
                'owasp': 'A05:2021 - Security Misconfiguration'
            },
            'CWE-327': {
                'name': 'Weak Cryptography',
                'description': 'Use of a Broken or Risky Cryptographic Algorithm',
                'severity': 'Medium',
                'rank': 28,
                'owasp': 'A02:2021 - Cryptographic Failures'
            },
            'CWE-98': {
                'name': 'PHP File Inclusion',
                'description': 'Improper Control of Filename for Include/Require',
                'severity': 'Critical',
                'rank': 29,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-134': {
                'name': 'Format String',
                'description': 'Use of Externally-Controlled Format String',
                'severity': 'High',
                'rank': 30,
                'owasp': 'A03:2021 - Injection'
            },
            'CWE-330': {
                'name': 'Weak Random',
                'description': 'Use of Insufficiently Random Values',
                'severity': 'Medium',
                'rank': 31,
                'owasp': 'A02:2021 - Cryptographic Failures'
            },
            'CWE-95': {
                'name': 'Eval Injection',
                'description': 'Improper Neutralization of Directives in Dynamically Evaluated Code',
                'severity': 'Critical',
                'rank': 32,
                'owasp': 'A03:2021 - Injection'
            }
        }
    
    def get_cwe_from_vulnerability_type(self, vuln_type: str) -> str:
        """
        Get CWE ID from vulnerability type
        
        Args:
            vuln_type: Vulnerability type name
            
        Returns:
            CWE ID string
        """
        # Direct mapping from vulnerability type to CWE
        type_to_cwe = {
            'SQL Injection': 'CWE-89',
            'Cross-Site Scripting (XSS)': 'CWE-79',
            'Cross-Site Scripting': 'CWE-79',
            'Command Injection': 'CWE-78',
            'OS Command Injection': 'CWE-78',
            'Buffer Overflow': 'CWE-120',
            'Path Traversal': 'CWE-22',
            'Insecure Deserialization': 'CWE-502',
            'Hardcoded Credentials': 'CWE-798',
            'Server-Side Request Forgery (SSRF)': 'CWE-918',
            'Server-Side Request Forgery': 'CWE-918',
            'XML External Entity (XXE)': 'CWE-611',
            'XML External Entity': 'CWE-611',
            'Weak Cryptography': 'CWE-327',
            'File Inclusion': 'CWE-98',
            'Code Injection': 'CWE-94',
            'Format String Vulnerability': 'CWE-134',
            'Format String': 'CWE-134',
            'Integer Overflow': 'CWE-190',
            'Use After Free': 'CWE-416',
            'Weak Randomness': 'CWE-330',
            'Weak Random': 'CWE-330',
            'Dangerous Import': 'CWE-95',
            'Information Disclosure': 'CWE-200',
            'Missing Authentication': 'CWE-306',
            'Improper Authentication': 'CWE-287'
        }
        
        return type_to_cwe.get(vuln_type, 'CWE-Other')
    
    def get_cwe_details(self, cwe_id: str) -> Dict[str, Any]:
        """
        Get details about a CWE
        
        Args:
            cwe_id: CWE identifier (e.g., 'CWE-89')
            
        Returns:
            Dictionary with CWE details
        """
        return self.cwe_database.get(cwe_id, {
            'name': 'Unknown',
            'description': f'Details for {cwe_id}',
            'severity': 'Medium',
            'rank': 999,
            'owasp': 'N/A'
        })
    
    def get_owasp_category(self, cwe_id: str) -> str:
        """
        Get OWASP Top 10 category for a CWE
        
        Args:
            cwe_id: CWE identifier
            
        Returns:
            OWASP category string
        """
        cwe_info = self.get_cwe_details(cwe_id)
        return cwe_info.get('owasp', 'N/A')
    
    def get_top_25_cwe_ids(self) -> List[str]:
        """
        Get list of CWE Top 25 IDs
        
        Returns:
            List of CWE IDs in Top 25
        """
        top_25 = [(cwe_id, info['rank']) for cwe_id, info in self.cwe_database.items() 
                  if info.get('rank', 999) <= 25]
        top_25.sort(key=lambda x: x[1])
        return [cwe_id for cwe_id, _ in top_25]
