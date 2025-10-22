"""PHP source code parser"""

import re
from typing import Dict, List, Any, Optional
from .base_parser import BaseParser


class PHPParser(BaseParser):
    """Parser for PHP source code"""
    
    def __init__(self):
        super().__init__('php')
        self.file_extensions = ['.php', '.php3', '.php4', '.php5', '.phtml']
        
    def parse(self, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse PHP source code
        
        Args:
            code: PHP source code
            file_path: Optional file path
            
        Returns:
            Dictionary with parsed information
        """
        try:
            lines = code.split('\n')
            
            return {
                'success': True,
                'code': code,
                'file_path': file_path,
                'language': self.language,
                'lines': lines,
                'num_lines': len(lines)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path,
                'language': self.language
            }
    
    def extract_functions(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        if not parsed_code.get('success'):
            return []
        
        functions = []
        lines = parsed_code['lines']
        
        # Pattern for PHP functions
        pattern = r'function\s+(\w+)\s*\(([^)]*)\)'
        
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line)
            if match:
                func_name = match.group(1)
                params = match.group(2)
                
                functions.append({
                    'name': func_name,
                    'parameters': params.strip(),
                    'line_number': i
                })
        
        return functions
    
    def extract_imports(self, parsed_code: Dict[str, Any]) -> List[str]:
        """Extract include/require statements"""
        if not parsed_code.get('success'):
            return []
        
        imports = []
        code = parsed_code['code']
        
        patterns = [
            r'require(?:_once)?\s*\(?[\'"]([^\'"]+)[\'"]',
            r'include(?:_once)?\s*\(?[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, code)
            imports.extend(matches)
        
        return imports
    
    def find_sql_injection(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find SQL injection vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        for i, line in enumerate(lines, 1):
            # Look for SQL queries with variable concatenation
            if any(keyword in line.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                # Check for string concatenation with variables
                if re.search(r'[\'\"].*?\$\w+.*?[\'\"]', line) or '.' in line and '$' in line:
                    issues.append({
                        'line': i,
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': 'Potential SQL injection via variable concatenation'
                    })
                    
            # Check for mysql_query with variables
            if 'mysql_query' in line or 'mysqli_query' in line:
                if '$' in line:
                    issues.append({
                        'line': i,
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': 'Potential SQL injection in database query'
                    })
        
        return issues
    
    def find_xss_vulnerabilities(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find Cross-Site Scripting (XSS) vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        for i, line in enumerate(lines, 1):
            # Look for echo/print with user input
            if re.search(r'echo\s+\$_(GET|POST|REQUEST|COOKIE)', line):
                issues.append({
                    'line': i,
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'description': 'Potential XSS via unfiltered user input'
                })
            
            # Check for print_r, var_dump with user input
            if re.search(r'(print_r|var_dump)\s*\(\s*\$_(GET|POST|REQUEST)', line):
                issues.append({
                    'line': i,
                    'type': 'Information Disclosure',
                    'severity': 'Medium',
                    'description': 'Potential information disclosure'
                })
        
        return issues
    
    def find_command_injection(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find command injection vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        dangerous_funcs = [
            'exec', 'shell_exec', 'system', 'passthru',
            'popen', 'proc_open', 'pcntl_exec', 'eval'
        ]
        
        for i, line in enumerate(lines, 1):
            for func in dangerous_funcs:
                if re.search(rf'\b{func}\s*\(', line) and '$' in line:
                    issues.append({
                        'line': i,
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'function': func,
                        'description': f'Potential command injection via {func}()'
                    })
        
        return issues
    
    def find_file_inclusion(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find file inclusion vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        for i, line in enumerate(lines, 1):
            # Look for include/require with user input
            if re.search(r'(include|require)(?:_once)?\s*\(?\s*\$_(GET|POST|REQUEST)', line):
                issues.append({
                    'line': i,
                    'type': 'File Inclusion',
                    'severity': 'Critical',
                    'description': 'Potential Local/Remote File Inclusion vulnerability'
                })
        
        return issues
    
    def find_insecure_deserialization(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find insecure deserialization vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        for i, line in enumerate(lines, 1):
            if 'unserialize' in line and '$' in line:
                issues.append({
                    'line': i,
                    'type': 'Insecure Deserialization',
                    'severity': 'High',
                    'description': 'Potential insecure deserialization'
                })
        
        return issues
