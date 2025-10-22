"""Java source code parser"""

import re
from typing import Dict, List, Any, Optional
from .base_parser import BaseParser


class JavaParser(BaseParser):
    """Parser for Java source code"""
    
    def __init__(self):
        super().__init__('java')
        self.file_extensions = ['.java']
        
    def parse(self, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse Java source code
        
        Args:
            code: Java source code
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
                'num_lines': len(lines),
                'package': self._extract_package(code),
                'class_names': self._extract_classes(code)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path,
                'language': self.language
            }
    
    def _extract_package(self, code: str) -> Optional[str]:
        """Extract package declaration"""
        match = re.search(r'package\s+([\w\.]+);', code)
        return match.group(1) if match else None
    
    def _extract_classes(self, code: str) -> List[str]:
        """Extract class names"""
        pattern = r'(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?class\s+(\w+)'
        matches = re.findall(pattern, code)
        return matches
    
    def extract_functions(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract method definitions"""
        if not parsed_code.get('success'):
            return []
        
        functions = []
        code = parsed_code['code']
        lines = parsed_code['lines']
        
        # Pattern for Java methods
        pattern = r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:synchronized)?\s*(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)'
        
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line)
            if match and not any(keyword in line for keyword in ['class', 'interface', 'enum']):
                return_type = match.group(1)
                method_name = match.group(2)
                params = match.group(3)
                
                functions.append({
                    'name': method_name,
                    'return_type': return_type,
                    'parameters': params.strip(),
                    'line_number': i
                })
        
        return functions
    
    def extract_imports(self, parsed_code: Dict[str, Any]) -> List[str]:
        """Extract import statements"""
        if not parsed_code.get('success'):
            return []
        
        imports = []
        code = parsed_code['code']
        
        pattern = r'import\s+(?:static\s+)?([\w\.]+(?:\.\*)?);'
        matches = re.findall(pattern, code)
        
        return matches
    
    def find_sql_injection_patterns(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find SQL injection vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        for i, line in enumerate(lines, 1):
            # Look for string concatenation in SQL queries
            if any(keyword in line for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'executeQuery', 'executeUpdate']):
                if '+' in line and ('"' in line or "'" in line):
                    issues.append({
                        'line': i,
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'description': 'Potential SQL injection via string concatenation'
                    })
        
        return issues
    
    def find_command_injection(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find command injection vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        dangerous_patterns = [
            'Runtime.getRuntime().exec',
            'ProcessBuilder',
            'Runtime.exec'
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in dangerous_patterns:
                if pattern in line:
                    issues.append({
                        'line': i,
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': f'Potential command injection using {pattern}'
                    })
        
        return issues
    
    def find_xxe_vulnerabilities(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find XML External Entity (XXE) vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        code = parsed_code['code']
        lines = parsed_code['lines']
        
        # Check for unsafe XML parsing
        if 'DocumentBuilderFactory' in code or 'SAXParserFactory' in code:
            for i, line in enumerate(lines, 1):
                if 'DocumentBuilderFactory' in line or 'SAXParserFactory' in line:
                    # Check if XXE protection is missing
                    next_lines = '\n'.join(lines[i:min(i+10, len(lines))])
                    if 'setFeature' not in next_lines or 'disallow-doctype-decl' not in next_lines:
                        issues.append({
                            'line': i,
                            'type': 'XXE Vulnerability',
                            'severity': 'High',
                            'description': 'XML parser may be vulnerable to XXE attacks'
                        })
        
        return issues
