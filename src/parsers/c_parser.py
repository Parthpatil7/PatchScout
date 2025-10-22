"""C/C++ source code parser"""

import re
from typing import Dict, List, Any, Optional
from .base_parser import BaseParser


class CParser(BaseParser):
    """Parser for C/C++ source code"""
    
    def __init__(self):
        super().__init__('c')
        self.file_extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']
        
    def parse(self, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse C/C++ source code
        
        Args:
            code: C/C++ source code
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
                'includes': self._extract_includes(code)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path,
                'language': self.language
            }
    
    def _extract_includes(self, code: str) -> List[str]:
        """Extract #include statements"""
        pattern = r'#include\s+[<"]([^>"]+)[>"]'
        matches = re.findall(pattern, code)
        return matches
    
    def extract_functions(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        if not parsed_code.get('success'):
            return []
        
        functions = []
        lines = parsed_code['lines']
        
        # Simple pattern for C/C++ functions
        pattern = r'^\s*(?:static\s+)?(?:inline\s+)?(\w+(?:\s*\*)?)\s+(\w+)\s*\(([^)]*)\)'
        
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line)
            if match and '{' in line or (i < len(lines) and '{' in lines[i]):
                return_type = match.group(1).strip()
                func_name = match.group(2)
                params = match.group(3).strip()
                
                functions.append({
                    'name': func_name,
                    'return_type': return_type,
                    'parameters': params,
                    'line_number': i
                })
        
        return functions
    
    def extract_imports(self, parsed_code: Dict[str, Any]) -> List[str]:
        """Extract include statements"""
        if not parsed_code.get('success'):
            return []
        
        return parsed_code.get('includes', [])
    
    def find_buffer_overflow(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find buffer overflow vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        # Dangerous functions
        dangerous_funcs = [
            'strcpy', 'strcat', 'sprintf', 'vsprintf',
            'gets', 'scanf', 'fscanf', 'sscanf'
        ]
        
        for i, line in enumerate(lines, 1):
            for func in dangerous_funcs:
                if re.search(rf'\b{func}\s*\(', line):
                    issues.append({
                        'line': i,
                        'type': 'Buffer Overflow',
                        'severity': 'Critical',
                        'function': func,
                        'description': f'Use of dangerous function {func}() that can cause buffer overflow'
                    })
        
        return issues
    
    def find_format_string_bugs(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find format string vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        format_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf']
        
        for i, line in enumerate(lines, 1):
            for func in format_funcs:
                # Look for calls without format string
                pattern = rf'{func}\s*\(\s*(\w+)\s*\)'
                if re.search(pattern, line):
                    issues.append({
                        'line': i,
                        'type': 'Format String Vulnerability',
                        'severity': 'High',
                        'description': f'Potential format string vulnerability in {func}()'
                    })
        
        return issues
    
    def find_use_after_free(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential use-after-free vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        freed_vars = set()
        
        for i, line in enumerate(lines, 1):
            # Track free() calls
            free_match = re.search(r'free\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                var_name = free_match.group(1)
                freed_vars.add(var_name)
                
                # Check next few lines for use of freed variable
                for j in range(i, min(i + 20, len(lines))):
                    if j > i and var_name in lines[j] and 'free' not in lines[j]:
                        issues.append({
                            'line': j + 1,
                            'type': 'Use After Free',
                            'severity': 'Critical',
                            'variable': var_name,
                            'description': f'Potential use of freed pointer {var_name}'
                        })
                        break
        
        return issues
    
    def find_integer_overflow(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential integer overflow vulnerabilities"""
        issues = []
        
        if not parsed_code.get('success'):
            return issues
        
        lines = parsed_code['lines']
        
        for i, line in enumerate(lines, 1):
            # Look for malloc/calloc with arithmetic
            if re.search(r'malloc\s*\([^)]*[\+\*][^)]*\)', line):
                issues.append({
                    'line': i,
                    'type': 'Integer Overflow',
                    'severity': 'High',
                    'description': 'Potential integer overflow in memory allocation'
                })
        
        return issues
