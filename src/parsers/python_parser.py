"""Python source code parser"""

import ast
from typing import Dict, List, Any, Optional
from .base_parser import BaseParser


class PythonParser(BaseParser):
    """Parser for Python source code"""
    
    def __init__(self):
        super().__init__('python')
        self.file_extensions = ['.py', '.pyw']
        
    def parse(self, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse Python source code
        
        Args:
            code: Python source code
            file_path: Optional file path
            
        Returns:
            Dictionary with parsed information
        """
        try:
            tree = ast.parse(code)
            
            return {
                'success': True,
                'ast': tree,
                'file_path': file_path,
                'language': self.language,
                'lines': code.split('\n'),
                'num_lines': len(code.split('\n'))
            }
        except SyntaxError as e:
            return {
                'success': False,
                'error': str(e),
                'error_line': e.lineno if hasattr(e, 'lineno') else None,
                'file_path': file_path,
                'language': self.language
            }
    
    def extract_functions(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        if not parsed_code.get('success'):
            return []
        
        functions = []
        tree = parsed_code['ast']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'line_number': node.lineno,
                    'args': [arg.arg for arg in node.args.args],
                    'decorators': [d.id if isinstance(d, ast.Name) else str(d) 
                                 for d in node.decorator_list],
                    'is_async': isinstance(node, ast.AsyncFunctionDef)
                })
        
        return functions
    
    def extract_imports(self, parsed_code: Dict[str, Any]) -> List[str]:
        """Extract import statements"""
        if not parsed_code.get('success'):
            return []
        
        imports = []
        tree = parsed_code['ast']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}" if module else alias.name)
        
        return imports
    
    def find_dangerous_functions(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Find potentially dangerous function calls
        
        Args:
            parsed_code: Parsed code dictionary
            
        Returns:
            List of dangerous function calls
        """
        dangerous_calls = []
        
        if not parsed_code.get('success'):
            return dangerous_calls
        
        # Dangerous functions to look for
        dangerous_funcs = {
            'eval': 'Code Injection',
            'exec': 'Code Injection',
            'compile': 'Code Injection',
            '__import__': 'Dynamic Import',
            'open': 'File Access',
            'input': 'User Input',
            'os.system': 'Command Execution',
            'subprocess.call': 'Command Execution',
            'subprocess.run': 'Command Execution',
            'subprocess.Popen': 'Command Execution',
            'pickle.loads': 'Insecure Deserialization',
            'yaml.load': 'Insecure Deserialization',
            'marshal.loads': 'Insecure Deserialization'
        }
        
        tree = parsed_code['ast']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                
                if func_name in dangerous_funcs:
                    dangerous_calls.append({
                        'function': func_name,
                        'line': node.lineno,
                        'risk_type': dangerous_funcs[func_name]
                    })
        
        return dangerous_calls
    
    def find_sql_patterns(self, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential SQL injection patterns"""
        sql_issues = []
        
        if not parsed_code.get('success'):
            return sql_issues
        
        tree = parsed_code['ast']
        lines = parsed_code.get('lines', [])
        
        for node in ast.walk(tree):
            # Look for string formatting with SQL keywords
            if isinstance(node, (ast.BinOp, ast.JoinedStr)):
                if hasattr(node, 'lineno'):
                    line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ''
                    
                    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE']
                    if any(keyword in line_content.upper() for keyword in sql_keywords):
                        # Check if using string concatenation or f-strings
                        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                            sql_issues.append({
                                'line': node.lineno,
                                'type': 'SQL Injection via String Concatenation',
                                'severity': 'High'
                            })
                        elif isinstance(node, ast.JoinedStr):
                            sql_issues.append({
                                'line': node.lineno,
                                'type': 'SQL Injection via f-string',
                                'severity': 'High'
                            })
        
        return sql_issues
