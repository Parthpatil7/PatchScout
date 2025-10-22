"""Main code analyzer orchestrating all components"""

from typing import Dict, List, Any, Optional
from pathlib import Path
import time

from ..parsers import JavaParser, PythonParser, CParser, PHPParser
from ..detectors import VulnerabilityDetector, CVEMapper, CWEMapper
from .language_detector import LanguageDetector


class CodeAnalyzer:
    """Main code analyzer coordinating parsing and detection"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize code analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.language_detector = LanguageDetector()
        self.vulnerability_detector = VulnerabilityDetector(config)
        self.cve_mapper = CVEMapper()
        self.cwe_mapper = CWEMapper()
        
        # Initialize parsers
        self.parsers = {
            'python': PythonParser(),
            'java': JavaParser(),
            'c': CParser(),
            'cpp': CParser(),  # Use C parser for C++
            'php': PHPParser()
        }
        
    def analyze_file(self, file_path: str, language: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a single file for vulnerabilities
        
        Args:
            file_path: Path to the file
            language: Optional language override
            
        Returns:
            Analysis results dictionary
        """
        start_time = time.time()
        
        # Detect language if not provided
        if not language:
            language = self.language_detector.detect(file_path)
            if not language:
                return {
                    'success': False,
                    'error': 'Unable to detect language',
                    'file_path': file_path
                }
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to read file: {str(e)}',
                'file_path': file_path
            }
        
        # Parse code
        parser = self.parsers.get(language.lower())
        if parser:
            parsed_code = parser.parse(code, file_path)
        else:
            parsed_code = {'success': True, 'code': code, 'lines': code.split('\n')}
        
        # Detect vulnerabilities
        vulnerabilities = self.vulnerability_detector.detect(code, language, file_path)
        
        # Add parser-specific vulnerabilities
        if parser and parsed_code.get('success'):
            vulnerabilities.extend(self._get_parser_vulnerabilities(parser, parsed_code))
        
        # Enhance vulnerabilities with CVE and CWE mappings
        for vuln in vulnerabilities:
            if 'cwe' not in vuln or not vuln['cwe']:
                vuln['cwe'] = self.cwe_mapper.get_cwe_from_vulnerability_type(vuln.get('type', ''))
            
            if 'cve' not in vuln:
                vuln['cve'] = self.cve_mapper.map_vulnerability_to_cve(vuln)
        
        processing_time = time.time() - start_time
        file_size_kb = len(code) / 1024
        
        return {
            'success': True,
            'file_path': file_path,
            'language': language,
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities),
            'processing_time': processing_time,
            'file_size_kb': file_size_kb,
            'lines_of_code': len(code.split('\n'))
        }
    
    def _get_parser_vulnerabilities(self, parser, parsed_code: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get language-specific vulnerabilities from parser"""
        vulnerabilities = []
        
        # Python-specific
        if isinstance(parser, PythonParser):
            dangerous_funcs = parser.find_dangerous_functions(parsed_code)
            for func in dangerous_funcs:
                vulnerabilities.append({
                    'type': func['risk_type'],
                    'severity': 'High',
                    'line_number': func['line'],
                    'code_snippet': f"Use of {func['function']}()",
                    'description': f"Dangerous function {func['function']}() detected",
                    'file_path': parsed_code.get('file_path', ''),
                    'language': 'python'
                })
            
            sql_issues = parser.find_sql_patterns(parsed_code)
            vulnerabilities.extend(sql_issues)
        
        # Java-specific
        elif isinstance(parser, JavaParser):
            sql_issues = parser.find_sql_injection_patterns(parsed_code)
            vulnerabilities.extend(sql_issues)
            
            cmd_issues = parser.find_command_injection(parsed_code)
            vulnerabilities.extend(cmd_issues)
            
            xxe_issues = parser.find_xxe_vulnerabilities(parsed_code)
            vulnerabilities.extend(xxe_issues)
        
        # C/C++-specific
        elif isinstance(parser, CParser):
            buffer_issues = parser.find_buffer_overflow(parsed_code)
            vulnerabilities.extend(buffer_issues)
            
            format_issues = parser.find_format_string_bugs(parsed_code)
            vulnerabilities.extend(format_issues)
            
            uaf_issues = parser.find_use_after_free(parsed_code)
            vulnerabilities.extend(uaf_issues)
            
            int_issues = parser.find_integer_overflow(parsed_code)
            vulnerabilities.extend(int_issues)
        
        # PHP-specific
        elif isinstance(parser, PHPParser):
            sql_issues = parser.find_sql_injection(parsed_code)
            vulnerabilities.extend(sql_issues)
            
            xss_issues = parser.find_xss_vulnerabilities(parsed_code)
            vulnerabilities.extend(xss_issues)
            
            cmd_issues = parser.find_command_injection(parsed_code)
            vulnerabilities.extend(cmd_issues)
            
            file_issues = parser.find_file_inclusion(parsed_code)
            vulnerabilities.extend(file_issues)
            
            deser_issues = parser.find_insecure_deserialization(parsed_code)
            vulnerabilities.extend(deser_issues)
        
        return vulnerabilities
    
    def analyze_directory(self, directory_path: str, recursive: bool = True) -> List[Dict[str, Any]]:
        """
        Analyze all supported files in a directory
        
        Args:
            directory_path: Path to the directory
            recursive: Whether to search recursively
            
        Returns:
            List of analysis results
        """
        results = []
        path = Path(directory_path)
        
        # Get all supported files
        if recursive:
            files = [f for f in path.rglob('*') if f.is_file()]
        else:
            files = [f for f in path.glob('*') if f.is_file()]
        
        for file_path in files:
            if self.language_detector.is_supported(str(file_path)):
                result = self.analyze_file(str(file_path))
                if result.get('success'):
                    results.append(result)
        
        return results
    
    def get_summary_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate summary statistics from analysis results
        
        Args:
            results: List of analysis results
            
        Returns:
            Summary statistics dictionary
        """
        total_files = len(results)
        total_vulnerabilities = sum(r.get('vulnerability_count', 0) for r in results)
        total_processing_time = sum(r.get('processing_time', 0) for r in results)
        
        # Count by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        # Count by type
        type_counts = {}
        # Count by language
        language_counts = {}
        
        for result in results:
            language = result.get('language', 'Unknown')
            language_counts[language] = language_counts.get(language, 0) + 1
            
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'Medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                vuln_type = vuln.get('type', 'Unknown')
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            'total_files_analyzed': total_files,
            'total_vulnerabilities': total_vulnerabilities,
            'total_processing_time': round(total_processing_time, 2),
            'average_time_per_file': round(total_processing_time / total_files, 2) if total_files > 0 else 0,
            'vulnerabilities_by_severity': severity_counts,
            'vulnerabilities_by_type': type_counts,
            'files_by_language': language_counts
        }
